package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// limitWriter passes writes to w and fails once more than n bytes are written.
type limitWriter struct {
	w       io.Writer
	n       int64
	written int64
}

var errDiffTooLarge = errors.New("diff too large")

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.written+int64(len(p)) > l.n {
		return 0, errDiffTooLarge
	}
	n, err := l.w.Write(p)
	l.written += int64(n)
	return n, err
}

// Diff returns the workspace patch and the host's summary of it: live from the guest while the box runs, else the
// patch saved at stop.
func (d *Daemon) Diff(ctx context.Context, ref string) ([]byte, api.DiffSummary, error) {
	b, err := d.lookup(ref)
	if err != nil {
		return nil, api.DiffSummary{}, err
	}
	b.mu.Lock()
	st, g := b.info.State, b.guest
	b.mu.Unlock()
	if st == api.StateRunning && g != nil {
		dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		var buf bytes.Buffer
		if err := guestDiff(dctx, g, &limitWriter{w: &buf, n: maxDiffBytes}); err != nil {
			if isTooLarge(err) {
				return nil, api.DiffSummary{}, limitErr("the workspace diff is over %d MiB",
					"keep build output and large files out of /workspace (write them under /tmp)", maxDiffBytes>>20)
			}
			return nil, api.DiffSummary{}, asAPIError(fmt.Errorf("diff from the guest: %w", err))
		}
		return buf.Bytes(), summarize(buf.Bytes()), nil
	}
	patch, err := b.savedPatch(ref)
	if err != nil {
		return nil, api.DiffSummary{}, err
	}
	return patch, summarize(patch), nil
}

// savedPatch reads the patch saved at stop, or says why there is none.
func (b *box) savedPatch(ref string) ([]byte, error) {
	patch, err := os.ReadFile(filepath.Join(b.dir, "diff.patch"))
	if err == nil {
		return patch, nil
	}
	if !os.IsNotExist(err) {
		return nil, asAPIError(err)
	}
	v := b.view()
	why := v.DiffError
	if why == "" {
		why = "a diff is saved when a running box is stopped cleanly"
	}
	return nil, errf(api.CodeNotFound, "", "box %s (%s) has no saved diff: %s", ref, v.State, why)
}

// gatedWrite is one file of a patch, decided as a Write.
type gatedWrite struct {
	path string
	call tracekit.Call
	dec  tracekit.Decision
	want fileState
}

// Apply applies the patch saved when the box stopped to a host checkout. Before anything is decided it validates
// every path (no .git, no escape, no symlinked parents, no copy or rename, nothing under the checkout's hooks dir,
// no change to a git-ignored file), leaves out new files the checkout ignores, refuses files that steer the next run
// or host automation unless AllowSensitive, and works out every file's new content in a scratch copy. Then it asks
// the signer about every file (Write, with the file's new sha256, mode, symlink status and the patch's sha256) and
// only if all are allowed runs `git apply --binary` in the checkout, with git's own config, hooks and filters kept
// out. Check validates and decides but writes nothing.
func (d *Daemon) Apply(ctx context.Context, ref string, req api.ApplyRequest) (api.ApplyResult, error) {
	b, err := d.lookup(ref)
	if err != nil {
		return api.ApplyResult{}, err
	}
	// one apply of a box at a time: a second waits for the first (which may be waiting for an approval)
	select {
	case b.applySem <- struct{}{}:
		defer func() { <-b.applySem }()
	case <-ctx.Done():
		return api.ApplyResult{}, errf(api.CodeCancelled, "", "gave up waiting for another apply of box %s to finish", ref)
	}
	b.calls.begin()
	defer b.calls.end()
	v := b.view()
	b.mu.Lock()
	run, runClosed, closedBy, closeReason := b.run, b.runClosed, b.runClosedBy, b.closeReason
	b.mu.Unlock()
	if alive(v.State) {
		return api.ApplyResult{}, errf(api.CodeConflict, "stop the box first so the patch can't change under you: `tkbox stop "+ref+"`",
			"box %s is %s", ref, v.State)
	}
	dir := req.Dir
	if dir == "" {
		dir = v.Workspace
	}
	if dir == "" {
		return api.ApplyResult{}, errf(api.CodeBadRequest, "pass --dir <checkout>", "box %s has no workspace to apply to", ref)
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return api.ApplyResult{}, errf(api.CodeBadRequest, "pass an absolute path", "dir %q is not an absolute, clean path", dir)
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return api.ApplyResult{}, errf(api.CodeBadRequest, "pass an existing directory (not a symlink)", "dir %s is not a directory", dir)
	}
	patchPath := filepath.Join(b.dir, "diff.patch")
	patch, err := b.savedPatch(ref)
	if err != nil {
		return api.ApplyResult{}, err
	}
	res := api.ApplyResult{Applied: []string{}, Patch: patchPath, Checked: req.Check}
	if len(bytes.TrimSpace(patch)) == 0 {
		return res, nil
	}
	// an unrecorded box's patch has no run to decide its writes in: a daemon that records (restarted with a signer)
	// does not write it ungated
	if v.Unrecorded && d.opts.Tracekit != nil {
		return api.ApplyResult{}, errf(api.CodeConflict, "review it with `tkbox diff "+ref+"`, then apply it yourself: git apply "+patchPath,
			"box %s ran unrecorded, so this recording daemon can't decide or record its writes; apply the saved patch by hand after review: %s", ref, patchPath)
	}
	// a recorded box's writes are decided in its own run, or not at all
	if !v.Unrecorded {
		byHand := "review the saved patch and apply it yourself: git apply " + patchPath
		switch {
		case runClosed && closedBy == "export":
			return api.ApplyResult{}, errf(api.CodeConflict, "apply before exporting; to apply anyway, "+byHand,
				"box %s's Tracekit run was closed by `tkbox export`, so its writes can no longer be recorded", ref)
		case runClosed:
			why := closeReason
			if why == "" {
				why = closedBy
			}
			return api.ApplyResult{}, errf(api.CodeConflict, "to apply anyway, "+byHand,
				"box %s's Tracekit run is closed (%s), so nothing more can be applied", ref, why)
		case run == nil && d.opts.Unrecorded:
			return api.ApplyResult{}, errf(api.CodeConflict, byHand,
				"box %s was recorded but this daemon runs unrecorded, so its writes can't be decided or recorded", ref)
		case run == nil:
			return api.ApplyResult{}, errf(api.CodeConflict, byHand,
				"the box's Tracekit run ended when the daemon restarted; apply the saved patch by hand after review: %s", patchPath)
		}
	}
	refuse := func(format string, a ...any) (api.ApplyResult, error) {
		msg := fmt.Sprintf(format, a...)
		b.event(api.EventApplyDecided, "apply", "apply refused: "+msg, map[string]any{"dir": dir})
		return api.ApplyResult{}, errf(api.CodeBadRequest, "nothing was applied", "%s", msg)
	}
	files, err := parsePatch(string(patch))
	if err != nil {
		return refuse("unsafe or unreadable patch: %v", err)
	}
	for _, f := range files {
		if f.Copy || f.Rename {
			return refuse("the patch copies or renames %q; a box never makes such patches, so it is refused", f.New)
		}
	}
	if _, problems := checkPatch(files, dir); len(problems) > 0 {
		return refuse("unsafe paths in the patch: %s", strings.Join(problems, "; "))
	}
	// git-ignored paths never reach the box: a new one is left out (build output, caches); a change to an existing
	// one claims a file the box never had, so the patch is refused
	var all []string
	for _, f := range files {
		all = append(all, f.Names...)
	}
	ignored, err := checkIgnored(ctx, dir, all, workspaceWasGit(v))
	if err != nil {
		var ae *api.ErrorDetail
		if errors.As(err, &ae) {
			b.event(api.EventApplyDecided, "apply", "apply refused: "+ae.Message, map[string]any{"dir": dir})
			return api.ApplyResult{}, ae
		}
		return api.ApplyResult{}, errf(api.CodeInternal, "check the checkout with `git status`; nothing was applied", "%v", err)
	}
	var kept []*patchFile
	for _, f := range files {
		switch {
		case f.Old != "" && ignored[f.Old]:
			return refuse("the patch changes %q, which the checkout ignores (.gitignore); ignored files never reach the box, so this patch did not come from it", f.Old)
		case f.Old == "" && ignored[f.New]:
			res.Ignored = append(res.Ignored, f.New)
		default:
			kept = append(kept, f)
		}
	}
	if len(res.Ignored) > 0 {
		b.event(api.EventApplyDecided, "apply", fmt.Sprintf("left out %d new files the checkout ignores", len(res.Ignored)),
			map[string]any{"dir": dir, "ignored": res.Ignored})
	}
	if len(kept) == 0 {
		return res, nil
	}
	paths, _ := checkPatch(kept, dir)
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return api.ApplyResult{}, asAPIError(err)
	}
	gitDir, hooks := gitDirs(ctx, dir)
	for _, p := range paths {
		if into := insideDir(realDir, p, hooks); into {
			return refuse("the patch writes %q, inside the checkout's git hooks dir (%s)", p, hooks)
		}
		if into := insideDir(realDir, p, gitDir); into {
			return refuse("the patch writes %q, inside the checkout's git dir (%s)", p, gitDir)
		}
	}
	for _, p := range paths {
		if isSensitive(p) {
			res.Sensitive = append(res.Sensitive, p)
		}
	}
	if len(res.Sensitive) > 0 && !req.AllowSensitive {
		b.event(api.EventApplyDecided, "apply", "apply refused: sensitive files", map[string]any{"dir": dir, "sensitive": res.Sensitive})
		return api.ApplyResult{}, errf(api.CodeBadRequest, "review them with `tkbox diff "+ref+"`, then run `tkbox apply "+ref+" --allow-sensitive`; nothing was applied",
			"the patch changes files that steer the next run or host automation: %s", strings.Join(res.Sensitive, ", "))
	}

	// the patch that is decided is the one that is applied: the kept sections, hashed
	var filtered strings.Builder
	for _, f := range kept {
		filtered.WriteString(f.Raw)
	}
	sum := sha256.Sum256([]byte(filtered.String()))
	res.SHA256 = hex.EncodeToString(sum[:])
	// each apply has its own copy of the patch it decides and applies
	pf, err := os.CreateTemp(b.dir, ".apply-*.patch")
	if err != nil {
		return api.ApplyResult{}, asAPIError(err)
	}
	applyPath := pf.Name()
	defer os.Remove(applyPath)
	_, err = pf.WriteString(filtered.String())
	if cerr := pf.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return api.ApplyResult{}, asAPIError(err)
	}
	pv, out, err := previewApply(ctx, dir, b.dir, kept, paths, applyPath)
	if err != nil {
		b.event(api.EventApplyDecided, "apply", "apply refused: the patch does not apply: "+out, map[string]any{"dir": dir})
		return api.ApplyResult{}, errf(api.CodeConflict, "the checkout changed since the box started; nothing was applied (the patch is at "+patchPath+")",
			"the patch does not apply to %s: %s", dir, firstLine(out, err))
	}
	defer os.RemoveAll(pv.scratch)
	want := pv.want

	var allowed []gatedWrite
	for _, p := range paths {
		g := gatedWrite{path: p, want: want[p]}
		if run != nil {
			args := map[string]any{"file_path": filepath.Join(dir, p), "sha256": g.want.sha256, "mode": g.want.mode,
				"symlink": g.want.symlink, "deleted": g.want.deleted, "patch_sha256": res.SHA256}
			if isSensitive(p) {
				args["sensitive"] = true
			}
			g.call = tracekit.Call{ID: b.nextCallID("write"), Tool: tracekit.ToolWrite, Args: args}
			out, err := d.opts.Gate(ctx, run, g.call, tracekit.GateHooks{OnAsk: func(id string) {
				b.event(api.EventApproval, "apply", fmt.Sprintf("waiting for approval %s to write %s: approve with: tracekit approvals approve %s", id, p, id),
					map[string]any{"approval_id": id, "path": p})
			}})
			if err != nil {
				completeWrites(d, b, run, allowed, "error", map[string]any{"written": false, "reason": "the signer did not answer about another file"})
				var rpc *tracekit.RPCError
				if errors.As(err, &rpc) && rpc.Code == "run_closed" {
					return api.ApplyResult{}, errf(api.CodeConflict, "to apply anyway, review the saved patch and apply it yourself: git apply "+patchPath,
						"the box's run is closed (exported or removed): nothing more can be applied")
				}
				return api.ApplyResult{}, errf(api.CodeUnavailable, "check the signer (`tracekit status`); nothing was applied",
					"the Tracekit signer did not answer about %s: %v", p, err)
			}
			if !out.Allowed {
				res.Denied = append(res.Denied, p)
				continue
			}
			g.dec = out.Decision
		}
		allowed = append(allowed, g)
	}
	if len(res.Denied) > 0 {
		completeWrites(d, b, run, allowed, "error", map[string]any{"written": false, "reason": "another file of the patch was denied"})
		b.event(api.EventApplyDecided, "apply", fmt.Sprintf("apply denied: %d of %d files refused", len(res.Denied), len(paths)),
			map[string]any{"dir": dir, "denied": res.Denied})
		return res, nil
	}
	if req.Check {
		completeWrites(d, b, run, allowed, "error", map[string]any{"written": false, "reason": "check only"})
		res.Applied = paths
		b.event(api.EventApplyDecided, "apply", fmt.Sprintf("apply check passed: %s", plural(len(paths), "file")),
			map[string]any{"dir": dir, "paths": paths, "check": true, "sha256": res.SHA256})
		return res, nil
	}
	// git never runs on the checkout itself: the patch was applied in the scratch copy, and what is written into the
	// checkout is that result, file by file, only once it is exactly what the signer decided and the checkout is still
	// as it was when the decisions were made. From here on the client can't stop it (the request's context is not used)
	if applyScratchHook != nil {
		applyScratchHook(pv.scratch)
	}
	var mismatch []string
	for _, p := range paths {
		if got, err := statFile(filepath.Join(pv.scratch, filepath.FromSlash(p))); err != nil || got != want[p] {
			mismatch = append(mismatch, p)
		}
	}
	if len(mismatch) > 0 {
		completeWrites(d, b, run, allowed, "error", map[string]any{"written": false, "differs_from_decision": mismatch})
		b.event(api.EventApplyDecided, "apply", "apply refused: the patched files differ from what was decided: "+strings.Join(mismatch, ", "),
			map[string]any{"dir": dir, "differ": mismatch})
		return api.ApplyResult{}, errf(api.CodeConflict, "nothing was written; try the apply again (the patch is at "+patchPath+")",
			"the patched %s differ from what was decided: %s", plural(len(mismatch), "file"), strings.Join(mismatch, ", "))
	}
	var changed []string
	for _, p := range paths {
		if got, err := statFile(filepath.Join(dir, filepath.FromSlash(p))); err != nil || got != pv.before[p] {
			changed = append(changed, p)
		}
	}
	if len(changed) > 0 {
		completeWrites(d, b, run, allowed, "error", map[string]any{"written": false, "checkout_changed": changed})
		b.event(api.EventApplyDecided, "apply", "apply refused: the checkout changed while it was decided: "+strings.Join(changed, ", "),
			map[string]any{"dir": dir, "changed": changed})
		return api.ApplyResult{}, errf(api.CodeConflict, "nothing was written; review the checkout with `git status` and apply again (the patch is at "+patchPath+")",
			"the checkout changed while the patch was decided: %s", strings.Join(changed, ", "))
	}
	if written, err := writeResults(dir, pv.scratch, paths, want); err != nil {
		completeWrites(d, b, run, allowed, "error", map[string]any{"written": len(written) > 0, "written_paths": written, "error": err.Error()})
		b.event(api.EventApplyDecided, "apply", "writing the patched files failed: "+err.Error(), map[string]any{"dir": dir, "written": written})
		if len(written) > 0 {
			return api.ApplyResult{}, errf(api.CodeConflict, "review the checkout with `git status` and `git diff` (the patch is at "+patchPath+")",
				"writing the patched files failed after writing %s: %s: %v", plural(len(written), "file"), strings.Join(written, ", "), err)
		}
		return api.ApplyResult{}, errf(api.CodeConflict, "nothing was written; check the checkout (the patch is at "+patchPath+")",
			"writing the patched files failed: %v", err)
	}
	// what landed must be what was decided
	var differ []string
	for _, p := range paths {
		if got, err := statFile(filepath.Join(dir, p)); err != nil || got != want[p] {
			differ = append(differ, p)
		}
	}
	if len(differ) > 0 {
		completeWrites(d, b, run, allowed, "error", map[string]any{"written": true, "differs_from_decision": differ})
		b.event(api.EventApplyDecided, "apply", "applied, but files differ from what was decided: "+strings.Join(differ, ", "),
			map[string]any{"dir": dir, "differ": differ})
		return api.ApplyResult{}, errf(api.CodeConflict, "the checkout changed while the patch was applied; review it with `git diff`",
			"applied, but %s differ from what was decided: %s", plural(len(differ), "file"), strings.Join(differ, ", "))
	}
	completeWrites(d, b, run, allowed, "ok", map[string]any{"written": true})
	res.Applied = paths
	b.event(api.EventApplyDecided, "apply", fmt.Sprintf("applied %s to %s", plural(len(paths), "file"), dir),
		map[string]any{"dir": dir, "paths": paths, "sha256": res.SHA256, "sensitive": res.Sensitive})
	return res, nil
}

// completeWrites completes every allowed Write of an apply.
func completeWrites(d *Daemon, b *box, run tracekit.Run, allowed []gatedWrite, status string, result map[string]any) {
	if run == nil {
		return
	}
	for _, g := range allowed {
		cctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
		if err := run.Complete(cctx, g.call, g.dec, status, result); err != nil {
			b.completeFailed("apply", err)
		}
		cancel()
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func firstLine(out string, err error) string {
	if out = strings.TrimSpace(out); out != "" {
		return out
	}
	return err.Error()
}

// fileState is what a file of the checkout is (or will be) after the patch.
type fileState struct {
	sha256  string // of the content, or of the target for a symlink; "" when deleted
	mode    string // "100644", "100755", "120000"; "" when deleted
	symlink bool
	deleted bool
}

func statFile(p string) (fileState, error) {
	fi, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return fileState{deleted: true}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		t, err := os.Readlink(p)
		if err != nil {
			return fileState{}, err
		}
		s := sha256.Sum256([]byte(t))
		return fileState{sha256: hex.EncodeToString(s[:]), mode: "120000", symlink: true}, nil
	case fi.Mode().IsRegular():
		f, err := os.Open(p)
		if err != nil {
			return fileState{}, err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return fileState{}, err
		}
		mode := "100644"
		if fi.Mode().Perm()&0o111 != 0 {
			mode = "100755"
		}
		return fileState{sha256: hex.EncodeToString(h.Sum(nil)), mode: mode}, nil
	}
	return fileState{}, fmt.Errorf("%s is neither a file nor a symlink", p)
}

// applyScratchHook, when set (tests), runs on the scratch copy after the decisions and before anything is written.
var applyScratchHook func(scratch string)

// preview is a patch applied in a scratch copy of the files it touches: what each path will be (want), what it was
// in the checkout when it was copied (before), and the scratch dir holding the result (the caller removes it).
type preview struct {
	scratch string
	want    map[string]fileState
	before  map[string]fileState
}

// previewApply applies the patch to a scratch copy of the files it touches. It fails (with git's output) when the
// patch does not apply to the checkout as it is now.
func previewApply(ctx context.Context, dir, scratch string, files []*patchFile, paths []string, patchPath string) (preview, string, error) {
	tmp, err := os.MkdirTemp(scratch, ".apply-preview-")
	if err != nil {
		return preview{}, "", err
	}
	pv := preview{scratch: tmp, want: map[string]fileState{}, before: map[string]fileState{}}
	fail := func(out string, err error) (preview, string, error) {
		os.RemoveAll(tmp)
		return preview{}, out, err
	}
	for _, p := range paths {
		st, err := statFile(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil {
			return fail(err.Error(), err)
		}
		pv.before[p] = st
	}
	for _, f := range files {
		if f.Old == "" {
			if _, err := os.Lstat(filepath.Join(dir, f.New)); err == nil {
				return fail(f.New+" already exists in the checkout", errors.New("exists"))
			}
			continue
		}
		if err := copyEntry(filepath.Join(dir, f.Old), filepath.Join(tmp, f.Old)); err != nil {
			return fail(err.Error(), err)
		}
	}
	if out, err := gitApply(ctx, tmp, scratch, patchPath); err != nil {
		return fail(out, err)
	}
	for _, p := range paths {
		st, err := statFile(filepath.Join(tmp, filepath.FromSlash(p)))
		if err != nil {
			return fail(err.Error(), err)
		}
		pv.want[p] = st
	}
	return pv, "", nil
}

// writeResults writes the decided results from the scratch copy into the checkout dir, deletions first: each file
// goes to a new temp file in its own dir (O_EXCL|O_NOFOLLOW), gets its mode and is renamed over the target; a symlink
// is made under a temp name and renamed; a deletion removes only a file or symlink. No parent may be a symlink (each
// one is checked with lstat just before the write). It returns the paths written before any failure.
func writeResults(dir, scratch string, paths []string, want map[string]fileState) ([]string, error) {
	var dels, puts []string
	for _, p := range paths {
		if want[p].deleted {
			dels = append(dels, p)
		} else {
			puts = append(puts, p)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dels))) // children before their parents
	sort.Strings(puts)
	var written []string
	for _, p := range append(dels, puts...) {
		if err := writeResult(dir, scratch, p, want[p]); err != nil {
			return written, fmt.Errorf("%s: %w", p, err)
		}
		written = append(written, p)
	}
	return written, nil
}

func writeResult(dir, scratch, p string, w fileState) error {
	rel := filepath.FromSlash(p)
	abs := filepath.Join(dir, rel)
	parent := filepath.Dir(abs)
	if err := realParents(dir, filepath.Dir(rel), !w.deleted); err != nil {
		return err
	}
	if w.deleted {
		fi, err := os.Lstat(abs)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() && fi.Mode()&os.ModeSymlink == 0 {
			return errors.New("is not a file or a symlink, so it is not deleted")
		}
		if err := os.Remove(abs); err != nil {
			return err
		}
		// like git apply, a dir the deletion left empty goes too
		for d := parent; d != dir && len(d) > len(dir); d = filepath.Dir(d) {
			if os.Remove(d) != nil {
				break
			}
		}
		return nil
	}
	src := filepath.Join(scratch, rel)
	tmp := filepath.Join(parent, ".tkbox-apply-"+randHex(8))
	if w.symlink {
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.Symlink(target, tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, abs); err != nil {
			os.Remove(tmp)
			return err
		}
		return nil
	}
	perm := os.FileMode(0o644)
	if fi, err := os.Lstat(abs); err == nil && fi.Mode().IsRegular() {
		perm = fi.Mode().Perm() // keep the file's own permission bits, with the decided executable bit
	}
	if w.mode == "100755" {
		if perm&0o111 == 0 {
			perm |= (perm & 0o444) >> 2
		}
	} else {
		perm &^= 0o111
	}
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Chmod(perm)
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, abs)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// realParents checks that every component of rel (a dir under root) is a real directory, not a symlink; with create,
// missing ones are made.
func realParents(root, rel string, create bool) error {
	if rel == "." || rel == "" {
		return nil
	}
	cur := root
	for _, c := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, c)
		fi, err := os.Lstat(cur)
		switch {
		case os.IsNotExist(err) && create:
			if err := os.Mkdir(cur, 0o777); err != nil {
				return err
			}
			continue
		case os.IsNotExist(err):
			return nil // a deletion under a dir that is gone: nothing to delete
		case err != nil:
			return err
		case fi.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("its parent %s is a symlink", cur)
		case !fi.IsDir():
			return fmt.Errorf("its parent %s is not a directory", cur)
		}
	}
	return nil
}

// copyEntry copies a regular file (with its permission bits) or a symlink.
func copyEntry(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist in the checkout", src)
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		t, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(t, dst)
	case fi.Mode().IsRegular():
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Chmod(dst, fi.Mode().Perm())
	}
	return fmt.Errorf("%s is neither a file nor a symlink", src)
}

// checkoutGitConf are the -c settings of every git command apply runs: no fsmonitor (a hook program or a daemon), no
// pager, no external diff and no untracked cache (an index write). Command-line settings beat every config file, the
// checkout's own .git/config and whatever it includes among them.
var checkoutGitConf = []string{"core.fsmonitor=false", "core.pager=cat", "diff.external=", "core.untrackedCache=false"}

// hostGitEnv is the env of a git command in the operator's checkout: the caller's without GIT_* (no GIT_DIR,
// GIT_EXTERNAL_DIFF, GIT_CONFIG_*) or PAGER, never prompting, paging or taking optional locks.
func hostGitEnv() []string {
	env := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") && !strings.HasPrefix(kv, "PAGER=") {
			env = append(env, kv)
		}
	}
	return append(env, "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C", "GIT_PAGER=cat", "PAGER=cat")
}

// checkoutGit is a git command run in the operator's real checkout dir, made unable to run a program there:
// hostGitEnv, no global or system config or attributes (the only config read is the checkout's own, and
// checkoutGitConf overrides everything in it that names a program), --no-pager, and conf as more -c settings (what
// the command needs from the global config, read with hostGitConfig, and core.hooksPath).
func checkoutGit(ctx context.Context, dir string, conf []string, args ...string) *exec.Cmd {
	a := []string{"--no-pager"}
	for _, c := range append(append([]string{}, checkoutGitConf...), conf...) {
		a = append(a, "-c", c)
	}
	cmd := exec.CommandContext(ctx, "git", append(a, args...)...)
	cmd.Dir = dir
	cmd.Env = append(hostGitEnv(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_ATTR_NOSYSTEM=1")
	return cmd
}

// hostGitConfig reads one path setting as git resolves it in dir from every config file (system, global, the
// checkout's own): `git config --type=path --get key`, "" when unset. Reading config runs no program; the value is
// passed on with -c, so the commands that use it still read no global or system config.
func hostGitConfig(ctx context.Context, dir, key string) string {
	a := []string{"--no-pager"}
	for _, c := range checkoutGitConf {
		a = append(a, "-c", c)
	}
	cmd := exec.CommandContext(ctx, "git", append(a, "config", "--type=path", "--get", key)...)
	cmd.Dir = dir
	cmd.Env = hostGitEnv()
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\n")
}

// scratchGitDir makes a fresh, empty bare git dir under scratch, for git commands that must read no repository's
// config. The caller removes it.
func scratchGitDir(ctx context.Context, scratch string) (string, error) {
	gitDir, err := os.MkdirTemp(scratch, ".apply-git-")
	if err != nil {
		return "", err
	}
	if out, err := checkoutGit(ctx, scratch, []string{"core.hooksPath=/dev/null"}, "init", "-q", "--bare", "--template=", gitDir).CombinedOutput(); err != nil {
		os.RemoveAll(gitDir)
		return "", fmt.Errorf("git init: %v %s", err, strings.TrimSpace(string(out)))
	}
	return gitDir, nil
}

// gitApply runs git apply --binary (never --unsafe-paths) on the work tree dir with a fresh, empty git dir made in
// scratch: neither the checkout's .git/config (filters, hooksPath, fsmonitor) nor the global or system config is
// read, so no filter driver, hook or other host program runs.
func gitApply(ctx context.Context, dir, scratch, patchPath string) (string, error) {
	actx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	gitDir, err := scratchGitDir(actx, scratch)
	if err != nil {
		return err.Error(), err
	}
	defer os.RemoveAll(gitDir)
	cmd := checkoutGit(actx, dir, []string{"core.hooksPath=/dev/null", "core.bare=false"},
		"--git-dir="+gitDir, "--work-tree="+dir, "apply", "--binary", "--whitespace=nowarn", patchPath)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// checkIgnored reports which of paths the checkout at dir ignores (.gitignore, .git/info/exclude, the global
// excludes file), as `git ls-files --exclude-standard` does when the workspace is built. When the box's workspace was
// not a git work tree nothing was left out of it, so nothing counts as ignored. Otherwise it fails closed: a dir
// that is not a git work tree (or where git fails) can't say which files never reached the box, so the apply is
// refused (an *api.ErrorDetail).
func checkIgnored(ctx context.Context, dir string, paths []string, wsWasGit bool) (map[string]bool, error) {
	out := map[string]bool{}
	if len(paths) == 0 || !wsWasGit {
		return out, nil
	}
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// the global excludes file is the one setting check-ignore needs from outside the checkout: it is read here and
	// passed with -c (checkoutGit reads no global config); git's default ($XDG_CONFIG_HOME/git/ignore) needs no config
	conf := []string{"core.hooksPath=/dev/null"}
	if ex := hostGitConfig(cctx, dir, "core.excludesFile"); ex != "" {
		conf = append(conf, "core.excludesFile="+ex)
	}
	rp := checkoutGit(cctx, dir, conf, "rev-parse", "--is-inside-work-tree")
	var rpErr bytes.Buffer
	rp.Stderr = &rpErr
	if o, err := rp.Output(); err != nil || strings.TrimSpace(string(o)) != "true" {
		why := strings.TrimSpace(rpErr.String())
		if why == "" && err != nil {
			why = err.Error()
		}
		if why == "" {
			why = "not inside a work tree"
		}
		return nil, errf(api.CodeConflict, "apply to a git checkout (--dir), or fix git there (`git status`); nothing was applied",
			"%s is not a git work tree (%s), but the box's workspace was one: which files git ignores there (and so never reached the box) can't be checked", dir, strings.SplitN(why, "\n", 2)[0])
	}
	cmd := checkoutGit(cctx, dir, conf, "check-ignore", "--stdin", "-z")
	cmd.Stdin = strings.NewReader(strings.Join(paths, "\x00") + "\x00")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return out, nil // none ignored
	}
	if err != nil {
		return nil, fmt.Errorf("git check-ignore in %s: %v %s", dir, err, strings.TrimSpace(stderr.String()))
	}
	for _, p := range strings.Split(stdout.String(), "\x00") {
		if p != "" {
			out[p] = true
		}
	}
	return out, nil
}

// gitDirs are the checkout's git dir and hooks dir as git itself resolves them: `git rev-parse --absolute-git-dir
// --git-path hooks` with core.hooksPath as the real config sets it (the repo's, global or system: read with
// hostGitConfig and passed with -c, since checkoutGit reads no global or system config). Both are absolute,
// symlinks resolved where they exist; "" when dir is not in a git repository.
func gitDirs(ctx context.Context, dir string) (gitDir, hooks string) {
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var conf []string
	if hp := hostGitConfig(cctx, dir, "core.hooksPath"); hp != "" {
		conf = []string{"core.hooksPath=" + hp}
	}
	cmd := checkoutGit(cctx, dir, conf, "rev-parse", "--path-format=absolute", "--absolute-git-dir", "--git-path", "hooks")
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) < 2 {
		return "", ""
	}
	lines = lines[len(lines)-2:] // a git without --path-format echoes it first
	abs := func(p string) string {
		if p == "" {
			return ""
		}
		if strings.HasPrefix(p, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				p = filepath.Join(home, p[2:])
			}
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p) // --git-path answers relative to the command's dir
		}
		return resolveExisting(filepath.Clean(p))
	}
	return abs(lines[0]), abs(lines[1])
}

// resolveExisting resolves the symlinks of p's longest existing ancestor (p itself may not exist yet).
func resolveExisting(p string) string {
	rest := ""
	for cur := p; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// insideDir reports whether writing rel under root (symlinks resolved) lands in target or below it. It compares
// case-insensitively, component by component (a case-insensitive file system writes GitHooks/x into githooks/), and,
// where they exist, by identity (os.SameFile) of target and each existing parent of rel.
func insideDir(root, rel, target string) bool {
	if target == "" {
		return false
	}
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if r, err := filepath.Rel(root, target); err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		tc := strings.Split(r, string(filepath.Separator))
		pc := strings.Split(filepath.FromSlash(rel), string(filepath.Separator))
		if r == "." {
			return true
		}
		if len(pc) >= len(tc) {
			match := true
			for i := range tc {
				if !strings.EqualFold(tc[i], pc[i]) {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	tfi, err := os.Stat(target)
	if err != nil {
		return false
	}
	for p := abs; ; {
		if fi, err := os.Lstat(p); err == nil && os.SameFile(fi, tfi) {
			return true
		}
		if p == root || len(p) <= len(root) {
			return false
		}
		p = filepath.Dir(p)
	}
}

// Export writes the box's Tracekit bundle and trust file. Refused while the box is alive or when it was unrecorded.
func (d *Daemon) Export(ctx context.Context, ref string, req api.ExportRequest) (api.ExportResult, error) {
	b, err := d.lookup(ref)
	if err != nil {
		return api.ExportResult{}, err
	}
	v := b.view()
	if alive(v.State) {
		return api.ExportResult{}, errf(api.CodeConflict, "stop it first: `tkbox stop "+ref+"`", "box %s is %s", ref, v.State)
	}
	if v.Unrecorded || v.RunID == "" {
		return api.ExportResult{}, errf(api.CodeNotSupported, "run boxes with a Tracekit signer to get a bundle",
			"box %s was unrecorded: there is no Tracekit run to export", ref)
	}
	if d.opts.Tracekit == nil {
		return api.ExportResult{}, errf(api.CodeUnavailable, "restart the daemon with a signer (without --unrecorded) to export",
			"this daemon runs unrecorded")
	}
	b.mu.Lock()
	lost := b.runLost
	b.mu.Unlock()
	if lost {
		b.event(api.EventSignerProblem, "lifecycle", "export refused: the run was left open by a daemon that stopped without closing it", nil)
		return api.ExportResult{}, errf(api.CodeConflict, "the signer still holds the run's records, but a bundle needs a closed run; start a new box for a bundle",
			"box %s's Tracekit run %s was left open: the daemon that held its token stopped without closing it (it crashed or was killed), and a restarted daemon can't close it", ref, v.RunID)
	}
	out := req.Out
	if out == "" || !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return api.ExportResult{}, errf(api.CodeBadRequest, "pass -o with an absolute path (the CLI resolves it)", "out %q is not an absolute path", out)
	}
	if fi, err := os.Stat(filepath.Dir(out)); err != nil || !fi.IsDir() {
		return api.ExportResult{}, errf(api.CodeBadRequest, "create the directory first, or pass -o in an existing one", "the directory of %s does not exist", out)
	}
	if err := b.closeRun(ctx, "export"); err != nil {
		var inflight errCallsInFlight
		if errors.As(err, &inflight) {
			return api.ExportResult{}, callsInFlightErr(ref, inflight.n)
		}
		return api.ExportResult{}, errf(api.CodeUnavailable, "check the signer (`tracekit status`) and export again",
			"could not close the Tracekit run of box %s: %v", ref, err)
	}
	trust := strings.TrimSuffix(out, ".tkb") + ".trust.json"
	if err := d.opts.Tracekit.Export(ctx, v.RunID, out, trust); err != nil {
		return api.ExportResult{}, asAPIError(fmt.Errorf("export: %w", err))
	}
	return api.ExportResult{RunID: v.RunID, Bundle: out, Trust: trust,
		Verify: tracekit.ShellQuote([]string{"tracekit", "verify", out, "--trust", trust})}, nil
}

// BuildImage builds (or finds cached) the rootfs for ref on this host's arch.
func (d *Daemon) BuildImage(ctx context.Context, ref string) (api.Image, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.ContainsAny(ref, " \t\n") {
		return api.Image{}, errf(api.CodeBadRequest, "e.g. `tkbox image build python:3.12-slim`", "image %q is not an OCI reference", ref)
	}
	r, err := d.opts.Builder.Rootfs(ctx, ref, d.opts.Arch)
	if err != nil {
		return api.Image{}, asAPIError(fmt.Errorf("build %s: %w", ref, err))
	}
	return api.Image{Ref: ref, Digest: r.Digest, Arch: r.Arch, Path: r.Path, Size: r.Size}, nil
}
