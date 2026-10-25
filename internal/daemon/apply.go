package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

// limitWriter fails once more than n bytes are written.
type limitWriter struct {
	buf bytes.Buffer
	n   int64
}

var errDiffTooLarge = errors.New("diff too large")

func (l *limitWriter) Write(p []byte) (int, error) {
	if int64(l.buf.Len()+len(p)) > l.n {
		return 0, errDiffTooLarge
	}
	return l.buf.Write(p)
}

// Diff returns the workspace patch and its summary: live from the guest while the box runs, else the patch saved at
// stop.
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
		lw := &limitWriter{n: maxDiffBytes}
		sum, err := g.Diff(dctx, maxDiffBytes, lw)
		if err != nil {
			var pe *proto.Error
			if errors.Is(err, errDiffTooLarge) || (errors.As(err, &pe) && pe.Code == proto.CodeTooLarge) {
				return nil, api.DiffSummary{}, limitErr("the workspace diff is over 64 MiB",
					"keep build output and large files out of /workspace (write them under /tmp)")
			}
			return nil, api.DiffSummary{}, asAPIError(fmt.Errorf("diff from the guest: %w", err))
		}
		return lw.buf.Bytes(), sum, nil
	}
	patch, err := os.ReadFile(filepath.Join(b.dir, "diff.patch"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, api.DiffSummary{}, errf(api.CodeNotFound, "a diff is saved when a running box is stopped cleanly (not with --kill)",
				"box %s (%s) has no saved diff", ref, st)
		}
		return nil, api.DiffSummary{}, asAPIError(err)
	}
	var sum api.DiffSummary
	if js, err := os.ReadFile(filepath.Join(b.dir, "diff.json")); err == nil {
		json.Unmarshal(js, &sum)
	}
	sum.Bytes = int64(len(patch))
	return patch, sum, nil
}

// Apply validates every path of the box's patch, asks the signer about every file (Write), and only if all are
// allowed runs `git apply --binary` in the target dir. Check validates and decides but writes nothing.
func (d *Daemon) Apply(ctx context.Context, ref string, req api.ApplyRequest) (api.ApplyResult, error) {
	b, err := d.lookup(ref)
	if err != nil {
		return api.ApplyResult{}, err
	}
	b.mu.Lock()
	ws, run := b.info.Workspace, b.run
	b.mu.Unlock()
	dir := req.Dir
	if dir == "" {
		dir = ws
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
	patch, _, err := d.Diff(ctx, ref)
	if err != nil {
		return api.ApplyResult{}, err
	}
	patchPath := filepath.Join(b.dir, "diff.patch")
	if b.state() == api.StateRunning {
		patchPath = filepath.Join(b.dir, fmt.Sprintf("apply-%d.patch", d.now().UnixNano()))
		if err := os.WriteFile(patchPath, patch, 0o600); err != nil {
			return api.ApplyResult{}, asAPIError(err)
		}
	}
	res := api.ApplyResult{Applied: []string{}, Patch: patchPath, Checked: req.Check}
	if len(bytes.TrimSpace(patch)) == 0 {
		return res, nil
	}
	files, err := parsePatch(string(patch))
	if err != nil {
		b.event(api.EventApplyDecided, "apply", "apply refused: "+err.Error(), map[string]any{"dir": dir})
		return api.ApplyResult{}, errf(api.CodeBadRequest, "nothing was applied", "unsafe or unreadable patch: %v", err)
	}
	paths, problems := checkPatch(files, dir)
	if len(problems) > 0 {
		b.event(api.EventApplyDecided, "apply", "apply refused: unsafe paths", map[string]any{"dir": dir, "problems": problems})
		return api.ApplyResult{}, errf(api.CodeBadRequest, "nothing was applied", "unsafe paths in the patch: %s", strings.Join(problems, "; "))
	}

	type gated struct {
		path string
		call tracekit.Call
		dec  tracekit.Decision
	}
	var allowed []gated
	if run != nil {
		for _, p := range paths {
			abs := filepath.Join(dir, p)
			call := tracekit.Call{ID: b.nextCallID("write"), Tool: tracekit.ToolWrite, Args: tracekit.WriteArgs(abs)}
			out, err := d.opts.Gate(ctx, run, call, tracekit.GateHooks{})
			if err != nil {
				return api.ApplyResult{}, errf(api.CodeUnavailable, "check the signer (`tracekit status`); nothing was applied",
					"the Tracekit signer did not answer about %s: %v", p, err)
			}
			if !out.Allowed {
				res.Denied = append(res.Denied, p)
				continue
			}
			allowed = append(allowed, gated{p, call, out.Decision})
		}
	} else {
		for _, p := range paths {
			allowed = append(allowed, gated{path: p})
		}
	}
	complete := func(status string, result map[string]any) {
		if run == nil {
			return
		}
		for _, g := range allowed {
			cctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
			if err := run.Complete(cctx, g.call, g.dec, status, result); err != nil {
				b.event(api.EventSignerProblem, "apply", "complete failed: "+err.Error(), nil)
			}
			cancel()
		}
	}
	if len(res.Denied) > 0 {
		complete("error", map[string]any{"written": false, "reason": "another file of the patch was denied"})
		b.event(api.EventApplyDecided, "apply", fmt.Sprintf("apply denied: %d of %d files refused", len(res.Denied), len(paths)),
			map[string]any{"dir": dir, "denied": res.Denied})
		return res, nil
	}
	if req.Check {
		res.Applied = paths
		b.event(api.EventApplyDecided, "apply", fmt.Sprintf("apply check passed: %d files", len(paths)),
			map[string]any{"dir": dir, "paths": paths, "check": true})
		return res, nil
	}
	if out, err := gitApply(ctx, dir, patchPath); err != nil {
		complete("error", map[string]any{"written": false, "error": out})
		b.event(api.EventApplyDecided, "apply", "git apply failed: "+out, map[string]any{"dir": dir})
		return api.ApplyResult{}, errf(api.CodeConflict, "the checkout changed since the box started; nothing was applied (the patch is at "+patchPath+")",
			"git apply failed: %s", out)
	}
	complete("ok", map[string]any{"written": true})
	res.Applied = paths
	b.event(api.EventApplyDecided, "apply", fmt.Sprintf("applied %d files to %s", len(paths), dir),
		map[string]any{"dir": dir, "paths": paths})
	return res, nil
}

// gitApply runs git apply --binary (never --unsafe-paths) in dir, without looking for a repository above dir.
func gitApply(ctx context.Context, dir, patchPath string) (string, error) {
	actx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(actx, "git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
		"apply", "--binary", "--whitespace=nowarn", patchPath)
	cmd.Dir = dir
	env := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
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
	out := req.Out
	if out == "" || !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return api.ExportResult{}, errf(api.CodeBadRequest, "pass -o with an absolute path (the CLI resolves it)", "out %q is not an absolute path", out)
	}
	if fi, err := os.Stat(filepath.Dir(out)); err != nil || !fi.IsDir() {
		return api.ExportResult{}, errf(api.CodeBadRequest, "create the directory first, or pass -o in an existing one", "the directory of %s does not exist", out)
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
