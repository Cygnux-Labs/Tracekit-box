package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/tracekit"
)

var verifyWait = 2 * time.Minute

// verify runs `tracekit verify run.tkb --trust run.trust.json --json` in dir and accepts only an intact, final run:
// Integrity VERIFIED and exit 0. It returns the report's Integrity.
func verify(ctx context.Context, bin, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, verifyWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "verify", filepath.Join(dir, "run.tkb"), "--trust",
		filepath.Join(dir, "run.trust.json"), "--json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var rep struct {
		ExitCode  *int   `json:"exit_code"`
		Integrity string `json:"integrity"`
		Checks    []struct {
			Check  string `json:"check"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if jerr := json.Unmarshal(out, &rep); jerr != nil || rep.ExitCode == nil {
		if err == nil {
			err = errors.New("it printed no JSON report")
		}
		return "", fmt.Errorf("tracekit verify: %v: %s", err, clip(strings.TrimSpace(stderr.String())))
	}
	if rep.Integrity == "VERIFIED" && *rep.ExitCode == 0 && err == nil {
		return rep.Integrity, nil
	}
	msg := fmt.Sprintf("tracekit verify says Integrity: %s (exit %d)", rep.Integrity, *rep.ExitCode)
	var exitErr *exec.ExitError
	if err != nil && !(errors.As(err, &exitErr) && exitErr.ExitCode() == *rep.ExitCode) {
		msg += ", and it ended with " + err.Error()
	}
	var failed []string
	for _, c := range rep.Checks {
		if c.Status == "fail" {
			failed = append(failed, c.Check+": "+c.Detail)
		}
	}
	if len(failed) > 0 {
		msg += ": " + clip(strings.Join(failed, "; "))
	}
	return "", errors.New(msg)
}

func clip(s string) string {
	if len(s) > 2048 {
		return s[:2048] + "…"
	}
	return s
}

// tally is what the table shows of one run, counted from its signed records:
//
//   - Commands: the Bash calls the signer decided (the box's commands);
//   - Connections: the WebFetch calls the signer decided (the connections that got as far as the signer);
//   - Held: the calls held for a person: the signer's ask decisions and Box's own approvals (tkbox.approval);
//   - Refused: the signer's deny decisions, its holds that never ran (no consumed approval), and the refusals Box
//     made itself (tkbox.egress) or for a secret headed to the wrong host (tkbox.secret.leak). A Box hold no one
//     approved ends in a tkbox.egress refusal, so it counts in both Held and Refused.
type tally struct {
	Commands, Connections, Held, Refused int
}

// maxFile caps what count reads of one file in a bundle.
const maxFile = 256 << 20

// count reads the bundle tracekit verify just checked. It reads only the run file and only when its SHA-256 is the
// one the verified manifest lists, and refuses a zip that names a file twice (where another reader could pick the
// other copy), so the records it counts are the ones that verified.
func count(tkb string) (tally, error) {
	zr, err := zip.OpenReader(tkb)
	if err != nil {
		return tally{}, fmt.Errorf("run.tkb: %w", err)
	}
	defer zr.Close()
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if files[f.Name] != nil {
			return tally{}, fmt.Errorf("run.tkb holds %s twice", f.Name)
		}
		files[f.Name] = f
	}
	read := func(name string) ([]byte, error) {
		f := files[name]
		if f == nil {
			return nil, fmt.Errorf("run.tkb has no %s", name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("run.tkb: %s: %w", name, err)
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, maxFile+1))
		if err == nil && len(b) > maxFile {
			err = fmt.Errorf("over %d MiB", maxFile>>20)
		}
		if err != nil {
			return nil, fmt.Errorf("run.tkb: %s: %w", name, err)
		}
		return b, nil
	}
	b, err := read("manifest.json")
	if err != nil {
		return tally{}, err
	}
	var manifest struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		return tally{}, fmt.Errorf("run.tkb: manifest.json: %w", err)
	}
	var runs []string
	for name := range manifest.Files {
		if strings.HasPrefix(name, "runs/") {
			runs = append(runs, name)
		}
	}
	if len(runs) != 1 {
		return tally{}, fmt.Errorf("run.tkb holds %d runs; a run folder holds the one run of one box", len(runs))
	}
	if b, err = read(runs[0]); err != nil {
		return tally{}, err
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != manifest.Files[runs[0]] {
		return tally{}, fmt.Errorf("run.tkb: %s does not match its SHA-256 in manifest.json", runs[0])
	}
	return tallyRecords(b)
}

// tallyRecords counts one run's records (JSON lines, each {"event": {"type", "data"}, …}).
func tallyRecords(b []byte) (tally, error) {
	var t tally
	commands, connections, denied, asked, ran := set{}, set{}, set{}, set{}, set{}
	approvalCall := map[string]string{} // the signer's approval id → the call it holds
	var consumed []string
	box := false
	for i, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec struct {
			Event struct {
				Type string          `json:"type"`
				Data json.RawMessage `json:"data"`
			} `json:"event"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return tally{}, fmt.Errorf("run.tkb: record %d: %w", i+1, err)
		}
		var d struct {
			ToolUseID  string `json:"tool_use_id"`
			Tool       string `json:"tool"`
			Decision   string `json:"decision"`
			Source     string `json:"source"`
			ApprovalID string `json:"approval_id"`
			Binding    struct {
				ToolCallID string `json:"tool_call_id"`
			} `json:"binding"`
		}
		switch rec.Event.Type {
		case "policy.decision", "input.observed", "approval.request", "approval.consumed":
			if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
				return tally{}, fmt.Errorf("run.tkb: record %d (%s): %w", i+1, rec.Event.Type, err)
			}
		}
		switch rec.Event.Type {
		case "policy.decision":
			switch d.Tool {
			case tracekit.ToolBash:
				commands[d.ToolUseID] = true
			case tracekit.ToolWebFetch:
				connections[d.ToolUseID] = true
			}
			switch d.Decision {
			case "deny":
				denied[d.ToolUseID] = true
			case "ask":
				asked[d.ToolUseID] = true
			}
		case "approval.request":
			approvalCall[d.ApprovalID] = d.Binding.ToolCallID
		case "approval.consumed":
			consumed = append(consumed, d.ApprovalID)
		case "input.observed":
			switch d.Source {
			case tracekit.SourceBox:
				box = true
			case tracekit.SourceApproval:
				t.Held++
			case tracekit.SourceEgress, tracekit.SourceSecretLeak:
				t.Refused++
			}
		}
	}
	if !box {
		return tally{}, fmt.Errorf("run.tkb is not a Tracekit Box run: it has no %s record", tracekit.SourceBox)
	}
	for _, id := range consumed {
		if call, ok := approvalCall[id]; ok {
			ran[call] = true
		}
	}
	t.Commands, t.Connections = len(commands), len(connections)
	t.Held += len(asked)
	t.Refused += len(denied)
	for id := range asked {
		if !ran[id] {
			t.Refused++
		}
	}
	return t, nil
}

type set map[string]bool
