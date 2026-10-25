package tracekit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Export runs the 1.4.2 CLI against the same signer:
//
//	tracekit signer trust [--config /etc/tracekit/signer.yaml] -o <trustOut>
//	tracekit export --v2 --run=<id> [--config /etc/tracekit/signer.yaml] -o <bundleOut>
//	tracekit verify <bundleOut> --trust <trustOut> --json
//
// with TRACEKIT_SIGNER set to our socket (export nudges the signer through it for a checkpoint). The CLI reads the
// signer's store itself: the same-user dev signer's by default, the system signer's through its signer.yaml. A run is
// final a few seconds after close_run; until then verify says "VERIFIED TO HEAD n (open)", so export and verify are
// retried until it says VERIFIED, for up to exportWait.

var (
	exportWait  = 60 * time.Second
	exportRetry = time.Second
)

func (c *client) Export(ctx context.Context, runID, bundleOut, trustOut string) error {
	if err := checkID("run_id", runID); err != nil {
		return err
	}
	if bundleOut == "" || trustOut == "" {
		return errors.New("tracekit export: bundle and trust paths are required")
	}
	bin := c.bin
	if bin == "" {
		bin = "tracekit"
	}
	var cfg []string
	if c.source == sourceSystem {
		if _, err := os.Stat(systemSignerYAML); err == nil {
			cfg = []string{"--config", systemSignerYAML}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, exportWait)
	defer cancel()
	if _, err := c.cli(ctx, bin, append(append([]string{"signer", "trust"}, cfg...), "-o", trustOut)...); err != nil {
		return err
	}
	for {
		err := c.exportOnce(ctx, bin, cfg, runID, bundleOut, trustOut)
		if !errors.Is(err, errNotFinal) && !errors.Is(err, errExportFailed) {
			return err // nil, a bundle that does not verify, or ctx
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("tracekit export of run %s: not final and verified within %s: %w", runID, exportWait,
				err)
		case <-time.After(exportRetry):
		}
	}
}

var (
	errNotFinal     = errors.New("the run is not final yet")
	errExportFailed = errors.New("tracekit export failed")
	errNotVerified  = errors.New("the bundle did not verify")
)

func (c *client) exportOnce(ctx context.Context, bin string, cfg []string, runID, bundleOut, trustOut string) error {
	args := append(append([]string{"export", "--v2", "--run=" + runID}, cfg...), "-o", bundleOut)
	if _, err := c.cli(ctx, bin, args...); err != nil {
		if ctx.Err() != nil {
			return err
		}
		// e.g. no checkpoint covers the run yet: retried
		return fmt.Errorf("%w: %v", errExportFailed, err)
	}
	out, err := c.cli(ctx, bin, "verify", bundleOut, "--trust", trustOut, "--json")
	var rep struct {
		ExitCode  *int   `json:"exit_code"`
		Integrity string `json:"integrity"`
		Failures  []any  `json:"failures"`
	}
	if jerr := json.Unmarshal(out, &rep); jerr != nil || rep.ExitCode == nil {
		if err == nil {
			err = fmt.Errorf("tracekit verify printed no JSON report")
		}
		return fmt.Errorf("%w: %v", errNotVerified, err)
	}
	switch {
	case rep.Integrity == "VERIFIED" && *rep.ExitCode == 0:
		return nil
	case strings.HasPrefix(rep.Integrity, "VERIFIED TO HEAD") || strings.HasPrefix(rep.Integrity, "VERIFIED ("):
		return fmt.Errorf("%w (%s)", errNotFinal, rep.Integrity)
	}
	failures, _ := json.Marshal(rep.Failures)
	return fmt.Errorf("%w: integrity %q, exit %d, failures %s", errNotVerified, rep.Integrity, *rep.ExitCode,
		clip(string(failures), 2048))
}

// cli runs the tracekit CLI with TRACEKIT_SIGNER naming our signer; its stderr goes into the error.
func (c *client) cli(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TRACEKIT_SIGNER=") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, "TRACEKIT_SIGNER="+c.t.where)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return stdout.Bytes(), fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args[:min(2, len(args))], " "), err,
			clip(msg, 4096))
	}
	return stdout.Bytes(), nil
}
