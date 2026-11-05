package tracekit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakeCLI is a tracekit CLI that logs each command line it is run with and answers verify --json with a final,
// verified run.
func fakeCLI(t *testing.T) (bin, argv string) {
	t.Helper()
	dir := t.TempDir()
	bin, argv = filepath.Join(dir, "tracekit"), filepath.Join(dir, "argv.log")
	script := "#!/bin/sh\necho \"$*\" >> '" + argv + "'\n" +
		"if [ \"$1\" = verify ]; then echo '{\"exit_code\":0,\"integrity\":\"VERIFIED\",\"failures\":[]}'; fi\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argv
}

// A signer started from its own signer.yaml (one with box_daemons, which a dev signer can't take) is exported through
// that config; with none named, the CLI's default (the dev signer's store) as before.
func TestExportPassesTheSignerConfig(t *testing.T) {
	noSystemConfig(t)
	f := newFakeSigner(t)
	bin, argv := fakeCLI(t)
	for _, tc := range []struct{ config, flag string }{
		{"/srv/tracekit-box/signer.yaml", " --config /srv/tracekit-box/signer.yaml"},
		{"", ""},
	} {
		os.Remove(argv)
		c, err := Dial(context.Background(), Options{Signer: f.path, TracekitBin: bin, Config: tc.config})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Export(context.Background(), "run-1", "/out/b.tkb", "/out/b.trust.json"); err != nil {
			t.Fatal(err)
		}
		c.Close()
		got, _ := os.ReadFile(argv)
		want := "signer trust" + tc.flag + " -o /out/b.trust.json\n" +
			"export --v2 --run=run-1" + tc.flag + " -o /out/b.tkb\n" +
			"verify /out/b.tkb --trust /out/b.trust.json --json\n"
		if string(got) != want {
			t.Errorf("config %q: the CLI ran\n%s\nwant\n%s", tc.config, got, want)
		}
	}
}
