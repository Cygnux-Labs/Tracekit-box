package image

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNetworkPythonSlim pulls python:3.12-slim from Docker Hub and builds its rootfs end to end.
// Run with TKBOX_NETWORK_TESTS=1 on a host with e2fsprogs (the Lima VM).
func TestNetworkPythonSlim(t *testing.T) {
	if os.Getenv("TKBOX_NETWORK_TESTS") != "1" {
		t.Skip("set TKBOX_NETWORK_TESTS=1 to pull from Docker Hub")
	}
	debugfs := needE2fs(t)
	cache := os.Getenv("TKBOX_NETWORK_CACHE") // reuse between runs if set
	b := newTestBuilder(t, nil, func(o *Options) {
		if cache != "" {
			o.CacheDir = cache
		}
	})
	start := time.Now()
	r, err := b.Rootfs(t.Context(), "python:3.12-slim", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	cold := time.Since(start)
	used := int64(0)
	filepath.Walk(filepath.Join(b.opts.CacheDir, "blobs"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			used += fi.Size()
		}
		return nil
	})
	t.Logf("python:3.12-slim arm64: %s in %s; ext4 %s (apparent); blobs %s; config %+v",
		r.Digest, cold.Round(time.Millisecond), human(r.Size), human(used), r.Config)
	fsck(t, r.Path)
	for path, want := range map[string]inodeStat{
		"/usr/sbin/tkbox-guest": {0, 0, 0o755, "regular"},
		"/usr/bin/su":           {0, 0, 0o4755, "regular"},
		"/tmp":                  {0, 0, 0o1777, "directory"},
	} {
		if got, ok := debugfsStat(t, debugfs, r.Path, path); !ok || got != want {
			t.Errorf("%s: got %+v (found %v), want %+v", path, got, ok, want)
		}
	}
	if got, ok := debugfsStat(t, debugfs, r.Path, "/usr/local/bin/python3.12"); !ok || got.typ != "regular" {
		t.Errorf("python3.12 missing: %+v", got)
	}
	start = time.Now()
	if _, err := b.Rootfs(t.Context(), "python:3.12-slim", "arm64"); err != nil {
		t.Fatal(err)
	}
	t.Logf("cached lookup: %s", time.Since(start).Round(time.Millisecond))
}
