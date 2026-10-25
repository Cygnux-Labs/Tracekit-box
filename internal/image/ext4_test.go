package image

import (
	"archive/tar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// needE2fs skips unless mkfs.ext4 and debugfs are installed (they are on Linux CI and in the Lima VM).
func needE2fs(t *testing.T) string {
	t.Helper()
	if _, err := findTool("", "mkfs.ext4"); err != nil {
		t.Skip("needs e2fsprogs: ", err)
	}
	debugfs, err := findTool("", "debugfs")
	if err != nil {
		t.Skip("needs e2fsprogs: ", err)
	}
	return debugfs
}

type inodeStat struct {
	uid, gid int
	mode     int64 // permission and special bits, as debugfs prints them
	typ      string
}

var (
	statMode  = regexp.MustCompile(`Type: (\S+)\s+Mode:\s+(\d+)`)
	statOwner = regexp.MustCompile(`User:\s+(\d+)\s+Group:\s+(\d+)`)
)

func debugfsStat(t *testing.T, debugfs, img, path string) (inodeStat, bool) {
	t.Helper()
	q, err := debugfsQuote(path)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command(debugfs, "-R", "stat "+q, img).CombinedOutput()
	m, o := statMode.FindSubmatch(out), statOwner.FindSubmatch(out)
	if m == nil || o == nil {
		return inodeStat{}, false
	}
	var s inodeStat
	s.typ = string(m[1])
	s.mode, _ = strconv.ParseInt(string(m[2]), 8, 64)
	s.uid, _ = strconv.Atoi(string(o[1]))
	s.gid, _ = strconv.Atoi(string(o[2]))
	return s, true
}

func fsck(t *testing.T, img string) {
	t.Helper()
	e2fsck, err := findTool("", "e2fsck")
	if err != nil {
		return
	}
	if out, err := exec.Command(e2fsck, "-fn", img).CombinedOutput(); err != nil {
		t.Errorf("e2fsck %s: %v\n%s", img, err, out)
	}
}

func TestRootfsExt4(t *testing.T) {
	debugfs := needE2fs(t)
	reg := newTestRegistry(t)
	reg.pushImage("org/py", "3", map[string]*testImage{"arm64": {layers: [][]byte{
		mkTar(t,
			ent{name: "usr/", typ: tar.TypeDir}, ent{name: "usr/sbin/", typ: tar.TypeDir}, ent{name: "usr/bin/", typ: tar.TypeDir},
			ent{name: "sbin", typ: tar.TypeSymlink, link: "usr/sbin"},
			ent{name: "usr/bin/su", body: "su", mode: 0o4755},
			ent{name: "usr/bin/wall", body: "wall", mode: 0o2755, gid: 5},
			ent{name: "tmp/", typ: tar.TypeDir, mode: 0o1777},
			ent{name: "home/app/", typ: tar.TypeDir, uid: 1000, gid: 1000, mode: 0o750},
			ent{name: "home/app/data", body: "secret", uid: 1000, gid: 1000, mode: 0o640},
			ent{name: `etc/we"ird name`, body: "x", uid: 5, gid: 6, mode: 0o600},
			ent{name: "etc/long-link", typ: tar.TypeSymlink, link: strings.Repeat("x/", 50) + "target", uid: 3, gid: 3},
			ent{name: "usr/bin/hard", typ: tar.TypeLink, link: "usr/bin/su"},
		),
		mkTar(t, ent{name: "etc/.wh.long-link"}, ent{name: "home/app/more", body: "more", uid: 1000, gid: 1000}),
	}}})
	var logs []string
	var logMu sync.Mutex
	b := newTestBuilder(t, reg, func(o *Options) {
		o.Logf = func(f string, a ...any) { logMu.Lock(); logs = append(logs, f); logMu.Unlock() }
	})
	ref := reg.host() + "/org/py:3"

	// Concurrent first builds share one result.
	var wg sync.WaitGroup
	results := make([]Rootfs, 4)
	errs := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func() { defer wg.Done(); results[i], errs[i] = b.Rootfs(t.Context(), ref, "arm64") }()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		if results[i].Path != results[0].Path {
			t.Fatalf("builds disagree: %s vs %s", results[i].Path, results[0].Path)
		}
	}
	r := results[0]
	if hits := reg.blobHits.Load(); hits != 3 { // config + 2 layers, once
		t.Errorf("blob fetches = %d, want 3", hits)
	}
	if r.Ref != ref || r.Name != ref || r.Arch != "arm64" || !strings.HasPrefix(r.Digest, "sha256:") || r.Size == 0 {
		t.Errorf("rootfs %+v", r)
	}
	if r.Config.User != "app" || r.Config.WorkingDir != "/app" || len(r.Config.Cmd) != 1 {
		t.Errorf("config %+v", r.Config)
	}
	fsck(t, r.Path)

	for path, want := range map[string]inodeStat{
		"/usr/sbin/tkbox-guest": {0, 0, 0o755, "regular"},
		"/usr/bin/su":           {0, 0, 0o4755, "regular"},
		"/usr/bin/hard":         {0, 0, 0o4755, "regular"},
		"/usr/bin/wall":         {0, 5, 0o2755, "regular"},
		"/tmp":                  {0, 0, 0o1777, "directory"},
		"/home/app":             {1000, 1000, 0o750, "directory"},
		"/home/app/data":        {1000, 1000, 0o640, "regular"},
		"/home/app/more":        {1000, 1000, 0o644, "regular"},
		`/etc/we"ird name`:      {5, 6, 0o600, "regular"},
		"/sbin":                 {0, 0, 0o777, "symlink"},
		"/proc":                 {0, 0, 0o555, "directory"},
		"/etc/tkbox":            {0, 0, 0o755, "directory"},
		"/workspace":            {0, 0, 0o755, "directory"},
		"/":                     {0, 0, 0o755, "directory"},
	} {
		got, ok := debugfsStat(t, debugfs, r.Path, path)
		if !ok || got != want {
			t.Errorf("%s: got %+v (found %v), want %+v", path, got, ok, want)
		}
	}
	if _, ok := debugfsStat(t, debugfs, r.Path, "/etc/long-link"); ok {
		t.Error("whited-out symlink is in the image")
	}
	if fi, err := os.Stat(r.Path); err != nil || fi.Mode().Perm() != 0o444 {
		t.Errorf("rootfs file mode: %v %v", fi, err)
	}

	// Cached: no further blob fetches, same file; the staging and temp files are gone.
	r2, err := b.Rootfs(t.Context(), ref, "arm64")
	if err != nil || r2.Path != r.Path || reg.blobHits.Load() != 3 {
		t.Fatalf("cached build: %+v %v (blob hits %d)", r2, err, reg.blobHits.Load())
	}
	if left, _ := os.ReadDir(b.dir("tmp")); len(left) != 0 {
		t.Errorf("tmp not cleaned: %v", left)
	}

	pinned := reg.host() + "/org/py@" + r.Digest
	if rp, err := b.Rootfs(t.Context(), pinned, "arm64"); err != nil || rp.Path != r.Path {
		t.Fatalf("pinned: %+v %v", rp, err)
	}

	// A new builder process with an unreachable registry falls back to the ref index, with a warning.
	reg.srv.Close()
	b2 := newTestBuilder(t, nil, func(o *Options) {
		o.CacheDir = b.opts.CacheDir
		o.GuestBinary = b.opts.GuestBinary
		o.StallTimeout = 5 * time.Second
		o.Logf = b.logf
	})
	r3, err := b2.Rootfs(t.Context(), ref, "arm64")
	if err != nil || r3.Path != r.Path || r3.Digest != r.Digest {
		t.Fatalf("offline: %+v %v", r3, err)
	}
	logMu.Lock()
	warned := len(logs) > 0 && strings.Contains(strings.Join(logs, "\n"), "using the cached")
	logMu.Unlock()
	if !warned {
		t.Errorf("no fallback warning: %q", logs)
	}
	// A digest pin is served from the cache without asking the registry at all.
	if rp, err := b2.Rootfs(t.Context(), pinned, "arm64"); err != nil || rp.Path != r.Path || rp.Ref != pinned {
		t.Errorf("pinned offline: %+v %v", rp, err)
	}
}

func TestDebugfsRefusesNewlineNames(t *testing.T) {
	needE2fs(t)
	reg := newTestRegistry(t)
	reg.pushImage("x", "v1", map[string]*testImage{"arm64": {layers: [][]byte{mkTar(t, ent{name: "etc/bad\nname", body: "x"})}}})
	b := newTestBuilder(t, reg, nil)
	_, err := b.Rootfs(t.Context(), reg.host()+"/x:v1", "arm64")
	if err == nil || !strings.Contains(err.Error(), "line break") {
		t.Fatalf("got %v", err)
	}
	if left, _ := os.ReadDir(b.dir("rootfs")); len(left) != 0 {
		t.Errorf("partial rootfs left: %v", left)
	}
}

func TestScratch(t *testing.T) {
	debugfs := needE2fs(t)
	b := newTestBuilder(t, nil, nil)
	out := filepath.Join(t.TempDir(), "upper.ext4")
	if err := b.Scratch(t.Context(), out, 64<<20); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Size() != 64<<20 {
		t.Fatalf("%v %v", fi, err)
	}
	stats, _ := exec.Command(debugfs, "-R", "stats", out).CombinedOutput()
	if !strings.Contains(string(stats), "has_journal") || !strings.Contains(string(stats), "tkbox-upper") {
		t.Errorf("scratch fs: %s", stats)
	}
	if got, ok := debugfsStat(t, debugfs, out, "/"); !ok || got.uid != 0 {
		t.Errorf("scratch root owner %+v", got)
	}
	fsck(t, out)
	if err := b.Scratch(t.Context(), out, 1<<20); err == nil {
		t.Error("tiny scratch accepted")
	}
}
