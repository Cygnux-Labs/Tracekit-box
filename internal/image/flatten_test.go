package image

import (
	"archive/tar"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStager(t *testing.T) *stager {
	t.Helper()
	st, err := newStager(t.TempDir(), Limits{}.withDefaults())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// applyTar runs one uncompressed layer through applyLayer.
func applyTar(t *testing.T, st *stager, tarBytes []byte) error {
	t.Helper()
	p := filepath.Join(t.TempDir(), "layer.tar")
	if err := os.WriteFile(p, tarBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	d := descriptor{Digest: digestOf(tarBytes), Size: int64(len(tarBytes))}
	return st.applyLayer(t.Context(), p, d, "", digestOf(tarBytes))
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

func TestWhiteouts(t *testing.T) {
	st := newTestStager(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(applyTar(t, st, mkTar(t,
		ent{name: "etc/", typ: tar.TypeDir},
		ent{name: "etc/a", body: "a"},
		ent{name: "etc/b", body: "b"},
		ent{name: "etc/dir/", typ: tar.TypeDir},
		ent{name: "etc/dir/f", body: "f"},
		ent{name: "opq/", typ: tar.TypeDir},
		ent{name: "opq/old", body: "old"},
		ent{name: "opq/olddir/f", body: "f"},
		ent{name: "opq/keep/", typ: tar.TypeDir},
		ent{name: "opq/keep/lower", body: "lower"},
		ent{name: "lnk", typ: tar.TypeSymlink, link: "/etc"},
	)))
	must(applyTar(t, st, mkTar(t,
		ent{name: "etc/.wh.a"},
		ent{name: "etc/.wh.dir"},
		ent{name: "etc/.wh.nothing"},
		ent{name: "missing/.wh.x"},
		ent{name: "opq/", typ: tar.TypeDir},
		ent{name: "opq/keep/", typ: tar.TypeDir}, // merged before the marker: its lower contents must go too
		ent{name: "opq/early", body: "same layer, before the marker"},
		ent{name: "opq/.wh..wh..opq"},
		ent{name: "opq/new", body: "new"},
		ent{name: "etc/.wh..wh.plnk"},
	)))
	r := st.root
	for p, want := range map[string]bool{
		"etc/a": false, "etc/b": true, "etc/dir": false, "opq/old": false, "opq/olddir": false,
		"opq/keep": true, "opq/keep/lower": false, "opq/early": true, "opq/new": true, "lnk": true,
		"etc/.wh.a": false, "opq/.wh..wh..opq": false, "missing": false,
	} {
		if got := exists(t, filepath.Join(r, p)); got != want {
			t.Errorf("%s exists = %v, want %v", p, got, want)
		}
	}
	// A whiteout through a symlinked parent deletes within root only.
	must(applyTar(t, st, mkTar(t, ent{name: "lnk/.wh.b"})))
	if exists(t, filepath.Join(r, "etc/b")) {
		t.Error("lnk/.wh.b did not remove etc/b")
	}
}

func TestHostileTarsStayInside(t *testing.T) {
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "secret")
	if err := os.WriteFile(sentinel, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideFiles := func() []string {
		var names []string
		filepath.WalkDir(outside, func(p string, d fs.DirEntry, err error) error {
			if p != outside {
				names = append(names, p)
			}
			return nil
		})
		return names
	}

	t.Run("dotdot", func(t *testing.T) {
		st := newTestStager(t)
		for _, name := range []string{"../x", "a/../../x", "./../x"} {
			err := applyTar(t, st, mkTar(t, ent{name: name, body: "x"}))
			if err == nil || !strings.Contains(err.Error(), "climbs out") {
				t.Errorf("%s: got %v", name, err)
			}
		}
		if exists(t, filepath.Join(filepath.Dir(st.root), "x")) {
			t.Error("wrote outside the staging dir")
		}
	})

	t.Run("absolute", func(t *testing.T) {
		st := newTestStager(t)
		if err := applyTar(t, st, mkTar(t, ent{name: sentinel, body: "pwned"}, ent{name: "/abs/file", body: "x"})); err != nil {
			t.Fatal(err)
		}
		if got := readStaged(t, st, strings.TrimPrefix(sentinel, "/")); got != "pwned" {
			t.Error("absolute name not rooted at staging")
		}
		if !exists(t, filepath.Join(st.root, "abs/file")) {
			t.Error("abs/file missing")
		}
	})

	t.Run("symlink to root then through it", func(t *testing.T) {
		st := newTestStager(t)
		err := applyTar(t, st, mkTar(t,
			ent{name: "evil", typ: tar.TypeSymlink, link: "/"},
			ent{name: "evil/etc/passwd", body: "root::0:0"},
			ent{name: "up", typ: tar.TypeSymlink, link: "../../../../../../.."},
			ent{name: "up/escaped", body: "x"},
			ent{name: "host", typ: tar.TypeSymlink, link: outside},
			ent{name: "host/secret", body: "overwritten?"},
			ent{name: "host/new/deep", body: "x"},
		))
		if err != nil {
			t.Fatal(err)
		}
		if got := readStaged(t, st, "etc/passwd"); got != "root::0:0" {
			t.Errorf("evil/etc/passwd landed elsewhere: %q", got)
		}
		if !exists(t, filepath.Join(st.root, "escaped")) {
			t.Error("up/escaped not rooted at staging")
		}
		rootedOutside := filepath.Join(st.root, strings.TrimPrefix(outside, "/"))
		if got := readStaged(t, st, filepath.Join(strings.TrimPrefix(outside, "/"), "secret")); got != "overwritten?" {
			t.Errorf("host/secret: %q", got)
		}
		if !exists(t, filepath.Join(rootedOutside, "new/deep")) {
			t.Error("host/new/deep not rooted at staging")
		}
	})

	t.Run("symlinked parent dir", func(t *testing.T) {
		st := newTestStager(t)
		err := applyTar(t, st, mkTar(t,
			ent{name: "d", typ: tar.TypeSymlink, link: outside},
			ent{name: "d/sub/", typ: tar.TypeDir},
			ent{name: "d/sub/file", body: "x"},
			ent{name: "rel", typ: tar.TypeSymlink, link: "../" + strings.Repeat("../", 20) + strings.TrimPrefix(outside, "/")},
			ent{name: "rel/file2", body: "x"},
		))
		if err != nil {
			t.Fatal(err)
		}
		if !exists(t, filepath.Join(st.root, strings.TrimPrefix(outside, "/"), "sub/file")) ||
			!exists(t, filepath.Join(st.root, strings.TrimPrefix(outside, "/"), "file2")) {
			t.Error("files under symlinked parents are not rooted at staging")
		}
	})

	t.Run("final symlink is replaced, not followed", func(t *testing.T) {
		st := newTestStager(t)
		err := applyTar(t, st, mkTar(t,
			ent{name: "f", typ: tar.TypeSymlink, link: sentinel},
			ent{name: "f", body: "replaced"},
			ent{name: "g", typ: tar.TypeSymlink, link: outside},
			ent{name: "g/", typ: tar.TypeDir},
		))
		if err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Lstat(filepath.Join(st.root, "f")); err != nil || !fi.Mode().IsRegular() {
			t.Errorf("f: %v %v", fi, err)
		}
		if fi, err := os.Lstat(filepath.Join(st.root, "g")); err != nil || !fi.IsDir() {
			t.Errorf("g: %v %v", fi, err)
		}
	})

	t.Run("hard links", func(t *testing.T) {
		st := newTestStager(t)
		for _, c := range []struct {
			ents []ent
			want string
		}{
			{[]ent{{name: "h", typ: tar.TypeLink, link: "../../../../" + strings.TrimPrefix(sentinel, "/")}}, "climbs out"},
			{[]ent{{name: "h", typ: tar.TypeLink, link: sentinel}}, "not in the image"},
			{[]ent{{name: "hd", typ: tar.TypeLink, link: "x"}, {name: "x/", typ: tar.TypeDir}}, "not in the image"},
			{[]ent{{name: "x/", typ: tar.TypeDir}, {name: "hd", typ: tar.TypeLink, link: "x"}}, "directory"},
			{[]ent{{name: "h", typ: tar.TypeLink, link: "/"}}, "image root"},
		} {
			err := applyTar(t, st, mkTar(t, c.ents...))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%+v: got %v, want %q", c.ents, err, c.want)
			}
		}
		// Valid: a link to a staged file is the same inode; a link to a symlink pointing outside stays a symlink.
		err := applyTar(t, st, mkTar(t,
			ent{name: "evil", typ: tar.TypeSymlink, link: "/"},
			ent{name: "real", body: "data", uid: 7, mode: 0o4750},
			ent{name: "evil/hl", typ: tar.TypeLink, link: "evil/real"},
			ent{name: "sl", typ: tar.TypeSymlink, link: sentinel},
			ent{name: "hsl", typ: tar.TypeLink, link: "sl"},
		))
		if err != nil {
			t.Fatal(err)
		}
		a, _ := os.Stat(filepath.Join(st.root, "real"))
		b, _ := os.Stat(filepath.Join(st.root, "hl"))
		if !os.SameFile(a, b) {
			t.Error("hl is not a hard link to real")
		}
		if st.meta["hl"] != st.meta["real"] || st.meta["real"].mode != 0o4750 {
			t.Errorf("meta %+v %+v", st.meta["hl"], st.meta["real"])
		}
		fi, err := os.Lstat(filepath.Join(st.root, "hsl"))
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			t.Errorf("hsl should be a symlink: %v %v", fi, err)
		}
	})

	t.Run("specials and loops", func(t *testing.T) {
		st := newTestStager(t)
		err := applyTar(t, st, mkTar(t,
			ent{name: "dev/null", typ: tar.TypeChar},
			ent{name: "dev/sda", typ: tar.TypeBlock},
			ent{name: "fifo", typ: tar.TypeFifo},
			ent{name: "hfifo", typ: tar.TypeLink, link: "fifo"},
		))
		if err != nil {
			t.Fatal(err)
		}
		if st.skipped["device"] != 2 || st.skipped["fifo"] != 1 || exists(t, filepath.Join(st.root, "fifo")) || exists(t, filepath.Join(st.root, "hfifo")) {
			t.Errorf("skipped %v", st.skipped)
		}
		err = applyTar(t, st, mkTar(t,
			ent{name: "loop", typ: tar.TypeSymlink, link: "loop"},
			ent{name: "loop/x", body: "x"},
		))
		if err == nil || !strings.Contains(err.Error(), "symbolic links") {
			t.Errorf("loop: got %v", err)
		}
		err = applyTar(t, st, mkTar(t, ent{name: "file", body: "x"}, ent{name: "file/child", body: "x"}))
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("file parent: got %v", err)
		}
	})

	if got := outsideFiles(); len(got) != 1 || got[0] != sentinel {
		t.Errorf("outside dir changed: %v", got)
	}
	if b, _ := os.ReadFile(sentinel); string(b) != "host secret" {
		t.Error("host file modified")
	}
}

func TestDebugfsQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/bin/x":         `"/usr/bin/x"`,
		`/a/we"ird name`:     `"/a/we""ird name"`,
		"/tab\there '$(x)' ": "\"/tab\there '$(x)' \"",
	} {
		if got, err := debugfsQuote(in); err != nil || got != want {
			t.Errorf("%q: got %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"/a\nb", "/a\rb", "/" + strings.Repeat("x", 4100)} {
		if _, err := debugfsQuote(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestFixupsCommands(t *testing.T) {
	st := newTestStager(t)
	if err := applyTar(t, st, mkTar(t,
		ent{name: "bin/", typ: tar.TypeDir, mode: 0o755},
		ent{name: "bin/su", body: "x", mode: 0o4755},
		ent{name: "home/app/", typ: tar.TypeDir, uid: 1000, gid: 1001, mode: 0o750},
		ent{name: "l", typ: tar.TypeSymlink, link: "bin"},
	)); err != nil {
		t.Fatal(err)
	}
	cmds, stats, err := fixups(st.root, st.meta)
	if err != nil {
		t.Fatal(err)
	}
	s := string(cmds)
	for _, want := range []string{`sif "/bin/su" mode 0104755`, `sif "/home/app" uid 1000`, `sif "/home/app" gid 1001`} {
		if !strings.Contains(s, want+"\n") {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, `"/l" mode`) {
		t.Error("symlink mode should not be set")
	}
	if stats.entries != 5 {
		t.Errorf("entries %d", stats.entries)
	}
}
