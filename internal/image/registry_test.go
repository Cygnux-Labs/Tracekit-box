package image

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseReference(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	for _, c := range []struct {
		in, name, host, repo, mref string
	}{
		{"python", "docker.io/library/python:latest", "registry-1.docker.io", "library/python", "latest"},
		{"python:3.12-slim", "docker.io/library/python:3.12-slim", "registry-1.docker.io", "library/python", "3.12-slim"},
		{"library/python:3", "docker.io/library/python:3", "registry-1.docker.io", "library/python", "3"},
		{"docker.io/org/app", "docker.io/org/app:latest", "registry-1.docker.io", "org/app", "latest"},
		{"index.docker.io/python", "docker.io/library/python:latest", "registry-1.docker.io", "library/python", "latest"},
		{"ghcr.io/org/team/app:v1.2", "ghcr.io/org/team/app:v1.2", "ghcr.io", "org/team/app", "v1.2"},
		{"localhost:5000/app", "localhost:5000/app:latest", "localhost:5000", "app", "latest"},
		{"localhost/app:x", "localhost/app:x", "localhost", "app", "x"},
		{"127.0.0.1:8443/a/b:c", "127.0.0.1:8443/a/b:c", "127.0.0.1:8443", "a/b", "c"},
		{"python@" + d, "docker.io/library/python@" + d, "registry-1.docker.io", "library/python", d},
		{"ghcr.io/o/a:t@" + d, "ghcr.io/o/a:t@" + d, "ghcr.io", "o/a", d},
		{"my-org/my__app.x", "docker.io/my-org/my__app.x:latest", "registry-1.docker.io", "my-org/my__app.x", "latest"},
	} {
		r, err := parseReference(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if r.Name() != c.name || r.apiHost() != c.host || r.Repo != c.repo || r.manifestRef() != c.mref {
			t.Errorf("%s: got name %s host %s repo %s ref %s", c.in, r.Name(), r.apiHost(), r.Repo, r.manifestRef())
		}
	}
	for _, bad := range []string{"", "Python", "python:", "python@sha256:abc", "python@md5:" + strings.Repeat("a", 32),
		"a//b", "-a", "a-", "a..b", "ghcr.io/", "python:-x", "python@sha256:" + strings.Repeat("AB", 32),
		"ho st/app", "a/b/../c", "app:" + strings.Repeat("x", 129)} {
		if _, err := parseReference(bad); err == nil {
			t.Errorf("%q: parsed, want error", bad)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	s, p := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/python:pull"`)
	if s != "Bearer" || p["realm"] != "https://auth.docker.io/token" || p["service"] != "registry.docker.io" || p["scope"] != "repository:library/python:pull" {
		t.Fatalf("got %s %v", s, p)
	}
	s, p = parseChallenge(`Bearer realm="https://x/t", error="insufficient_scope",scope=plain , q="a\"b"`)
	if s != "Bearer" || p["realm"] != "https://x/t" || p["scope"] != "plain" || p["q"] != `a"b` || p["error"] != "insufficient_scope" {
		t.Fatalf("got %s %v", s, p)
	}
	if s, _ := parseChallenge(`Basic realm="r"`); s != "Basic" {
		t.Fatal(s)
	}
}

func readStaged(t *testing.T, st *stager, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(st.root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPullTokenAuthPlatform(t *testing.T) {
	reg := newTestRegistry(t)
	reg.pushImage("org/app", "v1", map[string]*testImage{
		"amd64": {layers: [][]byte{mkTar(t, ent{name: "etc/arch", body: "amd64"})}},
		"arm64": {layers: [][]byte{
			mkTar(t, ent{name: "etc/", typ: tar.TypeDir}, ent{name: "etc/arch", body: "arm64"}, ent{name: "usr/sbin/", typ: tar.TypeDir},
				ent{name: "sbin", typ: tar.TypeSymlink, link: "usr/sbin"}),
			mkTar(t, ent{name: "usr/bin/su", body: "su", mode: 0o4755}, ent{name: "home/app/", typ: tar.TypeDir, uid: 1000, gid: 1000, mode: 0o750}),
		}, plain: true},
	})
	b := newTestBuilder(t, reg, nil)
	ref := reg.host() + "/org/app:v1"
	for _, arch := range []string{"arm64", "amd64"} {
		st, res, err := stageRef(t, b, ref, arch)
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		if got := readStaged(t, st, "etc/arch"); got != arch {
			t.Errorf("%s: picked the %s image", arch, got)
		}
		if res.config.Config.User != "app" || res.config.Config.WorkingDir != "/app" || len(res.config.Config.Env) != 2 {
			t.Errorf("%s: config %+v", arch, res.config.Config)
		}
		if arch == "arm64" {
			// /sbin is a symlink to usr/sbin: the guest lands in usr/sbin, root-owned 0755.
			if fi, err := os.Lstat(filepath.Join(st.root, "usr/sbin/tkbox-guest")); err != nil || !fi.Mode().IsRegular() {
				t.Errorf("guest not at usr/sbin/tkbox-guest: %v", err)
			}
			if m := st.meta["usr/sbin/tkbox-guest"]; m != (entryMeta{mode: 0o755}) {
				t.Errorf("guest meta %+v", m)
			}
			if m := st.meta["usr/bin/su"]; m.mode != 0o4755 {
				t.Errorf("su meta %+v", m)
			}
			if m := st.meta["home/app"]; m != (entryMeta{uid: 1000, gid: 1000, mode: 0o750}) {
				t.Errorf("home/app meta %+v", m)
			}
			if fi, _ := os.Stat(filepath.Join(st.root, "usr/bin/su")); fi.Mode()&os.ModeSetuid != 0 {
				t.Error("staged a setuid file on the host")
			}
			for _, d := range []string{"proc", "sys", "dev", "run", "tmp", "workspace", "etc/tkbox"} {
				if fi, err := os.Lstat(filepath.Join(st.root, d)); err != nil || !fi.IsDir() {
					t.Errorf("/%s missing: %v", d, err)
				}
			}
			if st.meta["tmp"].mode != 0o1777 {
				t.Errorf("/tmp meta %+v", st.meta["tmp"])
			}
		}
	}
	if reg.tokenHits.Load() == 0 {
		t.Error("no token fetched")
	}
	if _, _, err := stageRef(t, b, reg.host()+"/org/app:missing", "arm64"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing tag: %v", err)
	}
}

func TestNoMatchingPlatform(t *testing.T) {
	reg := newTestRegistry(t)
	reg.pushImage("x", "v1", map[string]*testImage{"amd64": {layers: [][]byte{mkTar(t, ent{name: "a"})}}})
	b := newTestBuilder(t, reg, nil)
	_, _, err := stageRef(t, b, reg.host()+"/x:v1", "arm64")
	if err == nil || !strings.Contains(err.Error(), "no linux/arm64 image (it has: linux/amd64)") {
		t.Fatalf("got %v", err)
	}
}

func TestDigestMismatchFails(t *testing.T) {
	reg := newTestRegistry(t)
	img := &testImage{layers: [][]byte{mkTar(t, ent{name: "a", body: strings.Repeat("x", 4096)})}}
	reg.pushImage("x", "v1", map[string]*testImage{"arm64": img})
	b := newTestBuilder(t, reg, nil)
	reg.corrupt[img.layerDig[0]] = true
	_, _, err := stageRef(t, b, reg.host()+"/x:v1", "arm64")
	if err == nil || !strings.Contains(err.Error(), "refusing unverified content") {
		t.Fatalf("corrupt layer: got %v", err)
	}
	if _, err := os.Stat(b.blobPath(img.layerDig[0])); !errors.Is(err, os.ErrNotExist) {
		t.Error("corrupt blob reached the cache")
	}
	tmp, _ := os.ReadDir(b.dir("tmp"))
	if len(tmp) != 0 {
		t.Errorf("partial files left in tmp: %v", tmp)
	}

	// A manifest asked for by digest must hash to it (fresh cache: the verified copy would be used otherwise).
	delete(reg.corrupt, img.layerDig[0])
	reg.corrupt[img.manifest] = true
	_, _, err = stageRef(t, newTestBuilder(t, reg, nil), reg.host()+"/x@"+img.manifest, "arm64")
	if err == nil || !strings.Contains(err.Error(), "refusing unverified content") {
		t.Fatalf("corrupt manifest: got %v", err)
	}

	// A cached blob that rots on disk is caught while extracting and removed.
	delete(reg.corrupt, img.manifest)
	if _, _, err := stageRef(t, b, reg.host()+"/x:v1", "arm64"); err != nil {
		t.Fatal(err)
	}
	p := b.blobPath(img.layerDig[0])
	data, _ := os.ReadFile(p)
	data[len(data)/2] ^= 0xff
	os.Chmod(p, 0o644)
	os.WriteFile(p, data, 0o644)
	if _, _, err := stageRef(t, b, reg.host()+"/x:v1", "arm64"); err == nil || !strings.Contains(err.Error(), "does not match its digest") {
		t.Fatalf("rotten cache: got %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Error("rotten blob not removed")
	}
}

func TestDiffIDMismatchFails(t *testing.T) {
	reg := newTestRegistry(t)
	img := &testImage{layers: [][]byte{mkTar(t, ent{name: "a"})}}
	reg.pushImage("x", "v1", map[string]*testImage{"arm64": img})
	// Re-push the manifest with a config whose diff_id lies.
	var man manifestDoc
	json.Unmarshal(reg.content[img.manifest], &man)
	var cfg map[string]any
	json.Unmarshal(reg.content[man.Config.Digest], &cfg)
	cfg["rootfs"] = map[string]any{"type": "layers", "diff_ids": []string{digestOf([]byte("other"))}}
	cb, _ := json.Marshal(cfg)
	man.Config.Digest, man.Config.Size = reg.put(cb, ""), int64(len(cb))
	mb, _ := json.Marshal(man)
	reg.tag("x", "lie", reg.put(mb, mtOCIManifest))
	b := newTestBuilder(t, reg, nil)
	_, _, err := stageRef(t, b, reg.host()+"/x:lie", "arm64")
	if err == nil || !strings.Contains(err.Error(), "uncompressed layer hashes to") {
		t.Fatalf("got %v", err)
	}
}

func TestRejectedFormats(t *testing.T) {
	reg := newTestRegistry(t)
	reg.tag("s1", "v1", reg.put([]byte(`{"schemaVersion":1,"name":"s1","tag":"v1","fsLayers":[]}`), mtSchema1Signed))
	reg.pushImage("z", "v1", map[string]*testImage{"arm64": {layers: [][]byte{mkTar(t, ent{name: "a"})}, layerMT: "application/vnd.oci.image.layer.v1.tar+zstd"}})
	big := `{"schemaVersion":2,"mediaType":"` + mtOCIManifest + `","pad":"` + strings.Repeat("x", 5<<20) + `"}`
	reg.tag("big", "v1", reg.put([]byte(big), mtOCIManifest))
	b := newTestBuilder(t, reg, nil)
	for ref, want := range map[string]string{
		"s1:v1":  "schema 1",
		"z:v1":   "zstd-compressed layers are not supported in v0",
		"big:v1": "ManifestBytes",
	} {
		_, _, err := stageRef(t, b, reg.host()+"/"+ref, "arm64")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", ref, err, want)
		}
	}
}

func TestLimits(t *testing.T) {
	reg := newTestRegistry(t)
	reg.pushImage("x", "v1", map[string]*testImage{"arm64": {layers: [][]byte{
		mkTar(t, ent{name: "a", body: strings.Repeat("a", 3000)}, ent{name: "b", body: strings.Repeat("b", 3000)}, ent{name: "c"}),
	}}})
	for _, c := range []struct {
		lim  Limits
		want string
	}{
		{Limits{LayerBytes: 5000}, "LayerBytes"},
		{Limits{ImageBytes: 5000}, "ImageBytes"},
		{Limits{ImageEntries: 2}, "ImageEntries"},
		{Limits{ConfigBytes: 10}, "ConfigBytes"},
		{Limits{Layers: 1, LayerBytes: 10}, "LayerBytes"},
	} {
		b := newTestBuilder(t, reg, func(o *Options) { o.Limits = c.lim })
		_, _, err := stageRef(t, b, reg.host()+"/x:v1", "arm64")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v, want %q", c.lim, err, c.want)
		}
	}
}

func TestHTTPSOnly(t *testing.T) {
	reg := newTestRegistry(t)
	reg.pushImage("x", "v1", map[string]*testImage{"arm64": {layers: [][]byte{mkTar(t, ent{name: "a"})}}})
	// Without the test CA the TLS server is untrusted: the pull fails as unreachable, it never downgrades.
	b := newTestBuilder(t, nil, nil)
	_, _, err := stageRef(t, b, reg.host()+"/x:v1", "arm64")
	var ue *unreachableError
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("got %v", err)
	}
}
