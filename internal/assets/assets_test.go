package assets

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type entry struct {
	name string
	body string
	typ  byte
	mode int64
}

func tgz(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Mode: e.mode, Size: int64(len(e.body))}
		if typ != tar.TypeReg {
			hdr.Size = 0
			hdr.Linkname = "target"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

// serve starts a TLS server returning body and points httpClient at it.
func serve(t *testing.T, body []byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	old := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = old })
	return srv, &hits
}

func onlyDest(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestEnsurePlainFile(t *testing.T) {
	body := []byte("kernel bytes")
	srv, hits := serve(t, body)
	dir := filepath.Join(t.TempDir(), "assets")
	a := Asset{Name: "vmlinux", Arch: "arm64", Version: "6.1", URL: srv.URL + "/vmlinux", SHA256: sum(body)}
	p, err := Ensure(context.Background(), dir, a)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, body) {
		t.Fatalf("content %q", got)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// Cached: no second download.
	if p2, err := Ensure(context.Background(), dir, a); err != nil || p2 != p || hits.Load() != 1 {
		t.Fatalf("second Ensure: %v %q hits=%d", err, p2, hits.Load())
	}
	if names := onlyDest(t, dir); len(names) != 1 {
		t.Fatalf("leftovers: %v", names)
	}
}

func TestEnsureBadHashLeavesNothing(t *testing.T) {
	srv, _ := serve(t, []byte("tampered"))
	dir := t.TempDir()
	a := Asset{Name: "vmlinux", Arch: "amd64", Version: "6.1", URL: srv.URL + "/vmlinux", SHA256: sum([]byte("original"))}
	_, err := Ensure(context.Background(), dir, a)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("err = %v", err)
	}
	if names := onlyDest(t, dir); len(names) != 0 {
		t.Fatalf("left behind: %v", names)
	}
}

func TestEnsureHTTPError(t *testing.T) {
	srv, _ := serve(t, nil)
	dir := t.TempDir()
	a := Asset{Name: "vmlinux", Arch: "amd64", Version: "6.1", URL: srv.URL + "/missing", SHA256: sum(nil)}
	if _, err := Ensure(context.Background(), dir, a); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v", err)
	}
	if names := onlyDest(t, dir); len(names) != 0 {
		t.Fatalf("left behind: %v", names)
	}
}

func TestEnsureTgzMember(t *testing.T) {
	arc := tgz(t,
		entry{name: "release-v1/README", body: "readme", mode: 0o644},
		entry{name: "release-v1/firecracker-v1", body: "#!fc", mode: 0o755},
	)
	srv, _ := serve(t, arc)
	dir := t.TempDir()
	a := Asset{Name: "firecracker", Arch: "arm64", Version: "v1", URL: srv.URL + "/fc.tgz", SHA256: sum(arc),
		Member: "release-v1/firecracker-v1"}
	p, err := Ensure(context.Background(), dir, a)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "#!fc" {
		t.Fatalf("content %q", got)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if names := onlyDest(t, dir); len(names) != 1 {
		t.Fatalf("leftovers: %v", names)
	}
}

func TestEnsureTgzRejects(t *testing.T) {
	cases := map[string][]entry{
		"traversal": {{name: "../evil", body: "x"}, {name: "rel/fc", body: "fc"}},
		"absolute":  {{name: "/etc/evil", body: "x"}, {name: "rel/fc", body: "fc"}},
		"symlink":   {{name: "rel/fc", typ: tar.TypeSymlink}},
		"missing":   {{name: "rel/other", body: "x"}},
		"duplicate": {{name: "rel/fc", body: "a"}, {name: "rel/fc", body: "b"}},
	}
	for name, ents := range cases {
		t.Run(name, func(t *testing.T) {
			arc := tgz(t, ents...)
			srv, _ := serve(t, arc)
			dir := t.TempDir()
			a := Asset{Name: "firecracker", Arch: "arm64", Version: "v1", URL: srv.URL + "/fc.tgz", SHA256: sum(arc), Member: "rel/fc"}
			if _, err := Ensure(context.Background(), dir, a); err == nil {
				t.Fatal("Ensure accepted a bad archive")
			}
			if names := onlyDest(t, dir); len(names) != 0 {
				t.Fatalf("left behind: %v", names)
			}
		})
	}
}

func TestEnsureValidates(t *testing.T) {
	good := Asset{Name: "vmlinux", Arch: "arm64", Version: "1", URL: "https://example.invalid/k", SHA256: strings.Repeat("a", 64)}
	bad := map[string]func(*Asset){
		"http":      func(a *Asset) { a.URL = "http://example.invalid/k" },
		"short sha": func(a *Asset) { a.SHA256 = "abcd" },
		"slash":     func(a *Asset) { a.Name = "../x" },
		"no arch":   func(a *Asset) { a.Arch = "" },
	}
	for name, mut := range bad {
		a := good
		mut(&a)
		if _, err := Ensure(context.Background(), t.TempDir(), a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPins(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		for _, f := range []func(string) (Asset, error){Kernel, Firecracker} {
			a, err := f(arch)
			if err != nil {
				t.Fatal(err)
			}
			if err := validate(a); err != nil || a.Arch != arch {
				t.Fatalf("%+v: %v", a, err)
			}
		}
	}
	if _, err := Kernel("riscv64"); err == nil {
		t.Fatal("riscv64 kernel pinned")
	}
	if a, _ := Firecracker("amd64"); !strings.HasSuffix(a.Member, "/firecracker-v1.17.0-x86_64") {
		t.Fatalf("member %q", a.Member)
	}
}
