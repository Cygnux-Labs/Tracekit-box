package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ent is one tar entry for tests.
type ent struct {
	name     string
	typ      byte // tar.TypeReg when zero
	body     string
	link     string
	mode     int64
	uid, gid int
}

func mkTar(t testing.TB, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: e.mode, Uid: e.uid, Gid: e.gid,
			ModTime: time.Unix(1700000000, 0), Format: tar.FormatPAX}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Mode == 0 {
			h.Mode = 0o644
			if h.Typeflag == tar.TypeDir {
				h.Mode = 0o755
			}
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// fakeELF is the smallest ELF64 header debug/elf accepts, for arch.
func fakeELF(arch string) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	machine := map[string]uint16{"arm64": 183, "amd64": 62}[arch]
	le := binary.LittleEndian
	le.PutUint16(h[16:], 2) // ET_EXEC
	le.PutUint16(h[18:], machine)
	le.PutUint32(h[20:], 1)
	le.PutUint16(h[52:], 64)
	le.PutUint16(h[54:], 56)
	le.PutUint16(h[58:], 64)
	return h
}

// testRegistry is a registry v2 on httptest TLS that demands a bearer token from its own /token endpoint.
type testRegistry struct {
	t   testing.TB
	srv *httptest.Server

	mu        sync.Mutex
	content   map[string][]byte // digest → bytes (blobs and manifests)
	types     map[string]string // digest → manifest media type
	tags      map[string]string // "repo:tag" → digest
	corrupt   map[string]bool   // digests served with a flipped byte
	tokenHits atomic.Int32
	blobHits  atomic.Int32
}

const testToken = "tok-123"

func newTestRegistry(t testing.TB) *testRegistry {
	r := &testRegistry{t: t, content: map[string][]byte{}, types: map[string]string{}, tags: map[string]string{},
		corrupt: map[string]bool{}}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *testRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "https://") }

func (r *testRegistry) serve(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/token" {
		r.tokenHits.Add(1)
		if req.URL.Query().Get("service") != "test-registry" || !strings.HasPrefix(req.URL.Query().Get("scope"), "repository:") {
			http.Error(w, "bad token request", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": testToken})
		return
	}
	path, ok := strings.CutPrefix(req.URL.Path, "/v2/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	var repo, kind, ref string
	for _, k := range []string{"/manifests/", "/blobs/"} {
		if i := strings.LastIndex(path, k); i >= 0 {
			repo, kind, ref = path[:i], k, path[i+len(k):]
		}
	}
	if req.Header.Get("Authorization") != "Bearer "+testToken {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test-registry",scope="repository:%s:pull"`, r.srv.URL, repo))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.mu.Lock()
	digest := ref
	if kind == "/manifests/" && !strings.HasPrefix(ref, "sha256:") {
		digest = r.tags[repo+":"+ref]
	}
	body, ok := r.content[digest]
	mt := r.types[digest]
	bad := r.corrupt[digest]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	if bad {
		body = append([]byte(nil), body...)
		body[len(body)/2] ^= 0xff
	}
	if kind == "/blobs/" {
		r.blobHits.Add(1)
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", mt)
		w.Header().Set("Docker-Content-Digest", digest)
	}
	w.Write(body)
}

func (r *testRegistry) put(b []byte, mt string) string {
	d := digestOf(b)
	r.mu.Lock()
	r.content[d] = b
	if mt != "" {
		r.types[d] = mt
	}
	r.mu.Unlock()
	return d
}

func (r *testRegistry) tag(repo, tag, digest string) {
	r.mu.Lock()
	r.tags[repo+":"+tag] = digest
	r.mu.Unlock()
}

// image is what pushImage builds for one architecture.
type testImage struct {
	layers   [][]byte // uncompressed tars
	layerMT  string   // default OCI tar+gzip
	plain    bool     // store layers uncompressed
	manifest string   // digest, filled in by pushImage
	layerDig []string
}

// pushImage pushes one image per arch and an index over them (plus an attestation entry) under repo:tag.
func (r *testRegistry) pushImage(repo, tag string, imgs map[string]*testImage) string {
	var idx []descriptor
	for _, arch := range []string{"amd64", "arm64"} {
		img := imgs[arch]
		if img == nil {
			continue
		}
		mdig := r.pushManifest(arch, img)
		idx = append(idx, descriptor{MediaType: mtOCIManifest, Digest: mdig, Size: int64(len(r.content[mdig])),
			Platform: &platform{OS: "linux", Architecture: arch, Variant: map[string]string{"arm64": "v8"}[arch]}})
	}
	idx = append(idx, descriptor{MediaType: mtOCIManifest, Digest: digestOf([]byte("att")), Size: 3,
		Platform: &platform{OS: "unknown", Architecture: "unknown"}})
	body, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mtOCIIndex, "manifests": idx})
	d := r.put(body, mtOCIIndex)
	r.tag(repo, tag, d)
	return d
}

func (r *testRegistry) pushManifest(arch string, img *testImage) string {
	var layers []descriptor
	var diffIDs []string
	for _, l := range img.layers {
		diffIDs = append(diffIDs, digestOf(l))
		blob, mt := gz(r.t, l), "application/vnd.oci.image.layer.v1.tar+gzip"
		if img.plain {
			blob, mt = l, "application/vnd.oci.image.layer.v1.tar"
		}
		if img.layerMT != "" {
			mt = img.layerMT
		}
		d := r.put(blob, "")
		img.layerDig = append(img.layerDig, d)
		layers = append(layers, descriptor{MediaType: mt, Digest: d, Size: int64(len(blob))})
	}
	cfg, _ := json.Marshal(map[string]any{
		"architecture": arch, "os": "linux",
		"config": map[string]any{"Env": []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}, "Cmd": []string{"python3"},
			"User": "app", "WorkingDir": "/app"},
		"rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs},
	})
	cd := r.put(cfg, "")
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config": descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: cd, Size: int64(len(cfg))},
		"layers": layers})
	img.manifest = r.put(man, mtOCIManifest)
	return img.manifest
}

func newTestBuilder(t testing.TB, reg *testRegistry, mod func(*Options)) *builder {
	t.Helper()
	dir := t.TempDir()
	guests := map[string]string{}
	for _, a := range []string{"arm64", "amd64"} {
		p := filepath.Join(dir, "tkbox-guest-"+a)
		if err := os.WriteFile(p, fakeELF(a), 0o755); err != nil {
			t.Fatal(err)
		}
		guests[a] = p
	}
	opts := Options{
		CacheDir:    filepath.Join(dir, "images"),
		GuestBinary: func(arch string) (string, error) { return guests[arch], nil },
		Logf:        t.Logf,
	}
	if reg != nil {
		opts.Transport = reg.srv.Client().Transport
	}
	if mod != nil {
		mod(&opts)
	}
	b, err := NewBuilder(opts)
	if err != nil {
		t.Fatal(err)
	}
	return b.(*builder)
}

// stageRef resolves and stages ref the way Rootfs does, without mkfs.
func stageRef(t testing.TB, b *builder, refStr, arch string) (*stager, *resolved, error) {
	t.Helper()
	ref, err := parseReference(refStr)
	if err != nil {
		t.Fatal(err)
	}
	guestPath, _, err := b.guest(arch)
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.resolve(t.Context(), ref, arch)
	if err != nil {
		return nil, nil, err
	}
	dir := t.TempDir()
	st, err := b.stage(t.Context(), res, dir, guestPath)
	return st, res, err
}
