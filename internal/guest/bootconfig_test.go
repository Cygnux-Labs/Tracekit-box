package guest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

func TestFetchBootConfigRetries(t *testing.T) {
	var tries atomic.Int32
	dial := func(ctx context.Context) (net.Conn, error) {
		if tries.Add(1) < 3 {
			return nil, errors.New("connection reset") // the host's listener is not up yet
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			f, err := proto.ReadFrame(b)
			var req proto.BootConfigRequest
			if err != nil || f.Decode(&req) != nil || req.Op != proto.OpBootConfig {
				return
			}
			proto.WriteJSON(b, proto.TypeJSON, proto.BootConfig{Version: proto.Version, BoxID: "b1"})
		}()
		return a, nil
	}
	cfg, err := FetchBootConfig(context.Background(), dial, 5*time.Second)
	if err != nil || cfg.BoxID != "b1" || tries.Load() != 3 {
		t.Fatalf("%+v %v after %d tries", cfg, err, tries.Load())
	}
}

func TestFetchBootConfigFailsClosed(t *testing.T) {
	start := time.Now()
	_, err := FetchBootConfig(context.Background(), func(ctx context.Context) (net.Conn, error) {
		return nil, errors.New("no host")
	}, 500*time.Millisecond)
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("want failure within the wait, got %v after %v", err, time.Since(start))
	}
	// a host refusal is final, and a config with unknown fields is rejected
	for _, reply := range []func(net.Conn){
		func(c net.Conn) { proto.WriteJSON(c, proto.TypeError, proto.Error{Code: proto.CodeNotFound, Message: "no box"}) },
		func(c net.Conn) { proto.WriteFrame(c, proto.TypeJSON, []byte(`{"version":1,"surprise":true}`)) },
	} {
		_, err := FetchBootConfig(context.Background(), func(ctx context.Context) (net.Conn, error) {
			a, b := net.Pipe()
			go func() { defer b.Close(); proto.ReadFrame(b); reply(b) }()
			return a, nil
		}, 300*time.Millisecond)
		if err == nil {
			t.Fatal("bad config accepted")
		}
	}
}

func TestCheckBootConfig(t *testing.T) {
	ok := proto.BootConfig{Version: proto.Version, BoxID: "b1", Workspace: &proto.WorkspaceMount{BaseDevice: "/dev/vdb", UpperDevice: "/dev/vdc"}}
	cfg := ok
	if err := CheckBootConfig(&cfg, "b1"); err != nil || cfg.ProxyListen != proto.DefaultProxyListen ||
		cfg.CABundlePath != proto.DefaultCABundlePath || cfg.Workspace.Path != proto.DefaultWorkspacePath {
		t.Fatalf("%+v %v", cfg, err)
	}
	for name, mut := range map[string]func(c *proto.BootConfig){
		"version": func(c *proto.BootConfig) { c.Version = 99 },
		"box id":  func(c *proto.BootConfig) { c.BoxID = "other" },
		"ws root": func(c *proto.BootConfig) { c.Workspace = &proto.WorkspaceMount{Path: "/", BaseDevice: "a", UpperDevice: "b"} },
		"ws dev":  func(c *proto.BootConfig) { c.Workspace = &proto.WorkspaceMount{Path: "/w"} },
		"ca path": func(c *proto.BootConfig) { c.CABundlePath = "rel.pem" },
	} {
		c := ok
		c.Workspace = &proto.WorkspaceMount{BaseDevice: "/dev/vdb", UpperDevice: "/dev/vdc"}
		mut(&c)
		if err := CheckBootConfig(&c, "b1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInstallCA(t *testing.T) {
	d := t.TempDir()
	sys1 := filepath.Join(d, "certs", "ca-certificates.crt")
	sys3 := filepath.Join(d, "cert.pem") // a symlink to sys1, as on Alpine
	missing := filepath.Join(d, "pki", "ca-bundle.crt")
	writeFile(t, d, "certs/ca-certificates.crt", "SYSTEM-ROOTS", 0o644)
	must(t, os.Symlink(sys1, sys3))
	bundle := filepath.Join(d, "etc", "tkbox", "ca-bundle.pem")
	pem := "-----BEGIN CERTIFICATE-----\nBOX\n-----END CERTIFICATE-----\n"
	must(t, InstallCA(pem, bundle, []string{sys1, missing, sys3}))
	got, _ := os.ReadFile(bundle)
	if string(got) != "SYSTEM-ROOTS\n"+pem {
		t.Fatalf("bundle %q", got)
	}
	sys, _ := os.ReadFile(sys1)
	if strings.Count(string(sys), "BOX") != 1 || !strings.HasPrefix(string(sys), "SYSTEM-ROOTS\n") {
		t.Fatalf("system bundle %q", sys)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("created a bundle the image did not have")
	}
	// no system bundle at all: the box bundle is the CA alone
	b2 := filepath.Join(d, "b2.pem")
	must(t, InstallCA(pem, b2, []string{missing}))
	if got, _ := os.ReadFile(b2); string(got) != pem {
		t.Fatalf("bundle %q", got)
	}
}

func TestWriteHosts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts")
	must(t, os.WriteFile(p, []byte("127.0.0.1 localhost\n10.0.0.1 db\n"), 0o644))
	must(t, WriteHosts(p, "tkbox-b1"))
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "127.0.0.1\tlocalhost tkbox-b1\n") || !strings.Contains(string(got), "10.0.0.1 db") ||
		strings.Count(string(got), "127.0.0.1") != 1 {
		t.Fatalf("hosts %q", got)
	}
}

func TestCmdlineValue(t *testing.T) {
	cl := "console=ttyS0 reboot=k root=/dev/vda ro init=/sbin/tkbox-guest tkbox.id=abc123 quiet\n"
	if v := CmdlineValue(cl, proto.CmdlineBoxID); v != "abc123" {
		t.Fatalf("got %q", v)
	}
	if v := CmdlineValue(cl, "nope"); v != "" {
		t.Fatalf("got %q", v)
	}
}

// TestForwarder pipes TCP through a stand-in for the vsock host connection and checks half-close both ways.
func TestForwarder(t *testing.T) {
	// the "host": reads everything until EOF, then answers and closes
	host, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer host.Close()
	go func() {
		for {
			c, err := host.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, _ := io.ReadAll(c)
				c.Write(append([]byte("got:"), b...))
			}()
		}
	}()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer l.Close()
	fw := &Forwarder{MaxConns: 2, Dial: func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", host.Addr().String())
	}}
	go fw.Serve(l)

	c, err := net.Dial("tcp", l.Addr().String())
	must(t, err)
	defer c.Close()
	payload := bytes.Repeat([]byte("CONNECT "), 100000)
	go func() {
		c.Write(payload)
		c.(*net.TCPConn).CloseWrite() // half-close: the host must see EOF and still be able to answer
	}()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, append([]byte("got:"), payload...)) {
		t.Fatalf("round trip: %v, %d bytes", err, len(got))
	}
}

func TestForwarderConnCap(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer l.Close()
	fw := &Forwarder{MaxConns: 1, Dial: func(ctx context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { <-block; b.Close() }()
		return a, nil
	}}
	go fw.Serve(l)
	c1, err := net.Dial("tcp", l.Addr().String())
	must(t, err)
	defer c1.Close()
	time.Sleep(100 * time.Millisecond)
	c2, err := net.Dial("tcp", l.Addr().String())
	must(t, err)
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("connection over the cap: want EOF, got %v", err)
	}
}
