package guest

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayCopiesBothDirections(t *testing.T) {
	local, client := tcpPair(t)
	remote, host := tcpPair(t)
	done := make(chan struct{})
	go func() { Relay(local, func() (net.Conn, error) { return remote, nil }); close(done) }()
	go func() {
		_, _ = io.WriteString(client, "guest\n")
		_ = client.(interface{ CloseWrite() error }).CloseWrite()
	}()
	got := make([]byte, 6)
	if _, err := io.ReadFull(host, got); err != nil || string(got) != "guest\n" {
		t.Fatalf("guest to host: %q, %v", got, err)
	}
	go func() {
		_, _ = io.WriteString(host, "signer\n")
		_ = host.(interface{ CloseWrite() error }).CloseWrite()
	}()
	back, err := io.ReadAll(client)
	if err != nil || string(back) != "signer\n" {
		t.Fatalf("host to guest: %q, %v", back, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not stop")
	}
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return <-accepted, c
}
