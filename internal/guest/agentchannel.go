package guest

import (
	"io"
	"net"
	"sync"
)

// Relay copies the signer stream in both directions and leaves framing to Tracekit.
func Relay(local net.Conn, dial func() (net.Conn, error)) {
	remote, err := dial()
	if err != nil {
		local.Close()
		return
	}
	var once sync.Once
	closeBoth := func() { once.Do(func() { local.Close(); remote.Close() }) }
	done := make(chan struct{}, 2)
	copyHalf := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyHalf(remote, local)
	go copyHalf(local, remote)
	<-done
	<-done
	closeBoth()
}
