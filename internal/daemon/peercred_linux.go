//go:build linux

package daemon

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID reads the peer's uid with SO_PEERCRED.
func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var serr error
	if err := raw.Control(func(fd uintptr) {
		var cred *unix.Ucred
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if serr == nil {
			uid = int(cred.Uid)
		}
	}); err != nil {
		return -1, err
	}
	return uid, serr
}
