//go:build !linux && !darwin

package daemon

import (
	"errors"
	"net"
)

// peerUID is unsupported here: every caller is refused (fail closed).
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("peer credentials are not supported on this OS")
}
