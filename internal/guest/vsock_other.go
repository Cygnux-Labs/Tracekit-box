//go:build !linux

package guest

import (
	"context"
	"errors"
	"net"
)

var errNoVsock = errors.New("vsock needs Linux")

func ListenVsock(port uint32) (net.Listener, error) { return nil, errNoVsock }

func DialVsock(ctx context.Context, cid, port uint32) (net.Conn, error) { return nil, errNoVsock }
