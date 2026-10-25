//go:build linux

package guest

import (
	"bytes"
	"errors"
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

// isWhiteoutDevice reports an overlayfs whiteout: a character device with device number 0:0.
func isWhiteoutDevice(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode()&fs.ModeCharDevice != 0 && st.Rdev == 0
}

// overlayXattrs reads the overlay xattrs of path (trusted.* as root, user.* for userxattr mounts).
func overlayXattrs(path string) (overlayAttrs, error) {
	var a overlayAttrs
	buf := make([]byte, 1024)
	n, err := unix.Llistxattr(path, buf)
	if errors.Is(err, unix.ERANGE) {
		if n, err = unix.Llistxattr(path, nil); err == nil {
			buf = make([]byte, n)
			n, err = unix.Llistxattr(path, buf)
		}
	}
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOENT) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	for _, name := range bytes.Split(buf[:n], []byte{0}) {
		var suffix string
		switch {
		case bytes.HasPrefix(name, []byte("trusted.overlay.")):
			suffix = string(name[len("trusted.overlay."):])
		case bytes.HasPrefix(name, []byte("user.overlay.")):
			suffix = string(name[len("user.overlay."):])
		default:
			continue
		}
		switch suffix {
		case "redirect":
			a.redirect = true
		case "metacopy":
			a.metacopy = true
		case "whiteout":
			a.whiteout = true
		case "opaque":
			v := make([]byte, 8)
			if m, err := unix.Lgetxattr(path, string(name), v); err == nil && m == 1 && v[0] == 'y' {
				a.opaque = true
			}
		}
	}
	return a, nil
}
