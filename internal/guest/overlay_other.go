//go:build !linux

package guest

import "io/fs"

// Overlayfs exists only on Linux: elsewhere an upper layer has no whiteouts or overlay xattrs.
func isWhiteoutDevice(fs.FileInfo) bool { return false }

func overlayXattrs(string) (overlayAttrs, error) { return overlayAttrs{}, nil }
