package image

import (
	"context"
	"errors"
)

// Options configures the builder.
type Options struct {
	CacheDir string // images/ under the state dir
	// GuestBinary returns the path of the tkbox-guest binary for arch ("arm64", "amd64").
	GuestBinary func(arch string) (string, error)
	// Mkfs is the mkfs.ext4 binary (default: found in PATH); Debugfs likewise (used to set owners without root).
	Mkfs    string
	Debugfs string
}

// NewBuilder returns the real Builder.
// STUB: agent C replaces this file.
func NewBuilder(opts Options) (Builder, error) { return nil, errors.New("image: not implemented") }

var _ = context.Background
