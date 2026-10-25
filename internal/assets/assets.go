// Package assets pins the binaries a box needs that we do not build: the Firecracker VMM and the guest kernel, by URL
// and sha256 per architecture, and fetches them into a cache dir with verification.
// STUB: agent A replaces this file (keep these signatures).
package assets

import (
	"context"
	"errors"
)

// Asset is one pinned download.
type Asset struct {
	Name   string // "firecracker", "vmlinux"
	Arch   string // "arm64" or "amd64" (GOARCH names)
	URL    string
	SHA256 string // hex of the downloaded file
	// Member, for a .tgz download, is the path inside the archive to extract (the asset is that member, and SHA256 is
	// of the archive). Empty for a plain file.
	Member  string
	Version string
}

// Kernel is the pinned guest kernel for arch.
func Kernel(arch string) (Asset, error) { return Asset{}, errors.New("assets: not implemented") }

// Firecracker is the pinned Firecracker release binary for arch.
func Firecracker(arch string) (Asset, error) { return Asset{}, errors.New("assets: not implemented") }

// Ensure returns the local path of a, downloading it into dir first if missing. The download is verified against
// a.SHA256 before it is moved into place (atomic rename); a mismatch is an error and leaves nothing behind.
func Ensure(ctx context.Context, dir string, a Asset) (string, error) {
	return "", errors.New("assets: not implemented")
}
