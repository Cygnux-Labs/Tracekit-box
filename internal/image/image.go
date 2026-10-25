// Package image builds the disks a box boots from: a read-only ext4 rootfs from any OCI image (pulled with our own
// registry v2 client, cached by manifest digest), the workspace base ext4 from a host checkout, and an empty
// read-write scratch ext4. The Builder interface and types are the contract (lead); builder.go and friends implement
// them (agent C). Tests above this package use imagefake.
package image

import "context"

// Rootfs is a built root filesystem image.
type Rootfs struct {
	Ref    string // the reference as given, e.g. "python:3.12-slim"
	Name   string // normalised, e.g. "docker.io/library/python:3.12-slim"
	Digest string // manifest digest of the platform image, "sha256:…"
	Arch   string // "arm64" or "amd64"
	Path   string // the ext4 file (read-only; shared by every box using this image)
	Size   int64
	Config Config
}

// Config is the part of the OCI image config a box uses.
type Config struct {
	Env        []string // KEY=VALUE, e.g. PATH from the image
	WorkingDir string
	Entrypoint []string
	Cmd        []string
	User       string
}

// Workspace is a built workspace base image.
type Workspace struct {
	Path  string // the ext4 file
	Files int    // regular files copied
	Bytes int64  // their total size
}

// Builder builds and caches images. Implementations are safe for concurrent use; concurrent builds of the same
// image share one result.
type Builder interface {
	// Rootfs returns the rootfs for ref on arch, pulling and building it if it is not cached. The image gets
	// /sbin/tkbox-guest (the guest binary for arch, mode 0755, owned by root) and the dirs the guest needs (/proc,
	// /sys, /dev, /run, /tmp, /workspace, /etc/tkbox); every file keeps the owner and mode its layer gave it.
	Rootfs(ctx context.Context, ref, arch string) (Rootfs, error)
	// Workspace builds an ext4 at out holding the files of dir: in a git work tree, the tracked and untracked
	// files that are not ignored (git ls-files -co --exclude-standard), so .env files a .gitignore covers stay out;
	// elsewhere every file. Never the .git dir. Symlinks are copied as symlinks; special files are skipped. Files are
	// owned by root in the image.
	Workspace(ctx context.Context, dir, out string) (Workspace, error)
	// Scratch creates an empty ext4 of sizeBytes (sparse) at out.
	Scratch(ctx context.Context, out string, sizeBytes int64) error
}
