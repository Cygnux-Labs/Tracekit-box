// Package imagefake is an image.Builder that writes small placeholder files instead of ext4 images.
package imagefake

import (
	"context"
	"os"
	"sync"

	"github.com/Cygnux-Labs/tracekit-box/internal/image"
)

type Builder struct {
	mu         sync.Mutex
	Dir        string // where Rootfs files go (required)
	Err        error
	Config     image.Config
	Rootfses   []string // refs asked for
	Workspaces []string // dirs asked for
	Scratches  []string
}

func (b *Builder) Rootfs(ctx context.Context, ref, arch string) (image.Rootfs, error) {
	b.mu.Lock()
	b.Rootfses = append(b.Rootfses, ref)
	b.mu.Unlock()
	if b.Err != nil {
		return image.Rootfs{}, b.Err
	}
	p := b.Dir + "/rootfs-fake.ext4"
	if err := os.WriteFile(p, []byte("fake rootfs"), 0o644); err != nil {
		return image.Rootfs{}, err
	}
	return image.Rootfs{Ref: ref, Name: ref, Digest: "sha256:" + fakeHex, Arch: arch, Path: p, Size: 11,
		Config: b.Config}, nil
}

func (b *Builder) Workspace(ctx context.Context, dir, out string) (image.Workspace, error) {
	b.mu.Lock()
	b.Workspaces = append(b.Workspaces, dir)
	b.mu.Unlock()
	if b.Err != nil {
		return image.Workspace{}, b.Err
	}
	return image.Workspace{Path: out}, os.WriteFile(out, []byte("fake workspace"), 0o644)
}

func (b *Builder) Scratch(ctx context.Context, out string, sizeBytes int64) error {
	b.mu.Lock()
	b.Scratches = append(b.Scratches, out)
	b.mu.Unlock()
	if b.Err != nil {
		return b.Err
	}
	return os.WriteFile(out, nil, 0o644)
}

const fakeHex = "0000000000000000000000000000000000000000000000000000000000000000"

var _ image.Builder = (*Builder)(nil)
