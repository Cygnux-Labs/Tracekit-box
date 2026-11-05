//go:build linux

package guest

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrepareAgentChannelDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the guest init runs as root")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "tkbox")
	if err := prepareAgentChannelDir(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
		t.Fatalf("new channel dir: %v %v", fi, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		t.Fatalf("new channel dir owner: %#v", fi.Sys())
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareAgentChannelDir(link); err == nil {
		t.Fatal("accepted symlink channel directory")
	}
}
