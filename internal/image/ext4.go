package image

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// tools finds mkfs.ext4 and debugfs: Options, then PATH, then the sbin dirs a non-root PATH often lacks.
func (b *builder) tools() (string, string, error) {
	mkfs, err := findTool(b.opts.Mkfs, "mkfs.ext4")
	if err != nil {
		return "", "", err
	}
	debugfs, err := findTool(b.opts.Debugfs, "debugfs")
	return mkfs, debugfs, err
}

func findTool(given, name string) (string, error) {
	if given != "" {
		return given, nil
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, d := range []string{"/usr/sbin", "/sbin", "/opt/homebrew/opt/e2fsprogs/sbin", "/usr/local/opt/e2fsprogs/sbin"} {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found: install e2fsprogs 1.43 or newer (apt install e2fsprogs)", name)
}

type fsStats struct {
	entries int   // inodes needed
	content int64 // bytes of data blocks, 4 KiB rounded
}

// fixups walks root and returns the debugfs commands that give each entry its real owner and mode (from meta;
// entries without meta become root-owned with their staged permissions), plus what the filesystem must hold.
func fixups(root string, meta map[string]entryMeta) ([]byte, fsStats, error) {
	var cmds bytes.Buffer
	var st fsStats
	// The root dir: mkfs -d copies the staging dir's mode, and root_owner sets the owner.
	cmds.WriteString("sif / mode 040755\n")
	seen := map[uint64]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		sys, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot read file owners on this platform")
		}
		rel := filepath.ToSlash(p[len(root)+1:])
		mode := uint32(sys.Mode)
		typ := mode & syscall.S_IFMT
		want, ok := meta[rel]
		if !ok {
			want = entryMeta{mode: mode & 0o777}
		}
		st.entries++
		switch typ {
		case syscall.S_IFREG:
			if uint64(sys.Nlink) > 1 {
				if seen[uint64(sys.Ino)] {
					break
				}
				seen[uint64(sys.Ino)] = true
			}
			st.content += (fi.Size() + 4095) &^ 4095
		case syscall.S_IFDIR:
			st.content += 4096
		case syscall.S_IFLNK:
			if fi.Size() >= 60 { // shorter targets live in the inode
				st.content += 4096
			}
		}
		var line []string
		if want.uid != sys.Uid {
			line = append(line, "uid "+strconv.FormatUint(uint64(want.uid), 10))
		}
		if want.gid != sys.Gid {
			line = append(line, "gid "+strconv.FormatUint(uint64(want.gid), 10))
		}
		if wm := typ | want.mode&0o7777; typ != syscall.S_IFLNK && wm != mode {
			line = append(line, "mode 0"+strconv.FormatUint(uint64(wm), 8))
		}
		if len(line) == 0 {
			return nil
		}
		q, err := debugfsQuote("/" + rel)
		if err != nil {
			return err
		}
		for _, f := range line {
			cmds.WriteString("sif " + q + " " + f + "\n")
		}
		return nil
	})
	return cmds.Bytes(), st, err
}

// debugfsQuote quotes a path for a debugfs command line: inside double quotes a quote is written twice. Command
// files are read line by line into a BUFSIZ buffer, so newlines, carriage returns and very long names cannot be
// expressed and fail the build.
func debugfsQuote(p string) (string, error) {
	if strings.ContainsAny(p, "\n\r\x00") {
		return "", fmt.Errorf("file name %q contains a line break, which debugfs cannot address; Box cannot set its owner, so it refuses the image (rename the file in the image)", p)
	}
	q := `"` + strings.ReplaceAll(p, `"`, `""`) + `"`
	if len(q) > 4000 {
		return "", fmt.Errorf("file path %.80q… is too long for debugfs to address; Box cannot set its owner, so it refuses the image", p)
	}
	return q, nil
}

// ext4Size leaves room for metadata and slack: 1.25 × content + 64 MiB, in whole MiB.
func ext4Size(content int64) int64 {
	n := content + content/4 + 64<<20
	return (n + 1<<20 - 1) &^ (1<<20 - 1)
}

// makeExt4 builds a journal-less ext4 at out from the staging dir and fixes owners and modes with debugfs, so no
// root is needed.
func makeExt4(ctx context.Context, mkfs, debugfs, staging string, meta map[string]entryMeta, out, label string) error {
	cmds, st, err := fixups(staging, meta)
	if err != nil {
		return err
	}
	size := ext4Size(st.content)
	inodes := st.entries + st.entries/2 + 1024
	if err := os.Truncate(out, size); err != nil {
		return err
	}
	if err := run(ctx, mkfs, "-q", "-F", "-d", staging, "-b", "4096", "-m", "0", "-E", "root_owner=0:0",
		"-O", "^has_journal", "-N", strconv.Itoa(inodes), "-L", label, out, strconv.FormatInt(size/1024, 10)+"k"); err != nil {
		return err
	}
	return runDebugfs(ctx, debugfs, out, cmds)
}

// runDebugfs applies a command file. debugfs exits 0 even when commands fail, so anything on stderr besides its
// version banner is an error.
func runDebugfs(ctx context.Context, debugfs, img string, cmds []byte) error {
	f, err := os.CreateTemp(filepath.Dir(img), ".debugfs-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(cmds); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	var stderr capBuffer
	cmd := exec.CommandContext(ctx, debugfs, "-w", "-f", f.Name(), img)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("debugfs: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var bad []string
	sc := bufio.NewScanner(strings.NewReader(stderr.String()))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "debugfs ") {
			bad = append(bad, l)
		}
	}
	if len(bad) > 0 {
		if len(bad) > 5 {
			bad = append(bad[:5], fmt.Sprintf("… and %d more", len(bad)-5))
		}
		return fmt.Errorf("debugfs could not set owners and modes: %s", strings.Join(bad, "; "))
	}
	return nil
}

func run(ctx context.Context, name string, args ...string) error {
	var out capBuffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s: %v: %s", filepath.Base(name), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// capBuffer keeps the first 64 KiB written to it.
type capBuffer struct{ bytes.Buffer }

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := 64<<10 - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// lockFile takes an exclusive flock on path, polling so ctx can cancel the wait.
func lockFile(ctx context.Context, path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, fmt.Errorf("locking %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
