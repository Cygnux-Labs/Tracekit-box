package guest

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

// cleanPath accepts an absolute path without NUL bytes and returns it cleaned.
func cleanPath(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) {
		return "", fmt.Errorf("path %q must be absolute", p)
	}
	if strings.IndexByte(p, 0) >= 0 {
		return "", errors.New("path contains a NUL byte")
	}
	return filepath.Clean(p), nil
}

func fileInfo(p string, fi fs.FileInfo) proto.FileInfo {
	return proto.FileInfo{Path: p, Size: fi.Size(), Mode: uint32(fi.Mode()), IsDir: fi.IsDir(), ModTime: fi.ModTime().Unix()}
}

// fsError maps a filesystem error to a protocol error code.
func fsError(c net.Conn, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		sendError(c, proto.CodeNotFound, err.Error())
	case errors.Is(err, fs.ErrPermission), errors.Is(err, fs.ErrExist):
		sendError(c, proto.CodeBadRequest, err.Error())
	default:
		sendError(c, proto.CodeInternal, err.Error())
	}
}

func (s *Server) handleStat(c net.Conn, f proto.Frame) {
	var req proto.StatRequest
	if err := f.Decode(&req); err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	p, err := cleanPath(req.Path)
	if err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	// lstat: a symlink is reported as one (Mode has fs.ModeSymlink), like stat(1) without -L
	fi, err := os.Lstat(p)
	if err != nil {
		fsError(c, err)
		return
	}
	proto.WriteJSON(c, proto.TypeJSON, fileInfo(p, fi))
}

func (s *Server) handleReadFile(c net.Conn, f proto.Frame) {
	var req proto.ReadFileRequest
	if err := f.Decode(&req); err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	p, err := cleanPath(req.Path)
	if err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	max := req.MaxBytes
	if max <= 0 {
		max = proto.DefaultMaxReadBytes
	}
	fh, err := os.Open(p)
	if err != nil {
		fsError(c, err)
		return
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		fsError(c, err)
		return
	}
	if !fi.Mode().IsRegular() {
		sendError(c, proto.CodeBadRequest, fmt.Sprintf("%s is not a regular file", p))
		return
	}
	if fi.Size() > max {
		sendError(c, proto.CodeTooLarge, fmt.Sprintf("%s is %d bytes, over max_bytes %d", p, fi.Size(), max))
		return
	}
	if err := proto.WriteJSON(c, proto.TypeJSON, fileInfo(p, fi)); err != nil {
		return
	}
	// the file may grow while it is read: never send more than max
	n, err := io.CopyBuffer(proto.ChunkWriter{W: c, Type: proto.TypeStdout}, io.LimitReader(fh, max+1), make([]byte, 256<<10))
	if err != nil {
		sendError(c, proto.CodeInternal, err.Error())
		return
	}
	if n > max {
		sendError(c, proto.CodeTooLarge, fmt.Sprintf("%s grew over max_bytes %d while being read", p, max))
		return
	}
	proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{})
}

// handleWriteFile streams TypeStdin frames into a temp file next to the target and renames it into place on
// TypeStdinEOF, so readers never see a partial file.
func (s *Server) handleWriteFile(c net.Conn, f proto.Frame) {
	var req proto.WriteFileRequest
	if err := f.Decode(&req); err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	p, err := cleanPath(req.Path)
	if err != nil {
		sendError(c, proto.CodeBadRequest, err.Error())
		return
	}
	if p == "/" {
		sendError(c, proto.CodeBadRequest, "cannot write /")
		return
	}
	// proto modes are unix permission bits; translate the special bits to Go's
	mode := fs.FileMode(req.Mode) & fs.ModePerm
	if req.Mode&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if req.Mode&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if req.Mode&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	if req.Mode == 0 {
		mode = 0o644
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fsError(c, err)
		return
	}
	tmp, err := os.CreateTemp(dir, ".tkbox-write-*")
	if err != nil {
		fsError(c, err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	for {
		fr, err := proto.ReadFrame(c)
		if err != nil {
			return // host gone mid-write: drop the temp file
		}
		switch fr.Type {
		case proto.TypeStdin:
			if _, err := tmp.Write(fr.Payload); err != nil {
				fsError(c, err)
				return
			}
			continue
		case proto.TypeStdinEOF:
		default:
			sendError(c, proto.CodeBadRequest, fmt.Sprintf("unexpected frame type %d in write_file", fr.Type))
			return
		}
		break
	}
	if err := tmp.Chmod(mode); err != nil {
		fsError(c, err)
		return
	}
	if err := tmp.Sync(); err != nil {
		fsError(c, err)
		return
	}
	if err := tmp.Close(); err != nil {
		fsError(c, err)
		return
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		fsError(c, err)
		return
	}
	committed = true
	proto.WriteJSON(c, proto.TypeExit, proto.ExitStatus{})
}
