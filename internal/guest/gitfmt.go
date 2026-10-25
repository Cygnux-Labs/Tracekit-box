package guest

import (
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
)

// Pieces of git's patch format: blob ids, C-style path quoting and "GIT binary patch" literals.

const zeroOID = "0000000000000000000000000000000000000000"

// blobHasher computes a git blob id (SHA-1 of "blob <size>\0" + content) of a known size.
func blobHasher(size int64) hash.Hash {
	h := sha1.New()
	h.Write([]byte("blob " + strconv.FormatInt(size, 10) + "\x00"))
	return h
}

func blobID(data []byte) string {
	h := blobHasher(int64(len(data)))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// quotePath returns prefix+p as git writes it in headers: C-quoted when p has control characters, '"', '\\' or bytes
// >= 0x80 (core.quotePath=true).
func quotePath(prefix, p string) string {
	s := prefix + p
	need := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == '"' || c == '\\' || c >= 0x7f {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\a':
			b.WriteString(`\a`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\v':
			b.WriteString(`\v`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if c < 0x20 || c >= 0x7f {
				fmt.Fprintf(&b, `\%03o`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

const b85chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

// b85Lines writes git's base85 lines: up to 52 bytes per line, prefixed by a length character ('A'..'Z' for 1..26,
// 'a'..'z' for 27..52).
type b85Lines struct {
	w   io.Writer
	buf [52]byte
	n   int
	out []byte
}

func (l *b85Lines) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		k := copy(l.buf[l.n:], p)
		l.n += k
		p = p[k:]
		if l.n == len(l.buf) {
			if err := l.flush(); err != nil {
				return total - len(p), err
			}
		}
	}
	return total, nil
}

func (l *b85Lines) flush() error {
	if l.n == 0 {
		return nil
	}
	out := l.out[:0]
	if l.n <= 26 {
		out = append(out, byte('A'+l.n-1))
	} else {
		out = append(out, byte('a'+l.n-27))
	}
	for i := 0; i < l.n; i += 4 {
		var acc uint32
		for j := 0; j < 4; j++ {
			acc <<= 8
			if i+j < l.n {
				acc |= uint32(l.buf[i+j])
			}
		}
		var enc [5]byte
		for j := 4; j >= 0; j-- {
			enc[j] = b85chars[acc%85]
			acc /= 85
		}
		out = append(out, enc[:]...)
	}
	out = append(out, '\n')
	l.out = out
	l.n = 0
	_, err := l.w.Write(out)
	return err
}

// writeBinaryLiteral writes a forward "literal" hunk of r's size bytes (git apply needs no reverse hunk). It fails if
// r does not yield exactly size bytes (the file changed under the diff).
func writeBinaryLiteral(w io.Writer, r io.Reader, size int64) error {
	if _, err := fmt.Fprintf(w, "GIT binary patch\nliteral %d\n", size); err != nil {
		return err
	}
	lines := &b85Lines{w: w}
	zw, _ := zlib.NewWriterLevel(lines, zlib.BestCompression)
	n, err := io.Copy(zw, io.LimitReader(r, size))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("%w: expected %d bytes, read %d", errChangedDuringDiff, size, n)
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := lines.flush(); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n")
	return err
}
