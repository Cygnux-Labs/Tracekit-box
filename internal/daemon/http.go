package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Cygnux-Labs/tracekit-box/internal/api"
	"github.com/Cygnux-Labs/tracekit-box/internal/proto"
)

type ctxKey int

const peerKey ctxKey = 0

// peer is who is on the other end of an API connection.
type peer struct {
	uid int
	err error
}

const maxBody = 1 << 20

// Handler is the HTTP API (internal/api). Every request is refused with 403 unless the connection's peer uid is the
// daemon's own or root.
func (d *Daemon) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", d.hHealth)
	mux.HandleFunc("POST /v1/boxes", d.hCreate)
	mux.HandleFunc("GET /v1/boxes", d.hList)
	mux.HandleFunc("GET /v1/boxes/{box}", d.hGet)
	mux.HandleFunc("POST /v1/boxes/{box}/exec", d.hExec)
	mux.HandleFunc("POST /v1/boxes/{box}/stop", d.hStop)
	mux.HandleFunc("DELETE /v1/boxes/{box}", d.hRemove)
	mux.HandleFunc("GET /v1/boxes/{box}/diff", d.hDiff)
	mux.HandleFunc("GET /v1/boxes/{box}/diff/summary", d.hDiffSummary)
	mux.HandleFunc("POST /v1/boxes/{box}/apply", d.hApply)
	mux.HandleFunc("POST /v1/boxes/{box}/export", d.hExport)
	mux.HandleFunc("GET /v1/boxes/{box}/events", d.hEvents)
	mux.HandleFunc("GET /v1/approvals", d.hApprovals)
	mux.HandleFunc("POST /v1/approvals/{id}", d.hDecide)
	mux.HandleFunc("POST /v1/images", d.hImage)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, errf(api.CodeNotFound, "see internal/api for the routes", "no route %s %s", r.Method, r.URL.Path))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(peerKey).(peer)
		if p.err != nil || !d.uidAllowed(p.uid) {
			why := "this daemon only answers its own uid or root"
			if p.err != nil {
				why = "could not read the caller's credentials: " + p.err.Error()
			}
			writeErr(w, errf(api.CodeForbidden, fmt.Sprintf("run tkbox as uid %d (or root)", d.ownUID), "%s", why))
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (d *Daemon) uidAllowed(uid int) bool {
	if d.allowUID != nil {
		return d.allowUID(uid)
	}
	return uid == d.ownUID || uid == 0
}

// connContext stores the peer credentials of each accepted connection.
func connContext(ctx context.Context, c net.Conn) context.Context {
	uid, err := peerUID(c)
	return context.WithValue(ctx, peerKey, peer{uid: uid, err: err})
}

func httpStatus(code string) int {
	switch code {
	case api.CodeBadRequest:
		return http.StatusBadRequest
	case api.CodeNotFound:
		return http.StatusNotFound
	case api.CodeConflict:
		return http.StatusConflict
	case api.CodeDenied, api.CodeForbidden:
		return http.StatusForbidden
	case api.CodeUnavailable:
		return http.StatusServiceUnavailable
	case api.CodeLimit:
		return http.StatusUnprocessableEntity
	case api.CodeTimeout:
		return http.StatusGatewayTimeout
	case api.CodeNotSupported:
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	e := asAPIError(err)
	writeJSON(w, httpStatus(e.Code), api.ErrorBody{Error: *e})
}

// maxExecBody caps an exec request: maxBody for the command, plus room for api.MaxStdinData of stdin_data in base64.
var maxExecBody = int64(maxBody + base64.StdEncoding.EncodedLen(api.MaxStdinData))

var errExecTooLarge = errf(api.CodeLimit, "put long commands in a script in /workspace and run that; stream input over 1 MiB (`tkbox exec -i`) or write it to a file",
	"the exec request is too large: the command is too long to record (over 1 MiB) or stdin_data is over 1 MiB")

func readJSON(r *http.Request, v any) error { return readJSONLimit(r, v, maxBody) }

func readJSONLimit(r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errf(api.CodeBadRequest, "send the JSON body internal/api documents for this route", "request body: %v", err)
	}
	return nil
}

func (d *Daemon) hHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.Health(r.Context()))
}

func (d *Daemon) hCreate(w http.ResponseWriter, r *http.Request) {
	var req api.CreateBoxRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	b, err := d.Create(r.Context(), req)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, b)
}

func (d *Daemon) hList(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, d.List()) }

func (d *Daemon) hGet(w http.ResponseWriter, r *http.Request) {
	b, err := d.Get(r.PathValue("box"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (d *Daemon) hStop(w http.ResponseWriter, r *http.Request) {
	var req api.StopRequest
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
	}
	b, err := d.Stop(r.Context(), r.PathValue("box"), req)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (d *Daemon) hRemove(w http.ResponseWriter, r *http.Request) {
	if err := d.Remove(r.Context(), r.PathValue("box")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) hDiff(w http.ResponseWriter, r *http.Request) {
	patch, sum, err := d.Diff(r.Context(), r.PathValue("box"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if sum.Files == nil {
		sum.Files = []proto.DiffFile{}
	}
	// the guest decides how large the summary is: only a small one rides in a header, the rest is at /diff/summary
	if js, _ := json.Marshal(sum); len(js) <= api.MaxDiffSummaryHeader {
		w.Header().Set(api.DiffSummaryHeader, string(js))
	} else {
		w.Header().Set(api.DiffSummaryOmittedHeader, "1")
	}
	w.Header().Set("Content-Type", "text/x-diff")
	w.Header().Set("Content-Length", strconv.Itoa(len(patch)))
	w.WriteHeader(http.StatusOK)
	w.Write(patch)
}

func (d *Daemon) hDiffSummary(w http.ResponseWriter, r *http.Request) {
	_, sum, err := d.Diff(r.Context(), r.PathValue("box"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if sum.Files == nil {
		sum.Files = []proto.DiffFile{}
	}
	writeJSON(w, http.StatusOK, sum)
}

func (d *Daemon) hApply(w http.ResponseWriter, r *http.Request) {
	var req api.ApplyRequest
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
	}
	res, err := d.Apply(r.Context(), r.PathValue("box"), req)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (d *Daemon) hExport(w http.ResponseWriter, r *http.Request) {
	var req api.ExportRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	res, err := d.Export(r.Context(), r.PathValue("box"), req)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (d *Daemon) hEvents(w http.ResponseWriter, r *http.Request) {
	b, err := d.lookup(r.PathValue("box"))
	if err != nil {
		writeErr(w, err)
		return
	}
	follow := r.URL.Query().Get("follow")
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	b.events.stream(r.Context(), w, flush, follow == "1" || follow == "true", func() bool { return alive(b.state()) })
}

func (d *Daemon) hApprovals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.Approvals())
}

func (d *Daemon) hDecide(w http.ResponseWriter, r *http.Request) {
	var dec api.ApprovalDecision
	if err := readJSON(r, &dec); err != nil {
		writeErr(w, err)
		return
	}
	p, _ := r.Context().Value(peerKey).(peer)
	a, err := d.DecideApproval(r.PathValue("id"), dec, p.uid)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (d *Daemon) hImage(w http.ResponseWriter, r *http.Request) {
	var req api.ImageBuildRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	img, err := d.BuildImage(r.Context(), req.Ref)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, img)
}

// hExec checks the request, upgrades the connection to tkbox-exec/1 and runs the exec on it.
func (d *Daemon) hExec(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), api.ExecUpgrade) {
		writeErr(w, errf(api.CodeBadRequest, "send Connection: Upgrade and Upgrade: "+api.ExecUpgrade, "exec needs a connection upgrade"))
		return
	}
	var req api.ExecRequest
	if err := readJSONLimit(r, &req, maxExecBody); err != nil {
		if strings.Contains(err.Error(), "http: request body too large") || r.ContentLength > maxExecBody {
			writeErr(w, errExecTooLarge)
			return
		}
		writeErr(w, err)
		return
	}
	b, e := d.prepareExec(r.PathValue("box"), req)
	if e != nil {
		writeErr(w, e)
		return
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		writeErr(w, errf(api.CodeUnavailable, "start the daemon again (`tkbox daemon`) and retry", "the daemon is shutting down"))
		return
	}
	d.wg.Add(1)
	d.mu.Unlock()
	defer d.wg.Done()
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		writeErr(w, errf(api.CodeInternal, "retry over the Unix socket with HTTP/1.1", "cannot upgrade: %v", err))
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "+api.ExecUpgrade+"\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}
	b.runExec(d.ctx, conn, brw.Reader, conn, req)
}

// Serve listens on the API socket and serves until ctx ends. It refuses to start while another daemon answers on
// the socket, removes a stale socket, and keeps the socket 0600 in a 0700 dir.
func (d *Daemon) Serve(ctx context.Context) error {
	l, err := ListenSocket(d.SocketPath())
	if err != nil {
		return err
	}
	return d.ServeListener(ctx, l)
}

// ServeListener serves the API on l until ctx ends.
func (d *Daemon) ServeListener(ctx context.Context, l net.Listener) error {
	srv := &http.Server{Handler: d.Handler(), ConnContext: connContext, ReadHeaderTimeout: 10 * time.Second,
		ErrorLog: d.log}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// ListenSocket creates the API socket at path: its dir is made 0700, a live daemon there is an error, a stale socket
// is removed (never anything that is not a socket), and the socket is chmod 0600.
func ListenSocket(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket: move it away", path)
		}
		c, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			c.Close()
			return nil, fmt.Errorf("another tkbox daemon is already listening on %s", path)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%s: %v (is another daemon starting?)", path, err)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove the stale socket %s: %w", path, err)
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
