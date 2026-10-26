package vmm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// The test binary doubles as a fake Firecracker: Launch runs it with "--api-sock <path> --id <id>" and an empty
// environment, so the box id picks the behavior:
//
//	fake-ok      serves the API; on InstanceStart serves CONNECT on the vsock UDS (port 1024 echoes, others close)
//	             and dials vsock.sock_1026 to send "hello from <id>\n"; exits 0 on SendCtrlAltDel
//	fake-nocad   like fake-ok but ignores SendCtrlAltDel
//	fake-badcfg  answers PUT /boot-source with a 400 fault_message
//	fake-exit    prints an error and exits 1 before serving the API
//	fake-crash   exits 3 right after InstanceStart
//	fake-spam    like fake-ok, and writes 100 KiB to stdout on InstanceStart
//
// Every request is appended to requests.log in the working directory (the state dir), and every argument the
// launcher passed, one per line, is in args.log there.
func init() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("Firecracker v1.17.0")
		os.Exit(0)
	}
	after := func(flag string) string {
		for i, a := range os.Args[1 : len(os.Args)-1] {
			if a == flag {
				return os.Args[i+2]
			}
		}
		return ""
	}
	if sock, id := after("--api-sock"), after("--id"); sock != "" && id != "" {
		os.WriteFile("args.log", []byte(strings.Join(os.Args[1:], "\n")), 0o600)
		fakeFirecracker(sock, id)
		os.Exit(0)
	}
}

type fakeReq struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
}

func fakeFirecracker(sock, id string) {
	go func() { time.Sleep(60 * time.Second); os.Exit(9) }() // never outlive a test run
	fmt.Printf("fake firecracker %s starting\n", id)
	if id == "fake-exit" {
		fmt.Fprintln(os.Stderr, "Failed to open the API socket: fake error")
		os.Exit(1)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(2)
	}
	logf, _ := os.OpenFile("requests.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	var mu sync.Mutex
	var udsPath string
	fault := func(w http.ResponseWriter, msg string) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"fault_message": msg})
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		rec := fakeReq{Method: r.Method, Path: r.URL.Path}
		if len(body) > 0 {
			rec.Body = body
		}
		b, _ := json.Marshal(rec)
		logf.Write(append(b, '\n'))
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			json.NewEncoder(w).Encode(map[string]string{"id": id, "state": "Not started"})
			return
		case r.URL.Path == "/boot-source" && id == "fake-badcfg":
			fault(w, "Invalid kernel path: fake")
			return
		case r.URL.Path == "/vsock":
			var v fcVsock
			json.Unmarshal(body, &v)
			mu.Lock()
			udsPath = v.UDSPath
			mu.Unlock()
		case r.URL.Path == "/actions":
			var a fcAction
			json.Unmarshal(body, &a)
			switch a.ActionType {
			case "InstanceStart":
				if id == "fake-crash" {
					w.WriteHeader(http.StatusNoContent)
					go func() {
						time.Sleep(50 * time.Millisecond)
						fmt.Fprintln(os.Stderr, "fatal: something broke")
						os.Exit(3)
					}()
					return
				}
				if id == "fake-spam" {
					os.Stdout.Write([]byte(strings.Repeat("x", 100<<10)))
				}
				mu.Lock()
				p := udsPath
				mu.Unlock()
				if err := fakeVsock(p, id); err != nil {
					fault(w, err.Error())
					return
				}
			case "SendCtrlAltDel":
				if id != "fake-nocad" {
					w.WriteHeader(http.StatusNoContent)
					go func() { time.Sleep(20 * time.Millisecond); os.Exit(0) }()
					return
				}
			default:
				fault(w, "unknown action")
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	http.Serve(l, h)
}

func fakeVsock(uds, id string) error {
	l, err := net.Listen("unix", uds)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				var port uint32
				if _, err := fmt.Sscanf(line, "CONNECT %d\n", &port); err != nil || port != 1024 {
					return // nothing listens: Firecracker closes the connection
				}
				fmt.Fprintf(c, "OK %d\n", 1073741824)
				io.Copy(c, br)
			}()
		}
	}()
	go func() {
		for i := 0; i < 100; i++ {
			if c, err := net.Dial("unix", uds+"_1026"); err == nil {
				fmt.Fprintf(c, "hello from %s\n", id)
				c.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return nil
}
