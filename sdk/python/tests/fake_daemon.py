"""A fake tkbox daemon for the SDK tests: a Unix-socket server in a thread that speaks the daemon API's HTTP/1.1, the
exec upgrade (Upgrade: tkbox-exec/1 -> 101) and the frames, written independently of the client so the two check each
other.

Exec behaviour is scripted by argv[0]:
  echo ARGS...  deciding/allow/running events, ARGS on stdout, exit 0
  cat           echoes stdin to stdout (needs stdin)
  fail N        "boom" on stderr, exit N
  deny          a deny decision with rule TK-D001, then a denied error frame
  nosigner      an unavailable error frame
  sleep         killed by the exec timeout
  curl HOST     a notice and a waiting_approval event, then exit 6
  big N         N bytes of "x" on stdout, split into frames of at most 1 MiB
  showreq       the received ExecRequest as JSON on stdout
  cancelled     a cancelled error frame (the command never started)
  nosuchcmd     a not_found error frame for a missing executable
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import socketserver
import struct
import tempfile
import threading
from typing import Any, Dict, List, Optional, Tuple

MAX_FRAME = 1 << 20
T_JSON, T_STDIN, T_STDOUT, T_STDERR, T_EXIT, T_ERROR, T_EOF, T_SIGNAL = range(8)

PATCH = (
    "diff --git a/x.txt b/x.txt\n"
    "new file mode 100644\n"
    "--- /dev/null\n"
    "+++ b/x.txt\n"
    "@@ -0,0 +1 @@\n"
    "+hi\n"
)


def _frame(typ: int, payload: bytes = b"") -> bytes:
    assert len(payload) <= MAX_FRAME
    return struct.pack(">BI", typ, len(payload)) + payload


def _jframe(typ: int, v: Any) -> bytes:
    return _frame(typ, json.dumps(v).encode())


def _short_dir() -> str:
    # AF_UNIX paths are limited to ~104 bytes on macOS; keep the socket path short.
    base = tempfile.gettempdir()
    if len(base) > 60 and os.path.isdir("/tmp"):
        base = "/tmp"
    return tempfile.mkdtemp(prefix="tkb-", dir=base)


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class FakeDaemon:
    def __init__(self) -> None:
        self.dir = _short_dir()
        self.path = os.path.join(self.dir, "tkbox.sock")
        self.boxes: Dict[str, Dict[str, Any]] = {}
        self.requests: List[Dict[str, Any]] = []  # every HTTP request: method, path, headers, body
        self.exec_requests: List[Dict[str, Any]] = []
        self.signer_ok = True
        self.max_boxes = 8
        self.huge_diff = 0  # files in the diff summary; set: a summary too large for a header
        self.summary_of: List[bytes] = []  # each /diff/summary describes the next of these patches instead of PATCH
        self.summary_calls = 0
        # what the fake's apply reports: paths of the patch that steer host automation, and ignored new files
        self.sensitive: List[str] = []
        self.ignored: List[str] = []
        self.approvals: Dict[str, Dict[str, Any]] = {
            "ap_1": {
                "id": "ap_1",
                "box_id": "b_1",
                "box_name": "demo",
                "kind": "egress",
                "target": "https://example.com:443",
                "state": "pending",
                "created_at": "2026-10-26T10:00:00Z",
                "expires_at": "2026-10-26T10:02:00Z",
            }
        }
        self.lock = threading.Lock()
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                try:
                    outer._handle(self.connection, self.rfile)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = _Server(self.path, Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def start(self) -> "FakeDaemon":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)

    # --- HTTP ----------------------------------------------------------------------------------------------------

    @staticmethod
    def _read_request(rfile) -> Optional[Tuple[str, str, Dict[str, str], bytes]]:
        line = rfile.readline()
        if not line:
            return None
        method, target, version = line.decode("latin-1").rstrip("\r\n").split(" ")
        assert version == "HTTP/1.1", version
        headers: Dict[str, str] = {}
        while True:
            h = rfile.readline()
            if h in (b"\r\n", b"\n", b""):
                break
            k, _, v = h.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()
        n = int(headers.get("content-length", "0"))
        body = rfile.read(n) if n else b""
        return method, target, headers, body

    @staticmethod
    def _respond(
        conn: socket.socket,
        status: int,
        body: Any = None,
        *,
        reason: str = "",
        headers: Optional[Dict[str, str]] = None,
        chunked: bool = False,
        content_type: str = "application/json",
    ) -> None:
        if body is None:
            data = b""
        elif isinstance(body, (bytes, str)):
            data = body.encode() if isinstance(body, str) else body
        else:
            data = json.dumps(body).encode()
        lines = [f"HTTP/1.1 {status} {reason or 'Status'}"]
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        if status != 204:
            lines.append(f"Content-Type: {content_type}")
            if chunked:
                lines.append("Transfer-Encoding: chunked")
            else:
                lines.append(f"Content-Length: {len(data)}")
        lines.append("Connection: close")
        out = ("\r\n".join(lines) + "\r\n\r\n").encode()
        if status != 204:
            if chunked:
                # uneven chunks, with an extension on one, to exercise the client's parser
                pieces = [data[i : i + 7] for i in range(0, len(data), 7)]
                for i, p in enumerate(pieces):
                    ext = ";x=y" if i == 1 else ""
                    out += f"{len(p):x}{ext}\r\n".encode() + p + b"\r\n"
                out += b"0\r\n\r\n"
            else:
                out += data
        conn.sendall(out)

    def _error(self, conn: socket.socket, status: int, code: str, message: str, hint: str = "", rule_ids=None) -> None:
        detail: Dict[str, Any] = {"code": code, "message": message}
        if hint:
            detail["hint"] = hint
        if rule_ids:
            detail["rule_ids"] = rule_ids
        self._respond(conn, status, {"error": detail})

    def _box(self, key: str) -> Optional[Dict[str, Any]]:
        for b in self.boxes.values():
            if b["id"] == key or b["name"] == key:
                return b
        return None

    def _handle(self, conn: socket.socket, rfile) -> None:
        req = self._read_request(rfile)
        if req is None:
            return
        method, target, headers, body = req
        path, _, query = target.partition("?")
        payload = json.loads(body) if body else None
        with self.lock:
            self.requests.append({"method": method, "path": path, "query": query, "headers": headers, "body": payload})
        parts = [p for p in path.split("/") if p]
        from urllib.parse import unquote

        parts = [unquote(p) for p in parts]

        if parts[:1] != ["v1"]:
            return self._respond(conn, 404, "404 page not found\n", content_type="text/plain")
        rest = parts[1:]

        if rest == ["health"] and method == "GET":
            return self._respond(
                conn,
                200,
                {
                    "version": "v0.1.0",
                    "api": "v1",
                    "arch": "arm64",
                    "kvm": True,
                    "signer": "/run/user/1000/tracekit/signer.sock",
                    "signer_ok": self.signer_ok,
                    "unrecorded": False,
                    "boxes": len(self.boxes),
                    "state_dir": "/home/me/.local/state/tkbox",
                },
            )

        if rest == ["boxes"] and method == "POST":
            return self._create(conn, payload or {})
        if rest == ["boxes"] and method == "GET":
            return self._respond(conn, 200, list(self.boxes.values()))

        if rest == ["approvals"] and method == "GET":
            return self._respond(conn, 200, [a for a in self.approvals.values() if a["state"] == "pending"])
        if len(rest) == 2 and rest[0] == "approvals" and method == "POST":
            ap = self.approvals.get(rest[1])
            if ap is None:
                return self._error(conn, 404, "not_found", f"no approval {rest[1]}")
            d = (payload or {}).get("decision")
            if d not in ("approve", "reject"):
                return self._error(conn, 400, "bad_request", "decision must be approve or reject")
            ap = dict(ap, state="approved" if d == "approve" else "rejected", decided_by="uid:501")
            if (payload or {}).get("scope"):
                ap["scope_seen"] = payload["scope"]
            self.approvals[rest[1]] = ap
            return self._respond(conn, 200, ap)

        if len(rest) >= 2 and rest[0] == "boxes":
            box = self._box(rest[1])
            if box is None:
                return self._error(conn, 404, "not_found", f"no box {rest[1]}", hint="list boxes with `tkbox ls`")
            sub = rest[2:]
            if sub == [] and method == "GET":
                return self._respond(conn, 200, box)
            if sub == [] and method == "DELETE":
                del self.boxes[box["name"]]
                return self._respond(conn, 204, reason="No Content")
            if sub == ["stop"] and method == "POST":
                box["state"] = "stopped"
                box["stop_reason"] = (payload or {}).get("reason") or ("killed" if (payload or {}).get("kill") else "stopped")
                return self._respond(conn, 200, box)
            if sub in (["diff"], ["diff", "summary"]) and method == "GET":
                summary = {"files": [{"path": "x.txt", "status": "added", "new_mode": 0o644}], "bytes": len(PATCH)}
                if self.huge_diff:  # thousands of long paths: too large for a header, like the real daemon's
                    summary = {"files": [{"path": "d/" + "x" * 180 + f"/f{i:05d}.txt", "status": "added"}
                                         for i in range(self.huge_diff)], "bytes": len(PATCH)}
                patch_sha = hashlib.sha256(PATCH.encode() if isinstance(PATCH, str) else PATCH).hexdigest()
                summary["patch_sha256"] = patch_sha
                if sub == ["diff", "summary"]:
                    with self.lock:
                        self.summary_calls += 1
                        if self.summary_of:  # a running box whose workspace changed: a summary of another patch
                            summary["patch_sha256"] = hashlib.sha256(self.summary_of.pop(0)).hexdigest()
                    return self._respond(conn, 200, summary)
                js = json.dumps(summary)
                hdrs = {"X-Tkbox-Diff-Summary": js} if len(js) <= 8192 else {"X-Tkbox-Diff-Summary-Omitted": "1"}
                hdrs["X-Tkbox-Diff-Sha256"] = patch_sha
                return self._respond(conn, 200, PATCH, headers=hdrs, chunked=True, content_type="text/x-diff")
            if sub == ["apply"] and method == "POST":
                p = payload or {}
                if box["state"] != "stopped":
                    return self._error(
                        conn, 409, "conflict", f"box {rest[1]} is {box['state']}",
                        hint=f"stop the box first so the patch can't change under you: `tkbox stop {rest[1]}`",
                    )
                if self.sensitive and not p.get("allow_sensitive"):
                    return self._error(
                        conn, 400, "bad_request",
                        "the patch changes files that steer the next run or host automation: " + ", ".join(self.sensitive),
                        hint=f"review them, then run `tkbox apply {rest[1]} --allow-sensitive`; nothing was applied",
                    )
                check = bool(p.get("check"))
                res: Dict[str, Any] = {
                    "applied": [] if check else ["x.txt"] + self.sensitive,
                    "patch": f"/state/boxes/{box['id']}/diff.patch",
                    "sha256": "ab" * 32,
                }
                if check:
                    res["checked"] = True
                if self.sensitive:
                    res["sensitive"] = list(self.sensitive)
                if self.ignored:
                    res["ignored"] = list(self.ignored)
                return self._respond(conn, 200, res)
            if sub == ["export"] and method == "POST":
                out = (payload or {}).get("out", "")
                if not out.startswith("/"):
                    return self._error(conn, 400, "bad_request", "out must be an absolute path")
                trust = out + ".trust.json"
                return self._respond(
                    conn,
                    200,
                    {"run_id": box["run_id"], "bundle": out, "trust": trust, "verify": f"tracekit verify {out} --trust {trust}"},
                )
            if sub == ["events"] and method == "GET":
                evs = [
                    {"time": "2026-10-26T10:00:00Z", "box_id": box["id"], "kind": "box.created", "door": "lifecycle"},
                    {"time": "2026-10-26T10:00:01Z", "box_id": box["id"], "kind": "exec.decided", "door": "exec",
                     "summary": "Bash 'echo hi': allow"},
                    {"time": "2026-10-26T10:00:02Z", "box_id": box["id"], "kind": "egress.denied", "door": "egress",
                     "data": {"host": "example.com", "port": 443}},
                ]
                body_s = "".join(json.dumps(e) + "\n" for e in evs)
                return self._respond(conn, 200, body_s, chunked=True, content_type="application/x-ndjson")
            if sub == ["exec"] and method == "POST":
                return self._exec(conn, rfile, headers, box, payload or {})
        return self._error(conn, 404, "not_found", f"no route {method} {path}")

    def _create(self, conn: socket.socket, req: Dict[str, Any]) -> None:
        if not self.signer_ok:
            return self._error(
                conn, 503, "unavailable", "the Tracekit signer is not answering",
                hint="start it with `tracekit up`, or run the daemon with --unrecorded to record nothing",
            )
        if not req.get("image"):
            return self._error(conn, 400, "bad_request", "image is required")
        name = req.get("name") or f"b_{len(self.boxes) + 1}"
        if self._box(name):
            return self._error(conn, 409, "conflict", f"a box named {name} exists", hint=f"pick another name or `tkbox rm {name}`")
        if len(self.boxes) >= self.max_boxes:
            return self._error(
                conn, 429, "limit", f"{self.max_boxes} boxes already exist (the daemon's limit)",
                hint="remove one with `tkbox rm <box>`",
            )
        for k, s in (req.get("secrets") or {}).items():
            if not s.get("hosts"):
                return self._error(conn, 400, "bad_request", f"secret {k} has no hosts")
        box_id = f"b_{len(self.boxes) + 1}"
        box = {
            "id": box_id,
            "name": name,
            "state": "running",
            "image": req["image"],
            "allow": req.get("allow") or [],
            "secrets": sorted((req.get("secrets") or {}).keys()),
            "env": req.get("env") or {},
            "workspace": req.get("workspace", ""),
            "limits": {"cpus": 2, "memory_mib": 2048, "disk_mib": 4096, "timeout": "1h0m0s", "exec_timeout": "30m0s",
                       **(req.get("limits") or {})},
            "inspect": req.get("inspect") or "bound",
            "run_id": "run_" + box_id,
            "created_at": "2026-10-26T10:00:00Z",
            "execs": 0,
        }
        self.boxes[name] = box
        self._respond(conn, 201, box, reason="Created")

    # --- exec ----------------------------------------------------------------------------------------------------

    def _exec(self, conn: socket.socket, rfile, headers: Dict[str, str], box: Dict[str, Any], req: Dict[str, Any]) -> None:
        if headers.get("upgrade") != "tkbox-exec/1" or "upgrade" not in headers.get("connection", "").lower():
            return self._error(conn, 400, "bad_request", "exec needs Upgrade: tkbox-exec/1")
        argv = req.get("argv") or []
        if not argv:
            return self._error(conn, 400, "bad_request", "argv is empty")
        with self.lock:
            self.exec_requests.append(req)
        box["execs"] += 1
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tkbox-exec/1\r\n\r\n")
        send = conn.sendall
        cmd = argv[0]

        def ev(**kw: Any) -> None:
            send(_jframe(T_JSON, kw))

        def read_stdin() -> bytes:
            buf = b""
            while True:
                hdr = rfile.read(5)
                if len(hdr) < 5:
                    raise AssertionError("stdin stream ended without TypeStdinEOF")
                typ, n = struct.unpack(">BI", hdr)
                payload = rfile.read(n) if n else b""
                if typ == T_EOF:
                    assert n == 0
                    return buf
                assert typ == T_STDIN, typ
                assert n <= MAX_FRAME
                buf += payload

        ev(state="deciding")
        if cmd == "deny":
            ev(state="deciding", decision="deny", rule_ids=["TK-D001"], message="destructive command")
            return send(_jframe(T_ERROR, {"code": "denied", "message": "the signer refused this command"}))
        if cmd == "nosigner":
            return send(_jframe(T_ERROR, {"code": "unavailable", "message": "the Tracekit signer is not answering"}))
        if cmd == "cancelled":
            return send(_jframe(T_ERROR, {"code": "cancelled", "message": "cancelled before the command started (nothing ran)"}))
        if cmd == "nosuchcmd":
            return send(_jframe(T_ERROR, {"code": "not_found", "message": "start nosuchcmd: executable file not found",
                                          "hint": "install it in the box or use an image that has it"}))
        ev(state="deciding", decision="allow")
        ev(state="running")
        if cmd == "echo":
            send(_frame(T_STDOUT, (" ".join(argv[1:]) + "\n").encode()))
            return send(_jframe(T_EXIT, {"code": 0, "duration_ms": 3}))
        if cmd == "cat":
            if "stdin_data" in req:
                assert not req.get("stdin"), "stdin_data and a streamed stdin"
                data = base64.b64decode(req["stdin_data"], validate=True)
            else:
                data = read_stdin() if req.get("stdin") else b""
            for i in range(0, len(data), MAX_FRAME):
                send(_frame(T_STDOUT, data[i : i + MAX_FRAME]))
            return send(_jframe(T_EXIT, {"code": 0}))
        if cmd == "fail":
            send(_frame(T_STDERR, b"boom\n"))
            return send(_jframe(T_EXIT, {"code": int(argv[1])}))
        if cmd == "sleep":
            return send(_jframe(T_EXIT, {"code": -1, "signal": "SIGKILL", "timed_out": True, "duration_ms": 1000}))
        if cmd == "stdin-unread":
            return send(_jframe(T_EXIT, {"code": -1, "signal": "SIGKILL", "stdin_truncated": True,
                                         "stdin_dropped_bytes": 4096}))
        if cmd == "curl":
            host = argv[1]
            ev(state="notice", message=f"egress: {host}:443 is not on the allowlist; waiting for `tkbox approve ap_2`")
            ev(state="waiting_approval", approval_id="ap_2", approver="tkbox")
            send(_frame(T_STDERR, b"curl: (56) CONNECT tunnel failed, response 403\n"))
            return send(_jframe(T_EXIT, {"code": 56}))
        if cmd == "big":
            data = b"x" * int(argv[1])
            for i in range(0, len(data), MAX_FRAME):
                send(_frame(T_STDOUT, data[i : i + MAX_FRAME]))
            return send(_jframe(T_EXIT, {"code": 0, "truncated": False}))
        if cmd == "showreq":
            send(_frame(T_STDOUT, json.dumps(req).encode()))
            return send(_jframe(T_EXIT, {"code": 0}))
        send(_frame(T_STDERR, f"sh: {cmd}: not found\n".encode()))
        send(_jframe(T_EXIT, {"code": 127}))
