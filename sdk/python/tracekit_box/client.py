"""A client of the tkbox daemon API (internal/api/api.go): HTTP/1.1 over the daemon's Unix socket, one connection per
request, and the exec stream (Upgrade: tkbox-exec/1, then frames)."""

from __future__ import annotations

import json
import os
import socket as _socket
import threading
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import quote

from . import frames
from .errors import DaemonUnreachable, ProtocolError, TkboxError, from_detail

__all__ = ["Client", "ExecResult", "Diff", "Secret", "Limits", "default_socket"]

VERSION = "0.1.0"
EXEC_UPGRADE = "tkbox-exec/1"
DIFF_SUMMARY_HEADER = "x-tkbox-diff-summary"

StdinLike = Union[bytes, bytearray, str, BinaryIO, None]
Seconds = Union[int, float, str, None]


def default_socket() -> str:
    """Where the daemon listens: $TKBOX_SOCKET, else <state dir>/run/tkbox.sock, where the state dir is /var/lib/tkbox
    as root and $XDG_STATE_HOME/tkbox (default ~/.local/state/tkbox) otherwise."""
    env = os.environ.get("TKBOX_SOCKET")
    if env:
        return env
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        state = "/var/lib/tkbox"
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        state = os.path.join(base, "tkbox")
    return os.path.join(state, "run", "tkbox.sock")


@dataclass
class Secret:
    """A secret bound to hosts. The box sees only a placeholder; the daemon's egress proxy swaps value into header
    (any request header when header is empty) only on requests to hosts."""

    value: str
    hosts: Sequence[str]
    header: str = ""

    def to_json(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"value": self.value, "hosts": [h.lower() for h in self.hosts]}
        if self.header:
            d["header"] = self.header
        return d

    def __repr__(self) -> str:  # never print the value
        return f"Secret(value='***', hosts={list(self.hosts)!r}, header={self.header!r})"


@dataclass
class Limits:
    """Limits of one box. None means the daemon's default (cpus 2, memory 2048 MiB, disk 4096 MiB, timeout 1h,
    exec_timeout 30m). Timeouts are seconds or Go duration strings ("30m")."""

    cpus: Optional[int] = None
    memory_mib: Optional[int] = None
    disk_mib: Optional[int] = None
    timeout: Seconds = None
    exec_timeout: Seconds = None

    def to_json(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        for k in ("cpus", "memory_mib", "disk_mib", "timeout", "exec_timeout"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


@dataclass
class ExecResult:
    """The outcome of one exec. exit_code is the process's exit code (-1 when a signal killed it)."""

    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""
    signal: str = ""
    timed_out: bool = False
    notices: List[str] = field(default_factory=list)  # messages of "notice" events (an egress refusal, an approval)
    events: List[Dict[str, Any]] = field(default_factory=list)  # every ExecEvent, in order
    duration_ms: int = 0
    truncated: bool = False  # output beyond the per-exec limit was dropped

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", "replace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", "replace")


@dataclass
class Diff:
    """A box's workspace changes: a git-format patch and the summary (files, bytes)."""

    patch: str
    summary: Dict[str, Any]

    @property
    def files(self) -> List[Dict[str, Any]]:
        return list(self.summary.get("files") or [])


class _Response:
    """A parsed HTTP response head plus a reader positioned at the body."""

    def __init__(self, sock: _socket.socket, reader: BinaryIO, status: int, reason: str, headers: Dict[str, str]):
        self.sock = sock
        self.reader = reader
        self.status = status
        self.reason = reason
        self.headers = headers

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def body_chunks(self) -> Iterator[bytes]:
        """Yield the body as it arrives (chunked, Content-Length, or until EOF)."""
        if self.status in (204, 304) or 100 <= self.status < 200:
            return
        te = self.header("transfer-encoding").lower()
        if "chunked" in te:
            while True:
                line = self.reader.readline(65537)
                if not line:
                    raise ProtocolError("connection closed in a chunked body")
                size_s = line.split(b";", 1)[0].strip()
                try:
                    size = int(size_s, 16)
                except ValueError:
                    raise ProtocolError(f"bad chunk size {size_s!r}") from None
                if size == 0:
                    while True:  # trailers, then the blank line
                        t = self.reader.readline(65537)
                        if not t or t in (b"\r\n", b"\n"):
                            return
                data = frames._read_exact(self.reader, size)
                if len(data) < size:
                    raise ProtocolError("connection closed in a chunk")
                self.reader.readline(3)  # CRLF after the chunk
                yield data
        length = self.header("content-length")
        if length:
            n = int(length)
            while n > 0:
                data = self.reader.read(min(n, 65536))
                if not data:
                    raise ProtocolError("connection closed before the end of the body")
                n -= len(data)
                yield data
            return
        while True:
            data = self.reader.read(65536)
            if not data:
                return
            yield data

    def body(self) -> bytes:
        return b"".join(self.body_chunks())

    def close(self) -> None:
        try:
            self.reader.close()
        finally:
            self.sock.close()


def _duration(v: Seconds) -> Union[int, float, str]:
    if isinstance(v, bool) or not isinstance(v, (int, float, str)):
        raise TypeError("a timeout is seconds (int or float) or a Go duration string like '30m'")
    return v


class Client:
    """A client of one tkbox daemon.

    socket: the daemon's Unix socket (default: default_socket()). timeout: seconds for each ordinary request (an exec
    stream has no client-side timeout: the daemon enforces the exec timeout and approval waits).
    """

    def __init__(self, socket: Optional[str] = None, timeout: Optional[float] = 300.0) -> None:
        self.socket = socket or default_socket()
        self.timeout = timeout

    # --- HTTP over the Unix socket -------------------------------------------------------------------------------

    def _connect(self, timeout: Optional[float]) -> _socket.socket:
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self.socket)
        except OSError as e:
            s.close()
            raise DaemonUnreachable(
                f"cannot reach the tkbox daemon at {self.socket}: {e.strerror or e}",
                hint="start it with `tkbox daemon`, or set TKBOX_SOCKET to its socket",
            ) from None
        return s

    def _send(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        upgrade: bool = False,
        timeout: Optional[float] = None,
        accept: str = "application/json",
    ) -> _Response:
        data = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        lines = [
            f"{method} {path} HTTP/1.1",
            "Host: tkbox",
            f"User-Agent: tracekit-box-python/{VERSION}",
            f"Accept: {accept}",
        ]
        if body is not None or method in ("POST", "PUT"):
            lines.append("Content-Type: application/json")
            lines.append(f"Content-Length: {len(data)}")
        if upgrade:
            lines.append("Connection: Upgrade")
            lines.append(f"Upgrade: {EXEC_UPGRADE}")
        else:
            lines.append("Connection: close")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        sock = self._connect(self.timeout if timeout is None else timeout)
        try:
            sock.sendall(head + data)
            reader = sock.makefile("rb")
            status, reason, headers = self._read_head(reader)
        except _socket.timeout:
            sock.close()
            raise TkboxError(f"{method} {path}: the daemon did not answer within {self.timeout}s", code="timeout") from None
        except OSError as e:
            sock.close()
            raise DaemonUnreachable(f"{method} {path}: connection to the tkbox daemon failed: {e}") from None
        except BaseException:
            sock.close()
            raise
        return _Response(sock, reader, status, reason, headers)

    @staticmethod
    def _read_head(reader: BinaryIO) -> Tuple[int, str, Dict[str, str]]:
        line = reader.readline(65537)
        if not line:
            raise ProtocolError("the daemon closed the connection without an answer")
        parts = line.decode("latin-1").rstrip("\r\n").split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/1."):
            raise ProtocolError(f"not an HTTP response: {line[:80]!r}")
        try:
            status = int(parts[1])
        except ValueError:
            raise ProtocolError(f"bad HTTP status {parts[1]!r}") from None
        reason = parts[2] if len(parts) > 2 else ""
        headers: Dict[str, str] = {}
        while True:
            h = reader.readline(65537)
            if not h:
                raise ProtocolError("connection closed in the response headers")
            if h in (b"\r\n", b"\n"):
                break
            k, sep, v = h.decode("latin-1").partition(":")
            if not sep:
                raise ProtocolError(f"bad header line {h[:80]!r}")
            k = k.strip().lower()
            v = v.strip()
            headers[k] = headers[k] + ", " + v if k in headers else v
        return status, reason, headers

    @staticmethod
    def _raise_for(resp: _Response, body: bytes) -> None:
        if 200 <= resp.status < 300:
            return
        try:
            detail = json.loads(body.decode("utf-8"))["error"]
            if not isinstance(detail, dict):
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            text = body.decode("utf-8", "replace").strip()[:500]
            raise TkboxError(
                f"HTTP {resp.status} {resp.reason}" + (f": {text}" if text else ""), status=resp.status
            ) from None
        raise from_detail(detail, resp.status)

    def _request(self, method: str, path: str, body: Any = None) -> Tuple[_Response, bytes]:
        resp = self._send(method, path, body)
        try:
            data = resp.body()
        except _socket.timeout:
            raise TkboxError(f"{method} {path}: timed out reading the answer", code="timeout") from None
        finally:
            resp.close()
        self._raise_for(resp, data)
        return resp, data

    def _json(self, method: str, path: str, body: Any = None) -> Any:
        _, data = self._request(method, path, body)
        if not data:
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except ValueError:
            raise ProtocolError(f"{method} {path}: the answer is not JSON") from None

    @staticmethod
    def _box_path(box: str, suffix: str = "") -> str:
        if not box:
            raise ValueError("box: an id or a name is required")
        return "/v1/boxes/" + quote(box, safe="") + suffix

    # --- API -----------------------------------------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        """GET /v1/health: version, arch, kvm, signer, signer_ok, unrecorded, boxes, state_dir."""
        return self._json("GET", "/v1/health")

    def create_box(
        self,
        image: str,
        *,
        name: Optional[str] = None,
        allow: Optional[Sequence[str]] = None,
        secrets: Optional[Mapping[str, Union[Secret, Mapping[str, Any]]]] = None,
        env: Optional[Mapping[str, str]] = None,
        workspace: Optional[str] = None,
        limits: Union[Limits, Mapping[str, Any], None] = None,
        inspect: Optional[str] = None,
        agent: Optional[str] = None,
        task: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /v1/boxes: create and start a box; returns the Box. Mirrors api.CreateBoxRequest.

        secrets maps an env var name to a Secret (or a dict {value, hosts, header}). workspace is a host directory
        (made absolute here) copied into /workspace. inspect is "bound" (default) or "all".
        """
        req: Dict[str, Any] = {"image": image}
        if name:
            req["name"] = name
        if allow:
            req["allow"] = [allow] if isinstance(allow, str) else list(allow)
        if secrets:
            out = {}
            for k, v in secrets.items():
                if isinstance(v, Secret):
                    out[k] = v.to_json()
                else:
                    if not v.get("hosts"):
                        raise ValueError(f"secret {k}: hosts is required (the hosts its value may be sent to)")
                    out[k] = dict(v)
            req["secrets"] = out
        if env:
            req["env"] = dict(env)
        if workspace:
            req["workspace"] = os.path.abspath(os.path.expanduser(workspace))
        if limits:
            req["limits"] = limits.to_json() if isinstance(limits, Limits) else dict(limits)
        if inspect:
            req["inspect"] = inspect
        if agent:
            req["agent"] = agent
        if task:
            req["task"] = task
        return self._json("POST", "/v1/boxes", req)

    run = create_box

    def list_boxes(self) -> List[Dict[str, Any]]:
        """GET /v1/boxes."""
        return self._json("GET", "/v1/boxes") or []

    def get_box(self, box: str) -> Dict[str, Any]:
        """GET /v1/boxes/{box} (an id or a name)."""
        return self._json("GET", self._box_path(box))

    def stop(self, box: str, *, kill: bool = False, reason: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/boxes/{box}/stop. kill=True kills the VM now instead of a clean shutdown."""
        req: Dict[str, Any] = {}
        if kill:
            req["kill"] = True
        if reason:
            req["reason"] = reason
        return self._json("POST", self._box_path(box, "/stop"), req)

    def rm(self, box: str) -> None:
        """DELETE /v1/boxes/{box} (a running box is stopped first)."""
        self._request("DELETE", self._box_path(box))

    def diff(self, box: str) -> Diff:
        """GET /v1/boxes/{box}/diff: the workspace patch and its summary."""
        resp, data = self._request("GET", self._box_path(box, "/diff"))
        summary: Dict[str, Any] = {"files": [], "bytes": len(data)}
        raw = resp.header(DIFF_SUMMARY_HEADER)
        if raw:
            try:
                summary = json.loads(raw)
            except ValueError:
                raise ProtocolError(f"bad {DIFF_SUMMARY_HEADER} header") from None
        return Diff(patch=data.decode("utf-8", "replace"), summary=summary)

    def apply(self, box: str, *, dir: Optional[str] = None, check: bool = False) -> Dict[str, Any]:
        """POST /v1/boxes/{box}/apply: decide every changed file with the signer, then write them to dir (default the
        box's workspace). check=True decides only and writes nothing. Returns {applied, denied, patch, checked}."""
        req: Dict[str, Any] = {}
        if dir:
            req["dir"] = os.path.abspath(os.path.expanduser(dir))
        if check:
            req["check"] = True
        return self._json("POST", self._box_path(box, "/apply"), req)

    def export(self, box: str, out: str) -> Dict[str, Any]:
        """POST /v1/boxes/{box}/export: write the run's .tkb to out and its trust file to <out>.trust.json. Returns
        {run_id, bundle, trust, verify}."""
        return self._json("POST", self._box_path(box, "/export"), {"out": os.path.abspath(os.path.expanduser(out))})

    def events(self, box: str, *, follow: bool = False) -> Iterator[Dict[str, Any]]:
        """GET /v1/boxes/{box}/events: the box's events, one dict per line. follow=True keeps reading new events until
        the daemon closes the stream (or the caller stops iterating)."""
        path = self._box_path(box, "/events") + ("?follow=1" if follow else "")
        resp = self._send("GET", path, timeout=None if follow else self.timeout, accept="application/x-ndjson")
        try:
            if not 200 <= resp.status < 300:
                self._raise_for(resp, resp.body())
            buf = b""
            for chunk in resp.body_chunks():
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        yield json.loads(line.decode("utf-8"))
            if buf.strip():
                yield json.loads(buf.decode("utf-8"))
        finally:
            resp.close()

    def approvals(self) -> List[Dict[str, Any]]:
        """GET /v1/approvals: pending Box approvals of every box."""
        return self._json("GET", "/v1/approvals") or []

    def approve(self, approval_id: str, *, scope: str = "once") -> Dict[str, Any]:
        """POST /v1/approvals/{id} approve. scope "box" approves the host for the rest of the box."""
        req: Dict[str, Any] = {"decision": "approve"}
        if scope and scope != "once":
            req["scope"] = scope
        return self._json("POST", "/v1/approvals/" + quote(approval_id, safe=""), req)

    def reject(self, approval_id: str) -> Dict[str, Any]:
        """POST /v1/approvals/{id} reject."""
        return self._json("POST", "/v1/approvals/" + quote(approval_id, safe=""), {"decision": "reject"})

    def build_image(self, ref: str) -> Dict[str, Any]:
        """POST /v1/images: pull and build (or reuse) the rootfs of ref."""
        return self._json("POST", "/v1/images", {"ref": ref})

    # --- exec ----------------------------------------------------------------------------------------------------

    def exec(
        self,
        box: str,
        argv: Sequence[str],
        stdin: StdinLike = None,
        env: Optional[Mapping[str, str]] = None,
        cwd: Optional[str] = None,
        timeout: Seconds = None,
        *,
        on_output: Optional[Callable[[str, bytes], None]] = None,
        on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> ExecResult:
        """Run argv in the box and wait for it. The signer decides the command before it starts.

        stdin: bytes, str or a binary file object sent to the process (else its stdin is /dev/null). timeout: seconds
        or a Go duration string (default: the box's exec timeout). on_output(stream, data) is called with "stdout" or
        "stderr" as output arrives; on_event(event) with each ExecEvent (deciding, waiting_approval, running, notice).

        Returns an ExecResult whatever the exit code. Raises Denied when the command is refused (with rule_ids),
        Unavailable when the signer can't be reached, and the other TkboxError classes for the other failures; the
        exception's stdout, stderr and events hold what arrived before it.
        """
        if isinstance(argv, str) or not argv:
            raise ValueError("argv: a non-empty list of strings, e.g. ['python', '-c', 'print(1)']")
        req: Dict[str, Any] = {"argv": [str(a) for a in argv]}
        if env:
            req["env"] = dict(env)
        if cwd:
            req["cwd"] = cwd
        if timeout is not None:
            req["timeout"] = _duration(timeout)
        if stdin is not None:
            req["stdin"] = True

        resp = self._send("POST", self._box_path(box, "/exec"), req, upgrade=True, timeout=None)
        try:
            if resp.status != 101:
                self._raise_for(resp, resp.body())
                raise ProtocolError(f"exec: expected 101 Switching Protocols, got {resp.status} {resp.reason}")
            if resp.header("upgrade") and resp.header("upgrade").lower() != EXEC_UPGRADE:
                raise ProtocolError(f"exec: the daemon upgraded to {resp.header('upgrade')!r}, not {EXEC_UPGRADE}")
            writer: Optional[threading.Thread] = None
            write_err: List[BaseException] = []
            if stdin is not None:
                writer = threading.Thread(target=self._pump_stdin, args=(resp.sock, stdin, write_err), daemon=True)
                writer.start()
            result = self._read_exec(resp.reader, on_output, on_event)
            if writer is not None:
                writer.join(timeout=5)
            return result
        finally:
            resp.close()

    @staticmethod
    def _pump_stdin(sock: _socket.socket, stdin: StdinLike, errs: List[BaseException]) -> None:
        try:
            if isinstance(stdin, str):
                stdin = stdin.encode("utf-8")
            if isinstance(stdin, (bytes, bytearray)):
                for f in frames.chunks(frames.TYPE_STDIN, bytes(stdin)):
                    sock.sendall(f)
            else:
                while True:
                    data = stdin.read(frames.MAX_FRAME)  # type: ignore[union-attr]
                    if not data:
                        break
                    if isinstance(data, str):
                        data = data.encode("utf-8")
                    sock.sendall(frames.encode(frames.TYPE_STDIN, data))
            sock.sendall(frames.encode(frames.TYPE_STDIN_EOF))
        except OSError as e:  # the exec ended (or was refused) before it read all of stdin
            errs.append(e)

    @staticmethod
    def _read_exec(
        reader: BinaryIO,
        on_output: Optional[Callable[[str, bytes], None]],
        on_event: Optional[Callable[[Dict[str, Any]], None]],
    ) -> ExecResult:
        out = bytearray()
        err = bytearray()
        events: List[Dict[str, Any]] = []
        notices: List[str] = []
        while True:
            try:
                f = frames.read(reader)
            except frames.FrameError as e:
                raise ProtocolError(f"exec: {e}") from None
            if f is None:
                raise ProtocolError("exec: the daemon closed the stream without an exit status")
            if f.type == frames.TYPE_STDOUT:
                out += f.payload
                if on_output:
                    on_output("stdout", f.payload)
            elif f.type == frames.TYPE_STDERR:
                err += f.payload
                if on_output:
                    on_output("stderr", f.payload)
            elif f.type == frames.TYPE_JSON:
                try:
                    ev = f.json()
                except ValueError:
                    raise ProtocolError("exec: malformed event frame") from None
                events.append(ev)
                if ev.get("state") == "notice" and ev.get("message"):
                    notices.append(ev["message"])
                if on_event:
                    on_event(ev)
            elif f.type == frames.TYPE_EXIT:
                try:
                    st = f.json()
                except ValueError:
                    raise ProtocolError("exec: malformed exit frame") from None
                return ExecResult(
                    exit_code=int(st.get("code", -1)),
                    stdout=bytes(out),
                    stderr=bytes(err),
                    signal=st.get("signal") or "",
                    timed_out=bool(st.get("timed_out")),
                    notices=notices,
                    events=events,
                    duration_ms=int(st.get("duration_ms") or 0),
                    truncated=bool(st.get("truncated")),
                )
            elif f.type == frames.TYPE_ERROR:
                try:
                    detail = f.json()
                    if not isinstance(detail, dict) or not detail.get("code"):
                        raise ValueError
                except ValueError:
                    detail = {"code": "internal", "message": "malformed error frame"}
                if not detail.get("rule_ids"):
                    # the decision event before a refusal names the rules
                    for ev in reversed(events):
                        if ev.get("rule_ids"):
                            detail = dict(detail, rule_ids=ev["rule_ids"])
                            break
                exc = from_detail(detail)
                exc.stdout, exc.stderr, exc.events = bytes(out), bytes(err), events
                raise exc
            else:
                raise ProtocolError(f"exec: unexpected frame type {f.type}")
