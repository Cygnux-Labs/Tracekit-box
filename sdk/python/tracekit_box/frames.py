"""The frame format of the exec stream (internal/proto/frame.go): [type u8][len u32 big-endian][payload].

A payload is at most MAX_FRAME bytes. After the daemon answers an exec request with 101 Switching Protocols, the
connection carries these frames in both directions.
"""

from __future__ import annotations

import json
import struct
from typing import Any, BinaryIO, NamedTuple, Optional

TYPE_JSON = 0  # a JSON header or event (ExecEvent from the daemon)
TYPE_STDIN = 1  # client -> daemon: stdin bytes
TYPE_STDOUT = 2  # daemon -> client: stdout bytes
TYPE_STDERR = 3  # daemon -> client: stderr bytes
TYPE_EXIT = 4  # daemon -> client: JSON ExitStatus, the last frame of a successful exec
TYPE_ERROR = 5  # daemon -> client: JSON Error, the last frame of a failed exec
TYPE_STDIN_EOF = 6  # client -> daemon: no more stdin (empty payload)
TYPE_SIGNAL = 7  # client -> daemon: JSON {"signal": "SIGINT"} for the running process group

MAX_FRAME = 1 << 20

_HEADER = struct.Struct(">BI")


class FrameError(Exception):
    """The peer sent something that is not a valid frame."""


class Frame(NamedTuple):
    type: int
    payload: bytes

    def json(self) -> Any:
        return json.loads(self.payload.decode("utf-8"))


def encode(typ: int, payload: bytes = b"") -> bytes:
    """One frame as bytes. Payloads over MAX_FRAME are refused: split data with chunks() first."""
    if len(payload) > MAX_FRAME:
        raise FrameError("frame payload larger than 1 MiB")
    return _HEADER.pack(typ, len(payload)) + payload


def encode_json(typ: int, value: Any) -> bytes:
    return encode(typ, json.dumps(value, separators=(",", ":")).encode("utf-8"))


def chunks(typ: int, data: bytes):
    """Yield data as frames of type typ, each at most MAX_FRAME bytes."""
    for i in range(0, len(data), MAX_FRAME):
        yield encode(typ, data[i : i + MAX_FRAME])


def _read_exact(r: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        b = r.read(n - len(buf))
        if not b:
            break
        buf += b
    return bytes(buf)


def read(r: BinaryIO) -> Optional[Frame]:
    """Read one frame. None means the peer closed cleanly between frames; a close mid-frame raises FrameError."""
    hdr = _read_exact(r, _HEADER.size)
    if not hdr:
        return None
    if len(hdr) < _HEADER.size:
        raise FrameError("connection closed in the middle of a frame header")
    typ, n = _HEADER.unpack(hdr)
    if n > MAX_FRAME:
        raise FrameError("frame larger than 1 MiB")
    payload = _read_exact(r, n)
    if len(payload) < n:
        raise FrameError("connection closed in the middle of a frame")
    return Frame(typ, payload)
