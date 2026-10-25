"""Errors of the tkbox daemon API as exceptions.

The daemon answers a failed request with an ErrorBody ({"error": {"code", "message", "rule_ids", "hint"}}) and ends a
failed exec stream with a TypeError frame ({"code", "message"}). Each code maps to one exception class; every class is a
TkboxError, so `except TkboxError` catches them all.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class TkboxError(Exception):
    """An error from the tkbox daemon (or from talking to it)."""

    code = "internal"

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        rule_ids: Optional[List[str]] = None,
        hint: str = "",
        status: Optional[int] = None,
    ) -> None:
        if code is not None:
            self.code = code
        self.message = message
        self.rule_ids = list(rule_ids or [])
        self.hint = hint
        self.status = status
        # Set on errors that end an exec stream: what the process printed and the events seen before the error.
        self.stdout = b""
        self.stderr = b""
        self.events: List[Dict[str, Any]] = []
        super().__init__(str(self))

    def __str__(self) -> str:
        s = f"{self.code}: {self.message}"
        if self.rule_ids:
            s += " [" + ", ".join(self.rule_ids) + "]"
        if self.hint:
            s += f" ({self.hint})"
        return s


class BadRequest(TkboxError):
    """The request was malformed or named something invalid (bad_request)."""

    code = "bad_request"


class NotFound(TkboxError):
    """No such box, approval or image (not_found)."""

    code = "not_found"


class Conflict(TkboxError):
    """The name is taken or the box is in the wrong state (conflict)."""

    code = "conflict"


class Denied(TkboxError):
    """The signer or a person refused the action (denied). rule_ids names the signer rules behind it."""

    code = "denied"


class Unavailable(TkboxError):
    """The Tracekit signer can't be reached, so Box refused the action: it fails closed (unavailable)."""

    code = "unavailable"


class LimitError(TkboxError):
    """A limit was hit (limit, or the guest's too_large / busy). The message says which, hint says what to do."""

    code = "limit"


class Forbidden(TkboxError):
    """This uid may not use the daemon (forbidden)."""

    code = "forbidden"


class TimedOut(TkboxError):
    """A box timeout or an approval timeout (timeout)."""

    code = "timeout"


class NotSupported(TkboxError):
    """The host can't do this, e.g. it has no /dev/kvm (not_supported)."""

    code = "not_supported"


class DaemonUnreachable(TkboxError):
    """The daemon's socket could not be reached at all."""

    code = "daemon_unreachable"


class ProtocolError(TkboxError):
    """The daemon answered something this SDK does not understand."""

    code = "protocol"


_BY_CODE = {
    "bad_request": BadRequest,
    "not_found": NotFound,
    "conflict": Conflict,
    "denied": Denied,
    "unavailable": Unavailable,
    "limit": LimitError,
    "too_large": LimitError,  # guest: a file or patch over its size limit
    "busy": LimitError,  # guest: too many concurrent execs
    "forbidden": Forbidden,
    "timeout": TimedOut,
    "not_supported": NotSupported,
}


def from_detail(detail: Dict[str, Any], status: Optional[int] = None) -> TkboxError:
    """The exception for an ErrorDetail (or a proto Error frame)."""
    code = str(detail.get("code") or "internal")
    cls = _BY_CODE.get(code, TkboxError)
    return cls(
        str(detail.get("message") or code),
        code=code,
        rule_ids=detail.get("rule_ids") or [],
        hint=str(detail.get("hint") or ""),
        status=status,
    )
