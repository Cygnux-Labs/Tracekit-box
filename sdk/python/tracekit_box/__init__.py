"""Python client of the Tracekit Box daemon (`tkbox daemon`): create boxes, run commands in them, take their changes
and export their signed record. Standard library only."""

from .client import VERSION as __version__
from .client import Client, Diff, ExecResult, Limits, Secret, default_socket
from .errors import (
    BadRequest,
    Conflict,
    DaemonUnreachable,
    Denied,
    Forbidden,
    LimitError,
    NotFound,
    NotSupported,
    ProtocolError,
    TimedOut,
    TkboxError,
    Unavailable,
)

__all__ = [
    "__version__",
    "Client",
    "Diff",
    "ExecResult",
    "Limits",
    "Secret",
    "default_socket",
    "TkboxError",
    "BadRequest",
    "Conflict",
    "DaemonUnreachable",
    "Denied",
    "Forbidden",
    "LimitError",
    "NotFound",
    "NotSupported",
    "ProtocolError",
    "TimedOut",
    "Unavailable",
]
