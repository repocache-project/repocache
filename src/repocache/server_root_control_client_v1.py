"""Non-installed, fixed-operation Linux socket client for #64.

This is an inert protocol consumer ONLY. A successful request is never a
successful operation: the sole accepted response is explicit NOT_IMPLEMENTED.
No CLI entrypoint, caller-selected pathname, unit, executable or JSON payload
is exposed. The client never requests other operations or writes host state.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import struct
from typing import Any

_SOCKET = "/run/repocache/server-control.sock"
_PARENT = "/run/repocache"
_REQUESTS = {
    "APPLY_V2": b"apply-v2\n",
    "RECOVER_V2": b"recover-v2\n",
}
_RESPONSE_LIMIT = 1024


class FixedControlClientError(ValueError):
    """Static refusal without caller-controlled or private details."""


def _refuse(code: str) -> None:
    raise FixedControlClientError("ROOT_CONTROL_CLIENT_" + code)


def _validate_parent_and_socket() -> None:
    """Refuse obviously foreign/mutable socket path before connecting."""
    try:
        run = os.lstat("/run")
        parent = os.lstat(_PARENT)
        leaf = os.lstat(_SOCKET)
    except OSError:
        _refuse("SOCKET_UNAVAILABLE")
    if (not stat.S_ISDIR(run.st_mode) or run.st_uid != 0
            or stat.S_IMODE(run.st_mode) & 0o022
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0 or parent.st_gid != 0
            or stat.S_IMODE(parent.st_mode) != 0o755
            or not stat.S_ISSOCK(leaf.st_mode)
            or leaf.st_uid != 0
            or stat.S_IMODE(leaf.st_mode) != 0o660
            or leaf.st_nlink != 1
            or leaf.st_dev != parent.st_dev):
        _refuse("SOCKET_UNSAFE")


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous reply objects at every JSON nesting level."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate reply key")
        result[key] = value
    return result


def _refuse_json_constant(_value: str) -> Any:
    raise ValueError("nonfinite JSON number")


def _parse_response(raw: bytes, *, operation: str) -> dict[str, Any]:
    if (type(raw) is not bytes or not 1 <= len(raw) <= _RESPONSE_LIMIT
            or not raw.endswith(b"\n") or raw.count(b"\n") != 1):
        _refuse("RESPONSE_INVALID")
    try:
        text = raw[:-1].decode("ascii", "strict")
        data = json.loads(
            text, object_pairs_hook=_unique_json_pairs,
            parse_constant=_refuse_json_constant,
        )
        expected = {
            "schema_version": 1,
            "status": "ROOT_TRANSACTION_NOT_IMPLEMENTED",
            "requested_operation": operation,
            "authorizes_nginx_reload": False,
            "authorizes_state_write": False,
            "authorizes_catalog_publication": False,
            "operator_action_executed": False,
        }
        if (type(data) is not dict or data != expected
                or type(data.get("schema_version")) is not int
                or any(type(data[k]) is not bool for k in (
                    "authorizes_nginx_reload", "authorizes_state_write",
                    "authorizes_catalog_publication", "operator_action_executed",
                ))):
            _refuse("RESPONSE_UNEXPECTED")
    except FixedControlClientError:
        raise
    except (UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        _refuse("RESPONSE_INVALID")
    canonical = (json.dumps(
        expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ) + "\n").encode("ascii")
    if raw != canonical:
        _refuse("RESPONSE_NONCANONICAL")
    return data


def request_fixed_inert_operation(operation: str) -> dict[str, Any]:
    """Request exactly one fixed operation; always return non-success.

    Caller OS group membership is decided by the separately protected
    systemd socket and root broker, never a CLI --yes flag. This function
    validates the *necessary* root peer UID but cannot authenticate installed
    signed code, SELinux/mount provenance or host-root namespace.
    """
    if type(operation) is not str or operation not in _REQUESTS:
        _refuse("OPERATION_REFUSED")
    _validate_parent_and_socket()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
            conn.settimeout(3.0)
            conn.connect(_SOCKET)
            peer = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"),
            )
            if len(peer) != struct.calcsize("3i"):
                _refuse("PEER_UNVERIFIED")
            pid, uid, _gid = struct.unpack("3i", peer)
            if pid <= 0 or uid != 0:
                _refuse("PEER_UNVERIFIED")
            packet = _REQUESTS[operation]
            if conn.send(packet) != len(packet):
                _refuse("REQUEST_INCOMPLETE")
            data, _ancillary, flags, _addr = conn.recvmsg(
                _RESPONSE_LIMIT + 1,
            )
            if flags & socket.MSG_TRUNC or len(data) > _RESPONSE_LIMIT:
                _refuse("RESPONSE_OVERSIZE")
    except FixedControlClientError:
        raise
    except (OSError, TimeoutError, ValueError, TypeError):
        _refuse("TRANSPORT_UNAVAILABLE")
    return _parse_response(data, operation=operation)
