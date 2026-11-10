"""Fixed native OS-authorized v2 client; no arbitrary root operation or CLI.

OS peer creds and the root-owned socket authorize the request. An external
--yes flag is NOT authorization. This module never reads root file contents
or chooses a unit, executable, config path, host directory or environment.
A missing reply is an UNKNOWN result: callers must reconcile persisted state
rather than assuming that the server rolled back an acknowledged commit.
"""
from __future__ import annotations

import json
import socket
import struct
from typing import Any

from repocache.server_root_control_client_v1 import (
    _REQUESTS, _RESPONSE_LIMIT, _SOCKET,
    _unique_json_pairs, _refuse_json_constant,
    _validate_parent_and_socket,
)


class NativeRootControlClientError(ValueError):
    """Stable redacted error codes; no server or caller content."""


def _deny(code: str) -> None:
    raise NativeRootControlClientError("NATIVE_ROOT_CLIENT_" + code)


def _parse_native_reply(raw: bytes, *, operation: str) -> dict[str, Any]:
    if (type(raw) is not bytes or not 1 <= len(raw) <= _RESPONSE_LIMIT
            or not raw.endswith(b"\n") or raw.count(b"\n") != 1):
        _deny("RESPONSE_INVALID")
    try:
        value = json.loads(
            raw[:-1].decode("ascii", "strict"),
            object_pairs_hook=_unique_json_pairs,
            parse_constant=_refuse_json_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _deny("RESPONSE_INVALID")
    if type(value) is not dict:
        _deny("RESPONSE_INVALID")
    canonical = (json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ) + "\n").encode("ascii")
    if canonical != raw:
        _deny("RESPONSE_NONCANONICAL")
    if value == {
        "schema_version": 1,
        "status": "DENIED",
        "requested_operation": operation,
        "code": "NATIVE_V2_OPERATION_REFUSED",
        "transaction_completed": False,
    }:
        _deny("OPERATION_REFUSED")
    success = {"APPLIED", "UNCHANGED"} if operation == "APPLY_V2" else (
        {"RECOVERED", "CLEAN"} if operation == "RECOVER_V2" else set()
    )
    if (type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or value.get("status") not in success
            or value.get("requested_operation") != operation
            or set(value) != {
                "schema_version", "status", "requested_operation",
                "state_generation", "transaction_completed",
                "nginx_reload_and_exposure_observed",
                "active_catalog_published",
            }
            or type(value["transaction_completed"]) is not bool
            or value["transaction_completed"] is not True
            or type(value["nginx_reload_and_exposure_observed"]) is not bool
            or type(value["active_catalog_published"]) is not bool):
        _deny("RESPONSE_UNEXPECTED")
    if operation == "APPLY_V2":
        if type(value["state_generation"]) is not int or not (
            0 <= value["state_generation"] < 2**63
        ):
            _deny("RESPONSE_UNEXPECTED")
    elif value["state_generation"] is not None:
        _deny("RESPONSE_UNEXPECTED")
    published = value["status"] == "APPLIED"
    if (value["active_catalog_published"] is not published
            or value["nginx_reload_and_exposure_observed"] is not published):
        _deny("RESPONSE_UNEXPECTED")
    return value


def request_native_fixed_v2(operation: str) -> dict[str, Any]:
    """Perform only apply-v2 or recover-v2 as a kernel-authorized operator.

    A transport failure after send is OUTCOME_UNCONFIRMED, never a claim that
    the privileged actor did not commit. No automatic retries or bypass.
    """
    if type(operation) is not str or operation not in _REQUESTS:
        _deny("OPERATION_REFUSED")
    try:
        _validate_parent_and_socket()
    except ValueError:
        _deny("SOCKET_UNTRUSTED")
    sent = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
            conn.settimeout(3.0)
            conn.connect(_SOCKET)
            creds = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
            if len(creds) != struct.calcsize("3i"):
                _deny("ROOT_PEER_UNVERIFIED")
            pid, uid, _gid = struct.unpack("3i", creds)
            if pid <= 0 or uid != 0:
                _deny("ROOT_PEER_UNVERIFIED")
            packet = _REQUESTS[operation]
            if conn.send(packet) != len(packet):
                _deny("REQUEST_INCOMPLETE")
            sent = True
            payload, _unused, flags, _addr = conn.recvmsg(
                _RESPONSE_LIMIT + 1,
            )
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                _deny("RESPONSE_TRUNCATED")
    except NativeRootControlClientError:
        raise
    except (OSError, ValueError, TypeError, TimeoutError):
        _deny("OUTCOME_UNCONFIRMED" if sent else "TRANSPORT_UNAVAILABLE")
    return _parse_native_reply(payload, operation=operation)
