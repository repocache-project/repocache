"""Actual fixed native root-control dispatcher for v0.6 (#31/#64).

Unlike the non-installed #254 protocol skeleton, this dispatches the two
fixed authenticated operations through the durable native v2/NGINX/catalog
transaction. It exposes no generic path, command, environment, JSON body
or shell. It MUST be installed only from a separately authenticated signed
release, with the reviewed root-owned systemd socket/unit and SELinux policy.
Uninstalled Python source and disposable CI never prove native readiness.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from typing import Any

from repocache.server_install_v1 import validate_os_identity
from repocache.server_native_v2_transaction_v1 import (
    NativeV2TransactionError, execute_native_fixed_v2_transaction,
)
from repocache.server_root_control_protocol_v1 import (
    FixedRootControlError, authorize_fixed_root_request,
)
from repocache.server_root_control_worker_v1 import (
    RootControlWorkerError, _systemd_listener,
)
from repocache.server_root_control_host_preflight_v1 import (
    NativeHostPreflightError,
)

_RELEASE_ID = "/usr/lib/os-release"
_KNOWN_RESULTS = {
    "NATIVE_V2_COMMITTED": "APPLIED",
    "NATIVE_V2_NO_CHANGE": "UNCHANGED",
    "NATIVE_V2_CLEAN": "CLEAN",
    "NATIVE_V2_ROLLED_BACK": "RECOVERED",
    "NATIVE_V2_UNPUBLISHED_WAL_DISCARDED": "RECOVERED",
}


class NativeControlDispatchError(ValueError):
    """Static root-worker errors; no user or filesystem details."""


def _deny(code: str) -> None:
    raise NativeControlDispatchError("NATIVE_ROOT_CONTROL_" + code)


def _native_distro() -> str:
    """Read one root-owned OS identity, never choose distro from socket."""
    try:
        file = os.lstat(_RELEASE_ID)
        parent = os.lstat("/usr/lib")
        if (not stat.S_ISREG(file.st_mode) or file.st_uid != 0
                or file.st_gid != 0 or file.st_nlink != 1
                or file.st_mode & 0o022
                or not 1 <= file.st_size <= 4096
                or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != 0 or parent.st_mode & 0o022):
            _deny("DISTRO_UNTRUSTED")
        fd = os.open(_RELEASE_ID, os.O_RDONLY | os.O_NOFOLLOW
                     | getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            raw = os.read(fd, 4097)
            after = os.fstat(fd)
            named = os.lstat(_RELEASE_ID)
            if (len(raw) != before.st_size or len(raw) > 4096
                    or (before.st_dev, before.st_ino, before.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_mtime_ns)
                    or (before.st_dev, before.st_ino)
                       != (named.st_dev, named.st_ino)):
                _deny("DISTRO_CHANGED")
        finally:
            os.close(fd)
        return validate_os_identity(
            raw.decode("ascii", "strict"), sys.version_info[:2],
        )
    except NativeControlDispatchError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        _deny("DISTRO_UNAVAILABLE")


def _exact_reply(operation: str, outcome: dict) -> dict:
    """No arbitrary underlying service/debug fields on the operator socket."""
    if operation not in ("APPLY_V2", "RECOVER_V2"):
        _deny("OPERATION_REFUSED")
    if type(outcome) is not dict or outcome.get("status") not in _KNOWN_RESULTS:
        _deny("OUTCOME_INVALID")
    if operation == "APPLY_V2" and outcome["status"] not in (
        "NATIVE_V2_COMMITTED", "NATIVE_V2_NO_CHANGE",
    ):
        _deny("OUTCOME_INVALID")
    if operation == "RECOVER_V2" and outcome["status"] not in (
        "NATIVE_V2_CLEAN", "NATIVE_V2_ROLLED_BACK",
        "NATIVE_V2_UNPUBLISHED_WAL_DISCARDED",
    ):
        _deny("OUTCOME_INVALID")
    generation = outcome.get("state_generation")
    if operation == "APPLY_V2":
        if type(generation) is not int or not 0 <= generation < 2**63:
            _deny("OUTCOME_INVALID")
    else:
        if generation is not None:
            _deny("OUTCOME_INVALID")
    return {
        "schema_version": 1,
        "status": _KNOWN_RESULTS[outcome["status"]],
        "requested_operation": operation,
        "state_generation": generation,
        "transaction_completed": True,
        "nginx_reload_and_exposure_observed": (
            outcome["status"] == "NATIVE_V2_COMMITTED"
        ),
        "active_catalog_published": (
            outcome["status"] == "NATIVE_V2_COMMITTED"
        ),
    }


def serve_one_native_fixed_request() -> dict[str, Any]:
    """One kernel credentialed message, one fixed transaction, one reply.

    If transport fails after a successful commit, the durable state remains
    authoritative. A caller must inspect/reconcile, never assume rollback
    based on a missing acknowledgment.
    """
    with _systemd_listener() as server:
        try:
            server.settimeout(3.0)
            conn, _address = server.accept()
        except (OSError, TimeoutError):
            _deny("ACCEPT_REFUSED")
        with conn:
            authorized = authorize_fixed_root_request(conn)
            if (authorized.get("status")
                    != "KERNEL_PEER_FIXED_OPERATION_SELECTED_ONLY"
                    or authorized.get("kernel_peer_credentials_checked") is not True
                    or authorized.get("host_root_provenance_verified") is not False
                    or authorized.get("authorizes_nginx_reload") is not False):
                _deny("PEER_SELECTION_REFUSED")
            operation = authorized.get("operation")
            if operation not in ("APPLY_V2", "RECOVER_V2"):
                _deny("OPERATION_REFUSED")
            distribution = _native_distro()
            try:
                outcome = execute_native_fixed_v2_transaction(
                    operation, distribution,
                )
                reply = _exact_reply(operation, outcome)
            except (NativeV2TransactionError, NativeControlDispatchError):
                # Never leak private NGINX, TLS, state or host exception text.
                reply = {
                    "schema_version": 1,
                    "status": "DENIED",
                    "requested_operation": operation,
                    "code": "NATIVE_V2_OPERATION_REFUSED",
                    "transaction_completed": False,
                }
            payload = (json.dumps(reply, sort_keys=True, separators=(",", ":"))
                       + "\n").encode("ascii")
            if len(payload) > 1024:
                _deny("REPLY_TOO_LARGE")
            try:
                conn.settimeout(3.0)
                if conn.send(payload) != len(payload):
                    _deny("REPLY_INCOMPLETE")
            except (OSError, TimeoutError):
                _deny("REPLY_UNAVAILABLE")
            return reply


def main() -> int:
    if len(sys.argv) != 1:
        print('{"code":"NATIVE_ROOT_CONTROL_ARGUMENTS_REFUSED"}')
        return 2
    try:
        outcome = serve_one_native_fixed_request()
    except (NativeControlDispatchError, RootControlWorkerError,
            FixedRootControlError, NativeHostPreflightError):
        outcome = {"status": "DENIED", "code": "NATIVE_ROOT_CONTROL_REFUSED"}
    except (OSError, TypeError, ValueError):
        outcome = {"status": "DENIED", "code": "NATIVE_ROOT_CONTROL_UNAVAILABLE"}
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0 if outcome.get("transaction_completed") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
