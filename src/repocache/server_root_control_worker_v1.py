"""Non-installed, fail-closed systemd socket worker skeleton for #64.

This entrypoint never invokes a privileged operation. It validates fixed
root-owned socket-activation metadata, authenticates one kernel-credentialed
request, and ALWAYS refuses execution. It is not a deployable NGINX helper.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import sys
from typing import Any

from repocache.server_root_control_protocol_v1 import (
    FixedRootControlError, _root_worker, _trusted_local_ids,
    authorize_fixed_root_request,
)

_FIXED_SOCKET = "/run/repocache/server-control.sock"
_RUNTIME_DIR = "/run/repocache"


class RootControlWorkerError(ValueError):
    """Fixed non-disclosing code; no filesystem or request data."""


def _deny(code: str) -> None:
    raise RootControlWorkerError(code)


def _validate_layout(
    runtime: os.stat_result, listener: os.stat_result, *, admin_gid: int,
) -> None:
    """Validate fixed-path metadata supplied by native lstat operations."""
    # Native systemd.socket DirectoryMode creates parent directories as
    # root:root. Admin users only need traverse (0755); they must NEVER
    # have directory write rights, even if they may connect to the socket.
    if (not stat.S_ISDIR(runtime.st_mode) or runtime.st_uid != 0
            or runtime.st_gid != 0
            or stat.S_IMODE(runtime.st_mode) != 0o755
            or not stat.S_ISSOCK(listener.st_mode)
            or listener.st_uid != 0 or listener.st_gid != admin_gid
            or stat.S_IMODE(listener.st_mode) != 0o660
            or listener.st_nlink != 1
            or listener.st_dev != runtime.st_dev):
        _deny("ROOT_CONTROL_SOCKET_OWNERSHIP_REFUSED")


def _validate_listener(server: socket.socket) -> None:
    """Fail closed on foreign/abstract/symlink socket activation."""
    if (server.family != socket.AF_UNIX
            or server.type & 0xF != socket.SOCK_SEQPACKET
            or server.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or server.getsockname() != _FIXED_SOCKET):
        _deny("ROOT_CONTROL_LISTENER_REFUSED")
    admin_gid, _service_uid = _trusted_local_ids()
    try:
        root = os.lstat("/run")
        runtime = os.lstat(_RUNTIME_DIR)
        listener = os.lstat(_FIXED_SOCKET)
    except OSError:
        _deny("ROOT_CONTROL_SOCKET_UNAVAILABLE")
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != 0
            or stat.S_IMODE(root.st_mode) & 0o022
            or not stat.S_ISDIR(runtime.st_mode)
            or runtime.st_nlink < 1):
        _deny("ROOT_CONTROL_RUNTIME_ROOT_UNSAFE")
    _validate_layout(runtime, listener, admin_gid=admin_gid)


def _systemd_listener() -> socket.socket:
    """Require one fd explicitly handed off by systemd at the fixed fd 3."""
    _root_worker()
    if (os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != "1"):
        _deny("ROOT_CONTROL_SOCKET_ACTIVATION_REQUIRED")
    try:
        fd = os.dup(3)
        try:
            server = socket.socket(fileno=fd)
        except (OSError, ValueError):
            os.close(fd)
            raise
    except (OSError, ValueError):
        _deny("ROOT_CONTROL_SOCKET_FD_INVALID")
    try:
        _validate_listener(server)
        return server
    except Exception:
        server.close()
        raise


def serve_one_fixed_request() -> dict[str, Any]:
    """Always refuse mutation, even after successful OS peer validation.

    The future production integration must use a separate verified dispatcher
    with native install, state, nginx and catalog acceptance. Do NOT replace
    this refusal with a generic callback or subprocess runner.
    """
    with _systemd_listener() as server:
        try:
            server.settimeout(3.0)
            conn, _addr = server.accept()
        except (OSError, TimeoutError):
            _deny("ROOT_CONTROL_ACCEPT_UNAVAILABLE")
        with conn:
            selected = authorize_fixed_root_request(conn)
            # One connection, one bounded message. No action is dispatched.
            return {
                "schema_version": 1,
                "status": "ROOT_TRANSACTION_NOT_IMPLEMENTED",
                "requested_operation": selected["operation"],
                "authorizes_nginx_reload": False,
                "authorizes_state_write": False,
                "authorizes_catalog_publication": False,
                "operator_action_executed": False,
            }


def main() -> int:
    """Noninteractive fixed response; never emit secret or caller input."""
    if len(sys.argv) != 1:
        print('{"code":"ROOT_CONTROL_ARGUMENTS_REFUSED"}')
        return 2
    try:
        # No live NGINX, state, catalog or host operation is ever called.
        result = serve_one_fixed_request()
    except (FixedRootControlError, RootControlWorkerError) as exc:
        result = {"status": "DENIED", "code": str(exc)}
    except (OSError, TypeError, ValueError):
        result = {"status": "DENIED", "code": "ROOT_CONTROL_UNAVAILABLE"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # An authenticated but *unimplemented* operation must never look like a
    # successful apply/recovery to any caller. Always exit nonzero.
    return 2


if __name__ == "__main__":  # intentionally NOT installed as an entrypoint
    raise SystemExit(main())
