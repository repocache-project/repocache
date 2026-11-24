"""Non-installed, fail-closed systemd socket worker skeleton for #64.

This entrypoint never invokes a privileged operation. It validates fixed
root-owned socket-activation metadata, authenticates one kernel-credentialed
request, and ALWAYS refuses execution. It is not a deployable NGINX helper.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import zipimport
from contextlib import ExitStack
import socket
import stat
import sys
from typing import Any

from repocache.server_root_control_protocol_v1 import (
    FixedRootControlError, _root_worker, _trusted_local_ids,
    authorize_fixed_root_request,
)
from repocache.server_root_control_host_preflight_v1 import (
    NativeHostPreflightError, require_socket_worker_host_preconditions,
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
        # The exact installed socket alone is not enough: require native
        # non-rootless PID1/systemd context before reading operator requests.
        # This is a necessary check, not installed-host attestation.
        require_socket_worker_host_preconditions()
        return server
    except Exception:
        server.close()
        raise



_RUNTIME_RECEIPT = ".native-worker-receipt-v1.json"
_PLACEMENT_PREFIX = ".native-worker-placement."
_WORKER = "/usr/libexec/repocache/server-control-worker"
_UNIT_NAMES = ("repocache-control.service", "repocache-control.socket",
               "repocache-nginx.service")
_RECEIPT_FILES = {"server-control-worker", "repocache.conf", *_UNIT_NAMES}


def _placement_receipt(raw: bytes) -> dict:
    """Closed installation-local receipt, never a new publisher trust anchor."""
    try:
        value = json.loads(raw.decode("ascii", "strict"))
        canonical = (json.dumps(value, sort_keys=True, separators=(",", ":"))
                     + "\n").encode("ascii")
        if (type(value) is not dict or canonical != raw or set(value) != {
                "schema_version", "status", "version", "source_sha",
                "archive_sha256", "manifest_sha256", "publisher_key_id",
                "files", "authorizes_host_installation",
                "authorizes_service_activation",
                } or type(value["schema_version"]) is not int
                or value["schema_version"] != 1
                or value["status"] != "AUTHENTICATED_WORKER_STAGED"
                or value["version"] != "0.6.0"
                or value["authorizes_host_installation"] is not False
                or value["authorizes_service_activation"] is not False
                or type(value["files"]) is not dict
                or set(value["files"]) != _RECEIPT_FILES
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value["publisher_key_id"])
                or not re.fullmatch(r"[0-9a-f]{40}", value["source_sha"])
                or any(not re.fullmatch(r"[0-9a-f]{64}", x)
                       for x in (value["archive_sha256"], value["manifest_sha256"],
                                 *value["files"].values()))):
            _deny("PLACEMENT_RECEIPT_INVALID")
        return value
    except (UnicodeError, TypeError, KeyError, ValueError, RecursionError):
        _deny("PLACEMENT_RECEIPT_INVALID")


def _metadata_no_acl(fd: int, *, directory: bool = False) -> os.stat_result:
    info = os.fstat(fd)
    if (info.st_uid != 0 or info.st_gid != 0
            or info.st_mode & 0o022
            or (directory and not stat.S_ISDIR(info.st_mode))
            or set(os.listxattr(fd)) - {"security.selinux"}):
        _deny("PLACEMENT_METADATA_UNSAFE")
    return info


def _placement_file_digest(root_fd: int, segments: tuple[str, ...],
                           mode: int, maximum: int) -> str:
    from repocache.server_protected_state_inspect_v1 import (
        _identity, _walk, _recheck, _FILE_FLAGS,
    )
    with ExitStack() as stack:
        parent, chain = _walk(root_fd, segments[:-1], stack, 0)
        _metadata_no_acl(root_fd, directory=True)
        for _, _, fd, _ in chain:
            _metadata_no_acl(fd, directory=True)
        fd = os.open(segments[-1], _FILE_FLAGS, dir_fd=parent)
        stack.callback(os.close, fd)
        info = _metadata_no_acl(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != mode
                or info.st_dev != os.fstat(parent).st_dev
                or not 1 <= info.st_size <= maximum):
            _deny("PLACEMENT_FILE_UNSAFE")
        digest = hashlib.sha256()
        length = 0
        while length <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - length))
            if not block:
                break
            digest.update(block)
            length += len(block)
        if (length != info.st_size or _identity(_metadata_no_acl(fd)) != _identity(info)
                or _identity(os.stat(segments[-1], dir_fd=parent,
                                     follow_symlinks=False)) != _identity(info)):
            _deny("PLACEMENT_FILE_CHANGED")
        _recheck(chain, 0)
        return digest.hexdigest()


def _effective_control_units() -> None:
    """Fixed PID1 observations; no caller-selected unit, path or command."""
    from repocache.server_native_nginx_effective_unit_v1 import (
        _safe_native_systemctl, _observe_systemd_pid1,
    )
    _safe_native_systemctl()
    _observe_systemd_pid1()
    common = ("Id", "Names", "FragmentPath", "DropInPaths", "LoadState",
              "ActiveState", "SubState", "NeedDaemonReload")
    for unit in _UNIT_NAMES[:2]:
        service = unit.endswith(".service")
        properties = common + (("MainPID", "User", "Group", "ProtectSystem",
                                "NoNewPrivileges", "RestrictNamespaces")
                               if service else ("Triggers", "Accept"))
        result = subprocess.run(
            ("/usr/bin/systemctl", "show", "--no-pager",
             *(f"--property={key}" for key in properties), unit),
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=5, check=False, shell=False,
        )
        if result.returncode or not 1 <= len(result.stdout) <= 8192:
            _deny("PLACEMENT_EFFECTIVE_UNIT_UNVERIFIED")
        fields = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in properties or key in fields:
                _deny("PLACEMENT_EFFECTIVE_UNIT_UNVERIFIED")
            fields[key] = value
        expected = {"Id": unit, "Names": unit,
                    "FragmentPath": "/etc/systemd/system/" + unit,
                    "DropInPaths": "", "LoadState": "loaded",
                    "NeedDaemonReload": "no"}
        if service:
            expected.update({"ActiveState": "activating", "SubState": "start",
                             "MainPID": str(os.getpid()), "User": "root",
                             "Group": "root", "ProtectSystem": "strict",
                             "NoNewPrivileges": "yes", "RestrictNamespaces": "yes"})
        else:
            expected.update({"ActiveState": "active",
                             "Triggers": "repocache-control.service", "Accept": "no"})
        if (set(fields) != set(properties)
                or any(fields[key] != value for key, value in expected.items())
                or (not service and fields["SubState"] not in ("listening", "running"))):
            _deny("PLACEMENT_EFFECTIVE_UNIT_UNVERIFIED")


def require_installed_control_receipt(root_fd: int, state_fd: int) -> None:
    """Recheck the local signed-install record and actual executing broker.

    The authenticated installer owns the receipt and marker. Matching them
    is not independent publisher signature re-verification. Root can always
    replace root-owned code; the protected boundary is the non-root peer.
    No external receipt/path/command is accepted, and no authority is granted
    by this observation in isolation.
    """
    from repocache.server_protected_state_store_v1 import _read_file
    try:
        loader = __loader__
        if (not isinstance(loader, zipimport.zipimporter)
                or loader.archive != _WORKER
                or sys.argv != [_WORKER] or not sys.flags.isolated):
            _deny("PLACEMENT_INSTALLED_WORKER_REQUIRED")
        _metadata_no_acl(state_fd, directory=True)
        raw = _read_file(state_fd, _RUNTIME_RECEIPT, 0, 8192)
        if raw is None:
            _deny("PLACEMENT_RECEIPT_REQUIRED")
        receipt = _placement_receipt(raw)
        complete = _PLACEMENT_PREFIX + "complete-" + hashlib.sha256(raw).hexdigest()
        for name in (_RUNTIME_RECEIPT, complete):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | os.O_CLOEXEC, dir_fd=state_fd)
            try:
                info = _metadata_no_acl(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                    _deny("PLACEMENT_METADATA_UNSAFE")
            finally:
                os.close(fd)
        if ({x for x in os.listdir(state_fd) if x.startswith(_PLACEMENT_PREFIX)} != {complete}
                or _read_file(state_fd, complete, 0, 0) != b""):
            _deny("PLACEMENT_MARKER_UNVERIFIED")
        paths = [(("usr", "libexec", "repocache", "server-control-worker"),
                  0o755, 16 * 1024 * 1024)]
        paths += [(("etc", "systemd", "system", unit), 0o644, 16384)
                  for unit in _UNIT_NAMES]
        for segments, mode, limit in paths:
            if _placement_file_digest(root_fd, segments, mode, limit) != receipt["files"][segments[-1]]:
                _deny("PLACEMENT_FILE_CONTENT_MISMATCH")
        _effective_control_units()
        if (_read_file(state_fd, _RUNTIME_RECEIPT, 0, 8192) != raw
                or _read_file(state_fd, complete, 0, 0) != b""
                or {x for x in os.listdir(state_fd) if x.startswith(_PLACEMENT_PREFIX)} != {complete}):
            _deny("PLACEMENT_RECEIPT_CHANGED")
    except RootControlWorkerError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _deny("PLACEMENT_UNVERIFIED")


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
            # Return the refusal on the authenticated seqpacket channel;
            # stdout belongs to the service journal, not the operator.
            result = {
                "schema_version": 1,
                "status": "ROOT_TRANSACTION_NOT_IMPLEMENTED",
                "requested_operation": selected["operation"],
                "authorizes_nginx_reload": False,
                "authorizes_state_write": False,
                "authorizes_catalog_publication": False,
                "operator_action_executed": False,
            }
            response = (json.dumps(
                result, sort_keys=True, separators=(",", ":"),
            ) + "\n").encode("ascii")
            try:
                conn.settimeout(3.0)
                written = conn.send(response)
                if written != len(response):
                    _deny("ROOT_CONTROL_RESPONSE_INCOMPLETE")
            except (OSError, TimeoutError):
                _deny("ROOT_CONTROL_RESPONSE_UNAVAILABLE")
            return result


def main() -> int:
    """Noninteractive fixed response; never emit secret or caller input."""
    if len(sys.argv) != 1:
        print('{"code":"ROOT_CONTROL_ARGUMENTS_REFUSED"}')
        return 2
    try:
        # No live NGINX, state, catalog or host operation is ever called.
        result = serve_one_fixed_request()
    except (FixedRootControlError, RootControlWorkerError,
            NativeHostPreflightError) as exc:
        result = {"status": "DENIED", "code": str(exc)}
    except (OSError, TypeError, ValueError):
        result = {"status": "DENIED", "code": "ROOT_CONTROL_UNAVAILABLE"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # An authenticated but *unimplemented* operation must never look like a
    # successful apply/recovery to any caller. Always exit nonzero.
    return 2


if __name__ == "__main__":  # intentionally NOT installed as an entrypoint
    raise SystemExit(main())
