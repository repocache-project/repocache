"""Read-only, fixed-name NGINX PID1 systemd observation (#27/#64).

A vendor unit on disk can be overridden or bypassed at runtime. Fixed
observations distinguish the distributor nginx.service from the separately
owned repocache-nginx.service; neither grants service authority. It does NOT
authorize systemctl, unit changes, reloads, package installations or state
writes, and it cannot attest native host-root or SELinux enforcement.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
import re
import socket
import time
import zipimport
import stat
import subprocess
from typing import Any

from repocache.server_native_nginx_service_unit_v1 import (
    inspect_native_nginx_unit,
)

_SYSTEMCTL = "/usr/bin/systemctl"
_UNIT = "nginx.service"
_PROPERTIES = (
    "Id", "Names", "FragmentPath", "DropInPaths", "LoadState",
    "ActiveState", "SubState", "MainPID", "CanReload",
    "NeedDaemonReload",
)
_FIXED_ARGS = (
    _SYSTEMCTL, "show", "--no-pager",
    *(f"--property={name}" for name in _PROPERTIES),
    _UNIT,
)


class EffectiveNginxUnitError(ValueError):
    """Fixed codes only; never expose systemctl output or private paths."""


def _deny(code: str) -> None:
    raise EffectiveNginxUnitError("NATIVE_NGINX_EFFECTIVE_" + code)


def _safe_native_systemctl() -> None:
    """Reject user-writable, shadowed, symlinked executable and ancestors."""
    for path, directory in (
        ("/", True), ("/usr", True), ("/usr/bin", True),
        (_SYSTEMCTL, False),
    ):
        try:
            seen = os.lstat(path)
        except OSError:
            _deny("EXECUTABLE_UNAVAILABLE")
        if ((not stat.S_ISDIR(seen.st_mode) if directory
             else not stat.S_ISREG(seen.st_mode))
                or seen.st_uid != 0 or seen.st_gid != 0
                or stat.S_IMODE(seen.st_mode) & 0o022
                or (not directory and seen.st_nlink != 1)):
            _deny("EXECUTABLE_UNSAFE")


def _observe_systemd_pid1() -> None:
    """Read a bounded kernel PID1 name before trusting an active unit snapshot.

    This is a fail-closed prerequisite, not proof of a native booted host,
    executable provenance or privileged service authority.
    """
    try:
        process = os.lstat("/proc/1")
        if (not stat.S_ISDIR(process.st_mode) or process.st_uid != 0
                or stat.S_IMODE(process.st_mode) & 0o022):
            _deny("PID1_IDENTITY_REFUSED")
        fd = os.open(
            "/proc/1/comm",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            comm = os.fstat(fd)
            if (not stat.S_ISREG(comm.st_mode) or comm.st_uid != 0
                    or os.read(fd, 32) != b"systemd\n"):
                _deny("PID1_IDENTITY_REFUSED")
        finally:
            os.close(fd)
        again = os.lstat("/proc/1")
        if (again.st_dev, again.st_ino, again.st_uid, again.st_mode) != (
                process.st_dev, process.st_ino, process.st_uid,
                process.st_mode):
            _deny("PID1_IDENTITY_REFUSED")
    except EffectiveNginxUnitError:
        raise
    except (OSError, TypeError, ValueError, OverflowError):
        _deny("PID1_UNAVAILABLE")


def _parse_fixed_unit_status(value: Any) -> dict[str, str]:
    if (type(value) is not str or not 1 <= len(value) <= 8192
            or "\x00" in value or "\r" in value):
        _deny("RESPONSE_INVALID")
    result = {}
    for line in value.splitlines():
        if "=" not in line:
            _deny("RESPONSE_INVALID")
        key, val = line.split("=", 1)
        if key not in _PROPERTIES or key in result or "\n" in val:
            _deny("RESPONSE_INVALID")
        result[key] = val
    if set(result) != set(_PROPERTIES):
        _deny("RESPONSE_INCOMPLETE")
    expected = {
        "Id": _UNIT,
        "Names": _UNIT,
        "FragmentPath": "/usr/lib/systemd/system/nginx.service",
        "DropInPaths": "",
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "CanReload": "yes",
        "NeedDaemonReload": "no",
    }
    if any(result[key] != expected[key] for key in expected):
        _deny("FOREIGN_OR_INACTIVE_UNIT")
    pid = result["MainPID"]
    if (not pid or len(pid) > 10 or not pid.isascii()
            or not pid.isdecimal()
            or not 2 <= int(pid) <= 2**31 - 1):
        _deny("INVALID_MAIN_PID")
    return result



def _observe_nginx_master_kernel(pid: int, *, dedicated: bool = False) -> None:
    """Narrow /proc inode/executable check, never a process authorization.

    Only a fixed OS-reported MainPID is accepted. This does not authenticate
    installed package signatures, PID1, NGINX listening sockets or SELinux;
    /proc changes and PID reuse may still race a later privileged operation.
    """
    if type(pid) is not int or not 2 <= pid <= 2**31 - 1:
        _deny("INVALID_MAIN_PID")
    proc = f"/proc/{pid}"
    if type(dedicated) is not bool:
        _deny("NGINX_MASTER_IDENTITY_REFUSED")
    binary = _CANDIDATE_EXECUTABLE if dedicated else "/usr/sbin/nginx"
    try:
        installed = os.lstat(binary)
        process = os.stat(proc)
        executing = os.stat(proc + "/exe")
        if (not stat.S_ISREG(installed.st_mode)
                or installed.st_uid != 0 or installed.st_gid != 0
                or stat.S_IMODE(installed.st_mode) != 0o755
                or installed.st_nlink != 1
                or not stat.S_ISDIR(process.st_mode)
                or process.st_uid != 0
                or (executing.st_dev, executing.st_ino)
                   != (installed.st_dev, installed.st_ino)):
            _deny("NGINX_MASTER_IDENTITY_REFUSED")
        fd = os.open(
            proc + "/comm", os.O_RDONLY | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            comm = os.fstat(fd)
            if (not stat.S_ISREG(comm.st_mode)
                    or comm.st_uid != 0 or os.read(fd, 32) != b"nginx\n"):
                _deny("NGINX_MASTER_IDENTITY_REFUSED")
        finally:
            os.close(fd)
        current = os.stat(proc)
        rechecked = os.stat(proc + "/exe")
        binary_again = os.lstat(binary)
        if ((current.st_dev, current.st_ino, current.st_uid, current.st_mode)
                != (process.st_dev, process.st_ino, process.st_uid, process.st_mode)
                or (rechecked.st_dev, rechecked.st_ino)
                   != (installed.st_dev, installed.st_ino)
                or any(getattr(binary_again, name) != getattr(installed, name)
                       for name in ("st_dev", "st_ino", "st_mode",
                                    "st_uid", "st_gid", "st_nlink"))):
            _deny("NGINX_MASTER_IDENTITY_REFUSED")
    except EffectiveNginxUnitError:
        raise
    except (OSError, TypeError, ValueError, OverflowError):
        _deny("NGINX_MASTER_IDENTITY_UNAVAILABLE")

def inspect_effective_native_nginx_unit(distribution: str) -> dict[str, Any]:
    """Observe fixed effective PID1 service only after vendor unit checks.

    Distro userspace CI may mock this check; booted systemd/SELinux
    acceptance is deliberately NOT supplied by a mocked stdout.
    """
    if type(distribution) is not str or distribution not in ("debian", "almalinux"):
        _deny("DISTRIBUTION_INVALID")
    vendor = inspect_native_nginx_unit(distribution)
    if vendor.code != "VENDOR_NGINX_UNIT_OBSERVED" or vendor.digest is None:
        _deny("VENDOR_UNIT_UNVERIFIED")
    _observe_systemd_pid1()
    _safe_native_systemctl()
    try:
        completed = subprocess.run(
            _FIXED_ARGS, shell=False, check=False, capture_output=True,
            text=True, timeout=5, cwd="/",
            stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            start_new_session=True,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        _deny("SYSTEMCTL_UNAVAILABLE")
    if (completed.returncode != 0 or type(completed.stdout) is not str
            or type(completed.stderr) is not str
            or len(completed.stderr) > 4096):
        _deny("SYSTEMCTL_FAILED")
    observed = _parse_fixed_unit_status(completed.stdout)
    _observe_nginx_master_kernel(int(observed["MainPID"]))
    # A service restart/replacement may race the gap between systemd show
    # and the kernel executable-inode lookup. Observe the fixed unit again:
    # changed MainPID or override/active state invalidates this snapshot.
    try:
        again = subprocess.run(
            _FIXED_ARGS, shell=False, check=False, capture_output=True,
            text=True, timeout=5, cwd="/",
            stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            start_new_session=True,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        _deny("SYSTEMCTL_RECHECK_UNAVAILABLE")
    if (again.returncode != 0 or type(again.stdout) is not str
            or type(again.stderr) is not str
            or len(again.stderr) > 4096):
        _deny("SYSTEMCTL_RECHECK_FAILED")
    rechecked = _parse_fixed_unit_status(again.stdout)
    if rechecked != observed:
        _deny("SYSTEMCTL_UNIT_CHANGED")
    return {
        "schema_version": 1,
        "status": "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION",
        "unit_name": _UNIT,
        "main_pid_observed": int(observed["MainPID"]),
        "kernel_nginx_master_executable_inode_observed": True,
        "vendor_unit_sha256": vendor.digest,
        "effective_unit_shape_observed": True,
        "kernel_systemd_pid1_comm_observed": True,
        "distro_package_owner_verified": False,
        "real_pid1_and_nginx_process_verified": False,
        "host_root_and_selinux_verified": False,
        "authorizes_systemctl": False,
        "authorizes_nginx_reload": False,
        "authorizes_nginx_install": False,
    }


# Separate from vendor package ownership. A claim is not activation authority.
OWNED_NGINX_CONFIG_MARKER_PREFIX = ".native-nginx-config-owner-v1-"
_OWN_UNIT = "repocache-nginx.service"
_OWN_PROPERTIES = _PROPERTIES
_OWN_SHOW = (_SYSTEMCTL, "show", "--no-pager",
             *(f"--property={name}" for name in _OWN_PROPERTIES), _OWN_UNIT)


def inspect_effective_owned_nginx_unit(*, active: bool) -> dict[str, Any]:
    """Read-only fixed REPOCACHE unit observation, not signed-file authority.

    The caller must independently verify installed signed unit/config bytes,
    native package provenance, ownership intent and any required state lock.
    No service operation is authorized by this observation.
    """
    return _inspect_effective_owned_nginx_unit(active=active, dedicated=False)


def _inspect_effective_owned_nginx_unit(*, active: bool, dedicated: bool,
                                        loading_profile: bool = False) -> dict[str, Any]:
    if (type(active) is not bool or type(dedicated) is not bool
            or type(loading_profile) is not bool
            or (loading_profile and (active or not dedicated))):
        _deny("OWN_UNIT_UNVERIFIED")
    try:
        _observe_systemd_pid1()
        _safe_native_systemctl()
        observed = []
        for sample in range(2):
            proc = subprocess.run(
                _OWN_SHOW, shell=False, check=False, capture_output=True,
                text=True, stdin=subprocess.DEVNULL, cwd="/", timeout=5,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                close_fds=True, start_new_session=True,
            )
            if (proc.returncode != 0 or type(proc.stdout) is not str
                    or not 1 <= len(proc.stdout) <= 8192 or
                    type(proc.stderr) is not str or len(proc.stderr) > 4096 or
                    "\x00" in proc.stdout or "\r" in proc.stdout):
                _deny("OWN_UNIT_UNVERIFIED")
            fields = {}
            for line in proc.stdout.splitlines():
                if "=" not in line:
                    _deny("OWN_UNIT_UNVERIFIED")
                key, value = line.split("=", 1)
                if key not in _OWN_PROPERTIES or key in fields:
                    _deny("OWN_UNIT_UNVERIFIED")
                fields[key] = value
            if set(fields) != set(_OWN_PROPERTIES):
                _deny("OWN_UNIT_UNVERIFIED")
            expected = {
                "Id": _OWN_UNIT, "Names": _OWN_UNIT,
                "FragmentPath": "/etc/systemd/system/" + _OWN_UNIT,
                "DropInPaths": _NAMESPACE_DROPIN_PATH if dedicated else "",
                "LoadState": "loaded",
                "ActiveState": "active" if active else "inactive",
                "SubState": "running" if active else "dead",
                "CanReload": "yes", "NeedDaemonReload": "no",
            }
            # Only the authenticated stopped-profile transition may observe
            # the exact old loaded unit with its new on-disk drop-in pending.
            # All ordinary observers still reject NeedDaemonReload=yes.
            if loading_profile and fields["NeedDaemonReload"] == "yes":
                expected.update(DropInPaths="", NeedDaemonReload="yes")
            if any(fields[k] != v for k, v in expected.items()):
                _deny("OWN_UNIT_UNVERIFIED")
            pid = fields["MainPID"]
            if active:
                if (not 1 <= len(pid) <= 10 or not pid.isascii() or not pid.isdecimal()
                        or not 2 <= int(pid) <= 2**31 - 1):
                    _deny("OWN_UNIT_UNVERIFIED")
                if dedicated:
                    _observe_nginx_master_kernel(int(pid), dedicated=True)
                else:
                    _observe_nginx_master_kernel(int(pid))
            elif pid != "0":
                _deny("OWN_UNIT_UNVERIFIED")
            observed.append(fields)
        if observed[0] != observed[1]:
            _deny("OWN_UNIT_CHANGED")
        return {"status": "NATIVE_REPOCACHE_NGINX_SERVICE_VERIFIED",
                "main_pid_observed": int(observed[0]["MainPID"]),
                "unit_name": _OWN_UNIT,
                **({"profile_loaded": observed[0]["NeedDaemonReload"] == "no"}
                   if loading_profile else {}),
                "authorizes_systemctl": False,
                "authorizes_nginx_reload": False,
                "authorizes_nginx_install": False}
    except EffectiveNginxUnitError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _deny("OWN_UNIT_UNVERIFIED")


# Private prerequisites for a future WAL-bound reload. Neither function
# grants service authority, and neither is exposed through socket dispatch.
_SIGNED_WORKER = "/usr/libexec/repocache/server-control-worker"
_SIGNED_UNIT_MEMBER = "repocache/_signed-owned-nginx.service"
_UNIT_MAX_BYTES = 16384
_BOOTSTRAP_ADDRESS = ("127.0.0.1", 8008)
_BOOTSTRAP_REQUEST = (
    b"GET /__repocache/private HTTP/1.1\r\n"
    b"Host: localhost\r\nConnection: close\r\n\r\n"
)


def _signed_owned_unit_bytes() -> bytes:
    """Read only the fixed member of the installed authenticated worker.

    A development source import is deliberately insufficient. This is a
    consistency check within the installed-worker trust boundary, not an
    independent re-verification of the publisher's signature.
    """
    loader = __loader__
    if (not isinstance(loader, zipimport.zipimporter)
            or loader.archive != _SIGNED_WORKER):
        _deny("SIGNED_OWN_UNIT_SOURCE_REQUIRED")
    try:
        raw = loader.get_data(_SIGNED_WORKER + "/" + _SIGNED_UNIT_MEMBER)
        if type(raw) is not bytes or not 1 <= len(raw) <= _UNIT_MAX_BYTES:
            _deny("SIGNED_OWN_UNIT_SOURCE_INVALID")
        return raw
    except OSError:
        _deny("SIGNED_OWN_UNIT_SOURCE_UNAVAILABLE")


# Inert candidate only. The existing signed unit remains authoritative
# until the dedicated domain, namespace, kernel egress and WAL lifecycle
# have been accepted together. Installed paths are not caller parameters.
_NAMESPACE_PATH = "/run/netns/repocache-nginx"
_CANDIDATE_EXECUTABLE = "/usr/libexec/repocache/nginx"
_NAMESPACE_DROPIN_DIR = _OWN_UNIT + ".d"
_NAMESPACE_DROPIN_LEAF = "90-repocache-dedicated.conf"
_NAMESPACE_DROPIN_STAGE = ".repocache-dedicated-unit.stage"
_NAMESPACE_PROFILE_RECEIPT = ".native-nginx-profile-v1.json"
_NAMESPACE_PROFILE_RECEIPT_MAX = 4096
_NAMESPACE_DROPIN_PATH = "/etc/systemd/system/" + _NAMESPACE_DROPIN_DIR + "/" + _NAMESPACE_DROPIN_LEAF
_MASTER_CAPABILITIES = "CAP_CHOWN CAP_KILL CAP_SETGID CAP_SETUID"
_OWN_EXEC_KEYS = ("ExecStartPre", "ExecStart", "ExecReload", "ExecStop")


def _closed_signed_owned_unit_contract(raw: bytes) -> dict[str, str]:
    """Decode the exact supported source contract, never inherited options."""
    expected = {
        "Type": "forking", "RuntimeDirectory": "repocache-nginx",
        "RuntimeDirectoryMode": "0755", "PIDFile": "/run/repocache-nginx/nginx.pid",
        "ExecStartPre": "/usr/sbin/nginx -t -q -c /etc/nginx/repocache.d/repocache.conf",
        "ExecStart": "/usr/sbin/nginx -c /etc/nginx/repocache.d/repocache.conf",
        "ExecReload": "/usr/sbin/nginx -s reload -c /etc/nginx/repocache.d/repocache.conf",
        "ExecStop": "/usr/sbin/nginx -s quit -c /etc/nginx/repocache.d/repocache.conf",
        "TimeoutStartSec": "30s", "TimeoutStopSec": "30s", "KillMode": "mixed",
        "NoNewPrivileges": "yes", "PrivateTmp": "yes", "ProtectHome": "yes",
        "ProtectSystem": "strict",
        "ReadWritePaths": "/run/repocache-nginx /var/cache/nginx/repocache-managed /var/log/nginx/repocache-managed",
        "UMask": "0027",
    }
    try:
        if (type(raw) is not bytes or not 1 <= len(raw) <= _UNIT_MAX_BYTES
                or any(byte != 10 and not 32 <= byte <= 126 for byte in raw)):
            _deny("NAMESPACE_UNIT_SOURCE_INVALID")
        # A closed line grammar avoids accepting configparser-specific
        # continuations, DEFAULT sections or delimiters that PID1 interprets
        # differently. Only whole-line comments and empty lines are ignored.
        lines = [line for line in raw.decode("ascii").splitlines()
                 if line and not line.startswith("#")]
        canonical = [
            "[Unit]", "Description=REPOCACHE isolated native NGINX service",
            "After=network.target", "[Service]",
            *(key + "=" + value for key, value in expected.items()),
            "[Install]", "WantedBy=multi-user.target",
        ]
        if lines != canonical:
            _deny("NAMESPACE_UNIT_SOURCE_INVALID")
        # Render only reviewed values, never raw syntax or comments that
        # might be interpreted differently by PID1.
        return expected
    except EffectiveNginxUnitError:
        raise
    except (UnicodeError, ValueError, TypeError):
        _deny("NAMESPACE_UNIT_SOURCE_INVALID")


def _render_owned_nginx_namespace_unit_candidate(raw: bytes, *, https_port: int) -> dict:
    """Pure closed unit proposal for a later authenticated transition.

    The trusted caller must bind https_port to the verified generation.
    The fixed namespace must be provisioned and verified separately.
    No policy, label, file, service, namespace or permission is changed.
    """
    import hashlib

    if type(https_port) is not int or not 1 <= https_port <= 65535:
        _deny("NAMESPACE_UNIT_PORT_INVALID")
    service = _closed_signed_owned_unit_contract(raw)
    for name in _OWN_EXEC_KEYS:
        service[name] = _CANDIDATE_EXECUTABLE + service[name][len("/usr/sbin/nginx"):]
    # A low listener additionally needs NET_BIND_SERVICE. Its actual
    # SELinux permission and native behavior remain separate gates.
    service.update({
        "CapabilityBoundingSet": _MASTER_CAPABILITIES + (
            " CAP_NET_BIND_SERVICE" if https_port < 1024 else ""),
        "NetworkNamespacePath": _NAMESPACE_PATH,
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
    })
    candidate = (
        "[Unit]\nDescription=REPOCACHE isolated native NGINX service\nAfter=network.target\n"
        "[Service]\n" + "".join(key + "=" + value + "\n" for key, value in service.items())
        + "[Install]\nWantedBy=multi-user.target\n"
    ).encode("ascii")
    return {
        "unit_bytes": candidate,
        "source_unit_sha256": hashlib.sha256(raw).hexdigest(),
        "candidate_unit_sha256": hashlib.sha256(candidate).hexdigest(),
        "https_port": https_port,
        "runtime_namespace_verified": False,
        "runtime_selinux_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_systemctl": False,
    }


def render_owned_nginx_namespace_unit_candidate(*, https_port: int) -> dict:
    """Internal installed-worker candidate; source imports confer no trust."""
    return _render_owned_nginx_namespace_unit_candidate(
        _signed_owned_unit_bytes(), https_port=https_port)


def _render_owned_nginx_namespace_dropin_candidate(raw: bytes, *, https_port: int) -> dict:
    """Exact runtime transition proposal for the already owned service.

    Reset systemd's list-valued Exec directives, rather than append a second
    executable. The inherited signed service contract is otherwise preserved.
    The caller must prove the old unit bytes and absence of foreign drop-ins,
    namespace ownership, labelled storage and durable recovery before use.
    """
    import hashlib

    candidate = _render_owned_nginx_namespace_unit_candidate(raw, https_port=https_port)
    service = candidate["unit_bytes"].decode("ascii").split("[Service]\n", 1)[1]
    service = service.split("[Install]\n", 1)[0]
    values = dict(row.split("=", 1) for row in service.splitlines())
    lines = ["[Service]"]
    for key in _OWN_EXEC_KEYS:
        # Avoid opening the vendor package's default log before loading our
        # fixed absolute config. Preserve all remaining signed arguments.
        command = values[key].replace(_CANDIDATE_EXECUTABLE + " ",
                                      _CANDIDATE_EXECUTABLE + " -e stderr ", 1)
        lines.extend((key + "=", key + "=" + command))
    for key in ("CapabilityBoundingSet", "NetworkNamespacePath", "RestrictAddressFamilies"):
        lines.append(key + "=" + values[key])
    dropin = ("\n".join(lines) + "\n").encode("ascii")
    return {**candidate, "dropin_bytes": dropin,
            "dropin_sha256": hashlib.sha256(dropin).hexdigest()}


def render_owned_nginx_namespace_dropin_candidate(*, https_port: int) -> dict:
    return _render_owned_nginx_namespace_dropin_candidate(
        _signed_owned_unit_bytes(), https_port=https_port)


def _read_exact_owned_unit_at(root_fd: int, expected: bytes, *,
                              owner_uid: int, owner_gid: int) -> tuple[int, ...]:
    """Descriptor-bound exact unit read. Test fixtures never confer authority."""
    from repocache.server_protected_state_inspect_v1 import (
        _FILE_FLAGS, _identity, _recheck, _walk,
    )
    if type(expected) is not bytes or not 1 <= len(expected) <= _UNIT_MAX_BYTES:
        _deny("SIGNED_OWN_UNIT_SOURCE_INVALID")
    try:
        with ExitStack() as stack:
            parent, chain = _walk(root_fd, ("etc", "systemd", "system"),
                                  stack, owner_uid)
            # Systemd's fixed local unit must be an ordinary root-owned file.
            fd = os.open(_OWN_UNIT, _FILE_FLAGS, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != owner_uid or info.st_gid != owner_gid
                    or stat.S_IMODE(info.st_mode) != 0o644
                    or info.st_dev != os.fstat(parent).st_dev
                    or info.st_size != len(expected)):
                _deny("SIGNED_OWN_UNIT_METADATA_MISMATCH")
            raw = bytearray()
            while len(raw) <= len(expected):
                block = os.read(fd, len(expected) + 1 - len(raw))
                if not block:
                    break
                raw.extend(block)
            identity = _identity(info)
            if (bytes(raw) != expected or _identity(os.fstat(fd)) != identity
                    or _identity(os.stat(_OWN_UNIT, dir_fd=parent,
                                         follow_symlinks=False)) != identity):
                _deny("SIGNED_OWN_UNIT_CONTENT_MISMATCH")
            _recheck(chain, owner_uid)
            return identity
    except EffectiveNginxUnitError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("SIGNED_OWN_UNIT_UNVERIFIED")


def _read_exact_namespace_dropin_at(root_fd: int, expected: bytes, *,
                                    owner_uid: int, owner_gid: int) -> tuple[int, ...]:
    return _read_namespace_profile_at(root_fd, expected, owner_uid=owner_uid,
                                      owner_gid=owner_gid, staged=False)[1]


def _read_namespace_profile_at(root_fd: int, expected: bytes, *,
                               owner_uid: int, owner_gid: int, staged: bool) -> tuple:
    """Read the single fixed persistent drop-in with retained descriptors.

    The expected bytes must come from the signed unit renderer in an installed
    worker. Detached roots are for tests only. No files are created or relabelled.
    """
    from repocache.server_protected_state_inspect_v1 import (
        _FILE_FLAGS, _identity, _recheck, _walk,
    )

    if (type(expected) is not bytes or not 1 <= len(expected) <= _UNIT_MAX_BYTES
            or type(staged) is not bool):
        _deny("NAMESPACE_DROPIN_SOURCE_INVALID")
    try:
        with ExitStack() as stack:
            parent, chain = _walk(
                root_fd, ("etc", "systemd", "system",
                          _NAMESPACE_DROPIN_STAGE if staged else _NAMESPACE_DROPIN_DIR),
                stack, owner_uid)
            info = os.fstat(parent)
            if (info.st_gid != owner_gid or stat.S_IMODE(info.st_mode) != 0o755
                    or set(os.listxattr(parent)) - {"security.selinux"}
                    or os.listdir(parent) != [_NAMESPACE_DROPIN_LEAF]):
                _deny("NAMESPACE_DROPIN_DIRECTORY_REFUSED")
            fd = os.open(_NAMESPACE_DROPIN_LEAF, _FILE_FLAGS, dir_fd=parent)
            stack.callback(os.close, fd)
            leaf = os.fstat(fd)
            if (not stat.S_ISREG(leaf.st_mode) or leaf.st_nlink != 1
                    or leaf.st_uid != owner_uid or leaf.st_gid != owner_gid
                    or stat.S_IMODE(leaf.st_mode) != 0o644
                    or leaf.st_dev != info.st_dev or leaf.st_size != len(expected)
                    or set(os.listxattr(fd)) - {"security.selinux"}):
                _deny("NAMESPACE_DROPIN_METADATA_REFUSED")
            raw = bytearray()
            while len(raw) <= len(expected):
                block = os.read(fd, len(expected) + 1 - len(raw))
                if not block:
                    break
                raw.extend(block)
            identity = _identity(leaf)
            if (bytes(raw) != expected or _identity(os.fstat(fd)) != identity
                    or _identity(os.stat(_NAMESPACE_DROPIN_LEAF, dir_fd=parent,
                                         follow_symlinks=False)) != identity
                    or os.listdir(parent) != [_NAMESPACE_DROPIN_LEAF]
                    or _identity(os.fstat(parent)) != _identity(info)):
                _deny("NAMESPACE_DROPIN_CONTENT_CHANGED")
            _recheck(chain, owner_uid)
            return (info.st_dev, info.st_ino), identity
    except EffectiveNginxUnitError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("NAMESPACE_DROPIN_UNVERIFIED")


def _stage_namespace_dropin_under_lock(root_fd: int, state_fd: int, raw: bytes, *,
                                        https_port: int, owner_uid: int,
                                        owner_gid: int, allow_create: bool) -> dict:
    """Prepare one fixed owned drop-in; never activate or reload systemd.

    The trusted caller retains the state lock and independently proves the
    signed source, inactive service before publication, executable receipt,
    generation, labels and namespace prerequisites. Detached roots are only
    tests. A partial stage without an exact durable receipt is preserved and
    refused. A receipt-bound complete stage can resume without adoption.
    """
    import hashlib
    from repocache.server_native_installed_storage_v1 import _rename_directory_noreplace
    from repocache.server_protected_state_inspect_v1 import (
        _DIRECTORY_FLAGS, _FILE_FLAGS, _identity, _recheck, _safe_directory, _walk,
    )
    from repocache.server_protected_state_store_v1 import _canonical, _read_file, _write_exclusive

    if (type(allow_create) is not bool or type(root_fd) is not int
            or type(state_fd) is not int or type(owner_uid) is not int
            or type(owner_gid) is not int or owner_uid != os.geteuid()
            or owner_gid != os.getegid()):
        _deny("NAMESPACE_PROFILE_INPUT_REFUSED")
    candidate = _render_owned_nginx_namespace_dropin_candidate(raw, https_port=https_port)
    expected = candidate["dropin_bytes"]
    limit = _NAMESPACE_PROFILE_RECEIPT_MAX
    try:
        with ExitStack() as stack:
            parent, chain = _walk(root_fd, ("etc", "systemd", "system"), stack, owner_uid)
            state, state_chain = _walk(root_fd, ("var", "lib", "repocache", "server"),
                                       stack, owner_uid)
            parent_id = _identity(os.fstat(parent))[:5]
            state_id = _identity(os.fstat(state_fd))[:6]
            if (_identity(os.fstat(state))[:6] != state_id
                    or state_id[4] != owner_gid or stat.S_IMODE(state_id[2]) != 0o700
                    or os.fstat(parent).st_gid != owner_gid
                    or set(os.listxattr(parent)) - {"security.selinux"}
                    or set(os.listxattr(state_fd)) - {"security.selinux"}):
                _deny("NAMESPACE_PROFILE_PARENT_REFUSED")
            unit_identity = _read_exact_owned_unit_at(
                root_fd, raw, owner_uid=owner_uid, owner_gid=owner_gid)

            def guard():
                _recheck(chain[:-1], owner_uid)
                _recheck(state_chain[:-1], owner_uid)
                for held, entry, identity in ((parent, chain[-1], parent_id),
                                               (state_fd, state_chain[-1], state_id)):
                    ancestor, name, _, _ = entry
                    if (_identity(_safe_directory(held, owner_uid))[:len(identity)] != identity
                            or _identity(os.stat(name, dir_fd=ancestor,
                                                 follow_symlinks=False))[:len(identity)] != identity):
                        _deny("NAMESPACE_PROFILE_PARENT_CHANGED")
                if _read_exact_owned_unit_at(
                        root_fd, raw, owner_uid=owner_uid, owner_gid=owner_gid) != unit_identity:
                    _deny("NAMESPACE_PROFILE_UNIT_CHANGED")

            def present(name):
                try:
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                    return True
                except FileNotFoundError:
                    return False

            def receipt():
                result = _read_file(state_fd, _NAMESPACE_PROFILE_RECEIPT, owner_uid, limit)
                if result is not None:
                    fd = os.open(_NAMESPACE_PROFILE_RECEIPT, _FILE_FLAGS, dir_fd=state_fd)
                    try:
                        info = os.fstat(fd)
                        if (info.st_gid != owner_gid
                                or set(os.listxattr(fd)) - {"security.selinux"}
                                or _identity(info) != _identity(os.stat(
                                    _NAMESPACE_PROFILE_RECEIPT, dir_fd=state_fd,
                                    follow_symlinks=False))
                                or os.read(fd, limit + 1) != result
                                or _identity(os.fstat(fd)) != _identity(info)):
                            _deny("NAMESPACE_PROFILE_RECEIPT_REFUSED")
                    finally:
                        os.close(fd)
                return result

            def observed(staged):
                return _read_namespace_profile_at(
                    root_fd, expected, owner_uid=owner_uid,
                    owner_gid=owner_gid, staged=staged)

            def record(identity):
                directory, leaf = identity
                return _canonical({
                    "schema_version": 1,
                    "source_unit_sha256": candidate["source_unit_sha256"],
                    "dropin_sha256": candidate["dropin_sha256"],
                    "https_port": https_port,
                    "directory_identity": list(directory),
                    "dropin_identity": list(leaf),
                    "authorizes_nginx_activation": False,
                }, limit=limit)

            guard()
            saved = receipt()
            staged = present(_NAMESPACE_DROPIN_STAGE)
            final = present(_NAMESPACE_DROPIN_DIR)
            if staged and final:
                _deny("NAMESPACE_PROFILE_COLLISION")
            if saved is None:
                if staged or final or not allow_create:
                    _deny("NAMESPACE_PROFILE_UNOWNED_OR_MISSING")
                # Stage outside systemd's drop-in lookup; no empty or partial
                # active directory is ever published. Any incomplete stage is
                # preserved for review, not automatically repaired by bytes.
                os.mkdir(_NAMESPACE_DROPIN_STAGE, 0o700, dir_fd=parent)
                stage = os.open(_NAMESPACE_DROPIN_STAGE, _DIRECTORY_FLAGS, dir_fd=parent)
                stack.callback(os.close, stage)
                os.fchmod(stage, 0o755)
                fd = os.open(_NAMESPACE_DROPIN_LEAF,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=stage)
                try:
                    os.fchmod(fd, 0o644)
                    if os.write(fd, expected) != len(expected):
                        _deny("NAMESPACE_PROFILE_WRITE_INCOMPLETE")
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(stage)
                os.fsync(parent)
                identity = observed(True)
                if identity[0] != (os.fstat(stage).st_dev, os.fstat(stage).st_ino):
                    _deny("NAMESPACE_PROFILE_STAGE_CHANGED")
                guard()
                saved = record(identity)
                _write_exclusive(state_fd, _NAMESPACE_PROFILE_RECEIPT, saved, owner_uid, limit)
                staged = True
            if not (staged or final):
                _deny("NAMESPACE_PROFILE_RECEIPT_WITHOUT_DIRECTORY")
            identity = observed(staged)
            if receipt() != saved or record(identity) != saved:
                _deny("NAMESPACE_PROFILE_RECEIPT_MISMATCH")
            guard()
            if staged:
                if not allow_create:
                    _deny("NAMESPACE_PROFILE_STAGE_PENDING")
                if present(_NAMESPACE_DROPIN_DIR) or observed(True) != identity:
                    _deny("NAMESPACE_PROFILE_COLLISION")
                # Durable receipt precedes the single same-parent no-replace
                # publication. The file identity survives directory rename.
                _rename_directory_noreplace(parent, _NAMESPACE_DROPIN_STAGE,
                                            parent, _NAMESPACE_DROPIN_DIR)
                os.fsync(parent)
            if (present(_NAMESPACE_DROPIN_STAGE) or observed(False) != identity
                    or receipt() != saved):
                _deny("NAMESPACE_PROFILE_PUBLICATION_CHANGED")
            guard()
            return {"receipt_sha256": hashlib.sha256(saved).hexdigest(),
                    "directory_identity": identity[0], "private_dropin_identity": identity[1],
                    "dropin_sha256": candidate["dropin_sha256"],
                    "receipt_matches_owned_dropin": True,
                    "authorizes_systemctl": False, "authorizes_nginx_activation": False}
    except EffectiveNginxUnitError:
        raise
    except (OSError, ValueError, TypeError, RecursionError):
        _deny("NAMESPACE_PROFILE_PLACEMENT_REFUSED")


def inspect_signed_owned_namespace_unit(*, https_port: int, active: bool) -> dict[str, Any]:
    """Observe the exact loaded signed base and persistent dedicated drop-in."""
    return _inspect_signed_owned_namespace_unit(
        https_port=https_port, active=active, loading_profile=False)


def _inspect_signed_owned_namespace_load_state(*, https_port: int) -> dict[str, Any]:
    """Read-only exact stopped profile transition, never service authority."""
    return _inspect_signed_owned_namespace_unit(
        https_port=https_port, active=False, loading_profile=True)


def _inspect_signed_owned_namespace_unit(*, https_port: int, active: bool,
                                         loading_profile: bool) -> dict[str, Any]:
    """Observe signed base, exact persistent drop-in and PID1 twice.

    The state/receipt owner must bind the port to the verified generation,
    verify the installed executable receipt, kernel namespace, labels and
    egress independently, and hold the appropriate lock. This function does
    not establish a durable transition or authorize any service operation.
    The legacy signed-unit observer continues to refuse all drop-ins.
    """
    from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS

    raw = _signed_owned_unit_bytes()
    candidate = _render_owned_nginx_namespace_dropin_candidate(raw, https_port=https_port)
    if type(active) is not bool or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        _deny("NAMESPACE_UNIT_OBSERVATION_REFUSED")
    try:
        with ExitStack() as stack:
            root_fd = os.open("/", _DIRECTORY_FLAGS)
            stack.callback(os.close, root_fd)

            def read():
                return (
                    _read_exact_owned_unit_at(root_fd, raw, owner_uid=0, owner_gid=0),
                    _read_exact_namespace_dropin_at(
                        root_fd, candidate["dropin_bytes"], owner_uid=0, owner_gid=0),
                )

            before = read()
            observed = _inspect_effective_owned_nginx_unit(
                active=active, dedicated=True, loading_profile=loading_profile)
            if read() != before:
                _deny("NAMESPACE_UNIT_CHANGED")
            return {**observed, "signed_worker_unit_bytes_match": True,
                    "private_unit_identity": before[0],
                    "private_dropin_identity": before[1],
                    "dropin_sha256": candidate["dropin_sha256"],
                    "runtime_namespace_verified": False,
                    "runtime_selinux_verified": False,
                    "authorizes_nginx_activation": False}
    except EffectiveNginxUnitError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("NAMESPACE_UNIT_UNVERIFIED")


def _validate_dedicated_master_status(raw: bytes, *, https_port: int) -> None:
    """Verify the exact root-master capability and credential boundary."""
    if (type(raw) is not bytes or not 1 <= len(raw) <= 65536
            or type(https_port) is not int or not 1 <= https_port <= 65535):
        _deny("NAMESPACE_MASTER_STATUS_REFUSED")
    keys = {b"Uid", b"Gid", b"CapEff", b"CapPrm", b"CapBnd", b"CapAmb", b"NoNewPrivs"}
    found = {}
    for line in raw.splitlines():
        key, sep, value = line.partition(b":")
        if key in keys:
            if not sep or key in found:
                _deny("NAMESPACE_MASTER_STATUS_REFUSED")
            found[key] = value.strip()
    if (set(found) != keys
            or any(found[k].split() != [b"0"] * 4 for k in (b"Uid", b"Gid"))
            or found[b"NoNewPrivs"] != b"1"):
        _deny("NAMESPACE_MASTER_STATUS_REFUSED")
    # CAP_CHOWN, CAP_KILL, CAP_SETGID, CAP_SETUID, and (only for
    # a low listener) CAP_NET_BIND_SERVICE. Never add DAC_OVERRIDE.
    expected = (1 << 0) | (1 << 5) | (1 << 6) | (1 << 7)
    if https_port < 1024:
        expected |= 1 << 10
    for key in (b"CapEff", b"CapPrm", b"CapBnd", b"CapAmb"):
        if (re.fullmatch(rb"[0-9a-f]{16}", found[key]) is None
                or int(found[key], 16) != (0 if key == b"CapAmb" else expected)):
            _deny("NAMESPACE_MASTER_CAPABILITIES_REFUSED")


def _sample_dedicated_master_runtime(pid: int, *, https_port: int,
                                     namespace_identity: tuple[int, int],
                                     executable_identity: tuple[int, int]) -> tuple:
    """Read bounded kernel evidence from the observed master, never signal it."""
    if type(pid) is not int or not 2 <= pid <= 2**31 - 1:
        _deny("INVALID_MAIN_PID")
    from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS
    with ExitStack() as stack:
        proc = os.open("/proc", _DIRECTORY_FLAGS)
        stack.callback(os.close, proc)
        master = os.open(str(pid), _DIRECTORY_FLAGS, dir_fd=proc)
        stack.callback(os.close, master)
        info = os.fstat(master)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_gid != 0 or info.st_mode & 0o022):
            _deny("NAMESPACE_MASTER_PROCESS_REFUSED")
        process_identity = (info.st_dev, info.st_ino)

        def read(parent, name, limit):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                         os.O_CLOEXEC, dir_fd=parent)
            try:
                seen = os.fstat(fd)
                if not stat.S_ISREG(seen.st_mode) or seen.st_uid != 0:
                    _deny("NAMESPACE_MASTER_PROC_REFUSED")
                data = bytearray()
                while len(data) <= limit:
                    block = os.read(fd, min(8192, limit + 1 - len(data)))
                    if not block:
                        break
                    data.extend(block)
                if not data or len(data) > limit:
                    _deny("NAMESPACE_MASTER_PROC_REFUSED")
                return bytes(data)
            finally:
                os.close(fd)

        def identity_at(name):
            value = os.stat(name, dir_fd=master)
            return value.st_dev, value.st_ino

        userns = os.stat("/proc/1/ns/user")
        if (identity_at("ns/net") != namespace_identity
                or identity_at("ns/user") != (userns.st_dev, userns.st_ino)
                or identity_at("exe") != executable_identity):
            _deny("NAMESPACE_MASTER_BINDING_REFUSED")
        attr = os.open("attr", _DIRECTORY_FLAGS, dir_fd=master)
        stack.callback(os.close, attr)
        domain = read(attr, "current", 4096).rstrip(b"\x00\n")
        if domain != b"system_u:system_r:repocache_nginx_t:s0":
            _deny("NAMESPACE_MASTER_DOMAIN_REFUSED")
        _validate_dedicated_master_status(read(master, "status", 65536),
                                          https_port=https_port)
        current = os.stat(str(pid), dir_fd=proc, follow_symlinks=False)
        if ((current.st_dev, current.st_ino) != process_identity
                or identity_at("ns/net") != namespace_identity
                or identity_at("exe") != executable_identity
                or identity_at("ns/user") != (userns.st_dev, userns.st_ino)):
            _deny("NAMESPACE_MASTER_BINDING_CHANGED")
        return process_identity


def _inspect_signed_owned_namespace_runtime(*, https_port: int,
                                            namespace_identity: tuple[int, int],
                                            executable_identity: tuple[int, int]) -> dict:
    """Bind the exact signed active unit to its retained dedicated netns.

    Identities must come from the separately authenticated boot/profile and
    executable receipts under the caller's existing state lock. This checks
    the master only, not the workers, policy module, storage or TLS; it never
    authorizes start, stop, reload, kernel mutation or catalog publication.
    """
    from repocache.server_native_egress_candidate_v1 import (
        _fixed_namespace_scope, NativeEgressCandidateError,
    )
    if (type(https_port) is not int or not 1 <= https_port <= 65535
            or any(type(pair) is not tuple or len(pair) != 2
                   or any(type(value) is not int or value <= 0 for value in pair)
                   for pair in (namespace_identity, executable_identity))):
        _deny("NAMESPACE_RUNTIME_INPUT_REFUSED")
    try:
        with _fixed_namespace_scope() as (net, identity, recheck):
            if identity != namespace_identity:
                _deny("NAMESPACE_MASTER_BINDING_REFUSED")
            observed = inspect_signed_owned_namespace_unit(https_port=https_port, active=True)
            pid = observed["main_pid_observed"]
            def sample():
                recheck()
                result = _sample_dedicated_master_runtime(
                    pid, https_port=https_port, namespace_identity=identity,
                    executable_identity=executable_identity)
                recheck()
                return result
            first = sample()
            if (inspect_signed_owned_namespace_unit(
                    https_port=https_port, active=True) != observed or sample() != first):
                _deny("NAMESPACE_MASTER_BINDING_CHANGED")
            return {**observed, "master_process_identity": first,
                    "master_namespace_identity": identity,
                    "master_executable_identity": executable_identity,
                    "runtime_namespace_verified": True,
                    "runtime_master_domain_verified": True,
                    "runtime_master_capabilities_verified": True}
    except EffectiveNginxUnitError:
        raise
    except (NativeEgressCandidateError, OSError, TypeError, ValueError, OverflowError):
        _deny("NAMESPACE_RUNTIME_UNVERIFIED")


def inspect_signed_owned_nginx_unit() -> dict[str, Any]:
    """Bind the active dedicated unit to its authenticated worker's bytes.

    The caller must retain the state lock, independently establish signed
    installed-worker and package provenance, validate the managed context
    and prove the live listener. No command mutation is performed here.
    """
    return _inspect_owned_nginx_unit_bytes(_signed_owned_unit_bytes())


def _inspect_owned_nginx_unit_bytes(expected: bytes) -> dict[str, Any]:
    """Read-only common observation for authenticated internal callers.

    The worker obtains expected bytes exclusively from its installed archive.
    The signed installer may pass the exact unit it independently authenticated
    and audited under the state lock. No socket request supplies these bytes.
    """
    from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS

    try:
        with ExitStack() as stack:
            root_fd = os.open("/", _DIRECTORY_FLAGS)
            stack.callback(os.close, root_fd)
            before = _read_exact_owned_unit_at(root_fd, expected,
                                              owner_uid=0, owner_gid=0)
            observed = inspect_effective_owned_nginx_unit(active=True)
            after = _read_exact_owned_unit_at(root_fd, expected,
                                             owner_uid=0, owner_gid=0)
            if before != after:
                _deny("SIGNED_OWN_UNIT_CHANGED")
            return {**observed, "signed_worker_unit_bytes_match": True,
                    "private_unit_identity": before}
    except EffectiveNginxUnitError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("SIGNED_OWN_UNIT_UNVERIFIED")


def _require_bootstrap_response(raw: bytes) -> None:
    """Accept only a complete, empty 204 response from the fixed probe."""
    if type(raw) is not bytes or not 1 <= len(raw) <= 8192:
        _deny("BOOTSTRAP_HEALTH_UNVERIFIED")
    head, separator, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if (not separator or body or not lines[0].startswith(b"HTTP/1.1 204 ")
            or any(byte < 32 or byte == 127 for byte in lines[0])):
        _deny("BOOTSTRAP_HEALTH_UNVERIFIED")
    lengths = []
    for line in lines[1:]:
        key, colon, value = line.partition(b":")
        if (not colon or not key or any(
                byte not in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for byte in key)
                or any((byte < 32 and byte != 9) or byte == 127 for byte in value)):
            _deny("BOOTSTRAP_HEALTH_UNVERIFIED")
        key = key.lower()
        if key in (b"transfer-encoding", b"content-encoding"):
            _deny("BOOTSTRAP_HEALTH_UNVERIFIED")
        if key == b"content-length":
            lengths.append(value.strip())
    if lengths not in ([], [b"0"]):
        _deny("BOOTSTRAP_HEALTH_UNVERIFIED")


def require_owned_bootstrap_health() -> None:
    """Check the original signed bootstrap endpoint after a rollback.

    Fixed loopback only, no proxy, DNS lookup of operator input, redirects,
    or credentials. A successful response does not identify the process;
    the WAL caller must also verify unit identity and exact context.
    """
    deadline = time.monotonic() + 10
    try:
        with socket.create_connection(_BOOTSTRAP_ADDRESS, timeout=4) as stream:
            stream.settimeout(4)
            stream.sendall(_BOOTSTRAP_REQUEST)
            raw = bytearray()
            while len(raw) <= 8192:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _deny("BOOTSTRAP_HEALTH_UNVERIFIED")
                stream.settimeout(min(4.0, remaining))
                block = stream.recv(min(4096, 8193 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            _require_bootstrap_response(bytes(raw))
    except EffectiveNginxUnitError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("BOOTSTRAP_HEALTH_UNVERIFIED")
