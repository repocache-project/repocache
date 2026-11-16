"""Fail-closed *necessary* native host-root prerequisites for issue #64.

This source never grants privilege, runs systemctl, changes a file, or makes a
container root into an attested production host. Before an installed broker
can use a Linux root-owned socket it must additionally prove its signed
installed binary, effective systemd units, package, SELinux/ACL/mount
provenance, and a complete authorized durable operation. These checks only
exclude common incorrect contexts and protect against accidental deployment.
"""
from __future__ import annotations

import os
import stat
from contextlib import ExitStack
from typing import Any

# Exact Linux initial user namespace mapping, not a subordinate/rootless map.
_INITIAL_UID_MAP = b"         0          0 4294967295\n"
_PROC_MAX = 128
_SYSTEMD_DIRECTORIES = ("/run", "/run/systemd", "/run/systemd/system")
_SERVICE_DIRECTORIES = (
    "/run/systemd/system", "/run/repocache",
    "/etc/nginx/conf.d", "/var/lib/repocache/server", "/var/lib/repocache/public",
    "/var/log/nginx", "/var/cache/nginx", "/usr/libexec/repocache",
)
_SERVICE_FILES = (
    "/etc/nginx/nginx.conf", "/usr/bin/systemctl", "/usr/sbin/nginx",
    "/usr/libexec/repocache/server-control-worker",
)
_SERVICE_SOCKETS = ("/run/systemd/private", "/run/repocache/server-control.sock")


class NativeHostPreflightError(ValueError):
    """Static error codes only: never include host data or procfs strings."""


def _deny(code: str) -> None:
    raise NativeHostPreflightError("NATIVE_HOST_" + code)


def _read_proc(path: str) -> bytes:
    """Read only a fixed procfs path, with bounded bytes and no content leaks."""
    try:
        fd = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        _deny("PROC_UNAVAILABLE")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            _deny("PROC_UNTRUSTED")
        raw = os.read(fd, _PROC_MAX + 1)
        if len(raw) > _PROC_MAX or not raw:
            _deny("PROC_INVALID")
        return raw
    except OSError:
        _deny("PROC_UNAVAILABLE")
    finally:
        os.close(fd)


def _namespace_pair(kind: str) -> tuple[tuple[int, int], tuple[int, int]]:
    """Read kernel namespace identities, without interpreting symlink text."""
    if kind not in ("mnt", "user", "pid"):
        _deny("NAMESPACE_KIND_REFUSED")
    try:
        initial = os.stat("/proc/1/ns/" + kind)
        worker = os.stat("/proc/self/ns/" + kind)
        if (not stat.S_ISREG(initial.st_mode)
                or not stat.S_ISREG(worker.st_mode)):
            _deny("NAMESPACE_UNAVAILABLE")
        return ((initial.st_dev, initial.st_ino), (worker.st_dev, worker.st_ino))
    except NativeHostPreflightError:
        raise
    except OSError:
        _deny("NAMESPACE_UNAVAILABLE")


def _same_namespace(kind: str) -> None:
    initial, worker = _namespace_pair(kind)
    if initial != worker:
        _deny("NAMESPACE_DIFFERENT")


def _path_snapshot(
    root_fd: int, path: str, *, leaf_type: int,
) -> tuple[tuple[int, ...], ...]:
    """Record the actual inode at each component without following symlinks."""
    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

    components = path.lstrip("/").split("/")
    with ExitStack() as stack:
        parent = root_fd
        chain = [identity(os.fstat(root_fd))]
        for index, name in enumerate(components):
            expected = stat.S_IFDIR if index != len(components) - 1 else leaf_type
            fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
                         | (os.O_DIRECTORY if expected == stat.S_IFDIR else 0),
                         dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if stat.S_IFMT(info.st_mode) != expected:
                _deny("SERVICE_MOUNT_VIEW_UNSAFE")
            chain.append(identity(info))
            parent = fd
    return tuple(chain)


def _matching_service_mount_view() -> None:
    """Compare only fixed service paths through read-only kernel descriptors."""
    flags = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
    try:
        with ExitStack() as stack:
            local = os.open("/", flags | os.O_NOFOLLOW)
            stack.callback(os.close, local)
            # Only this kernel-owned proc link is intentionally dereferenced.
            # Do not use the resulting descriptor to open arbitrary paths,
            # run commands, or change the worker's mount namespace.
            host = os.open("/proc/1/root", flags)
            stack.callback(os.close, host)
            for paths, leaf_type in (
                (_SERVICE_DIRECTORIES, stat.S_IFDIR),
                (_SERVICE_FILES, stat.S_IFREG),
                (_SERVICE_SOCKETS, stat.S_IFSOCK),
            ):
                for path in paths:
                    reference = _path_snapshot(host, path, leaf_type=leaf_type)
                    if (_path_snapshot(local, path, leaf_type=leaf_type) != reference
                            or _path_snapshot(host, path, leaf_type=leaf_type) != reference):
                        _deny("SERVICE_MOUNT_VIEW_DIFFERENT")
    except OSError:
        _deny("SERVICE_MOUNT_VIEW_UNAVAILABLE")


def _root_identity() -> None:
    try:
        if (os.getuid() != 0 or os.geteuid() != 0
                or os.getresuid() != (0, 0, 0)
                or os.getgid() != 0 or os.getegid() != 0
                or os.getresgid() != (0, 0, 0)):
            _deny("INITIAL_ROOT_REQUIRED")
    except AttributeError:
        _deny("LINUX_CREDENTIALS_UNAVAILABLE")


def _require_host_context(*, service_mount_view: bool) -> dict[str, Any]:
    _root_identity()
    if _read_proc("/proc/1/comm") != b"systemd\n":
        _deny("SYSTEMD_PID1_REQUIRED")
    for kind in ("user", "pid"):
        _same_namespace(kind)
    if _read_proc("/proc/self/uid_map") != _INITIAL_UID_MAP:
        _deny("INITIAL_USER_NAMESPACE_REQUIRED")
    try:
        runtime = [os.lstat(path) for path in _SYSTEMD_DIRECTORIES]
    except OSError:
        _deny("SYSTEMD_RUNTIME_MISSING")
    for info in runtime:
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
            _deny("SYSTEMD_RUNTIME_UNSAFE")
    private_mount = False
    if service_mount_view:
        mount_pair = _namespace_pair("mnt")
        private_mount = mount_pair[0] != mount_pair[1]
        # Check fixed path identities even when a unit unexpectedly starts
        # without its filesystem sandbox. This does not attest the unit.
        _matching_service_mount_view()
        if _namespace_pair("mnt") != mount_pair:
            _deny("NAMESPACE_CHANGED")
    else:
        _same_namespace("mnt")
    return {
        "schema_version": 1,
        "status": "NATIVE_HOST_NECESSARY_PRECONDITIONS_ONLY",
        "initial_root_credentials_observed": True,
        "initial_user_namespace_mapping_observed": True,
        "pid1_systemd_and_matching_namespaces_observed": not private_mount,
        "private_mount_and_fixed_service_view_observed": private_mount,
        "signed_installed_binary_verified": False,
        "effective_systemd_unit_verified": False,
        "selinux_acl_mount_ownership_verified": False,
        "host_root_provenance_verified": False,
        "authorizes_host_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }


def require_native_host_preconditions() -> dict[str, Any]:
    """Require PID 1 namespace equality for standalone native observations."""
    return _require_host_context(service_mount_view=False)


def require_socket_worker_host_preconditions() -> dict[str, Any]:
    """Check the fixed service view without treating it as host attestation."""
    return _require_host_context(service_mount_view=True)
