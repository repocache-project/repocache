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
from typing import Any

# Exact Linux initial user namespace mapping, not a subordinate/rootless map.
_INITIAL_UID_MAP = b"         0          0 4294967295\n"
_PROC_MAX = 128


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


def _same_namespace(kind: str) -> None:
    """Compare namespace kernel inodes; textual links are not authority."""
    if kind not in ("mnt", "user", "pid"):
        _deny("NAMESPACE_KIND_REFUSED")
    try:
        initial = os.stat("/proc/1/ns/" + kind)
        worker = os.stat("/proc/self/ns/" + kind)
        if (not stat.S_ISREG(initial.st_mode)
                or not stat.S_ISREG(worker.st_mode)
                or (initial.st_dev, initial.st_ino)
                   != (worker.st_dev, worker.st_ino)):
            _deny("NAMESPACE_DIFFERENT")
    except NativeHostPreflightError:
        raise
    except OSError:
        _deny("NAMESPACE_UNAVAILABLE")


def _root_identity() -> None:
    try:
        if (os.getuid() != 0 or os.geteuid() != 0
                or os.getresuid() != (0, 0, 0)
                or os.getgid() != 0 or os.getegid() != 0
                or os.getresgid() != (0, 0, 0)):
            _deny("INITIAL_ROOT_REQUIRED")
    except AttributeError:
        _deny("LINUX_CREDENTIALS_UNAVAILABLE")


def require_native_host_preconditions() -> dict[str, Any]:
    """Deny rootless/userns/foreign-PID1/booted-service mismatches.

    Passing is NOT authentication, a signed installation measurement or a
    permission to reload nginx. In particular, systemd PID1 inside a
    privileged container could satisfy these *necessary* checks.
    """
    _root_identity()
    if _read_proc("/proc/1/comm") != b"systemd\n":
        _deny("SYSTEMD_PID1_REQUIRED")
    for kind in ("mnt", "user", "pid"):
        _same_namespace(kind)
    if _read_proc("/proc/self/uid_map") != _INITIAL_UID_MAP:
        _deny("INITIAL_USER_NAMESPACE_REQUIRED")
    try:
        run = os.lstat("/run")
        systemd = os.lstat("/run/systemd")
        booted = os.lstat("/run/systemd/system")
    except OSError:
        _deny("SYSTEMD_RUNTIME_MISSING")
    for info in (run, systemd, booted):
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
            _deny("SYSTEMD_RUNTIME_UNSAFE")
    return {
        "schema_version": 1,
        "status": "NATIVE_HOST_NECESSARY_PRECONDITIONS_ONLY",
        "initial_root_credentials_observed": True,
        "initial_user_namespace_mapping_observed": True,
        "pid1_systemd_and_matching_namespaces_observed": True,
        "signed_installed_binary_verified": False,
        "effective_systemd_unit_verified": False,
        "selinux_acl_mount_ownership_verified": False,
        "host_root_provenance_verified": False,
        "authorizes_host_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }
