"""Descriptor-pinned, read-only cache free-space observation for #97.

This is a bounded Linux filesystem observation, not NGINX cache telemetry,
storage ownership authorization, installer, cleanup, source writer or service.
A named cache path is never accepted from a client or JSON document.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
import stat
from typing import Any

from repocache.server_cache_pressure_policy_v1 import (
    MAX_INT, preview_cache_pressure,
)
from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _identity, _recheck, _safe_directory, _walk,
)

_CACHE_PARENT = ("var", "cache", "nginx")
_CACHE_LEAF = "repocache-managed"


def _valid_uid(uid: Any) -> bool:
    return type(uid) is int and 0 <= uid <= 2**32 - 2


def _capacity(fd: int) -> tuple[int, int]:
    """Read free bytes and inodes from the *opened* inode, never a path."""
    info = os.fstatvfs(fd)
    values = (info.f_frsize, info.f_bavail, info.f_favail)
    if (any(type(v) is not int or v < 0 for v in values)
            or not 0 < info.f_frsize <= MAX_INT
            or info.f_bavail > MAX_INT // info.f_frsize
            or info.f_favail > MAX_INT):
        raise ValueError("CACHE_CAPACITY_UNVERIFIED")
    return info.f_bavail * info.f_frsize, info.f_favail


def _observe_under_root(root_fd: int, *, root_uid: int, cache_uid: int
                        ) -> tuple[int, int]:
    """Testable read-only seam; caller FD/UIDs do not authenticate host root.

    A future installed probe must obtain the real host root descriptor,
    independently prove signed ownership and reviewed UID policy. No caller
    may treat a result of this function as authorization for a write.
    """
    if (type(root_fd) is not int or root_fd < 0
            or not _valid_uid(root_uid) or not _valid_uid(cache_uid)):
        raise ValueError("CACHE_OBSERVATION_ARGUMENT_INVALID")
    with ExitStack() as stack:
        _safe_directory(root_fd, root_uid)
        parent_fd, recorded = _walk(
            root_fd, _CACHE_PARENT, stack, root_uid,
        )
        parent_before = _identity(_safe_directory(parent_fd, root_uid))
        leaf_before = os.stat(
            _CACHE_LEAF, dir_fd=parent_fd, follow_symlinks=False,
        )
        leaf_fd = os.open(_CACHE_LEAF, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        stack.callback(os.close, leaf_fd)
        leaf = os.fstat(leaf_fd)
        if (not stat.S_ISDIR(leaf.st_mode)
                or leaf.st_uid != cache_uid
                or stat.S_IMODE(leaf.st_mode) & 0o022
                or leaf.st_dev != os.fstat(parent_fd).st_dev
                or _identity(leaf_before) != _identity(leaf)):
            raise ValueError("CACHE_ROOT_UNTRUSTED")
        free_bytes, free_inodes = _capacity(leaf_fd)
        if (_identity(os.fstat(leaf_fd)) != _identity(leaf)
                or _identity(os.stat(
                    _CACHE_LEAF, dir_fd=parent_fd, follow_symlinks=False,
                )) != _identity(leaf)
                or _identity(_safe_directory(parent_fd, root_uid))
                   != parent_before):
            raise ValueError("CACHE_ROOT_CHANGED")
        _recheck(recorded, root_uid)
    return free_bytes, free_inodes


def observe_cache_pressure_under_root(
    root_fd: int, *,
    root_uid: int,
    cache_uid: int,
    warning_free_bytes: int,
    critical_free_bytes: int,
    recovery_margin_bytes: int,
    previous_level: str,
) -> dict[str, Any]:
    """Return redacted partial policy classification from a real statvfs.

    This deliberately cannot assert a healthy/normal cache because file mode,
    NGINX writability, SELinux, active cache occupancy, and cache-manager
    state cannot be inferred from POSIX filesystem free-space counters.
    """
    # Validate all operator policy values before any host observation.
    fallback = preview_cache_pressure(
        free_bytes=None,
        warning_free_bytes=warning_free_bytes,
        critical_free_bytes=critical_free_bytes,
        recovery_margin_bytes=recovery_margin_bytes,
        previous_level=previous_level,
        measurements_complete=False,
        disk_writable=None,
    )
    try:
        free_bytes, free_inodes = _observe_under_root(
            root_fd, root_uid=root_uid, cache_uid=cache_uid,
        )
    except (OSError, ValueError):
        return {
            **fallback,
            "status": "READ_ONLY_CACHE_PRESSURE_PARTIAL",
            "observation_code": "CACHE_ROOT_OR_CAPACITY_UNVERIFIED",
            "free_inodes_observed": None,
            "cache_root_ownership_observed": False,
            "authorizes_installation": False,
        }
    observed = preview_cache_pressure(
        free_bytes=free_bytes,
        warning_free_bytes=warning_free_bytes,
        critical_free_bytes=critical_free_bytes,
        recovery_margin_bytes=recovery_margin_bytes,
        previous_level=previous_level,
        measurements_complete=False,
        disk_writable=None,
    )
    if free_inodes == 0:
        observed["pressure_level"] = "critical"
        observed["reason_code"] = "FILESYSTEM_INODES_EXHAUSTED"
    return {
        **observed,
        "status": "READ_ONLY_CACHE_PRESSURE_PARTIAL",
        "observation_code": "FIXED_CACHE_FREE_SPACE_OBSERVED",
        "free_inodes_observed": free_inodes,
        "cache_root_ownership_observed": True,
        "authorizes_installation": False,
    }


def inspect_default_cache_pressure(*, warning_free_bytes: int,
                                   critical_free_bytes: int,
                                   recovery_margin_bytes: int,
                                   previous_level: str) -> dict[str, Any]:
    """Read fixed host namespace; do not infer UID of packaged NGINX user.

    Without independently reviewed operator-owned cache UID/manifest, the
    default probe requires UID 0 at the leaf, and otherwise returns unknown.
    It never adjusts permissions or attempts to make paths writable.
    """
    root = os.open("/", _DIRECTORY_FLAGS)
    try:
        return observe_cache_pressure_under_root(
            root, root_uid=0, cache_uid=0,
            warning_free_bytes=warning_free_bytes,
            critical_free_bytes=critical_free_bytes,
            recovery_margin_bytes=recovery_margin_bytes,
            previous_level=previous_level,
        )
    finally:
        os.close(root)
