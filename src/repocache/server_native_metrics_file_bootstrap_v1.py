"""Fixture-only inode-owned, private NGINX metrics file provisioning (#29).

Separate installed host root worker, authentication, SELinux, logrotate
transaction and service validation remain mandatory. This module cannot be
called against the current namespace's '/'.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
import stat
from typing import Any, Callable

from repocache.server_native_repository_cache_v1 import _read_record
from repocache.server_native_storage_bootstrap_v1 import (
    _LEAF, _canonical, _no_unverified_xattrs, _proof, _read_marker,
    _structural,
)
from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _identity, _recheck, _safe_directory, _walk,
)

_PARENT = ("var", "log", "nginx")
_FILE = "metrics.jsonl"
_MARKER = ".repocache-metrics-log.owner-v1"
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
           | getattr(os, "O_CLOEXEC", 0))
_READ = (os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
         | getattr(os, "O_CLOEXEC", 0))


class NativeMetricsBootstrapError(ValueError):
    """Non-disclosing, fixed-code refusal."""


def _deny(code: str) -> None:
    raise NativeMetricsBootstrapError("NATIVE_METRICS_" + code)


def _existing(log_dir: int, owner_dir: int, owner_uid: int,
              owner_gid: int) -> dict[str, int]:
    fd = os.open(_FILE, _READ, dir_fd=log_dir)
    try:
        _no_unverified_xattrs(fd)
        before = os.fstat(fd)
        named = os.stat(_FILE, dir_fd=log_dir, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != owner_uid or before.st_gid != owner_gid
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_dev != os.fstat(log_dir).st_dev
                or _identity(before) != _identity(named)):
            _deny("FILE_UNTRUSTED")
        expected = {"schema": 1, "kind": "metrics-log", **_proof(before)}
        if _read_record(owner_dir, _MARKER, owner_uid, owner_gid) != expected:
            _deny("MARKER_MISMATCH")
        if (_identity(os.fstat(fd)) != _identity(before)
                or _identity(os.stat(
                    _FILE, dir_fd=log_dir, follow_symlinks=False
                )) != _identity(before)):
            _deny("FILE_CHANGED")
        return expected
    finally:
        os.close(fd)


def bootstrap_private_metrics_file_under_root(
    root_fd: int, *, owner_uid: int, owner_gid: int,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Create or verify a fixed log inode and protected marker in a fixture.

    A missing file alongside an existing marker, or an unmarked pre-existing
    file, is a *hard stop*. No adoption, truncation, deletion or chmod repair.
    """
    if (type(root_fd) is not int or root_fd < 0
            or any(type(v) is not int or not 0 <= v <= 2**32 - 2
                   for v in (owner_uid, owner_gid))
            or (inject_fault is not None and not callable(inject_fault))):
        _deny("ARGUMENT_INVALID")
    try:
        actual = os.stat("/", follow_symlinks=False)
        supplied = os.fstat(root_fd)
        if (supplied.st_dev, supplied.st_ino) == (actual.st_dev, actual.st_ino):
            _deny("LIVE_ROOT_FORBIDDEN")
        with ExitStack() as stack:
            _safe_directory(root_fd, owner_uid)
            parent_fd, ancestry = _walk(root_fd, _PARENT, stack, owner_uid)
            parent = _safe_directory(parent_fd, owner_uid)
            _no_unverified_xattrs(parent_fd)
            if parent.st_gid != owner_gid:
                _deny("PARENT_UNTRUSTED")
            log_fd = os.open(_LEAF, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            stack.callback(os.close, log_fd)
            root = os.fstat(log_fd)
            if (not stat.S_ISDIR(root.st_mode)
                    or root.st_uid != owner_uid
                    or root.st_gid != owner_gid
                    or stat.S_IMODE(root.st_mode) != 0o750
                    or root.st_dev != parent.st_dev
                    or _structural(root) != _structural(
                        os.stat(_LEAF, dir_fd=parent_fd,
                                follow_symlinks=False)
                    ) or _read_marker(parent_fd, root_uid=owner_uid) != {
                        "schema": 1, "kind": "log", **_proof(root)
                    }):
                _deny("LOG_ROOT_UNTRUSTED")
            _no_unverified_xattrs(log_fd)
            try:
                os.stat(_FILE, dir_fd=log_fd, follow_symlinks=False)
                file_present = True
            except FileNotFoundError:
                file_present = False
            try:
                os.stat(_MARKER, dir_fd=parent_fd, follow_symlinks=False)
                marker_present = True
            except FileNotFoundError:
                marker_present = False
            if file_present != marker_present:
                _deny("PARTIAL_OR_FOREIGN_FILE")
            created = not file_present
            if created:
                new_fd = os.open(_FILE, _CREATE, 0o600, dir_fd=log_fd)
                try:
                    os.fchmod(new_fd, 0o600)
                    os.fsync(new_fd)
                finally:
                    os.close(new_fd)
                os.fsync(log_fd)
                if inject_fault is not None:
                    inject_fault("log_file_durable")
                current = os.stat(
                    _FILE, dir_fd=log_fd, follow_symlinks=False,
                )
                if (not stat.S_ISREG(current.st_mode)
                        or current.st_uid != owner_uid
                        or current.st_gid != owner_gid
                        or stat.S_IMODE(current.st_mode) != 0o600
                        or current.st_nlink != 1 or current.st_size != 0
                        or current.st_dev != root.st_dev):
                    _deny("NEW_FILE_UNTRUSTED")
                body = _canonical({
                    "schema": 1, "kind": "metrics-log", **_proof(current),
                })
                marker_fd = os.open(_MARKER, _CREATE, 0o600,
                                    dir_fd=parent_fd)
                try:
                    os.fchmod(marker_fd, 0o600)
                    if os.write(marker_fd, body) != len(body):
                        _deny("MARKER_WRITE_INCOMPLETE")
                    os.fsync(marker_fd)
                finally:
                    os.close(marker_fd)
                os.fsync(parent_fd)
                if inject_fault is not None:
                    inject_fault("log_marker_durable")
            proof = _existing(log_fd, parent_fd, owner_uid, owner_gid)
            if (_structural(os.fstat(log_fd))[:5] != _structural(root)[:5]
                    or _structural(os.fstat(parent_fd))[:5]
                       != _structural(parent)[:5]):
                _deny("ROOT_CHANGED")
            _recheck(ancestry[:-1], owner_uid)
        return {
            "schema_version": 1,
            "status": "PRIVATE_METRICS_FILE_FIXTURE_VERIFIED",
            "file_created": created,
            "existing_log_bytes_preserved": not created,
            "owned_file_inode": proof["ino"],
            "fixed_metrics_mode": "0600",
            "root_owned_marker_verified": True,
            "installed_host_root_authenticated": False,
            "selinux_enforcing_verified": False,
            "nginx_worker_access_verified": False,
            "authorizes_host_installation": False,
            "authorizes_nginx_reload": False,
            "authorizes_logrotate_installation": False,
            "authorizes_log_cleanup": False,
        }
    except NativeMetricsBootstrapError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        _deny("OBSERVATION_UNVERIFIED")
