"""Fixed, durable, fixture-bound bootstrap of the #31 protected state lock.

This mutates a passed-in isolated Linux root directory; it is NOT a public
installer, trusted host-root entry point or OS authorization mechanism.
A future signed privileged installer must independently authenticate its
root namespace/manifest before calling any state mutation.
"""
from __future__ import annotations

from contextlib import ExitStack
import fcntl
import os
import stat
from typing import Any, Callable

from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _identity, _recheck, _safe_directory, _walk,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME, _locked

_PARENT = ("var", "lib")
_ROOT_NAME = "repocache"
_STATE_NAME = "server"
_DIRECTORY_MODE = 0o700
_LOCK_MODE = 0o600
_CREATE_LOCK = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0))


class ProtectedBootstrapError(ValueError):
    """Static error codes only, no caller values or filesystem paths."""


def _deny(code: str) -> None:
    raise ProtectedBootstrapError("PROTECTED_BOOTSTRAP_" + code)


def _structural(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink)


def _verified_directory(parent_fd: int, name: str, expected_uid: int,
                        stack: ExitStack, *, mode: int) -> tuple[int, tuple[int, ...]]:
    """Pin one existing strict root-owned component and reject races/links."""
    before = os.fstat(parent_fd)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    stack.callback(os.close, fd)
    pinned = os.fstat(fd)
    again = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(pinned.st_mode)
            or pinned.st_uid != expected_uid or pinned.st_gid != os.fstat(parent_fd).st_gid
            or stat.S_IMODE(pinned.st_mode) != mode
            or pinned.st_dev != before.st_dev
            or _structural(named) != _structural(pinned)
            or _structural(again) != _structural(pinned)
            or _structural(before) != _structural(os.fstat(parent_fd))):
        _deny("OWNERSHIP_OR_MOUNT_UNVERIFIED")
    return fd, _structural(pinned)


def _lock_identity(directory_fd: int, uid: int) -> tuple[int, ...]:
    fd = os.open(LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                 getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    try:
        pinned = os.fstat(fd)
        named = os.stat(LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISREG(pinned.st_mode) or pinned.st_uid != uid
                or pinned.st_gid != os.fstat(directory_fd).st_gid
                or stat.S_IMODE(pinned.st_mode) != _LOCK_MODE
                or pinned.st_nlink != 1 or pinned.st_size != 0
                or pinned.st_dev != os.fstat(directory_fd).st_dev
                or _identity(pinned) != _identity(named)):
            _deny("LOCK_UNTRUSTED")
        return _structural(pinned)
    finally:
        os.close(fd)


def bootstrap_protected_namespace_under_root(
    root_fd: int, *, owner_uid: int,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Create ONLY /var/lib/repocache/server and its fixed lock in a fixture.

    Existing complete structure is verified, never replaced. Interrupted
    *incomplete* installation is refused, not silently adopted or cleaned.
    Caller-provided root FDs and UIDs are not proof of root or approval.
    No OS package, server state, NGINX, service, cache or TLS is modified.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or not 0 <= owner_uid <= 2**32 - 2
            or (inject_fault is not None and not callable(inject_fault))):
        _deny("ARGUMENT_INVALID")
    try:
        with ExitStack() as stack:
            lib_fd, chain = _walk(root_fd, _PARENT, stack, owner_uid)
            # Existing /var/lib is an owned, non-world-writable native anchor.
            lib_before = _structural(_safe_directory(lib_fd, owner_uid))
            try:
                os.stat(_ROOT_NAME, dir_fd=lib_fd, follow_symlinks=False)
                fresh = False
            except FileNotFoundError:
                fresh = True
                os.mkdir(_ROOT_NAME, mode=_DIRECTORY_MODE, dir_fd=lib_fd)
                os.fsync(lib_fd)
                if inject_fault is not None:
                    inject_fault("root_dir_durable")
            repocache_fd, _ = _verified_directory(
                lib_fd, _ROOT_NAME, owner_uid, stack, mode=_DIRECTORY_MODE,
            )
            if fresh:
                # A concurrent parent or preexisting child never becomes
                # an implicit third-party adoption.
                os.mkdir(_STATE_NAME, mode=_DIRECTORY_MODE, dir_fd=repocache_fd)
                os.fsync(repocache_fd)
                if inject_fault is not None:
                    inject_fault("state_dir_durable")
            state_fd, state_initial = _verified_directory(
                repocache_fd, _STATE_NAME, owner_uid, stack, mode=_DIRECTORY_MODE,
            )
            if fresh:
                fd = os.open(LOCK_NAME, _CREATE_LOCK, _LOCK_MODE, dir_fd=state_fd)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(state_fd)
                if inject_fault is not None:
                    inject_fault("lock_durable")
            lock = _lock_identity(state_fd, owner_uid)
            if (_structural(os.fstat(state_fd)) != state_initial
                    or _structural(_safe_directory(lib_fd, owner_uid)) != lib_before):
                _deny("ANCESTRY_CHANGED")
            _recheck(chain[:-1], owner_uid)
            # Use exactly the real #31 state lock/identity checks; a second
            # writer cannot skip the existing serialized state boundary.
            with _locked(root_fd, owner_uid):
                if _lock_identity(state_fd, owner_uid) != lock:
                    _deny("LOCK_CHANGED")
            return {
                "schema_version": 1,
                "status": ("FRESH_PROTECTED_LOCK_DURABLE"
                           if fresh else "EXISTING_PROTECTED_LOCK_VALIDATED"),
                "state_directory_created": fresh,
                "state_lock_validated": True,
                "host_root_provenance_authenticated": False,
                "operator_authorization_authenticated": False,
                "installed_release_authenticated": False,
                "authorizes_installation": False,
                "authorizes_state_write": False,
                "authorizes_nginx_activation": False,
            }
    except ProtectedBootstrapError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("UNVERIFIED_STATE")
