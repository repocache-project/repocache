"""Fixture-scoped per-repository native NGINX cache ownership (#29/#95).

This is a real descriptor-relative filesystem primitive for detached test
roots, NOT an installed root writer. The enclosing cache root must already
be bootstrapped with its root-owned fixed marker. The protected parent,
not the NGINX-writable cache root, holds each repository's inode marker.

No repository removal, cache deletion, service action or catalog publishing
is implemented. The future authenticated #31 transaction must bind repository
IDs and all-time history to protected state, install-time NGINX ownership,
SELinux contexts and native root privilege before any production use.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
import os
import stat
from typing import Any, Callable

from repocache.server_install_v1 import ID
from repocache.server_native_storage_bootstrap_v1 import (
    _CACHE_PARENT, _LEAF, _canonical, _no_unverified_xattrs,
    _proof, _read_marker, _structural, _unique,
)
from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _identity, _recheck, _safe_directory, _walk,
)

_MAX_MARKER = 512
_READ = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
         | getattr(os, "O_CLOEXEC", 0))
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
           | getattr(os, "O_CLOEXEC", 0))


class RepositoryCacheBootstrapError(ValueError):
    """Stable redacted failures, never paths, package names or cache bytes."""


def _deny(code: str) -> None:
    raise RepositoryCacheBootstrapError("REPOSITORY_CACHE_" + code)


def _marker_name(repository_id: str) -> str:
    return ".repocache-repository-" + repository_id + ".owner-v1"


def _present(directory_fd: int, leaf: str) -> bool:
    try:
        os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _read_record(parent_fd: int, marker: str, root_uid: int,
                 root_gid: int) -> dict[str, Any]:
    """Read only one pinned root-owned marker in the non-worker parent."""
    fd = os.open(marker, _READ, dir_fd=parent_fd)
    try:
        _no_unverified_xattrs(fd)
        before = os.fstat(fd)
        named = os.stat(marker, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != root_uid or before.st_gid != root_gid
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_dev != os.fstat(parent_fd).st_dev
                or not 1 <= before.st_size <= _MAX_MARKER
                or _identity(before) != _identity(named)):
            _deny("MARKER_UNTRUSTED")
        raw = os.read(fd, _MAX_MARKER + 1)
        if (len(raw) != before.st_size
                or _identity(os.fstat(fd)) != _identity(before)
                or _identity(os.stat(marker, dir_fd=parent_fd,
                                    follow_symlinks=False)) != _identity(before)):
            _deny("MARKER_CHANGED")
        try:
            value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique)
        except (ValueError, UnicodeError, TypeError, RecursionError):
            _deny("MARKER_INVALID")
        if (type(value) is not dict
                or raw != _canonical(value)):
            _deny("MARKER_INVALID")
        return value
    finally:
        os.close(fd)


def _snapshot(parent_fd: int, cache_fd: int, repository_id: str, *,
              root_uid: int, cache_uid: int, cache_gid: int
              ) -> tuple[bool, dict[str, Any] | None]:
    """An existing cache is adopted only with exact externally pinned identity."""
    marker = _marker_name(repository_id)
    exists = _present(cache_fd, repository_id)
    marked = _present(parent_fd, marker)
    if exists != marked:
        _deny("PARTIAL_OR_FOREIGN_DIRECTORY")
    if not exists:
        return False, None
    fd = os.open(repository_id, _DIRECTORY_FLAGS, dir_fd=cache_fd)
    try:
        _no_unverified_xattrs(fd)
        info = os.fstat(fd)
        named = os.stat(repository_id, dir_fd=cache_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode)
                or info.st_uid != cache_uid or info.st_gid != cache_gid
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_dev != os.fstat(cache_fd).st_dev
                or _structural(info) != _structural(named)):
            _deny("DIRECTORY_UNTRUSTED")
        expected = {
            "schema": 1, "kind": "repository-cache",
            "repository_id": repository_id, **_proof(info),
        }
        if _read_record(
            parent_fd, marker, root_uid, os.fstat(parent_fd).st_gid
        ) != expected:
            _deny("MARKER_MISMATCH")
        if _structural(os.fstat(fd)) != _structural(
            os.stat(repository_id, dir_fd=cache_fd, follow_symlinks=False)
        ):
            _deny("DIRECTORY_CHANGED")
        return True, expected
    finally:
        os.close(fd)


def bootstrap_repository_cache_under_root(
    root_fd: int, *, root_uid: int, cache_uid: int, cache_gid: int,
    repository_id: str, inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Durably create or verify one isolated repository directory in a fixture.

    Caller-selected IDs are *only* validated path components, not approvals.
    A root-owned parent marker protects the directory identity from the
    NGINX-writable cache root. All existing package bytes are retained.
    A crash between mkdir and marker is a hard stop, never auto-cleaned.
    """
    if (type(root_fd) is not int or root_fd < 0
            or any(type(v) is not int or not 0 <= v <= 2**32 - 2
                   for v in (root_uid, cache_uid, cache_gid))
            or type(repository_id) is not str
            or ID.fullmatch(repository_id) is None
            or (inject_fault is not None and not callable(inject_fault))):
        _deny("ARGUMENT_INVALID")
    try:
        opened = os.fstat(root_fd)
        native_root = os.stat("/", follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) == (
            native_root.st_dev, native_root.st_ino
        ):
            _deny("LIVE_ROOT_FORBIDDEN")
        with ExitStack() as stack:
            _safe_directory(root_fd, root_uid)
            parent_fd, ancestry = _walk(
                root_fd, _CACHE_PARENT, stack, root_uid,
            )
            parent = _safe_directory(parent_fd, root_uid)
            _no_unverified_xattrs(parent_fd)
            cache_fd = os.open(_LEAF, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            stack.callback(os.close, cache_fd)
            _no_unverified_xattrs(cache_fd)
            cache = os.fstat(cache_fd)
            named = os.stat(_LEAF, dir_fd=parent_fd, follow_symlinks=False)
            if (not stat.S_ISDIR(cache.st_mode)
                    or cache.st_uid != cache_uid
                    or cache.st_gid != cache_gid
                    or stat.S_IMODE(cache.st_mode) != 0o700
                    or cache.st_dev != parent.st_dev
                    or _structural(cache) != _structural(named)
                    or _read_marker(parent_fd, root_uid=root_uid) != {
                        "schema": 1, "kind": "cache", **_proof(cache),
                    }):
                _deny("CACHE_ROOT_UNTRUSTED")
            exists, _record = _snapshot(
                parent_fd, cache_fd, repository_id,
                root_uid=root_uid, cache_uid=cache_uid, cache_gid=cache_gid,
            )
            if not exists:
                # No destructive 'repair' on an ambiguous partial bootstrap.
                os.mkdir(repository_id, mode=0o700, dir_fd=cache_fd)
                os.fsync(cache_fd)
                if inject_fault:
                    inject_fault("directory_durable")
                repo_fd = os.open(repository_id, _DIRECTORY_FLAGS,
                                  dir_fd=cache_fd)
                try:
                    os.fchown(repo_fd, cache_uid, cache_gid)
                    os.fchmod(repo_fd, 0o700)
                    os.fsync(repo_fd)
                finally:
                    os.close(repo_fd)
                os.fsync(cache_fd)
                if inject_fault:
                    inject_fault("ownership_durable")
                # Build immutable ownership evidence from re-opened inodes.
                repo_fd = os.open(repository_id, _DIRECTORY_FLAGS,
                                  dir_fd=cache_fd)
                try:
                    observed = os.fstat(repo_fd)
                    record = {
                        "schema": 1, "kind": "repository-cache",
                        "repository_id": repository_id,
                        **_proof(observed),
                    }
                finally:
                    os.close(repo_fd)
                marker = _marker_name(repository_id)
                marker_fd = os.open(marker, _CREATE, 0o600, dir_fd=parent_fd)
                try:
                    os.fchmod(marker_fd, 0o600)
                    payload = _canonical(record)
                    if len(payload) > _MAX_MARKER:
                        _deny("MARKER_OVERSIZE")
                    if os.write(marker_fd, payload) != len(payload):
                        _deny("MARKER_WRITE_FAILED")
                    os.fsync(marker_fd)
                finally:
                    os.close(marker_fd)
                os.fsync(parent_fd)
                if inject_fault:
                    inject_fault("marker_durable")
            repeated, _ = _snapshot(
                parent_fd, cache_fd, repository_id,
                root_uid=root_uid, cache_uid=cache_uid, cache_gid=cache_gid,
            )
            if not repeated:
                _deny("DIRECTORY_CHANGED")
            if (_structural(os.fstat(cache_fd))[:5]
                    != _structural(cache)[:5]
                    or _structural(os.fstat(parent_fd))[:5]
                       != _structural(parent)[:5]):
                _deny("ANCESTOR_CHANGED")
            # The immediate parent is mutated only by our own marker; higher
            # ancestors must retain complete trusted descriptor identities.
            _recheck(ancestry[:-1], root_uid)
        return {
            "schema_version": 1,
            "status": "FIXTURE_REPOSITORY_CACHE_VERIFIED",
            "repository_id": repository_id,
            "directory_created": not exists,
            "existing_cache_contents_preserved": exists,
            "root_owned_identity_marker_verified": True,
            "trusted_repository_approval_verified": False,
            "signed_nginx_package_identity_verified": False,
            "selinux_enforcing_verified": False,
            "host_root_provenance_verified": False,
            "authorizes_host_installation": False,
            "authorizes_nginx_activation": False,
            "authorizes_cache_cleanup": False,
        }
    except RepositoryCacheBootstrapError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        _deny("UNVERIFIED_STATE")
