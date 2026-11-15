"""Fixture-scoped, durable ownership of fixed native NGINX cache and log roots.

This internal primitive is NOT a host installer or delegated root entry point.
It accepts an already authenticated *fixture* root descriptor and numeric
owners. A future signed host installer must independently prove actual root
namespace, operator, trusted NGINX package UID/GID, SELinux and state WAL.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
import os
import stat
from typing import Any, Callable

from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _identity, _recheck, _safe_directory, _walk,
)

_CACHE_PARENT = ("var", "cache", "nginx")
_LOG_PARENT = ("var", "log", "nginx")
_LEAF = "repocache-managed"
_MARKER = ".repocache-managed.owner-v1"
_MAX_MARKER = 1024
_READ = (os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
         | getattr(os, "O_CLOEXEC", 0))
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
           | getattr(os, "O_CLOEXEC", 0))


class NativeStorageBootstrapError(ValueError):
    """Redacted, non-path-containing refusal codes."""


def _deny(code: str) -> None:
    raise NativeStorageBootstrapError("NATIVE_STORAGE_" + code)


def _structural(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode,
            value.st_uid, value.st_gid, value.st_nlink)


def _proof(value: os.stat_result) -> dict[str, int]:
    return {
        "dev": value.st_dev, "ino": value.st_ino,
        "uid": value.st_uid, "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
    }


def _no_unverified_xattrs(fd: int) -> None:
    # POSIX ACLs, security.selinux, capabilities and unknown xattr namespaces
    # require explicit native policy and preservation. No implicit adoption.
    try:
        if os.listxattr(fd):
            _deny("XATTR_OR_SELINUX_UNVERIFIED")
    except OSError:
        _deny("XATTR_OR_SELINUX_UNVERIFIED")


def _read_marker(fd: int, *, root_uid: int) -> dict[str, Any]:
    opened = os.open(_MARKER, _READ, dir_fd=fd)
    try:
        _no_unverified_xattrs(opened)
        before = os.fstat(opened)
        named = os.stat(_MARKER, dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != root_uid or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 1 <= before.st_size <= _MAX_MARKER
                or _identity(before) != _identity(named)
                or before.st_dev != os.fstat(fd).st_dev):
            _deny("MARKER_UNTRUSTED")
        content = bytearray()
        while len(content) <= _MAX_MARKER:
            part = os.read(opened, _MAX_MARKER + 1 - len(content))
            if not part:
                break
            content.extend(part)
        if len(content) != before.st_size:
            _deny("MARKER_CHANGED")
        try:
            parsed = json.loads(bytes(content).decode("ascii"),
                                object_pairs_hook=_unique)
        except (UnicodeError, ValueError, TypeError):
            _deny("MARKER_INVALID")
        if (type(parsed) is not dict
                or set(parsed) != {"schema", "kind", "dev", "ino",
                                   "uid", "gid", "mode"}
                or parsed.get("schema") != 1
                or type(parsed.get("schema")) is not int
                or any(type(parsed[key]) is not int or parsed[key] < 0
                       for key in ("dev", "ino", "uid", "gid", "mode"))
                or bytes(content) != _canonical(parsed)
                or _identity(before) != _identity(os.fstat(opened))
                or _identity(before) != _identity(os.stat(
                    _MARKER, dir_fd=fd, follow_symlinks=False
                ))):
            _deny("MARKER_INVALID")
        return parsed
    finally:
        os.close(opened)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def _precheck_one(root_fd: int, stack: ExitStack, *,
                  kind: str, segments: tuple[str, ...],
                  root_uid: int, desired_uid: int, desired_gid: int,
                  mode: int) -> None:
    """Read-only two-root preflight, before the first mkdir or owner write.

    A later pre-existing foreign log/cache root must not leave the other
    root partially provisioned. This is not a substitute for the normal
    *second* open/recheck during mutation (which handles concurrent swaps).
    """
    parent_fd, ancestry = _walk(root_fd, segments, stack, root_uid)
    parent = _safe_directory(parent_fd, root_uid)
    _no_unverified_xattrs(parent_fd)
    parent_identity = _structural(parent)
    try:
        os.stat(_LEAF, dir_fd=parent_fd, follow_symlinks=False)
        leaf_present = True
    except FileNotFoundError:
        leaf_present = False
    try:
        os.stat(_MARKER, dir_fd=parent_fd, follow_symlinks=False)
        marker_present = True
    except FileNotFoundError:
        marker_present = False
    if leaf_present != marker_present:
        _deny("PARTIAL_OR_FOREIGN_ROOT")
    if leaf_present:
        leaf_fd = os.open(_LEAF, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        stack.callback(os.close, leaf_fd)
        _no_unverified_xattrs(leaf_fd)
        leaf = os.fstat(leaf_fd)
        named = os.stat(_LEAF, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(leaf.st_mode)
                or leaf.st_uid != desired_uid or leaf.st_gid != desired_gid
                or stat.S_IMODE(leaf.st_mode) != mode
                or leaf.st_dev != parent.st_dev
                or _structural(leaf) != _structural(named)):
            _deny("ROOT_UNTRUSTED")
        if _read_marker(parent_fd, root_uid=root_uid) != {
            "schema": 1, "kind": kind, **_proof(leaf),
        }:
            _deny("MARKER_MISMATCH")
        if (_structural(os.fstat(leaf_fd)) != _structural(
                os.stat(_LEAF, dir_fd=parent_fd, follow_symlinks=False)
        )):
            _deny("ROOT_CHANGED")
    if _structural(_safe_directory(parent_fd, root_uid)) != parent_identity:
        _deny("ROOT_CHANGED")
    _recheck(ancestry, root_uid)


def _ensure_one(root_fd: int, stack: ExitStack, *,
                kind: str, segments: tuple[str, ...],
                root_uid: int, desired_uid: int, desired_gid: int,
                mode: int, inject_fault: Callable[[str], None] | None
                ) -> bool:
    parent_fd, ancestry = _walk(root_fd, segments, stack, root_uid)
    parent = _safe_directory(parent_fd, root_uid)
    _no_unverified_xattrs(parent_fd)
    original = _structural(parent)
    try:
        os.stat(_LEAF, dir_fd=parent_fd, follow_symlinks=False)
        leaf_exists = True
    except FileNotFoundError:
        leaf_exists = False
    try:
        os.stat(_MARKER, dir_fd=parent_fd, follow_symlinks=False)
        marker_exists = True
    except FileNotFoundError:
        marker_exists = False
    if leaf_exists != marker_exists:
        _deny("PARTIAL_OR_FOREIGN_ROOT")
    fresh = not leaf_exists
    if fresh:
        # The trusted root-owned parent is not writable by the worker.
        # Any crash between mkdir and durable owner marker fails closed
        # on re-entry; there is deliberately no recursive deletion.
        os.mkdir(_LEAF, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        if inject_fault is not None:
            inject_fault(kind + "_directory_durable")

    leaf_fd = os.open(_LEAF, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    stack.callback(os.close, leaf_fd)
    if fresh:
        os.fchown(leaf_fd, desired_uid, desired_gid)
        os.fchmod(leaf_fd, mode)
        os.fsync(leaf_fd)
        os.fsync(parent_fd)
        if inject_fault is not None:
            inject_fault(kind + "_ownership_durable")

    _no_unverified_xattrs(leaf_fd)
    target = os.fstat(leaf_fd)
    named = os.stat(_LEAF, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(target.st_mode)
            or target.st_uid != desired_uid or target.st_gid != desired_gid
            or stat.S_IMODE(target.st_mode) != mode
            or target.st_dev != parent.st_dev
            or _structural(target) != _structural(named)):
        _deny("ROOT_UNTRUSTED")
    evidence = {"schema": 1, "kind": kind, **_proof(target)}
    if fresh:
        payload = _canonical(evidence)
        descriptor = os.open(_MARKER, _CREATE, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(descriptor, 0o600)
            written = os.write(descriptor, payload)
            if written != len(payload):
                _deny("MARKER_WRITE_INCOMPLETE")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
        if inject_fault is not None:
            inject_fault(kind + "_marker_durable")
    elif _read_marker(parent_fd, root_uid=root_uid) != evidence:
        _deny("MARKER_MISMATCH")
    if _read_marker(parent_fd, root_uid=root_uid) != evidence:
        _deny("MARKER_CHANGED")
    if (_structural(os.fstat(leaf_fd))
            != _structural(os.stat(
                _LEAF, dir_fd=parent_fd, follow_symlinks=False,
            )) or _structural(_safe_directory(parent_fd, root_uid))[:5]
               != original[:5]):
        _deny("ROOT_CHANGED")
    # Only the immediate root-owned parent may change metadata due to our
    # own creation; all higher ancestors must retain full identities.
    _recheck(ancestry[:-1], root_uid)
    return fresh


def bootstrap_native_nginx_storage_under_root(
    root_fd: int, *, root_uid: int, cache_uid: int, cache_gid: int,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Create fixed cache+log roots with persistent external ownership markers.

    All paths are constants, not operator input. Without independently
    authenticated host-root, package identity and SELinux, no production
    code may invoke this function. It does not install, reload or start NGINX.
    """
    ids = (root_uid, cache_uid, cache_gid)
    if (type(root_fd) is not int or root_fd < 0
            or any(type(v) is not int or not 0 <= v <= 2**32 - 2
                   for v in ids)
            or (inject_fault is not None and not callable(inject_fault))):
        _deny("ARGUMENT_INVALID")
    try:
        # A caller-supplied FD is never authorization to change the host.
        # This module is deliberately limited to detached fixture roots.
        # A separately reviewed installed worker must use its own signed,
        # authenticated host entry and must not reuse this fixture API.
        opened_root = os.fstat(root_fd)
        namespace_root = os.stat("/", follow_symlinks=False)
        if (opened_root.st_dev, opened_root.st_ino) == (
                namespace_root.st_dev, namespace_root.st_ino):
            _deny("LIVE_ROOT_FORBIDDEN")
        with ExitStack() as stack:
            _safe_directory(root_fd, root_uid)
            # Refuse a conflicting existing cache OR log root before any
            # creation/chown, so failure on the second cannot half-provision
            # the first. _ensure_one revalidates after this inspection.
            for kind, segments, uid, gid, mode in (
                ("cache", _CACHE_PARENT, cache_uid, cache_gid, 0o700),
                ("log", _LOG_PARENT, root_uid, os.fstat(root_fd).st_gid, 0o750),
            ):
                _precheck_one(
                    root_fd, stack, kind=kind, segments=segments,
                    root_uid=root_uid, desired_uid=uid,
                    desired_gid=gid, mode=mode,
                )
            cache_fresh = _ensure_one(
                root_fd, stack, kind="cache", segments=_CACHE_PARENT,
                root_uid=root_uid, desired_uid=cache_uid,
                desired_gid=cache_gid, mode=0o700,
                inject_fault=inject_fault,
            )
            log_fresh = _ensure_one(
                root_fd, stack, kind="log", segments=_LOG_PARENT,
                root_uid=root_uid, desired_uid=root_uid,
                desired_gid=os.fstat(root_fd).st_gid, mode=0o750,
                inject_fault=inject_fault,
            )
        return {
            "schema_version": 1,
            "status": "FIXED_NATIVE_STORAGE_FIXTURE_VERIFIED",
            "cache_directory_created": cache_fresh,
            "log_directory_created": log_fresh,
            "existing_cache_contents_preserved": not cache_fresh,
            "existing_log_contents_preserved": not log_fresh,
            "signed_nginx_package_identity_verified": False,
            "selinux_enforcing_verified": False,
            "host_root_provenance_verified": False,
            "operator_authorization_verified": False,
            "authorizes_host_installation": False,
            "authorizes_nginx_activation": False,
            "authorizes_cache_cleanup": False,
        }
    except NativeStorageBootstrapError:
        raise
    except (OSError, ValueError, TypeError, OverflowError):
        _deny("UNVERIFIED_STATE")
