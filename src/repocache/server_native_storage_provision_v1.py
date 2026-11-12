"""Fixture-only fixed NGINX cache/log storage provisioning (#29).

Not a host installer: root_fd/UID/expected inodes are untrusted caller inputs.
No public entry point or authorization to mutate a native host exists.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
import stat
from typing import Any, Callable

from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _safe_directory, _walk, _recheck,
)

_TARGETS = (
    ("cache", ("var", "cache", "nginx"), "repocache-managed"),
    ("logs", ("var", "log", "nginx"), "repocache-managed"),
)
_MODE = 0o700
_KEYS = frozenset({"dev", "ino", "uid", "gid", "mode"})


class NativeStorageProvisionError(ValueError):
    """A static, redacted error code, never untrusted path text."""


def _fail(code: str) -> None:
    raise NativeStorageProvisionError("NATIVE_STORAGE_" + code)


def _record(info: os.stat_result) -> dict[str, int]:
    return {"dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid,
            "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}


def _structural(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink)


def _read_leaf(parent: int, name: str, uid: int,
               stack: ExitStack) -> dict[str, int]:
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    reread = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode)
            or _structural(named) != _structural(info)
            or _structural(reread) != _structural(info)
            or info.st_dev != os.fstat(parent).st_dev
            or info.st_uid != uid or info.st_gid != os.fstat(parent).st_gid
            or stat.S_IMODE(info.st_mode) != _MODE):
        _fail("UNOWNED_OR_CHANGED_LEAF")
    return _record(info)


def provision_native_storage_under_root(
    root_fd: int, *, root_uid: int, cache_uid: int,
    existing: dict[str, dict[str, int]] | None = None,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Create exact cache/log leaf directories; preserve data on repeat.

    First installation requires both paths absent; repeat requires exact
    recorded identity of both leaves, to be supplied only by an authenticated
    installed ownership manifest in a future reviewed privileged caller.
    Interrupted partial installs fail closed, never silently adopted/deleted.
    Parent package directories must already exist and be safely root-owned.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(root_uid) is not int or type(cache_uid) is not int
            or not 0 <= root_uid <= 2**32 - 2
            or not 0 <= cache_uid <= 2**32 - 2
            or (inject_fault is not None and not callable(inject_fault))):
        _fail("ARGUMENT_INVALID")
    if existing is not None:
        if type(existing) is not dict or set(existing) != {"cache", "logs"}:
            _fail("EXPECTED_MANIFEST_INVALID")
        for key, uid in (("cache", cache_uid), ("logs", root_uid)):
            item = existing[key]
            if (type(item) is not dict or set(item) != _KEYS
                    or any(type(v) is not int or not 0 <= v <= 2**63-1
                           for v in item.values())
                    or item["dev"] == 0 or item["ino"] == 0
                    or item["uid"] != uid or item["mode"] != _MODE):
                _fail("EXPECTED_MANIFEST_INVALID")
    try:
        with ExitStack() as stack:
            paths = []
            for label, parent_segments, name in _TARGETS:
                parent, chain = _walk(root_fd, parent_segments,
                                      stack, root_uid)
                before = _structural(_safe_directory(parent, root_uid))
                try:
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    present = False
                else:
                    present = True
                if present != (existing is not None):
                    _fail("UNOWNED_OR_PARTIAL_NAMESPACE")
                if present:
                    observed = _read_leaf(
                        parent, name,
                        cache_uid if label == "cache" else root_uid, stack)
                    if observed != existing[label]:
                        _fail("MANIFEST_INODE_DRIFT")
                paths.append((label, parent, name, chain, before))
            if existing is not None:
                for _, _, _, chain, _ in paths:
                    _recheck(chain, root_uid)
                records = {key: dict(existing[key]) for key in ("cache", "logs")}
            else:
                records = {}
                for label, parent, name, chain, before in paths:
                    target_uid = cache_uid if label == "cache" else root_uid
                    os.mkdir(name, mode=_MODE, dir_fd=parent)
                    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
                    stack.callback(os.close, fd)
                    initial = os.fstat(fd)
                    named = os.stat(name, dir_fd=parent,
                                    follow_symlinks=False)
                    if (not stat.S_ISDIR(initial.st_mode)
                            or _structural(initial) != _structural(named)
                            or initial.st_uid != root_uid
                            or initial.st_dev != os.fstat(parent).st_dev
                            or stat.S_IMODE(initial.st_mode) != _MODE):
                        _fail("CREATED_LEAF_UNVERIFIED")
                    if target_uid != root_uid:
                        os.fchown(fd, target_uid, initial.st_gid)
                    os.fsync(fd)
                    os.fsync(parent)
                    now = os.fstat(fd)
                    renamed = os.stat(name, dir_fd=parent,
                                      follow_symlinks=False)
                    if (_structural(now) != _structural(renamed)
                            or now.st_uid != target_uid
                            or stat.S_IMODE(now.st_mode) != _MODE):
                        _fail("CREATED_LEAF_CHANGED")
                    parent_after = _structural(
                        _safe_directory(parent, root_uid))
                    # mkdir may increment the parent link count by 1.
                    if (parent_after[:5] != before[:5]
                            or parent_after[5] not in
                               (before[5], before[5] + 1)):
                        _fail("PARENT_CHANGED")
                    _recheck(chain[:-1], root_uid)
                    records[label] = _record(now)
                    if inject_fault is not None:
                        inject_fault(label + "_durable")
            return {
                "schema_version": 1,
                "status": ("FRESH_STORAGE_CREATED" if existing is None
                           else "EXISTING_STORAGE_VALIDATED"),
                "directory_identities": records,
                "existing_data_retained": existing is not None,
                "host_root_authenticated": False,
                "operator_authorization_verified": False,
                "selinux_contexts_verified": False,
                "nginx_writability_verified": False,
                "authorizes_host_installation": False,
                "authorizes_cache_cleanup": False,
            }
    except NativeStorageProvisionError:
        raise
    except (OSError, ValueError, TypeError):
        _fail("STATE_UNVERIFIED")
