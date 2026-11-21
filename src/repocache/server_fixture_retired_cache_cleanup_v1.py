"""Explicit retired-repository cache object purge in DETACHED TEST ROOTS ONLY.

This is a bounded, descriptor-relative destruction rehearsal for #95. It is
neither an installed root operation nor a reusable host force-cleanup API:
fixture callbacks cannot establish actual NGINX transfer quiescence or owner
approval. Never call this entrypoint from a service, CLI or real host writer.

A successful pass removes only verified levels=1:2 cache *objects* under the
selected retired repository; the marked repository directory, immutable v2
retirement record and other repository namespaces remain untouched. If a
fault occurs after the first unlink, the partial purge may be resumed only
after a fresh complete preflight. No false atomic-deletion claim is made.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
import stat
from typing import Any, Callable

from repocache.server_fixture_multi_resource_wal_v1 import (
    V2_STATE, INCLUDE, CATALOG, MANIFEST, _read_all, _validate_old,
    _check_no_auxiliary_pending,
)
from repocache.server_install_v1 import ID
from repocache.server_native_repository_cache_v1 import _snapshot
from repocache.server_native_storage_bootstrap_v1 import (
    _CACHE_PARENT, _LEAF, _no_unverified_xattrs, _proof, _read_marker,
    _structural,
)
from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _identity, _safe_directory, _walk,
)
from repocache.server_proposed_state_v2_store import (
    _legacy_refusal, _read_v2,
)
from repocache.server_protected_state_store_v1 import _locked
from repocache.server_repository_cache_cleanup_preview_v1 import (
    _FILE_FLAGS, _HEX1, _HEX2, _HEX32, _MAX_ENTRIES,
    _metadata, preview_repository_cache_cleanup_under_root,
)

_MAX_INT = 2**63 - 1


class FixtureRetiredCacheCleanupError(ValueError):
    """Only fixed redacted test-fixture error codes."""


def _deny(code: str) -> None:
    raise FixtureRetiredCacheCleanupError("FIXTURE_RETIRED_CACHE_" + code)


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return _identity(info) + (info.st_blocks,)


def _inventory(
    directory_fd: int, *, level: int, uid: int, gid: int, dev: int,
    prefix: tuple[str, ...], counter: list[int],
) -> list[tuple[tuple[str, ...], bool, tuple[int, ...]]]:
    """Read all selected cache entries without following even one symlink."""
    if level not in (0, 1, 2):
        _deny("LAYOUT_INVALID")
    before = os.fstat(directory_fd)
    _metadata(before, uid=uid, gid=gid, dev=dev, directory=True)
    _no_unverified_xattrs(directory_fd)
    pattern = (_HEX1, _HEX2, _HEX32)[level]
    found: list[tuple[tuple[str, ...], bool, tuple[int, ...]]] = []
    with os.scandir(directory_fd) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        counter[0] += 1
        if counter[0] > _MAX_ENTRIES or pattern.fullmatch(name) is None:
            _deny("LAYOUT_INVALID")
        is_dir = level < 2
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _metadata(observed, uid=uid, gid=gid, dev=dev, directory=is_dir)
        child_fd = os.open(
            name, _DIRECTORY_FLAGS if is_dir else _FILE_FLAGS,
            dir_fd=directory_fd,
        )
        try:
            checked = os.fstat(child_fd)
            _metadata(checked, uid=uid, gid=gid, dev=dev, directory=is_dir)
            _no_unverified_xattrs(child_fd)
            if _identity(observed) != _identity(checked):
                _deny("ENTRY_CHANGED")
            if is_dir:
                found.extend(_inventory(
                    child_fd, level=level + 1, uid=uid, gid=gid,
                    dev=dev, prefix=(*prefix, name), counter=counter,
                ))
            else:
                if checked.st_size < 0 or checked.st_blocks < 0:
                    _deny("ENTRY_CHANGED")
            if (_identity(os.fstat(child_fd)) != _identity(checked)
                    or _identity(os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False,
                    )) != _identity(checked)):
                _deny("ENTRY_CHANGED")
            found.append(((*prefix, name), is_dir, _fingerprint(checked)))
        finally:
            os.close(child_fd)
    if _structural(os.fstat(directory_fd)) != _structural(before):
        _deny("DIRECTORY_CHANGED")
    return found


def _erase_verified_entry(
    repo_fd: int, path: tuple[str, ...], is_dir: bool,
    fingerprint: tuple[int, ...], frozen_by_path: dict[tuple[str, ...], tuple[int, ...]],
    *, uid: int, gid: int, dev: int,
) -> None:
    """Recheck every ancestor and final inode immediately before unlink."""
    with ExitStack() as stack:
        parent = repo_fd
        parent_path: tuple[str, ...] = ()
        for component in path[:-1]:
            parent_path = (*parent_path, component)
            parent_next = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
            stack.callback(os.close, parent_next)
            _metadata(os.fstat(parent_next), uid=uid, gid=gid,
                      dev=dev, directory=True)
            _no_unverified_xattrs(parent_next)
            if (_structural(os.fstat(parent_next))[:5]
                    != frozen_by_path[parent_path][:5]):
                _deny("ANCESTOR_CHANGED")
            parent = parent_next
        name = path[-1]
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _metadata(before, uid=uid, gid=gid, dev=dev, directory=is_dir)
        checked = os.open(
            name, _DIRECTORY_FLAGS if is_dir else _FILE_FLAGS,
            dir_fd=parent,
        )
        stack.callback(os.close, checked)
        actual = os.fstat(checked)
        _metadata(actual, uid=uid, gid=gid, dev=dev, directory=is_dir)
        _no_unverified_xattrs(checked)
        # Parent directory timestamps are expected to change as children
        # are removed; final entries must retain the exact initial inode.
        if (not is_dir and _fingerprint(before) != fingerprint
                or not is_dir and _fingerprint(actual) != fingerprint
                or is_dir and _structural(before)[:5] != fingerprint[:5]
                or is_dir and _structural(actual)[:5] != fingerprint[:5]
                or _identity(before) != _identity(actual)):
            _deny("ENTRY_CHANGED")
        if is_dir:
            os.rmdir(name, dir_fd=parent)
        else:
            os.unlink(name, dir_fd=parent)
        os.fsync(parent)


def purge_fixture_retired_repository_cache_objects_under_root(
    root_fd: int, *, root_uid: int, cache_uid: int, cache_gid: int,
    repository_id: str, expected_state_generation: int,
    expected_state_sha256: str,
    expected_cache_files: int, expected_allocated_file_bytes: int,
    assert_fixture_quiescent: Callable[[], None],
    inject_fixture_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Purge ONLY disposable fixture objects after explicit scope agreement.

    A caller-controlled callback is *not* a proof of host NGINX quiescence.
    The actual '/' is forbidden before the lock or any cache/path action.
    The protected v2 tombstone and the immutable owner marker must survive.
    """
    if (type(root_fd) is not int or root_fd < 0
            or any(type(v) is not int or not 0 <= v <= 2**32 - 2
                   for v in (root_uid, cache_uid, cache_gid))
            or type(repository_id) is not str
            or ID.fullmatch(repository_id) is None
            or type(expected_state_generation) is not int
            or not 1 <= expected_state_generation <= _MAX_INT
            or type(expected_state_sha256) is not str
            or len(expected_state_sha256) != 64
            or any(ch not in "0123456789abcdef"
                   for ch in expected_state_sha256)
            or type(expected_cache_files) is not int
            or not 0 <= expected_cache_files <= _MAX_ENTRIES
            or type(expected_allocated_file_bytes) is not int
            or not 0 <= expected_allocated_file_bytes <= _MAX_INT
            or not callable(assert_fixture_quiescent)
            or (inject_fixture_fault is not None
                and not callable(inject_fixture_fault))):
        _deny("ARGUMENT_INVALID")
    try:
        native = os.stat("/", follow_symlinks=False)
        root = os.fstat(root_fd)
        if (native.st_dev, native.st_ino) == (root.st_dev, root.st_ino):
            _deny("LIVE_ROOT_FORBIDDEN")
        with _locked(root_fd, root_uid) as state_dir:
            _legacy_refusal(state_dir, root_uid)
            _check_no_auxiliary_pending(state_dir, root_uid)
            state, raw = _read_v2(state_dir, root_uid)
            if state is None or raw is None:
                _deny("STATE_REQUIRED")
            owned = _read_all(state_dir, root_uid)
            if owned[V2_STATE] != raw:
                _deny("STATE_DRIFT")
            if any(owned[n] is not None for n in (INCLUDE, CATALOG, MANIFEST)):
                _validate_old(owned)
            if (state["state_generation"] != expected_state_generation
                    or hashlib.sha256(raw).hexdigest()
                       != expected_state_sha256):
                _deny("STALE_STATE")
            retired = {
                r["id"] for r in state["id_reservations"]
                if r["status"] == "retired"
            }
            if (repository_id not in retired
                    or repository_id in {
                        r["id"] for r in state["repository_records"]
                    }):
                _deny("REPOSITORY_NOT_RETIRED")

            with ExitStack() as stack:
                _safe_directory(root_fd, root_uid)
                parent_fd, _ = _walk(root_fd, _CACHE_PARENT, stack, root_uid)
                parent = _safe_directory(parent_fd, root_uid)
                _no_unverified_xattrs(parent_fd)
                cache_fd = os.open(_LEAF, _DIRECTORY_FLAGS, dir_fd=parent_fd)
                stack.callback(os.close, cache_fd)
                cache = os.fstat(cache_fd)
                if (cache.st_dev != parent.st_dev
                        or cache.st_uid != cache_uid
                        or cache.st_gid != cache_gid
                        or stat.S_IMODE(cache.st_mode) != 0o700
                        or _read_marker(parent_fd, root_uid=root_uid) != {
                            "schema": 1, "kind": "cache", **_proof(cache),
                        }):
                    _deny("CACHE_ROOT_UNTRUSTED")
                exists, marker = _snapshot(
                    parent_fd, cache_fd, repository_id,
                    root_uid=root_uid, cache_uid=cache_uid,
                    cache_gid=cache_gid,
                )
                if not exists or marker is None:
                    _deny("REPOSITORY_CACHE_UNTRACKED")
                repo_fd = os.open(
                    repository_id, _DIRECTORY_FLAGS, dir_fd=cache_fd,
                )
                stack.callback(os.close, repo_fd)
                repo_info = os.fstat(repo_fd)
                _metadata(repo_info, uid=cache_uid, gid=cache_gid,
                          dev=cache.st_dev, directory=True)
                _no_unverified_xattrs(repo_fd)
                sample = preview_repository_cache_cleanup_under_root(
                    root_fd, root_uid=root_uid, cache_uid=cache_uid,
                    cache_gid=cache_gid, repository_id=repository_id,
                )
                if (sample["cache_files_observed"] != expected_cache_files
                        or sample["allocated_file_bytes_observed"]
                           != expected_allocated_file_bytes):
                    _deny("SCOPE_CHANGED")
                first = _inventory(
                    repo_fd, level=0, uid=cache_uid, gid=cache_gid,
                    dev=cache.st_dev, prefix=(), counter=[0],
                )
                # This callback is TEST-ONLY: only an installed, independently
                # reviewed native worker can prove real master/transfer drain.
                try:
                    if assert_fixture_quiescent() is not None:
                        _deny("QUIESCENCE_NOT_ESTABLISHED")
                except Exception:
                    _deny("QUIESCENCE_NOT_ESTABLISHED")
                second = _inventory(
                    repo_fd, level=0, uid=cache_uid, gid=cache_gid,
                    dev=cache.st_dev, prefix=(), counter=[0],
                )
                if second != first:
                    _deny("CONTENT_CHANGED")
                if (_structural(os.fstat(repo_fd))
                        != _structural(repo_info)):
                    _deny("REPOSITORY_ROOT_CHANGED")

                frozen_by_path = {parts: fingerprint
                                  for parts, _, fingerprint in first}
                files_removed = 0
                for parts, directory, fingerprint in first:
                    _erase_verified_entry(
                        repo_fd, parts, directory, fingerprint,
                        frozen_by_path, uid=cache_uid, gid=cache_gid,
                        dev=cache.st_dev,
                    )
                    if not directory:
                        files_removed += 1
                    if inject_fixture_fault is not None:
                        inject_fixture_fault("entry_removed")
                if files_removed != expected_cache_files:
                    _deny("FINAL_SCOPE_MISMATCH")
                verified = preview_repository_cache_cleanup_under_root(
                    root_fd, root_uid=root_uid, cache_uid=cache_uid,
                    cache_gid=cache_gid, repository_id=repository_id,
                )
                if (verified["cache_files_observed"] != 0
                        or verified["cache_directories_observed"] != 0):
                    _deny("FINAL_SCOPE_MISMATCH")
                if (_read_v2(state_dir, root_uid) != (state, raw)
                        or _read_all(state_dir, root_uid) != owned):
                    _deny("STATE_DRIFT")
                return {
                    "schema_version": 1,
                    "status": "PURGED_DETACHED_FIXTURE_CACHE_OBJECTS_ONLY",
                    "repository_id": repository_id,
                    "state_generation": expected_state_generation,
                    "verified_cache_files_removed": files_removed,
                    "verified_allocated_bytes_preflight": (
                        expected_allocated_file_bytes
                    ),
                    "repository_cache_marker_preserved": True,
                    "retirement_ledger_preserved": True,
                    "fixture_only": True,
                    "actual_host_transfer_quiescence_verified": False,
                    "native_security_review_verified": False,
                    "authorizes_installed_cache_cleanup": False,
                }
    except FixtureRetiredCacheCleanupError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        _deny("OPERATION_REFUSED")
