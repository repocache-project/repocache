"""Read-only, inode-pinned preview of one repository's native NGINX cache.

Issue #95/#29: restrict inspection to the existing fixture-owned
levels=1:2 cache layout. This is NOT cleanup authorization or a root helper.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
import re
import stat
from typing import Any

from repocache.server_cache_pressure_policy_v1 import MAX_INT
from repocache.server_install_v1 import ID
from repocache.server_native_repository_cache_v1 import _snapshot
from repocache.server_native_storage_bootstrap_v1 import (
    _CACHE_PARENT, _LEAF, _no_unverified_xattrs, _proof, _read_marker,
    _structural,
)
from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _identity, _recheck, _safe_directory, _walk,
)
from repocache.server_proposed_state_v2_store import (
    _legacy_refusal, _pending, _read_v2,
)
from repocache.server_protected_state_store_v1 import _locked

_FILE_FLAGS = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
               | getattr(os, "O_CLOEXEC", 0))
_HEX1 = re.compile(r"[0-9a-f]\Z", re.ASCII)
_HEX2 = re.compile(r"[0-9a-f]{2}\Z", re.ASCII)
_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_MAX_ENTRIES = 20_000


class RepositoryCacheCleanupPreviewError(ValueError):
    """Stable refusal code that never reveals cache path or contents."""


def _deny(code: str) -> None:
    raise RepositoryCacheCleanupPreviewError("CACHE_CLEANUP_" + code)


def _metadata(value: os.stat_result, *, uid: int, gid: int,
              dev: int, directory: bool) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if (value.st_dev != dev or value.st_uid != uid or value.st_gid != gid
            or mode & 0o7022  # no SGID, SUID, sticky or group/world writes
            or value.st_ino <= 0
            or (not directory and value.st_nlink != 1)
            or (directory and not stat.S_ISDIR(value.st_mode))
            or (not directory and not stat.S_ISREG(value.st_mode))):
        _deny("CONTENT_UNTRUSTED")


def _scan(fd: int, *, level: int, uid: int, gid: int, dev: int,
          count: list[int]) -> tuple[int, int, int, int]:
    """Bounded fd-relative scan; never read cache payload or follow symlinks.

    Only native NGINX levels=1:2 hex hierarchy is currently supported.
    Any foreign file, concurrently changing inode or exceeded bound refuses
    the *whole* preview; no partial list can be mistaken for a cleanup plan.
    """
    original = os.fstat(fd)
    _metadata(original, uid=uid, gid=gid, dev=dev, directory=True)
    _no_unverified_xattrs(fd)
    files, dirs, logical, allocated = 0, 0, 0, 0
    with os.scandir(fd) as listing:
        for entry in listing:
            count[0] += 1
            if count[0] > _MAX_ENTRIES:
                _deny("ENTRY_LIMIT_EXCEEDED")
            name = entry.name
            pattern = (_HEX1 if level == 0 else
                       _HEX2 if level == 1 else _HEX32)
            if type(name) is not str or pattern.fullmatch(name) is None:
                _deny("UNEXPECTED_CACHE_LAYOUT")
            expected_directory = level < 2
            first = os.stat(name, dir_fd=fd, follow_symlinks=False)
            # Never *open* a special node merely to discover its type.
            # O_NONBLOCK avoids one FIFO hang, but a device can still have
            # observable open-side effects. Refuse foreign inode kind,
            # ownership, links, mount and permissions before any open(2).
            # The opened descriptor is rechecked against this preflight
            # immediately below to detect substitution between the calls.
            _metadata(first, uid=uid, gid=gid, dev=dev,
                      directory=expected_directory)
            opened = os.open(
                name, _DIRECTORY_FLAGS if expected_directory else _FILE_FLAGS,
                dir_fd=fd,
            )
            try:
                seen = os.fstat(opened)
                _metadata(seen, uid=uid, gid=gid, dev=dev,
                          directory=expected_directory)
                if _identity(first) != _identity(seen):
                    _deny("CONTENT_CHANGED")
                _no_unverified_xattrs(opened)
                if expected_directory:
                    subfiles, subdirs, sublogical, suballocated = _scan(
                        opened, level=level + 1, uid=uid, gid=gid,
                        dev=dev, count=count,
                    )
                    files += subfiles
                    dirs += 1 + subdirs
                    logical += sublogical
                    allocated += suballocated
                else:
                    if (type(seen.st_size) is not int or seen.st_size < 0
                            or type(seen.st_blocks) is not int
                            or seen.st_blocks < 0):
                        _deny("CONTENT_SIZE_UNVERIFIED")
                    files += 1
                    logical += seen.st_size
                    allocated += seen.st_blocks * 512
                if (logical > MAX_INT or allocated > MAX_INT
                        or _identity(os.fstat(opened)) != _identity(seen)
                        or _identity(os.stat(
                            name, dir_fd=fd, follow_symlinks=False
                        )) != _identity(seen)):
                    _deny("CONTENT_CHANGED")
            finally:
                os.close(opened)
    if _identity(os.fstat(fd)) != _identity(original):
        _deny("DIRECTORY_CHANGED")
    return files, dirs, logical, allocated


def preview_repository_cache_cleanup_under_root(
    root_fd: int, *, root_uid: int, cache_uid: int, cache_gid: int,
    repository_id: str,
) -> dict[str, Any]:
    """Describe inode-verified fixture cache bytes, never expose paths/files.

    The caller-provided repository ID is an untrusted component, not an
    administrative approval. Installed root is forbidden even for this
    inspection; an authenticated host/NGINX manager and a separate reviewed
    destructive operation would still be necessary for force-cleanup.
    """
    if (type(root_fd) is not int or root_fd < 0
            or any(type(v) is not int or not 0 <= v <= 2**32 - 2
                   for v in (root_uid, cache_uid, cache_gid))
            or type(repository_id) is not str
            or ID.fullmatch(repository_id) is None):
        _deny("ARGUMENT_INVALID")
    try:
        native = os.stat("/", follow_symlinks=False)
        root = os.fstat(root_fd)
        if (root.st_dev, root.st_ino) == (native.st_dev, native.st_ino):
            _deny("LIVE_ROOT_FORBIDDEN")
        with ExitStack() as stack:
            _safe_directory(root_fd, root_uid)
            parent_fd, ancestry = _walk(
                root_fd, _CACHE_PARENT, stack, root_uid,
            )
            _no_unverified_xattrs(parent_fd)
            parent = _safe_directory(parent_fd, root_uid)
            cache_fd = os.open(_LEAF, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            stack.callback(os.close, cache_fd)
            cache = os.fstat(cache_fd)
            if (not stat.S_ISDIR(cache.st_mode)
                    or cache.st_dev != parent.st_dev
                    or cache.st_uid != cache_uid or cache.st_gid != cache_gid
                    or stat.S_IMODE(cache.st_mode) != 0o700
                    or _read_marker(parent_fd, root_uid=root_uid) != {
                        "schema": 1, "kind": "cache", **_proof(cache),
                    }):
                _deny("CACHE_ROOT_UNTRUSTED")
            exists, _ = _snapshot(
                parent_fd, cache_fd, repository_id,
                root_uid=root_uid, cache_uid=cache_uid, cache_gid=cache_gid,
            )
            if not exists:
                _deny("REPOSITORY_UNTRACKED")
            repo_fd = os.open(
                repository_id, _DIRECTORY_FLAGS, dir_fd=cache_fd,
            )
            stack.callback(os.close, repo_fd)
            before = os.fstat(repo_fd)
            if (before.st_dev != cache.st_dev
                    or before.st_uid != cache_uid
                    or before.st_gid != cache_gid
                    or stat.S_IMODE(before.st_mode) != 0o700):
                _deny("REPOSITORY_ROOT_UNTRUSTED")
            files, dirs, logical, allocated = _scan(
                repo_fd, level=0, uid=cache_uid, gid=cache_gid,
                dev=before.st_dev, count=[0],
            )
            # Detect a swap/relink or concurrent cache-manager mutation.
            if (_identity(os.fstat(repo_fd)) != _identity(before)
                    or _identity(os.stat(
                        repository_id, dir_fd=cache_fd,
                        follow_symlinks=False
                    )) != _identity(before)
                    or _structural(os.fstat(cache_fd))[:5]
                       != _structural(cache)[:5]
                    or _structural(os.fstat(parent_fd))[:5]
                       != _structural(parent)[:5]):
                _deny("ROOT_CHANGED")
            again, _ = _snapshot(
                parent_fd, cache_fd, repository_id,
                root_uid=root_uid, cache_uid=cache_uid, cache_gid=cache_gid,
            )
            if not again:
                _deny("ROOT_CHANGED")
            _recheck(ancestry, root_uid)
        return {
            "schema_version": 1,
            "status": "FIXTURE_CACHE_CLEANUP_PREVIEW_ONLY",
            "repository_id": repository_id,
            "cache_files_observed": files,
            "cache_directories_observed": dirs,
            "apparent_file_bytes_observed": logical,
            "allocated_file_bytes_observed": allocated,
            "bounded_layout_and_marker_observed": True,
            "trusted_repository_deletion_approval_verified": False,
            "nginx_quiescence_verified": False,
            "installed_root_provenance_verified": False,
            "selinux_enforcing_verified": False,
            "actual_reclaimable_space_verified": False,
            "authorizes_cache_cleanup": False,
            "authorizes_repository_removal": False,
            "authorizes_nginx_reload": False,
        }
    except RepositoryCacheCleanupPreviewError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        _deny("OBSERVATION_UNVERIFIED")


def preview_locked_retired_repository_cache_cleanup_under_root(
    root_fd: int, *, root_uid: int, cache_uid: int, cache_gid: int,
    repository_id: str, expected_state_generation: int,
    expected_state_sha256: str,
) -> dict[str, Any]:
    """Join actual *fixture* retired-v2 history and owned cache under one lock.

    Unlike a caller-supplied 'retired' flag, this opens the persisted state-v2
    record through the existing owner-pinned exclusive descriptor lock. It
    refuses pending recovery, absent or still-allocated IDs, stale generation
    and whole-state digest mismatch BEFORE scanning even one cache object.
    The selected repository's complete cache is then inspected by the strict
    existing bounded, O_NOFOLLOW ownership/layout preview under that lock.

    No host-root authority, trusted operator intent or NGINX quiescence is
    established by a test root descriptor. This is strictly read-only and
    cannot grant permission to unlink a single file, even on a passing
    fixture report. An installed native writer must recheck all invariants
    inside its independently authorized transaction and prove live worker
    quiescence before any explicit force cleanup.
    """
    if (type(root_fd) is not int or root_fd < 0
            or any(type(v) is not int or not 0 <= v <= 2**32 - 2
                   for v in (root_uid, cache_uid, cache_gid))
            or type(repository_id) is not str
            or ID.fullmatch(repository_id) is None
            or type(expected_state_generation) is not int
            or not 1 <= expected_state_generation < 2**63
            or type(expected_state_sha256) is not str
            or len(expected_state_sha256) != 64
            or any(ch not in "0123456789abcdef"
                   for ch in expected_state_sha256)):
        _deny("LOCKED_ARGUMENT_INVALID")
    try:
        with _locked(root_fd, root_uid) as state_fd:
            _legacy_refusal(state_fd, root_uid)
            if _pending(state_fd, root_uid):
                _deny("LOCKED_RECOVERY_REQUIRED")
            state, raw = _read_v2(state_fd, root_uid)
            if state is None or raw is None:
                _deny("LOCKED_STATE_REQUIRED")
            digest = hashlib.sha256(raw).hexdigest()
            if (state["state_generation"] != expected_state_generation
                    or digest != expected_state_sha256):
                _deny("LOCKED_STATE_CHANGED")

            historical = {entry["id"]: entry
                          for entry in state["id_reservations"]}
            entry = historical.get(repository_id)
            if (entry is None or entry["status"] != "retired"
                    or any(row["id"] == repository_id
                           for row in state["repository_records"])):
                _deny("LOCKED_REPOSITORY_NOT_RETIRED")

            # The immutable tombstone and cache directory identity must
            # agree on the exact selected ID; a forged caller-side reservation
            # snapshot cannot substitute for the persisted ledger.
            observed = preview_repository_cache_cleanup_under_root(
                root_fd, root_uid=root_uid, cache_uid=cache_uid,
                cache_gid=cache_gid, repository_id=repository_id,
            )
            again, current = _read_v2(state_fd, root_uid)
            _legacy_refusal(state_fd, root_uid)
            if (_pending(state_fd, root_uid) or again != state
                    or current != raw):
                _deny("LOCKED_STATE_CHANGED")
            return {
                **observed,
                "status": "LOCKED_RETIRED_CACHE_PREVIEW_ONLY",
                "state_generation": expected_state_generation,
                "protected_state_sha256": digest,
                "fixture_retirement_and_cache_correspondence_observed": True,
                "state_lock_held_during_inspection": True,
                "state_lock_still_held_after_return": False,
                "installed_nginx_quiescence_verified": False,
                "signed_operator_force_cleanup_verified": False,
                "authorizes_cache_cleanup": False,
                "authorizes_repository_removal": False,
                "authorizes_nginx_reload": False,
            }
    except RepositoryCacheCleanupPreviewError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        _deny("LOCKED_PROTECTED_UNVERIFIED")
