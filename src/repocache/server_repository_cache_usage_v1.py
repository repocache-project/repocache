"""Bounded read-only observation of selected, marked NGINX cache repositories.

#29/#97/#95: these values are fixture-only occupancy hints, not an
authenticated global cache inventory, deletion plan or host-side authority.
"""
from __future__ import annotations

from typing import Any

from repocache.server_cache_pressure_policy_v1 import MAX_INT
from repocache.server_install_v1 import ID
from repocache.server_repository_cache_cleanup_preview_v1 import (
    RepositoryCacheCleanupPreviewError,
    preview_repository_cache_cleanup_under_root,
)

_MAX_REPOSITORIES = 500
_MAX_OBSERVED_ENTRIES = 100_000
_FIELDS = (
    ("cache_files_observed", "cache_files_observed"),
    ("cache_directories_observed", "cache_directories_observed"),
    ("apparent_file_bytes_observed", "apparent_file_bytes_observed"),
    ("allocated_file_bytes_observed", "allocated_file_bytes_observed"),
)


class CacheUsageObservationError(ValueError):
    """Redacted refusal; never return partial or untrusted measurements."""


def _deny(code: str) -> None:
    raise CacheUsageObservationError("CACHE_USAGE_" + code)


def preview_owned_repository_cache_usage_under_root(
    root_fd: int, *, root_uid: int, cache_uid: int, cache_gid: int,
    repository_ids: tuple[str, ...],
) -> dict[str, Any]:
    """Sum verified per-repository fixture observations with strict bounds.

    The list of IDs comes from an UNTRUSTED caller: no completeness claim.
    Each scan pins, validates and rechecks its own native cache ownership
    marker. These scans are sequential, not an atomic multi-repository view.
    A missing/foreign/malformed repository aborts the whole result.
    """
    if (type(root_fd) is not int or root_fd < 0
            or any(type(uid) is not int or not 0 <= uid <= 2**32 - 2
                   for uid in (root_uid, cache_uid, cache_gid))
            or type(repository_ids) is not tuple
            or not 1 <= len(repository_ids) <= _MAX_REPOSITORIES
            or any(type(rid) is not str or ID.fullmatch(rid) is None
                   for rid in repository_ids)
            or len(set(repository_ids)) != len(repository_ids)):
        _deny("ARGUMENT_INVALID")

    totals = {name: 0 for name, _ in _FIELDS}
    rows: list[dict[str, Any]] = []
    try:
        for repository_id in sorted(repository_ids):
            sample = preview_repository_cache_cleanup_under_root(
                root_fd, root_uid=root_uid, cache_uid=cache_uid,
                cache_gid=cache_gid, repository_id=repository_id,
            )
            # A future change to the preflight must not accidentally turn
            # an unverified or authorizing result into a usage measurement.
            if (type(sample) is not dict
                    or sample.get("status") != "FIXTURE_CACHE_CLEANUP_PREVIEW_ONLY"
                    or sample.get("repository_id") != repository_id
                    or sample.get("bounded_layout_and_marker_observed") is not True
                    or any(sample.get(key) is not False for key in (
                        "trusted_repository_deletion_approval_verified",
                        "nginx_quiescence_verified",
                        "installed_root_provenance_verified",
                        "selinux_enforcing_verified",
                        "actual_reclaimable_space_verified",
                        "authorizes_cache_cleanup",
                        "authorizes_repository_removal",
                        "authorizes_nginx_reload",
                    ))):
                _deny("SOURCE_UNVERIFIED")
            row = {"repository_id": repository_id}
            for dest, source in _FIELDS:
                value = sample.get(source)
                if type(value) is not int or not 0 <= value <= MAX_INT:
                    _deny("COUNTER_INVALID")
                if totals[dest] > MAX_INT - value:
                    _deny("COUNTER_OVERFLOW")
                totals[dest] += value
                row[dest] = value
            # The cumulative work is explicitly bounded even when each
            # individual repository remains inside the scan's own bound.
            if (totals["cache_files_observed"]
                    + totals["cache_directories_observed"]
                    > _MAX_OBSERVED_ENTRIES):
                _deny("ENTRY_LIMIT_EXCEEDED")
            rows.append(row)
    except CacheUsageObservationError:
        raise
    except RepositoryCacheCleanupPreviewError:
        _deny("OBSERVATION_UNVERIFIED")
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        _deny("OBSERVATION_UNVERIFIED")

    return {
        "schema_version": 1,
        "status": "SELECTED_CACHE_USAGE_OBSERVATION_ONLY",
        "repository_ids_observed": [r["repository_id"] for r in rows],
        "selected_repository_usage": rows,
        **totals,
        "selected_repository_count": len(rows),
        "all_repository_ids_authenticated": False,
        "full_cache_inventory_verified": False,
        "multi_repository_snapshot_atomic": False,
        "nginx_cache_manager_verified": False,
        "selinux_enforcing_verified": False,
        "actual_reclaimable_space_verified": False,
        "authorizes_cache_cleanup": False,
        "authorizes_nginx_reload": False,
        "authorizes_state_commit": False,
        "authorizes_operator_alert_publish": False,
    }



def preview_locked_v2_repository_cache_usage_under_root(
    root_fd: int, *, root_uid: int, cache_uid: int, cache_gid: int,
    expected_state_generation: int, expected_state_sha256: str,
) -> dict[str, Any]:
    """Join ALL bounded protected v2 IDs to owned cache-root usage in a fixture.

    Unlike caller-selected usage, the ID set comes from an actual canonical,
    exclusive-lock-read all-time v2 ledger. An unmarked/foreign cache directory
    or repository owner marker in the managed namespace is a hard refusal.
    Only existing marked cache roots are scanned; disabled/retired repositories
    that never created cache storage have explicit zero rows. A desired-active
    repository without its marked root is a hard refusal.

    The state snapshot is locked; NGINX workers are not. This is neither an
    atomic live cache-manager snapshot nor operator authentication and it
    provides NO root, catalog-publication or cleanup authority.
    """
    from contextlib import ExitStack
    import hashlib
    import os
    import stat

    from repocache.server_fixture_multi_resource_wal_v1 import (
        V2_STATE, INCLUDE, CATALOG, MANIFEST,
        _check_no_auxiliary_pending, _read_all, _validate_old,
    )
    from repocache.server_native_repository_cache_v1 import (
        _snapshot,
    )
    from repocache.server_native_storage_bootstrap_v1 import (
        _CACHE_PARENT, _LEAF, _no_unverified_xattrs, _proof, _read_marker,
    )
    from repocache.server_protected_state_inspect_v1 import (
        _DIRECTORY_FLAGS, _safe_directory, _walk,
    )
    from repocache.server_proposed_state_v2_store import (
        _legacy_refusal, _read_v2,
    )
    from repocache.server_protected_state_store_v1 import _locked

    if (type(root_fd) is not int or root_fd < 0
            or any(type(x) is not int or not 0 <= x <= 2**32 - 2
                   for x in (root_uid, cache_uid, cache_gid))
            or type(expected_state_generation) is not int
            or not 1 <= expected_state_generation <= MAX_INT
            or type(expected_state_sha256) is not str
            or len(expected_state_sha256) != 64
            or any(ch not in "0123456789abcdef"
                   for ch in expected_state_sha256)):
        _deny("LOCKED_ARGUMENT_INVALID")

    try:
        native = os.stat("/", follow_symlinks=False)
        supplied = os.fstat(root_fd)
        if (native.st_dev, native.st_ino) == (supplied.st_dev, supplied.st_ino):
            _deny("LOCKED_LIVE_ROOT_FORBIDDEN")
        with _locked(root_fd, root_uid) as state_dir:
            _legacy_refusal(state_dir, root_uid)
            _check_no_auxiliary_pending(state_dir, root_uid)
            state, state_bytes = _read_v2(state_dir, root_uid)
            if state is None or state_bytes is None:
                _deny("LOCKED_STATE_REQUIRED")
            owned = _read_all(state_dir, root_uid)
            if owned[V2_STATE] != state_bytes:
                _deny("LOCKED_STATE_CHANGED")
            if any(owned[n] is not None for n in (INCLUDE, CATALOG, MANIFEST)):
                _validate_old(owned)
            if (state["state_generation"] != expected_state_generation
                    or hashlib.sha256(state_bytes).hexdigest()
                       != expected_state_sha256):
                _deny("LOCKED_STATE_CHANGED")

            ledger = {
                row["id"]: row for row in state["id_reservations"]
            }
            current = {
                row["id"]: row for row in state["repository_records"]
            }
            if len(ledger) > _MAX_REPOSITORIES:
                _deny("LOCKED_HISTORY_LIMIT_EXCEEDED")
            all_ids = sorted(ledger)
            with ExitStack() as stack:
                _safe_directory(root_fd, root_uid)
                parent_fd, _ancestry = _walk(
                    root_fd, _CACHE_PARENT, stack, root_uid,
                )
                parent = _safe_directory(parent_fd, root_uid)
                _no_unverified_xattrs(parent_fd)
                cache_fd = os.open(_LEAF, _DIRECTORY_FLAGS, dir_fd=parent_fd)
                stack.callback(os.close, cache_fd)
                cache = os.fstat(cache_fd)
                _no_unverified_xattrs(cache_fd)
                if (cache.st_dev != parent.st_dev
                        or cache.st_uid != cache_uid
                        or cache.st_gid != cache_gid
                        or stat.S_IMODE(cache.st_mode) != 0o700
                        or _read_marker(parent_fd, root_uid=root_uid) != {
                            "schema": 1, "kind": "cache", **_proof(cache),
                        }):
                    _deny("LOCKED_CACHE_PARENT_UNTRUSTED")

                def marker_names() -> set[str]:
                    with os.scandir(parent_fd) as listing:
                        names = [entry.name for entry in listing
                                 if entry.name.startswith(
                                     ".repocache-repository-"
                                 )]
                    if len(names) > _MAX_REPOSITORIES:
                        _deny("LOCKED_MARKER_SET_UNVERIFIED")
                    expected = {
                        ".repocache-repository-" + rid + ".owner-v1"
                        for rid in all_ids
                    }
                    if any(name not in expected for name in names):
                        _deny("LOCKED_FOREIGN_CACHE_MARKER")
                    return set(names)

                def cache_names() -> set[str]:
                    with os.scandir(cache_fd) as listing:
                        names = [entry.name for entry in listing]
                    if (len(names) > _MAX_REPOSITORIES
                            or any(name not in ledger for name in names)):
                        _deny("LOCKED_FOREIGN_CACHE_DIRECTORY")
                    return set(names)

                previous_markers = marker_names()
                previous_cache_names = cache_names()
                present = []
                for rid in all_ids:
                    exists, marker = _snapshot(
                        parent_fd, cache_fd, rid,
                        root_uid=root_uid, cache_uid=cache_uid,
                        cache_gid=cache_gid,
                    )
                    if exists:
                        if marker is None:
                            _deny("LOCKED_REPOSITORY_MARKER_MISSING")
                        present.append(rid)
                    elif (rid in current
                          and current[rid]["desired_state"] == "active"):
                        _deny("LOCKED_ACTIVE_CACHE_ROOT_MISSING")
                if set(present) != previous_cache_names:
                    _deny("LOCKED_REPOSITORY_SET_DRIFT")
                if previous_markers != {
                    ".repocache-repository-" + rid + ".owner-v1"
                    for rid in present
                }:
                    _deny("LOCKED_MARKER_SET_DRIFT")
                observed = (
                    preview_owned_repository_cache_usage_under_root(
                        root_fd, root_uid=root_uid,
                        cache_uid=cache_uid, cache_gid=cache_gid,
                        repository_ids=tuple(present),
                    ) if present else None
                )
                sample_rows = (
                    {row["repository_id"]: row
                     for row in observed["selected_repository_usage"]}
                    if observed else {}
                )
                totals = {
                    dest: (observed[dest] if observed else 0)
                    for dest, _ in _FIELDS
                }
                rows = []
                for rid in all_ids:
                    row = {
                        "repository_id": rid,
                        "history_status": ledger[rid]["status"],
                        "desired_state": (
                            current[rid]["desired_state"]
                            if rid in current else "removed"
                        ),
                        "owned_cache_root_present": rid in sample_rows,
                    }
                    row.update({
                        key: sample_rows.get(rid, {}).get(key, 0)
                        for key, _ in _FIELDS
                    })
                    rows.append(row)
                # Detect noncooperating state/owner writers and newly
                # introduced/unmarked cache roots before returning. NGINX
                # byte growth remains non-atomic between sequential scans.
                _legacy_refusal(state_dir, root_uid)
                _check_no_auxiliary_pending(state_dir, root_uid)
                if (_read_v2(state_dir, root_uid) != (state, state_bytes)
                        or _read_all(state_dir, root_uid) != owned
                        or marker_names() != previous_markers
                        or cache_names() != previous_cache_names):
                    _deny("LOCKED_OBSERVATION_DRIFT")
                for rid in present:
                    still, _ = _snapshot(
                        parent_fd, cache_fd, rid,
                        root_uid=root_uid, cache_uid=cache_uid,
                        cache_gid=cache_gid,
                    )
                    if not still:
                        _deny("LOCKED_OBSERVATION_DRIFT")

                return {
                    "schema_version": 1,
                    "status": "LOCKED_V2_MARKED_CACHE_USAGE_FIXTURE_ONLY",
                    "state_generation": expected_state_generation,
                    "protected_state_sha256": expected_state_sha256,
                    "protected_history_rows": rows,
                    "protected_historic_repository_count": len(rows),
                    "marked_cache_root_count": len(present),
                    **totals,
                    "fixture_all_ids_from_committed_v2_ledger": True,
                    "state_lock_held_during_observation": True,
                    "state_lock_still_held_after_return": False,
                    "full_cache_inventory_verified": False,
                    "multi_repository_snapshot_atomic": False,
                    "nginx_cache_manager_verified": False,
                    "actual_reclaimable_space_verified": False,
                    "installed_root_provenance_verified": False,
                    "native_operator_authorization_verified": False,
                    "authorizes_cache_cleanup": False,
                    "authorizes_nginx_reload": False,
                    "authorizes_catalog_publication": False,
                }
    except CacheUsageObservationError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        _deny("LOCKED_OBSERVATION_UNVERIFIED")
