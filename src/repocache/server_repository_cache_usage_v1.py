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
