"""Read-only cache filesystem observation -> conservative inert alarm (#97).

Joins existing descriptor-pinned statvfs inspection with the deterministic
hysteresis reducer, without promoting incomplete metrics to NORMAL or
claiming authenticated host monitoring, notifications or NGINX authority.
"""
from __future__ import annotations

from typing import Any

from repocache.server_cache_pressure_alarm_v1 import (
    CachePressureAlarmError, _prior, evaluate_cache_pressure_alarm,
)
from repocache.server_cache_pressure_observe_v1 import (
    observe_cache_pressure_under_root,
)
from repocache.server_repository_cache_usage_v1 import (
    preview_owned_repository_cache_usage_under_root,
)



class NativePressureAlarmObservationError(ValueError):
    """Static redacted refusal only."""


def preview_observed_cache_pressure_alarm(
    root_fd: int, *, root_uid: int, cache_uid: int,
    warning_free_bytes: int, critical_free_bytes: int,
    recovery_margin_bytes: int, previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read a fixed cache root and conservatively reduce one alarm sample.

    A pinned directory and statvfs never prove trusted persisted alarm state,
    NGINX writable storage, installed host ownership or actual cache manager
    success. The return value is untrusted ephemeral telemetry only.
    """
    try:
        _seq, previous_level, _stale = _prior(previous)
        observation = observe_cache_pressure_under_root(
            root_fd, root_uid=root_uid, cache_uid=cache_uid,
            warning_free_bytes=warning_free_bytes,
            critical_free_bytes=critical_free_bytes,
            recovery_margin_bytes=recovery_margin_bytes,
            previous_level=previous_level,
        )
        if (observation.get("status") != "READ_ONLY_CACHE_PRESSURE_PARTIAL"
                or observation.get("authorizes_installation") is not False
                or type(observation.get("cache_root_ownership_observed")) is not bool):
            raise ValueError("unexpected source observation")
        verified_root = observation["cache_root_ownership_observed"]
        alarm = evaluate_cache_pressure_alarm(
            free_bytes=(observation["free_bytes_observed"] if verified_root
                        else None),
            free_inodes=(observation["free_inodes_observed"] if verified_root
                         else None),
            disk_writable=(observation["disk_writable_observed"] if verified_root
                           else None),
            measurements_complete=False,  # statvfs is always incomplete
            warning_free_bytes=warning_free_bytes,
            critical_free_bytes=critical_free_bytes,
            recovery_margin_bytes=recovery_margin_bytes,
            previous=previous,
        )
        if (alarm.get("metrics_source_authenticated") is not False
                or alarm.get("authorizes_operator_alert_publish") is not False):
            raise ValueError("non-authorizing alarm boundary drift")
    except (ValueError, TypeError, RecursionError, KeyError, OverflowError):
        raise NativePressureAlarmObservationError(
            "NATIVE_PRESSURE_OBSERVATION_INVALID"
        ) from None
    return {
        "schema_version": 1,
        "status": "READ_ONLY_PARTIAL_PRESSURE_ALARM_CANDIDATE",
        "filesystem_observation": observation,
        "alarm_candidate": alarm,
        "nginx_writability_proven": False,
        "telemetry_complete": False,
        "prior_alarm_authenticated": False,
        "nginx_cache_manager_verified": False,
        "operator_alert_delivered": False,
        "authorizes_operator_alert_publish": False,
        "authorizes_nginx_cache_bypass": False,
        "authorizes_nginx_reload": False,
        "authorizes_cache_cleanup": False,
    }



def preview_observed_cache_pressure_alarm_with_selected_usage(
    root_fd: int, *, root_uid: int, cache_uid: int, cache_gid: int,
    repository_ids: tuple[str, ...],
    warning_free_bytes: int, critical_free_bytes: int,
    recovery_margin_bytes: int, previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Join strictly selected cache occupancy to conservative partial pressure.

    This returns two sequential descriptor-pinned *fixture* observations,
    NEVER an atomic snapshot or complete installed cache inventory.
    Unowned/missing/malformed repositories and root drift fail the entire
    observation instead of reporting missing usage as zero.
    """
    try:
        # Scan the selected ownership markers first; no pressure result is
        # returned if a single repository cannot be verified.
        selected = preview_owned_repository_cache_usage_under_root(
            root_fd, root_uid=root_uid, cache_uid=cache_uid,
            cache_gid=cache_gid, repository_ids=repository_ids,
        )
        alarm = preview_observed_cache_pressure_alarm(
            root_fd, root_uid=root_uid, cache_uid=cache_uid,
            warning_free_bytes=warning_free_bytes,
            critical_free_bytes=critical_free_bytes,
            recovery_margin_bytes=recovery_margin_bytes, previous=previous,
        )
        observation = alarm["filesystem_observation"]
        candidate = alarm["alarm_candidate"]
        # Neither observation can authenticate the root/metric producer,
        # certify complete occupancy, prove actual reclaimable space, or
        # authorize any installed action. Assert this at the seam, rather
        # than relying on future source changes to preserve these flags.
        if (type(selected) is not dict
                or selected.get("status") != "SELECTED_CACHE_USAGE_OBSERVATION_ONLY"
                or selected.get("selected_repository_count") != len(repository_ids)
                or selected.get("full_cache_inventory_verified") is not False
                or selected.get("multi_repository_snapshot_atomic") is not False
                or selected.get("authorizes_cache_cleanup") is not False
                or selected.get("authorizes_nginx_reload") is not False
                or selected.get("actual_reclaimable_space_verified") is not False
                or type(alarm) is not dict
                or alarm.get("status") != "READ_ONLY_PARTIAL_PRESSURE_ALARM_CANDIDATE"
                or alarm.get("telemetry_complete") is not False
                or alarm.get("authorizes_operator_alert_publish") is not False
                or type(observation) is not dict
                or observation.get("cache_root_ownership_observed") is not True
                or type(candidate) is not dict
                or candidate.get("measurements_complete") is not False
                or candidate.get("metrics_source_authenticated") is not False
                or type(candidate.get("next_state")) is not dict
                or candidate["next_state"].get("telemetry_stale") is not True):
            raise ValueError("inconsistent partial observation boundary")

        rows = selected.get("selected_repository_usage")
        counts = ("cache_files_observed", "cache_directories_observed",
                  "apparent_file_bytes_observed", "allocated_file_bytes_observed")
        if (type(rows) is not list or len(rows) != len(repository_ids)
                or any(type(row) is not dict for row in rows)
                or sorted(row.get("repository_id") for row in rows)
                   != sorted(repository_ids)):
            raise ValueError("unverified selected repositories")
        for field in counts:
            if (any(type(row.get(field)) is not int or row[field] < 0
                    for row in rows)
                    or type(selected.get(field)) is not int
                    or selected[field] != sum(row[field] for row in rows)):
                raise ValueError("inconsistent selected cache counters")
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise NativePressureAlarmObservationError(
            "NATIVE_PRESSURE_SELECTED_USAGE_INVALID"
        ) from None

    return {
        "schema_version": 1,
        "status": "READ_ONLY_SELECTED_USAGE_PARTIAL_PRESSURE_CANDIDATE",
        "selected_cache_usage": selected,
        "partial_pressure_alarm": alarm,
        "observed_selected_allocated_bytes": selected[
            "allocated_file_bytes_observed"
        ],
        "observed_filesystem_free_bytes": observation["free_bytes_observed"],
        "selected_ids_complete_or_authenticated": False,
        "cross_sample_atomic": False,
        "nginx_writability_proven": False,
        "actual_reclaimable_space_verified": False,
        "telemetry_complete": False,
        "prior_alarm_authenticated": False,
        "authorizes_operator_alert_publish": False,
        "authorizes_nginx_cache_bypass": False,
        "authorizes_nginx_reload": False,
        "authorizes_cache_cleanup": False,
        "authorizes_state_commit": False,
    }
