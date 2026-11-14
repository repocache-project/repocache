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
