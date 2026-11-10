"""Pure, non-authorizing native-cache pressure policy preview (#97).

This module neither probes filesystems nor reads NGINX state. The caller
supplies explicitly qualified observations; incomplete telemetry cannot
turn into an invented zero or an assertion of healthy storage. Activation,
cache deletion, upstream fallback and host safety require separate owners.
"""
from __future__ import annotations

from typing import Any

MAX_INT = 2**63 - 1
LEVELS = frozenset(("unknown", "normal", "warning", "critical"))


class CachePressurePolicyError(ValueError):
    """Fixed-code refusal without leaking storage paths or repository data."""


def _unsigned(value: Any, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or not (1 if positive else 0) <= value <= MAX_INT:
        raise CachePressurePolicyError("CACHE_PRESSURE_" + name + "_INVALID")
    return value


def preview_cache_pressure(
    *,
    free_bytes: int | None,
    warning_free_bytes: int,
    critical_free_bytes: int,
    recovery_margin_bytes: int,
    previous_level: str,
    measurements_complete: bool,
    disk_writable: bool | None,
) -> dict[str, Any]:
    """Classify observations with conservative hysteresis, never mutate.

    Free space is a filesystem observation, NOT cache occupancy, eviction
    success or a hard quota. No measured value implies nothing about
    missing cache objects. A known low-space or read-only condition remains
    visible even if other metrics are incomplete; otherwise the outcome is
    unknown until all required observations are available.

    Recovery from critical needs > critical + margin, and recovery from
    warning needs > warning + margin; escalation is immediate at or below
    thresholds. A large margin may conservatively retain an alarm.
    """
    warning = _unsigned(warning_free_bytes, "WARNING", positive=True)
    critical = _unsigned(critical_free_bytes, "CRITICAL", positive=True)
    margin = _unsigned(recovery_margin_bytes, "MARGIN")
    if warning < critical:
        raise CachePressurePolicyError("CACHE_PRESSURE_THRESHOLD_ORDER_INVALID")
    if type(previous_level) is not str or previous_level not in LEVELS:
        raise CachePressurePolicyError("CACHE_PRESSURE_PREVIOUS_LEVEL_INVALID")
    if type(measurements_complete) is not bool:
        raise CachePressurePolicyError("CACHE_PRESSURE_TELEMETRY_INVALID")
    if disk_writable is not None and type(disk_writable) is not bool:
        raise CachePressurePolicyError("CACHE_PRESSURE_WRITABILITY_INVALID")
    if free_bytes is not None:
        _unsigned(free_bytes, "FREE_BYTES")

    if disk_writable is False:
        level, cause = "critical", "STORAGE_WRITE_REFUSED"
    elif free_bytes is None:
        level, cause = "unknown", "FREE_SPACE_UNAVAILABLE"
    elif free_bytes <= critical:
        level, cause = "critical", "CRITICAL_FREE_SPACE"
    elif previous_level == "critical" and free_bytes <= critical + margin:
        level, cause = "critical", "CRITICAL_RECOVERY_HYSTERESIS"
    elif free_bytes <= warning:
        level, cause = "warning", "LOW_FREE_SPACE"
    elif previous_level in ("critical", "warning") and free_bytes <= warning + margin:
        level, cause = "warning", "WARNING_RECOVERY_HYSTERESIS"
    elif not measurements_complete or disk_writable is None:
        level, cause = "unknown", "OBSERVATION_INCOMPLETE"
    else:
        level, cause = "normal", "THRESHOLDS_SATISFIED"

    return {
        "status": "POLICY_PREVIEW_ONLY",
        "pressure_level": level,
        "reason_code": cause,
        "previous_level": previous_level,
        "free_bytes_observed": free_bytes,
        "measurements_complete": measurements_complete,
        "disk_writable_observed": disk_writable,
        "recovery_margin_bytes": margin,
        "nginx_manager_behavior_verified": False,
        "cache_occupancy_verified": False,
        "upstream_fallback_verified": False,
        "authorizes_nginx_policy_apply": False,
        "authorizes_cache_cleanup": False,
        "authorizes_source_rewrite": False,
    }
