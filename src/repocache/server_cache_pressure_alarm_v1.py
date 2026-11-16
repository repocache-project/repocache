"""Deterministic, non-authorizing native cache-pressure alarm transitions (#97).

Preserves the last confirmed alarm on incomplete telemetry. Produces
candidate events only: no host writes, NGINX eviction or client-source edits.
"""
from __future__ import annotations

from typing import Any

from repocache.server_cache_pressure_policy_v1 import (
    CachePressurePolicyError, MAX_INT, preview_cache_pressure,
)

_LEVELS = frozenset(("normal", "warning", "critical", "unknown"))
_STATE_KEYS = frozenset(("schema_version", "sequence", "alarm_level",
                         "telemetry_stale"))
_SEVERITY = {"unknown": -1, "normal": 0, "warning": 1, "critical": 2}


class CachePressureAlarmError(ValueError):
    """Static refusal code; never logs filesystem or repository paths."""


def _prior(value: Any) -> tuple[int, str, bool]:
    if value is None:
        return 0, "unknown", False
    if (type(value) is not dict or value.keys() != _STATE_KEYS
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["sequence"]) is not int
            or not 0 <= value["sequence"] < MAX_INT
            or type(value["alarm_level"]) is not str
            or value["alarm_level"] not in _LEVELS
            or type(value["telemetry_stale"]) is not bool):
        raise CachePressureAlarmError("CACHE_ALARM_PREVIOUS_STATE_INVALID")
    return value["sequence"], value["alarm_level"], value["telemetry_stale"]


def evaluate_cache_pressure_alarm(
    *, free_bytes: int | None, free_inodes: int | None,
    warning_free_bytes: int, critical_free_bytes: int,
    recovery_margin_bytes: int, disk_writable: bool | None,
    measurements_complete: bool,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reduce one filesystem/metrics observation into a stable alarm event.

    A caller must persist next_state in separately authenticated protected
    state before it can issue authoritative operator notifications. Here,
    free space and prior state are *untrusted inputs* for CI/planning only.
    """
    sequence, prev_level, stale_before = _prior(previous)
    # A successor must itself remain a valid, replayable prior state.
    if sequence >= MAX_INT - 1:
        raise CachePressureAlarmError("CACHE_ALARM_SEQUENCE_EXHAUSTED")
    if free_inodes is not None and (
        type(free_inodes) is not int or not 0 <= free_inodes <= MAX_INT
    ):
        raise CachePressureAlarmError("CACHE_ALARM_INODE_COUNT_INVALID")
    try:
        policy = preview_cache_pressure(
            free_bytes=free_bytes, warning_free_bytes=warning_free_bytes,
            critical_free_bytes=critical_free_bytes,
            recovery_margin_bytes=recovery_margin_bytes,
            previous_level=prev_level, measurements_complete=measurements_complete,
            disk_writable=disk_writable,
        )
    except CachePressurePolicyError:
        raise CachePressureAlarmError("CACHE_ALARM_POLICY_INVALID") from None

    level = policy["pressure_level"]
    reason = policy["reason_code"]
    # A fully measured free byte counter does not prove free inodes;
    # stale/incomplete metrics cannot dismiss a prior warning/critical.
    complete = (measurements_complete and free_bytes is not None
                and free_inodes is not None and disk_writable is not None)
    hard_refusal = disk_writable is False or free_inodes == 0
    if free_inodes == 0:
        level, reason = "critical", "FILESYSTEM_INODES_EXHAUSTED"
    if not complete and not hard_refusal:
        if _SEVERITY[prev_level] > _SEVERITY[level]:
            level, reason = prev_level, "ALARM_HELD_ON_INCOMPLETE_TELEMETRY"
        elif level == "normal":
            # Prevent optimistic NORMAL without a complete measurement.
            level, reason = "unknown", "TELEMETRY_INCOMPLETE"
    stale = not complete
    events: list[str] = []
    if stale and not stale_before:
        events.append("CACHE_TELEMETRY_INCOMPLETE")
    if not stale and stale_before:
        events.append("CACHE_TELEMETRY_RESTORED")
    if level != prev_level:
        if _SEVERITY[level] > _SEVERITY[prev_level]:
            events.append("CACHE_PRESSURE_" + level.upper())
        elif level == "normal" and prev_level in ("warning", "critical"):
            events.append("CACHE_PRESSURE_RECOVERED")
        elif level == "warning" and prev_level == "critical" and complete:
            events.append("CACHE_PRESSURE_DOWNGRADED")
    return {
        "schema_version": 1,
        "status": "INERT_CACHE_PRESSURE_ALARM_CANDIDATE",
        "next_state": {
            "schema_version": 1,
            "sequence": sequence + 1,
            "alarm_level": level,
            "telemetry_stale": stale,
        },
        "event_codes": events,
        "reason_code": reason,
        "free_bytes_observed": free_bytes,
        "free_inodes_observed": free_inodes,
        "measurements_complete": complete,
        "last_state_authenticated": False,
        "metrics_source_authenticated": False,
        "authorizes_cache_delete": False,
        "authorizes_nginx_policy_apply": False,
        "authorizes_client_fallback_apply": False,
        "authorizes_operator_alert_publish": False,
    }
