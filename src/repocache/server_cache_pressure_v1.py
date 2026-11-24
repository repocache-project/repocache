"""Read-only disk pressure evaluation for native NGINX cache policy (#97).

The caller owns acquisition and completeness of filesystem and cache metrics.
A proposal is never permission to change NGINX, cache objects or client sources.
No filesystem, network, process or privileged action is performed here.
"""
from __future__ import annotations

from typing import Any

from repocache.server_install_v1 import validate_install_document

MAX_BYTES = 2**63 - 1
LEVELS = frozenset(("unknown", "normal", "warning", "critical"))


class CachePressureError(ValueError):
    """Fixed redacted validation codes, not operator-supplied measurements."""


def _deny(code: str) -> None:
    raise CachePressureError("CACHE_PRESSURE_" + code)


def _metric(value: Any, *, allow_none: bool) -> bool:
    if value is None and allow_none:
        return False
    if type(value) is not int or not 0 <= value <= MAX_BYTES:
        _deny("METRIC_INVALID")
    return True


def evaluate_cache_pressure(
    document: Any, *,
    filesystem_total_bytes: int | None,
    filesystem_free_bytes: int | None,
    cache_used_bytes: int | None,
    sample_complete: bool,
    previous_level: str = "unknown",
    recovery_hysteresis_bytes: int = 0,
) -> dict[str, Any]:
    """Evaluate a complete, coherent observation against validated policy.

    Thresholds are the existing install-v1 warning/critical free-byte values.
    The hysteresis setting is an explicit *evaluation input*, not a persisted
    or installed configuration change. Previous alerts transition down in
    severity immediately, but recover only above threshold + hysteresis.
    Missing or partial data returns unknown; it is never interpreted as zero
    usage or used to authorize pressure mitigation.
    """
    if type(sample_complete) is not bool:
        _deny("COMPLETENESS_INVALID")
    if type(previous_level) is not str or previous_level not in LEVELS:
        _deny("PREVIOUS_LEVEL_INVALID")
    _metric(recovery_hysteresis_bytes, allow_none=False)
    try:
        snapshot = validate_install_document(document, for_apply=True)
    except (ValueError, TypeError, RecursionError):
        _deny("POLICY_INVALID")
    limits = snapshot["deployment"]["cache_policy"]["disk_pressure"]
    warning = limits["warning_free_bytes"]
    critical = limits["critical_free_bytes"]

    observations = (filesystem_total_bytes, filesystem_free_bytes,
                    cache_used_bytes)
    complete_fields = all(_metric(value, allow_none=True) for value in observations)
    complete = sample_complete and complete_fields
    if complete:
        total, free, used = observations
        if total == 0 or free > total or used > total - free:
            _deny("METRICS_INCONSISTENT")
        if free < critical:
            raw = "critical"
        elif free < warning:
            raw = "warning"
        else:
            raw = "normal"

        if previous_level == "critical" and raw != "critical":
            if free < critical + recovery_hysteresis_bytes:
                level = "critical"
            elif free < warning + recovery_hysteresis_bytes:
                level = "warning"
            else:
                level = "normal"
        elif previous_level == "warning" and raw == "normal":
            level = ("warning" if free < warning + recovery_hysteresis_bytes
                     else "normal")
        else:
            level = raw
    else:
        level = "unknown"

    advisory = {
        "unknown": "RECHECK_COMPLETE_METRICS",
        "normal": "NO_PRESSURE_ALERT",
        "warning": "INSPECT_CACHE_CAPACITY",
        "critical": "INSPECT_DISK_AND_UPSTREAM_FALLBACK",
    }[level]
    return {
        "schema_version": 1,
        "status": "CACHE_PRESSURE_READ_ONLY_OBSERVATION",
        "level": level,
        "measurement_complete": complete,
        "previous_level": previous_level,
        "warning_free_bytes": warning,
        "critical_free_bytes": critical,
        "recovery_hysteresis_bytes": recovery_hysteresis_bytes,
        "action_advisory": advisory,
        "no_pressure_in_sample": level == "normal",
        "native_cache_eviction_observed": False,
        "native_nginx_capability_verified": False,
        "authorizes_cache_deletion": False,
        "authorizes_nginx_reload": False,
        "authorizes_client_source_change": False,
    }
