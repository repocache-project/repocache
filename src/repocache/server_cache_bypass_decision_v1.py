"""Pure pressure-to-NGINX cache-bypass recovery proposal (#97).

This is an untrusted, non-activating Stage-A decision. It never reads a
filesystem, interrogates NGINX, restores a service, writes trusted state or
selects a genuine administrator-approved configuration. An installed worker
must separately authenticate the pressure observation, durable previous
state, host root, NGINX transaction and all privileges before any effect.
"""
from __future__ import annotations

from typing import Any

from repocache.server_cache_pressure_alarm_v1 import (
    CachePressureAlarmError, evaluate_cache_pressure_alarm,
)
from repocache.server_install_v1 import validate_install_document
from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError, render_repository_nginx_bundle_candidate,
)

_HARD_CRITICAL_REASONS = frozenset((
    "STORAGE_WRITE_REFUSED",
    "FILESYSTEM_INODES_EXHAUSTED",
    "CRITICAL_FREE_SPACE",
))


class CachePressureBypassError(ValueError):
    """Static rejection code; never reveal caller source names or host paths."""


def preview_cache_pressure_nginx_recovery_candidate(
    document: dict[str, Any],
    *,
    expected_state_generation: int,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
    free_bytes: int | None,
    free_inodes: int | None,
    disk_writable: bool | None,
    measurements_complete: bool,
    recovery_margin_bytes: int,
    previous_alarm: dict[str, Any] | None = None,
    previously_bypassed_ids: tuple[str, ...] = (),
    native_min_free_supported: bool = False,
) -> dict[str, Any]:
    """Propose cache-off for observed critical pressure, or a safe restore.

    Scope is all *desired-active* repository routes only. Never call this a
    current exposure map: desired state, prior bypass and measured counters
    are caller-supplied, unauthenticated information. Incomplete telemetry
    cannot clear an existing bypass. A directly observed read-only cache,
    exhausted inodes or critical free bytes may propose immediate bypass,
    but never dispatch or reload an installed NGINX service.
    """
    try:
        snapshot = validate_install_document(document, for_apply=True)
        # Render before classifying to exercise the exact pin/CA/generation
        # constraints. A partial invalid bundle is never returned.
        normal = render_repository_nginx_bundle_candidate(
            snapshot,
            expected_state_generation=expected_state_generation,
            candidate_pins_by_repository=candidate_pins_by_repository,
            ca_bundle_path=ca_bundle_path,
            native_min_free_supported=native_min_free_supported,
        )
        active = tuple(normal["proposed_repository_ids"])
        if (type(previously_bypassed_ids) is not tuple
                or len(previously_bypassed_ids) > len(active)
                or any(type(item) is not str for item in previously_bypassed_ids)
                or len(set(previously_bypassed_ids)) != len(previously_bypassed_ids)
                or not set(previously_bypassed_ids).issubset(active)):
            raise CachePressureBypassError("CACHE_BYPASS_PRIOR_IDS_INVALID")

        thresholds = snapshot["deployment"]["cache_policy"]["disk_pressure"]
        alarm = evaluate_cache_pressure_alarm(
            free_bytes=free_bytes,
            free_inodes=free_inodes,
            disk_writable=disk_writable,
            measurements_complete=measurements_complete,
            warning_free_bytes=thresholds["warning_free_bytes"],
            critical_free_bytes=thresholds["critical_free_bytes"],
            recovery_margin_bytes=recovery_margin_bytes,
            previous=previous_alarm,
        )
        level = alarm["next_state"]["alarm_level"]
        # A directly observed hard failure must not be hidden by absent
        # peripheral metrics. Stale historic alarm state, alone, cannot
        # invent a *new* failure and cannot authorize an NGINX change.
        confirmed_critical = (
            level == "critical"
            and (
                alarm["measurements_complete"]
                or alarm["reason_code"] in _HARD_CRITICAL_REASONS
            )
        )
        if confirmed_critical:
            selected = active
            decision = "PROPOSE_BYPASS_ON_OBSERVED_CRITICAL"
        elif level == "normal" and alarm["measurements_complete"]:
            selected = ()
            decision = "PROPOSE_RESTORE_AFTER_VERIFIED_RECOVERY"
        else:
            selected = previously_bypassed_ids
            decision = "HOLD_LAST_BYPASS_WHILE_NOT_RECOVERED"

        candidate = render_repository_nginx_bundle_candidate(
            snapshot,
            expected_state_generation=expected_state_generation,
            candidate_pins_by_repository=candidate_pins_by_repository,
            ca_bundle_path=ca_bundle_path,
            native_min_free_supported=native_min_free_supported,
            cache_bypass_repository_ids=selected,
        )
        # No scenario may alter the pinned upstream or cache-path policy;
        # only the selected existing location's proxy_cache value may vary.
        if (candidate["http_upstream_fragment"]
                != normal["http_upstream_fragment"]
                or candidate["proposed_repository_ids"]
                != normal["proposed_repository_ids"]):
            raise CachePressureBypassError("CACHE_BYPASS_RENDER_CHANGED")
    except CachePressureBypassError:
        raise
    except (CachePressureAlarmError, NginxRepositoryBundleError,
            ValueError, TypeError, KeyError, RecursionError):
        raise CachePressureBypassError("CACHE_BYPASS_CANDIDATE_INVALID") from None

    return {
        "schema_version": 1,
        "status": "NON_ACTIVATING_PRESSURE_BYPASS_CANDIDATE",
        "decision_code": decision,
        "alarm_candidate": alarm,
        "bypass_repository_ids": candidate[
            "cache_bypass_recovery_candidate_repository_ids"
        ],
        "nginx_candidate": candidate,
        "metrics_source_authenticated": False,
        "previous_alarm_state_authenticated": False,
        "previous_bypass_state_authenticated": False,
        "installed_nginx_exposure_verified": False,
        "host_root_authenticated": False,
        "nginx_manager_recovery_verified": False,
        "authorizes_nginx_policy_apply": False,
        "authorizes_nginx_reload": False,
        "authorizes_cache_cleanup": False,
        "authorizes_catalog_publication": False,
        "authorizes_client_fallback_apply": False,
    }
