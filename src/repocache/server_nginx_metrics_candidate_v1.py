"""Deterministic opt-in per-repository NGINX metric logging candidate (#29).

Source-only, nonactivating fragments. Never make independent routes, override
existing audited logs or treat the desired-active config as live exposure.
"""
from __future__ import annotations

from typing import Any

from repocache.server_install_v1 import validate_install_document

# Fixed installer-owned log leaf, not JSON or operator input.
# The installed CLI must be explicitly configured to read this location.
METRICS_LOG = "/var/log/nginx/repocache-managed/metrics.jsonl"
_NGINX_FORMAT = (
    "log_format repocache_metrics escape=json\n"
    "    '{\"time_iso8601\":\"$time_iso8601\",'\n"
    "    '\"repocache_repository\":\"$repocache_metric_repo\",'\n"
    "    '\"status\":\"$status\",'\n"
    "    '\"upstream_cache_status\":\"$upstream_cache_status\",'\n"
    "    '\"body_bytes_sent\":\"$body_bytes_sent\",'\n"
    "    '\"request_time\":\"$request_time\"}';\n"
)


class NginxMetricsCandidateError(ValueError):
    """Fixed refusal codes; never quote untrusted repository fields."""


def render_nginx_metrics_candidate(document: dict[str, Any]) -> dict[str, Any]:
    """Propose format and location additions for validated active IDs.

    This remains strictly separate from the authoritative route generator.
    There is no live state, operator, ownership, log-inheritance or protected
    transaction verification; this result cannot be spliced into production
    NGINX until an independently reviewed manager performs those checks.
    """
    try:
        doc = validate_install_document(document, for_apply=True)
    except (ValueError, TypeError, RecursionError):
        raise NginxMetricsCandidateError("NGINX_METRICS_DOCUMENT_INVALID") from None

    enabled = doc["deployment"]["logging"]["metrics_opt_in"]
    # The closed install contract validates the Boolean and lowercase IDs.
    active = {}
    if enabled:
        for repo in doc["repositories"]:
            if repo["desired_state"] != "active":
                continue
            if "id" not in repo:
                raise NginxMetricsCandidateError(
                    "NGINX_METRICS_ACTIVE_ID_UNALLOCATED"
                )
            name = repo["id"]
            if name in active:
                raise NginxMetricsCandidateError(
                    "NGINX_METRICS_DUPLICATE_ID"
                )
            active[name] = (
                f'set $repocache_metric_repo "/__repocache/repos/{name}/";\n'
                f"access_log {METRICS_LOG} repocache_metrics;\n"
            )
    return {
        "schema_version": 1,
        "status": "NGINX_METRICS_CANDIDATE_ONLY",
        "opt_in_requested": enabled,
        "http_log_format_fragment": _NGINX_FORMAT if enabled and active else "",
        "location_directives_by_repository": dict(sorted(active.items())),
        "metrics_path_candidate": METRICS_LOG if enabled and active else None,
        "requires_approved_route_binding": bool(active),
        "audit_logging_inheritance_verified": False,
        "nginx_syntax_verified": False,
        "active_exposure_verified": False,
        "managed_log_ownership_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
    }
