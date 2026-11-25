"""Fixed, opt-in NGINX metrics logrotate candidate from install-v1 (#29).

Do not install this candidate without independently verified root-owned
log paths, effective dedicated REPOCACHE NGINX unit and a signed root transaction.
"""
from __future__ import annotations

from typing import Any

from repocache.server_install_v1 import validate_install_document

_ROOT = "/var/log/nginx/repocache-managed"
_LOG = _ROOT + "/metrics.jsonl"
_OWNED_UNIT = "repocache-nginx.service"


class NativeMetricsRotationCandidateError(ValueError):
    """Redacted fixed-code candidate refusal."""


def render_native_metrics_rotation_candidate(
    document: dict[str, Any],
) -> dict[str, Any]:
    """Propose a restricted logrotate profile without touching a host.

    The profile intentionally has no service hook. It is a transaction input,
    not a standalone scheduled profile. A signed worker must hold the state
    lock, reconcile the rotated inode, and verify reopen of the owned unit.
    The vendor NGINX service must never be signalled by this candidate.
    """
    try:
        doc = validate_install_document(document, for_apply=True)
        dep = doc["deployment"]
        if dep["paths"]["log_root"] != _ROOT:
            raise ValueError("unsupported managed log namespace")
        enabled = dep["logging"].get("metrics_opt_in", False)
        days = dep["logging"]["retention_days"]
        # Already validated as bool and 1..3650 by the closed v1 schema.
        if type(enabled) is not bool or type(days) is not int:
            raise ValueError("invalid logging policy")
    except (ValueError, KeyError, TypeError, RecursionError):
        raise NativeMetricsRotationCandidateError(
            "METRICS_ROTATION_DOCUMENT_INVALID"
        ) from None

    if not enabled:
        content = ""
    else:
        content = (
            _LOG + " {\n"
            "    daily\n"
            f"    rotate {days}\n"
            "    missingok\n"
            "    notifempty\n"
            "    compress\n"
            "    delaycompress\n"
            "    create 0600 root root\n"
            "}\n"
        )
    return {
        "schema_version": 1,
        "status": "FIXED_METRICS_LOGROTATE_CANDIDATE_ONLY",
        "enabled": enabled,
        "rotation_candidate": content,
        "retention_days": days if enabled else None,
        "managed_log_path": _LOG if enabled else None,
        "requires_exact_vendor_nginx_unit": False,
        "required_owned_nginx_unit": _OWNED_UNIT if enabled else None,
        "requires_locked_rotation_transaction": enabled,
        "requires_external_reopen_after_marker_reconcile": enabled,
        "authorizes_standalone_scheduled_rotation": False,
        "requires_authenticated_root_install": enabled,
        "actual_nginx_reopen_verified": False,
        "live_log_retention_verified": False,
        "authorizes_logrotate_installation": False,
        "authorizes_nginx_signal": False,
    }
