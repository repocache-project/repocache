"""Fixed, opt-in NGINX metrics logrotate candidate from install-v1 (#29).

Do not install this candidate without independently verified root-owned
log paths, effective vendor systemd NGINX unit and a signed root transaction.
"""
from __future__ import annotations

from typing import Any

from repocache.server_install_v1 import validate_install_document

_ROOT = "/var/log/nginx/repocache-managed"
_LOG = _ROOT + "/metrics.jsonl"
_REOPEN = "/usr/bin/systemctl kill --kill-who=main --signal=USR1 nginx.service"


class NativeMetricsRotationCandidateError(ValueError):
    """Redacted fixed-code candidate refusal."""


def render_native_metrics_rotation_candidate(
    document: dict[str, Any],
) -> dict[str, Any]:
    """Propose a restricted logrotate profile without touching a host.

    The unit reopen hook is fixed; the renderer does NOT authenticate the
    service it might later signal. Activation MUST remain withheld until
    a signed installer pins NGINX unit ownership under the state lock.
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
            "    sharedscripts\n"
            "    postrotate\n"
            f"        {_REOPEN}\n"
            "    endscript\n"
            "}\n"
        )
    return {
        "schema_version": 1,
        "status": "FIXED_METRICS_LOGROTATE_CANDIDATE_ONLY",
        "enabled": enabled,
        "rotation_candidate": content,
        "retention_days": days if enabled else None,
        "managed_log_path": _LOG if enabled else None,
        "requires_exact_vendor_nginx_unit": enabled,
        "requires_authenticated_root_install": enabled,
        "actual_nginx_reopen_verified": False,
        "live_log_retention_verified": False,
        "authorizes_logrotate_installation": False,
        "authorizes_nginx_signal": False,
    }
