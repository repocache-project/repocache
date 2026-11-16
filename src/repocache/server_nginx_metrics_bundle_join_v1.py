"""Compose repository routing and opt-in metrics as one inert NGINX candidate.

Issue #28/#29: join *existing* validated renderers without making a second
routing database, and refuse partial, unexpected or duplicate locations.
This code has no service, network, filesystem or publication side effects.
"""
from __future__ import annotations

from typing import Any

from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError, render_repository_nginx_bundle_candidate,
)
from repocache.server_nginx_metrics_candidate_v1 import (
    NginxMetricsCandidateError, render_nginx_metrics_candidate,
)

_LIMIT = 1_048_576


class JoinedNginxCandidateError(ValueError):
    """Finite refusal code without untrusted repository or path text."""


def render_repository_nginx_metrics_join(
    document: dict[str, Any], *, expected_state_generation: int,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
) -> dict[str, Any]:
    """Bind metrics to each generated repository location, not to new routes.

    It is intentionally NOT an authoritative NGINX configuration: inherited
    audit logs must be reviewed and retained by the future privileged
    transaction, with exact host nginx -t and rollback before activation.
    """
    try:
        bundle = render_repository_nginx_bundle_candidate(
            document, expected_state_generation=expected_state_generation,
            candidate_pins_by_repository=candidate_pins_by_repository,
            ca_bundle_path=ca_bundle_path,
        )
        metrics = render_nginx_metrics_candidate(document)
    except (NginxRepositoryBundleError, NginxMetricsCandidateError,
            ValueError, TypeError):
        raise JoinedNginxCandidateError("JOINED_NGINX_INPUT_INVALID") from None

    identifiers = bundle["proposed_repository_ids"]
    decorations = metrics["location_directives_by_repository"]
    if (type(identifiers) is not list or type(decorations) is not dict
            or (metrics["opt_in_requested"] and set(decorations) != set(identifiers))
            or (not metrics["opt_in_requested"] and bool(decorations))):
        raise JoinedNginxCandidateError("JOINED_NGINX_ROUTE_SET_MISMATCH")
    server = bundle["server_location_fragment"]
    baseline = server
    for repository_id in identifiers:
        marker = f"location ^~ /__repocache/repos/{repository_id}/ {{\n"
        if server.count(marker) != 1:
            raise JoinedNginxCandidateError("JOINED_NGINX_ROUTE_AMBIGUOUS")
        if repository_id in decorations:
            directive = decorations[repository_id]
            if (type(directive) is not str or "\r" in directive
                    or not directive.endswith(";\n")
                    or "location " in directive
                    or len(directive) > 512):
                raise JoinedNginxCandidateError("JOINED_NGINX_METRIC_UNSAFE")
            server = server.replace(marker, marker + directive, 1)
    http = metrics["http_log_format_fragment"] + bundle["http_upstream_fragment"]
    if (len(http.encode("utf-8")) + len(server.encode("utf-8")) > _LIMIT
            or server.count("location ^~ /__repocache/repos/") != len(identifiers)
            or (not metrics["opt_in_requested"] and server != baseline)):
        raise JoinedNginxCandidateError("JOINED_NGINX_OUTPUT_INVALID")
    return {
        "schema_version": 1,
        "status": "ROUTES_AND_METRICS_JOINED_CANDIDATE_ONLY",
        "http_fragment": http,
        "server_fragment": server,
        "proposed_repository_ids": list(identifiers),
        "metrics_enabled": metrics["opt_in_requested"],
        "metrics_repository_ids": sorted(decorations),
        "audited_existing_access_log_inheritance": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "trusted_active_state_verified": False,
    }
