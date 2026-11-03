"""Pure, non-authorizing multi-repository NGINX candidate assembly (#28).

The reviewed #18/#95 declarative document is only a proposed configuration.
Even desired_state=active and a complete candidate pin snapshot do NOT prove
operator approval, protected state, current generation, installed exposure or
catalog eligibility. Only a future privileged, locked transaction can decide
whether to activate a staged configuration and publish discovery.
"""
from __future__ import annotations

from typing import Any

from repocache.server_install_v1 import MAX_INT, validate_install_document
from repocache.server_nginx_pin_render_v1 import (
    PinnedNginxError,
    render_pinned_upstream_fragments,
)

_MAX_BUNDLE_BYTES = 1024 * 1024


class NginxRepositoryBundleError(ValueError):
    """Redacted failure: no attacker-controlled host, pin or path values."""


def render_repository_nginx_bundle_candidate(
    document: dict[str, Any],
    *,
    expected_state_generation: int,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
) -> dict[str, Any]:
    """Compose only desired-active, fully identified v1 repository fragments.

    Every desired-active repository must supply one complete candidate IP set;
    disabled and unknown IDs cannot be present. No partial bundle on failure.
    This is not a complete nginx.conf or a runtime authorization decision.

    The caller MUST NOT use proposed_repository_ids as a discovery catalog:
    it is an untrusted plan, not a record of actually exposed routes.
    """
    if (type(expected_state_generation) is not int
            or not 0 <= expected_state_generation <= MAX_INT):
        raise NginxRepositoryBundleError("NGINX_BUNDLE_GENERATION_INVALID")
    try:
        snapshot = validate_install_document(document, for_apply=True)
    except (ValueError, TypeError, RecursionError):
        raise NginxRepositoryBundleError("NGINX_BUNDLE_DOCUMENT_INVALID") from None
    if snapshot["expected_state_generation"] != expected_state_generation:
        raise NginxRepositoryBundleError("NGINX_BUNDLE_STALE_GENERATION")

    active: dict[str, dict[str, Any]] = {}
    for repository in snapshot["repositories"]:
        if repository["desired_state"] == "active":
            repository_id = repository.get("id")
            if repository_id is None:
                raise NginxRepositoryBundleError("NGINX_BUNDLE_UNALLOCATED_REPOSITORY")
            active[repository_id] = repository
    if (type(candidate_pins_by_repository) is not dict
            or len(candidate_pins_by_repository) != len(active)
            or set(candidate_pins_by_repository) != set(active)):
        raise NginxRepositoryBundleError("NGINX_BUNDLE_PIN_SET_INCOMPLETE")

    upstreams: list[str] = []
    locations: list[str] = []
    pin_count = 0
    for repository_id in sorted(active):
        # Reuse the existing strict #215 renderer and its complete DNS
        # snapshot checks, but validate a single entry rather than repeatedly
        # revalidating an entire potentially 500-repository document.
        scoped = {**snapshot, "repositories": [active[repository_id]]}
        try:
            fragment = render_pinned_upstream_fragments(
                scoped,
                repository_id=repository_id,
                candidate_pins_by_host=candidate_pins_by_repository[repository_id],
                ca_bundle_path=ca_bundle_path,
            )
        except (ValueError, TypeError):
            raise NginxRepositoryBundleError("NGINX_BUNDLE_UNSAFE_CANDIDATE") from None
        upstreams.append(fragment["http_upstream_fragment"])
        locations.append(fragment["server_location_fragment"])
        pin_count += fragment["pin_count"]

    http_fragment = "".join(upstreams)
    server_fragment = "".join(locations)
    if (len(http_fragment.encode("utf-8"))
            + len(server_fragment.encode("utf-8")) > _MAX_BUNDLE_BYTES):
        raise NginxRepositoryBundleError("NGINX_BUNDLE_SIZE_EXCEEDED")

    return {
        "schema_version": 1,
        "status": "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY",
        "expected_state_generation": expected_state_generation,
        "proposed_repository_ids": sorted(active),
        "http_upstream_fragment": http_fragment,
        "server_location_fragment": server_fragment,
        "pin_count": pin_count,
        "requires_nginx_t_and_activation": True,
        "trusted_state_provenance_verified": False,
        "operator_approval_verified": False,
        "active_exposure_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
    }
