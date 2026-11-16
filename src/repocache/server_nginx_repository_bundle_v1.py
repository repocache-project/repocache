"""Pure, non-authorizing multi-repository NGINX candidate assembly (#28).

The reviewed #18/#95 declarative document is only a proposed configuration.
Even desired_state=active and a complete candidate pin snapshot do NOT prove
operator approval, protected state, current generation, installed exposure or
catalog eligibility. Only a future privileged, locked transaction can decide
whether to activate a staged configuration and publish discovery.
"""
from __future__ import annotations

import re
from typing import Any

from repocache.server_install_v1 import MAX_INT, _path, validate_install_document
from repocache.server_nginx_tls_listener_candidate_v1 import (
    NativeTLSListenerCandidateError, render_native_tls_listener_candidate,
)
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
    native_min_free_supported: bool = False,
    cache_bypass_repository_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Compose only desired-active, fully identified v1 repository fragments.

    Every desired-active repository must supply one complete candidate IP set;
    disabled and unknown IDs cannot be present. No partial bundle on failure.
    This is not a complete nginx.conf or a runtime authorization decision.

    The caller MUST NOT use proposed_repository_ids as a discovery catalog:
    it is an untrusted plan, not a record of actually exposed routes.
    """
    if type(native_min_free_supported) is not bool:
        raise NginxRepositoryBundleError("NGINX_BUNDLE_MIN_FREE_CAPABILITY_INVALID")
    if (type(expected_state_generation) is not int
            or not 0 <= expected_state_generation <= MAX_INT):
        raise NginxRepositoryBundleError("NGINX_BUNDLE_GENERATION_INVALID")
    try:
        snapshot = validate_install_document(document, for_apply=True)
    except (ValueError, TypeError, RecursionError):
        raise NginxRepositoryBundleError("NGINX_BUNDLE_DOCUMENT_INVALID") from None
    if snapshot["expected_state_generation"] != expected_state_generation:
        raise NginxRepositoryBundleError("NGINX_BUNDLE_STALE_GENERATION")

    # Validate the fixed CA path even with zero desired-active repositories.
    # Inactive outputs must not become an input-validation bypass.
    if (type(ca_bundle_path) is not str or len(ca_bundle_path) > 2048
            or re.fullmatch(r"/[A-Za-z0-9_./+-]+", ca_bundle_path, re.ASCII)
            is None):
        raise NginxRepositoryBundleError("NGINX_BUNDLE_CA_INVALID")
    try:
        _path(ca_bundle_path, "CA reference")
    except ValueError:
        raise NginxRepositoryBundleError("NGINX_BUNDLE_CA_INVALID") from None

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
    # This pure candidate requests per-repository *read bypass*, not installed
    # policy or automatic pressure monitoring. Refuse every unknown/disabled
    # ID; a partial or mistyped request must not silently change routes.
    if (type(cache_bypass_repository_ids) is not tuple
            or len(cache_bypass_repository_ids) > len(active)
            or any(type(item) is not str for item in cache_bypass_repository_ids)
            or len(set(cache_bypass_repository_ids)) != len(cache_bypass_repository_ids)
            or not set(cache_bypass_repository_ids).issubset(active)):
        raise NginxRepositoryBundleError("NGINX_BUNDLE_BYPASS_IDS_INVALID")

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
                native_min_free_supported=native_min_free_supported,
                cache_bypass_for_recovery=(
                    repository_id in cache_bypass_repository_ids
                ),
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
        "native_min_free_candidate_emitted": native_min_free_supported and bool(active),
        "cache_bypass_recovery_candidate_repository_ids": sorted(cache_bypass_repository_ids),
        "cache_bypass_activation_verified": False,
        "native_min_free_supported_verified": False,
        "requires_nginx_t_and_activation": True,
        "trusted_state_provenance_verified": False,
        "operator_approval_verified": False,
        "active_exposure_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
    }



def render_repository_https_server_candidate(
    document: dict[str, Any],
    *,
    expected_state_generation: int,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
    native_min_free_supported: bool = False,
    cache_bypass_repository_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Compose a COMPLETE HTTPS server block and its http{} dependencies.

    This joins two already reviewed candidate-only renderers. A positive
    output is *not* a trusted root-owned include, signed operator approval,
    live service, authenticated TLS identity, firewall permission or catalog.
    A future #31/#64 writer must verify those independently under one lock.
    All-or-nothing assembly ensures the TLS and repository fragments share
    the exact same validated document and expected generation.
    """
    try:
        validated = validate_install_document(document, for_apply=True)
        bundle = render_repository_nginx_bundle_candidate(
            validated,
            expected_state_generation=expected_state_generation,
            candidate_pins_by_repository=candidate_pins_by_repository,
            ca_bundle_path=ca_bundle_path,
            native_min_free_supported=native_min_free_supported,
            cache_bypass_repository_ids=cache_bypass_repository_ids,
        )
        tls = render_native_tls_listener_candidate(validated)
    except (NginxRepositoryBundleError, NativeTLSListenerCandidateError,
            ValueError, TypeError, RecursionError):
        raise NginxRepositoryBundleError(
            "NGINX_HTTPS_BUNDLE_INPUT_INVALID"
        ) from None
    if (bundle["status"] != "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY"
            or tls["status"] != "NATIVE_TLS_LISTENER_CANDIDATE_ONLY"
            or bundle["authorizes_nginx_activation"] is not False
            or bundle["authorizes_catalog_publication"] is not False
            or tls["authorizes_nginx_activation"] is not False
            or tls["authorizes_firewall_change"] is not False):
        raise NginxRepositoryBundleError("NGINX_HTTPS_BUNDLE_UNSAFE_RESULT")

    http = bundle["http_upstream_fragment"]
    server = (
        "server {\n"
        + tls["server_context_fragment"]
        + bundle["server_location_fragment"]
        + "}\n"
    )
    if (len(http.encode("utf-8")) + len(server.encode("utf-8"))
            > _MAX_BUNDLE_BYTES + 4096):
        raise NginxRepositoryBundleError("NGINX_HTTPS_BUNDLE_SIZE_EXCEEDED")
    # No default_server, wildcard listener, catch-all proxy, resolver or
    # separate catalog is generated. The caller supplies only configuration
    # fragments in the correct stock NGINX http{} directive context.
    return {
        "schema_version": 1,
        "status": "HTTPS_REPOSITORY_SERVER_CANDIDATE_ONLY",
        "expected_state_generation": expected_state_generation,
        "proposed_repository_ids": bundle["proposed_repository_ids"],
        "http_context_fragment": http,
        "server_block_fragment": server,
        "pin_count": bundle["pin_count"],
        "cache_bypass_recovery_candidate_repository_ids":
            bundle["cache_bypass_recovery_candidate_repository_ids"],
        "firewall_mutation_requested": tls["firewall_mutation_requested"],
        "tls_material_or_hostname_verified": False,
        "native_nginx_syntax_verified": False,
        "installed_nginx_or_operator_authority_verified": False,
        "active_route_exposure_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "authorizes_firewall_change": False,
    }
