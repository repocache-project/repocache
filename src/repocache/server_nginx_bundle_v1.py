"""Compose non-activating, numeric-IP NGINX candidates for issue #28.

All active repositories are rendered together from a validated deployment
document. Inert desired state cannot establish approval, protected origin
or successful activation; the output never authorizes NGINX or catalog writes.
"""
from __future__ import annotations

from typing import Any

from repocache.server_install_v1 import validate_install_document
from repocache.server_nginx_pin_render_v1 import (
    PinnedNginxError,
    render_pinned_upstream_fragments,
)


class PinnedNginxBundleError(ValueError):
    """Redacted failure of the complete candidate bundle."""


def render_pinned_repository_bundle(
    document: dict[str, Any], *,
    pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
    native_min_free_supported: bool = False,
    cache_bypass_for_recovery: bool = False,
) -> dict[str, Any]:
    """Render every explicitly active ID as one inert, ordered pair of fragments.

    The caller must supply exact per-repository DNS-address candidates, not
    a global union; each is independently checked by the existing safe
    single-repository renderer. An invalid last repository rejects the whole
    result instead of returning partial NGINX configuration.
    """
    if (type(pins_by_repository) is not dict or len(pins_by_repository) > 64
            or any(type(key) is not str or type(value) is not dict
                   for key, value in pins_by_repository.items())):
        raise PinnedNginxBundleError("BUNDLE_PIN_INPUT_INVALID")
    if (type(native_min_free_supported) is not bool
            or type(cache_bypass_for_recovery) is not bool):
        raise PinnedNginxBundleError("BUNDLE_OPTIONS_INVALID")
    try:
        doc = validate_install_document(document, for_apply=True)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise PinnedNginxBundleError("BUNDLE_DOCUMENT_INVALID") from None

    active_ids = sorted(
        row["id"] for row in doc["repositories"]
        if row["desired_state"] == "active" and "id" in row
    )
    # A desired-active repository with no durable ID cannot be exposed.
    if (len(active_ids) > 64
            or len(active_ids) != sum(
                row["desired_state"] == "active" for row in doc["repositories"]
            )
            or set(active_ids) != set(pins_by_repository)):
        raise PinnedNginxBundleError("BUNDLE_ACTIVE_PIN_SET_MISMATCH")

    fragments = []
    for identifier in active_ids:
        try:
            candidate = render_pinned_upstream_fragments(
                doc,
                repository_id=identifier,
                candidate_pins_by_host=pins_by_repository[identifier],
                ca_bundle_path=ca_bundle_path,
                native_min_free_supported=native_min_free_supported,
                cache_bypass_for_recovery=cache_bypass_for_recovery,
            )
        except (PinnedNginxError, ValueError, TypeError, RecursionError, OverflowError):
            raise PinnedNginxBundleError("BUNDLE_REPOSITORY_INVALID") from None
        fragments.append(candidate)

    return {
        "schema_version": 1,
        "status": "RENDER_BUNDLE_CANDIDATE_ONLY",
        "repository_ids": active_ids,
        "http_upstream_fragment": "".join(
            candidate["http_upstream_fragment"] for candidate in fragments
        ),
        "server_location_fragment": "".join(
            candidate["server_location_fragment"] for candidate in fragments
        ),
        "pin_count": sum(candidate["pin_count"] for candidate in fragments),
        "native_min_free_candidate_emitted": native_min_free_supported,
        "cache_bypass_recovery_candidate_emitted": cache_bypass_for_recovery,
        "native_min_free_supported_verified": False,
        "requires_nginx_t_and_activation": True,
        "trusted_state_provenance_verified": False,
        "runtime_destination_enforcement_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
    }
