"""Bounded all-or-nothing mixed repository state preview for #95.

Non-authoritative: approval, trusted state, NGINX activation and catalog
publication must be verified separately under a protected transaction lock.
"""
from __future__ import annotations

from typing import Any

from repocache.server_install_v1 import MAX_INT, validate_install_document
from repocache.server_repository_plan_v1 import RepositoryPlanError, plan_repository_change


class MixedRepositoryStateError(ValueError):
    """Static, input-free refusal of an invalid state-change batch."""


def plan_mixed_repository_states(
    current_document: dict[str, Any], *, current_generation: int,
    changes: tuple[tuple[str, str], ...],
) -> dict[str, Any]:
    """Preview a mix of up to 64 (repository ID, active/disabled) changes atomically."""
    if type(current_generation) is not int or not 0 <= current_generation <= MAX_INT:
        raise MixedRepositoryStateError("BATCH_STATE_GENERATION_INVALID")
    if (type(changes) is not tuple or not 1 <= len(changes) <= 64
            or any(type(change) is not tuple or len(change) != 2
                   or type(change[0]) is not str or type(change[1]) is not str
                   or change[1] not in ("active", "disabled")
                   for change in changes)):
        raise MixedRepositoryStateError("BATCH_STATE_SELECTOR_INVALID")
    try:
        base = validate_install_document(current_document, for_apply=True)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise MixedRepositoryStateError("BATCH_STATE_DOCUMENT_INVALID") from None
    if base["expected_state_generation"] != current_generation:
        raise MixedRepositoryStateError("BATCH_STATE_STALE_GENERATION")
    if any("id" not in row for row in base["repositories"]):
        raise MixedRepositoryStateError("BATCH_STATE_UNALLOCATED_ID")

    available = {row["id"] for row in base["repositories"]}
    seen: set[str] = set()
    candidate = base
    outcomes: list[dict[str, str]] = []
    for identifier, desired_state in changes:
        if identifier in seen or identifier not in available:
            raise MixedRepositoryStateError("BATCH_STATE_TARGET_INVALID")
        seen.add(identifier)
        try:
            result = plan_repository_change(
                candidate, current_generation=current_generation,
                operation="enable" if desired_state == "active" else "disable",
                repository_id=identifier,
            )
        except (RepositoryPlanError, ValueError, TypeError, RecursionError, OverflowError):
            raise MixedRepositoryStateError("BATCH_STATE_TARGET_INVALID") from None
        candidate = result["candidate_document"]
        outcomes.append({
            "repository_id": identifier,
            "desired_state": desired_state,
            "result": "STATE_CHANGE_CANDIDATE" if result["changed"] else "ALREADY_CURRENT",
        })
    return {
        "schema_version": 1,
        "status": "BATCH_STATE_PLAN_ONLY",
        "expected_state_generation": current_generation,
        "changed": candidate != base,
        "per_repository": outcomes,
        "candidate_document": candidate,
        "operator_authorization_verified": False,
        "trusted_state_generation_verified": False,
        "native_nginx_routes_reconciled": False,
        "active_catalog_reconciled": False,
        "authorizes_state_write": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
    }
