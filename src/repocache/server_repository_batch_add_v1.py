"""Atomic, non-authorizing multi-add repository candidate planner (#95).

Candidate-only ID allocation; no ledger authority, catalogue publication,
root helper, persisted state, installed NGINX reload or cleanup.
"""
from __future__ import annotations

from typing import Any

from repocache.server_install_v1 import MAX_INT, validate_install_document
from repocache.server_repository_plan_v1 import (
    RepositoryPlanError, _reserved_snapshot, plan_repository_change,
    propose_automatic_repository_id,
)


class BatchRepositoryAddError(ValueError):
    """Redacted static refusal at the multi-add input boundary."""


def plan_batch_repository_additions(
    current_document: dict[str, Any], *, current_generation: int,
    proposed_repositories: tuple[dict[str, Any], ...],
    reserved_ids: set[str] | frozenset[str],
) -> dict[str, Any]:
    """Preview distinct repository adds as one all-or-nothing candidate.

    An ID-omitted proposal obtains a deterministic suggestion from the
    validated canonical upstream/layout identity. Existing exact matches
    are no-op candidates. Different definitions for an occupied ID,
    repeated targets, duplicate upstream identities and historical
    tombstones refuse the WHOLE preview. The caller's supplied reservation
    set is not proof of a protected all-time, transaction-locked ledger.
    """
    if (type(current_generation) is not int
            or not 0 <= current_generation <= MAX_INT):
        raise BatchRepositoryAddError("BATCH_ADD_GENERATION_INVALID")
    # A bounded 64-item pure batch avoids quadratic repeated schema checks
    # becoming an adversarial untrusted-input work amplifier. Installed
    # transaction sizing remains independently governed.
    if (type(proposed_repositories) is not tuple
            or not 1 <= len(proposed_repositories) <= 64
            or any(type(row) is not dict for row in proposed_repositories)):
        raise BatchRepositoryAddError("BATCH_ADD_PROPOSALS_INVALID")
    try:
        base = validate_install_document(current_document, for_apply=True)
        if base["expected_state_generation"] != current_generation:
            raise BatchRepositoryAddError("BATCH_ADD_STALE_GENERATION")
        if any("id" not in item for item in base["repositories"]):
            raise BatchRepositoryAddError("BATCH_ADD_UNALLOCATED_ID")
        # Check and freeze caller-owned reservation snapshot before planning;
        # it is still untrusted, never durable or authoritative.
        reservations = set(_reserved_snapshot(base, reserved_ids))
    except BatchRepositoryAddError:
        raise
    except (RepositoryPlanError, ValueError, TypeError, RecursionError, OverflowError):
        raise BatchRepositoryAddError("BATCH_ADD_BASE_INVALID") from None

    candidate = base
    per_repository: list[dict[str, Any]] = []
    seen: set[str] = set()
    for proposed in proposed_repositories:
        try:
            auto = "id" not in proposed
            if auto:
                proposed_id = propose_automatic_repository_id(
                    candidate, proposed, current_generation=current_generation,
                    reserved_ids=reservations,
                )["repository_id"]
                complete = {**proposed, "id": proposed_id}
            else:
                proposed_id = proposed["id"]
                complete = proposed
            if type(proposed_id) is not str or proposed_id in seen:
                raise ValueError("duplicate batch target")
            previous = candidate
            plan = plan_repository_change(
                previous, current_generation=current_generation,
                operation="add", proposed_repository=complete,
                reserved_ids=reservations,
            )
            candidate = plan["candidate_document"]
            seen.add(proposed_id)
            reservations.add(proposed_id)
            per_repository.append({
                "repository_id": proposed_id,
                "id_assignment": "AUTO_SUGGESTED" if auto else "EXPLICIT",
                "result": "ADD_CANDIDATE" if plan["changed"] else "ALREADY_PRESENT",
            })
        except (RepositoryPlanError, ValueError, TypeError, RecursionError,
                OverflowError):
            raise BatchRepositoryAddError("BATCH_ADD_REPOSITORY_INVALID") from None

    return {
        "schema_version": 1,
        "status": "BATCH_ADD_PLAN_ONLY",
        "expected_state_generation": current_generation,
        "changed": candidate != base,
        "per_repository": per_repository,
        "candidate_document": candidate,
        "id_eligibility": "CALLER_SNAPSHOT_ONLY",
        "all_time_reservation_ledger_persisted": False,
        "operator_authorization_verified": False,
        "native_nginx_routes_reconciled": False,
        "active_catalog_reconciled": False,
        "authorizes_state_write": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
    }
