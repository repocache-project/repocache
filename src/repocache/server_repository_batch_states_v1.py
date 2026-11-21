"""Pure, all-or-nothing multi-target repository state intent for issue #95.

This is a candidate-document planner, NOT a native repository controller.
No operation here changes NGINX, the published client catalog, storage or
protected state. An installed transaction must independently reauthorize
every selected repository and reconcile the complete live generation.
"""
from __future__ import annotations

import copy
from typing import Any

from repocache.server_install_v1 import ID, MAX_INT, validate_install_document


class BatchRepositoryStateError(ValueError):
    """Static, non-sensitive refusal code."""


def plan_batch_repository_states(
    current_document: dict[str, Any], *, current_generation: int,
    operation: str, repository_ids: tuple[str, ...],
) -> dict[str, Any]:
    """Build one validated enable/disable candidate with per-ID outcomes.

    Unknown valid IDs produce a local NOT_FOUND result, allowing independent
    valid targets to be represented without mutation. Invalid selectors or
    an invalid document refuse the entire batch. In particular, the status
    ALREADY_ACTIVE is *desired-state only*, not evidence of a live route.
    """
    if (type(current_generation) is not int
            or not 0 <= current_generation <= MAX_INT
            or type(operation) is not str
            or operation not in ("enable", "disable")):
        raise BatchRepositoryStateError("BATCH_STATE_OPERATION_INVALID")
    if (type(repository_ids) is not tuple
            or not 1 <= len(repository_ids) <= 500
            or any(type(item) is not str or ID.fullmatch(item) is None
                   for item in repository_ids)
            or len(repository_ids) != len(set(repository_ids))):
        raise BatchRepositoryStateError("BATCH_STATE_SELECTORS_INVALID")
    try:
        base = validate_install_document(current_document, for_apply=True)
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise BatchRepositoryStateError("BATCH_STATE_DOCUMENT_INVALID") from None
    if base["expected_state_generation"] != current_generation:
        raise BatchRepositoryStateError("BATCH_STATE_STALE_GENERATION")
    if any("id" not in row for row in base["repositories"]):
        raise BatchRepositoryStateError("BATCH_STATE_UNALLOCATED_ID")

    candidate = copy.deepcopy(base)
    positions = {row["id"]: row for row in candidate["repositories"]}
    desired = "active" if operation == "enable" else "disabled"
    per_repository: list[dict[str, str]] = []
    for identifier in repository_ids:
        row = positions.get(identifier)
        if row is None:
            result = "NOT_FOUND"
        elif row["desired_state"] == desired:
            result = "ALREADY_" + desired.upper()
        else:
            row["desired_state"] = desired
            result = desired.upper() + "_CANDIDATE"
        per_repository.append({"repository_id": identifier, "result": result})
    try:
        validated = validate_install_document(candidate, for_apply=True)
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise BatchRepositoryStateError("BATCH_STATE_CANDIDATE_INVALID") from None
    return {
        "schema_version": 1,
        "status": "BATCH_STATE_PLAN_ONLY",
        "operation": operation,
        "expected_state_generation": current_generation,
        "per_repository": per_repository,
        "changed": validated != base,
        "candidate_document": validated,
        "operator_authorization_verified": False,
        "native_nginx_routes_reconciled": False,
        "active_catalog_reconciled": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "authorizes_state_write": False,
        "authorizes_cache_cleanup": False,
    }
