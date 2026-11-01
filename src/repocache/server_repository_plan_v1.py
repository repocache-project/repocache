"""Plan explicit-ID server repository changes without any host or state mutation.

This is a non-authoritative v1 planning primitive for #95. It accepts only
already-validated *candidate* configuration snapshots and produces another
validated candidate. It does NOT inspect trusted persistent state, allocate
durable IDs, authorize NGINX actions, activate routes, publish catalogs, or
remove cached data. The future transactional engine must independently check
the expected generation, authorization, ownership, validation and rollback
on the real host before any commit.
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from repocache.server_install_v1 import (
    ID,
    MAX_INT,
    _layout_identity,
    _upstream,
    validate_install_document,
)

_OPERATIONS = frozenset({"add", "update", "enable", "disable", "remove"})


class RepositoryPlanError(ValueError):
    """An inert repository change was refused; messages omit input values."""


def _id(value: Any) -> str:
    if type(value) is not str or ID.fullmatch(value) is None:
        raise RepositoryPlanError("repository_id: invalid or missing explicit ID")
    return value


def plan_repository_change(
    current_document: dict[str, Any],
    *,
    current_generation: int,
    operation: str,
    repository_id: str | None = None,
    proposed_repository: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a side-effect-free *intent* based on a fully-IDed v1 document.

    The generation argument is only a caller-provided comparison value. No
    persistent state is read, locked or trusted by this routine. The result
    is NEVER authorization to apply a change or proof of actual exposure.
    Auto-ID allocation requires a durable, generation-aware identity ledger
    and is deliberately not implemented in this first increment.
    """
    if type(current_generation) is not int or not 0 <= current_generation <= MAX_INT:
        raise RepositoryPlanError("current_generation: invalid")
    if type(operation) is not str or operation not in _OPERATIONS:
        raise RepositoryPlanError("operation: unsupported")
    base = validate_install_document(current_document, for_apply=True)
    if base["expected_state_generation"] != current_generation:
        raise RepositoryPlanError("expected_state_generation: stale candidate")
    if any("id" not in item for item in base["repositories"]):
        raise RepositoryPlanError("repositories: durable identifiers required")

    draft = copy.deepcopy(base)
    repos = draft["repositories"]
    positions = {item["id"]: i for i, item in enumerate(repos)}
    target: str

    if operation == "add":
        if repository_id is not None or type(proposed_repository) is not dict:
            raise RepositoryPlanError("add: explicit-ID repository object required")
        target = _id(proposed_repository.get("id"))
        value = copy.deepcopy(proposed_repository)
        position = positions.get(target)
        if position is not None:
            if repos[position] != value:
                raise RepositoryPlanError("add: repository ID already in use")
        else:
            repos.append(value)
    elif operation == "update":
        target = _id(repository_id)
        if type(proposed_repository) is not dict:
            raise RepositoryPlanError("update: complete repository object required")
        if _id(proposed_repository.get("id")) != target:
            raise RepositoryPlanError("update: repository ID must remain stable")
        if target not in positions:
            raise RepositoryPlanError("update: repository not found")
        repos[positions[target]] = copy.deepcopy(proposed_repository)
    else:
        target = _id(repository_id)
        if proposed_repository is not None:
            raise RepositoryPlanError("operation: unexpected repository object")
        position = positions.get(target)
        if operation == "remove":
            if position is not None:
                del repos[position]
        elif position is None:
            raise RepositoryPlanError("state change: repository not found")
        else:
            repos[position]["desired_state"] = (
                "active" if operation == "enable" else "disabled"
            )

    # The existing strict #18/#25 validator remains the sole v1 syntax,
    # identity-collision, upstream, trust-reference and path policy gate.
    # Even desired_state="active" is only intent, never verified exposure.
    validated = validate_install_document(draft, for_apply=True)
    return {
        "schema_version": 1,
        "operation": operation,
        "repository_id": target,
        "changed": validated != base,
        "status": "PLAN_ONLY",
        "candidate_document": validated,
    }


def _canonical_identity(repo: dict[str, Any]) -> str:
    """Match the strict v1 validator's identity, ignoring administrative state."""
    host, port, path = _upstream(repo["upstream"]["base_url"])
    return json.dumps(
        [repo["kind"], host, port, path,
         _layout_identity(repo["kind"], repo["layout"])],
        sort_keys=True, separators=(",", ":"),
    )


def propose_automatic_repository_id(
    current_document: dict[str, Any],
    proposed_repository: dict[str, Any],
    *,
    current_generation: int,
    reserved_ids: set[str] | frozenset[str],
) -> dict[str, Any]:
    """Suggest an ID, never reserve it or promise persistent uniqueness.

    A trusted future state engine MUST supply its durable, atomically locked
    *all-time* reservation/tombstone set, then recheck it at commit. This
    routine only computes a reproducible, collision-resistant candidate.
    Callers cannot safely commit its result without that separate engine.
    """
    if type(current_generation) is not int or not 0 <= current_generation <= MAX_INT:
        raise RepositoryPlanError("current_generation: invalid")
    if type(reserved_ids) not in (set, frozenset) or len(reserved_ids) > 10000:
        raise RepositoryPlanError("reserved_ids: trusted bounded set required")
    if any(type(item) is not str or ID.fullmatch(item) is None
           for item in reserved_ids):
        raise RepositoryPlanError("reserved_ids: invalid ID")
    if type(proposed_repository) is not dict or "id" in proposed_repository:
        raise RepositoryPlanError("automatic ID: ID must be omitted")
    existing = validate_install_document(current_document, for_apply=True)
    if existing["expected_state_generation"] != current_generation:
        raise RepositoryPlanError("expected_state_generation: stale candidate")
    if any("id" not in item for item in existing["repositories"]):
        raise RepositoryPlanError("repositories: durable identifiers required")
    if not {item["id"] for item in existing["repositories"]} <= reserved_ids:
        raise RepositoryPlanError("reserved_ids: live repository not reserved")

    # Reuse the *same strict input validator* for future candidate identity;
    # never generate IDs based on unvalidated, ambiguous attacker input.
    isolated = copy.deepcopy(existing)
    isolated["repositories"] = [copy.deepcopy(proposed_repository)]
    validated = validate_install_document(isolated, for_apply=True)
    candidate = validated["repositories"][0]
    canonical = _canonical_identity(candidate)
    for present in existing["repositories"]:
        if _canonical_identity(present) == canonical:
            return {"schema_version": 1, "status": "PLAN_ONLY",
                    "repository_id": present["id"], "existing": True}

    # Hash the canonical identity rather than an input-supplied display name.
    # Tombstones prevent reuse, even when the same upstream is added later.
    for nonce in range(256):
        digest = hashlib.sha256(
            (canonical + "#" + str(nonce)).encode("utf-8")
        ).hexdigest()
        identifier = "repo-" + digest[:32]
        if identifier not in reserved_ids:
            return {"schema_version": 1, "status": "PLAN_ONLY",
                    "repository_id": identifier, "existing": False}
    raise RepositoryPlanError("automatic ID: reservation conflict")
