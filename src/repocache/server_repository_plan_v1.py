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
    _host,
    _repository_identity,
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


def _validated_candidate(base: dict[str, Any],
                         proposed: dict[str, Any]) -> dict[str, Any]:
    """Validate untrusted proposals BEFORE copying their nested contents.

    The closed v1 validator enforces JSON-compatible schema, 16-level depth,
    1 MiB encoded bound and host policy before returning its independent copy.
    It also validates deployment/trust references in the actual context.
    """
    if type(proposed) is not dict:
        raise RepositoryPlanError("repository: complete object required")
    isolated = {**base, "repositories": [proposed]}
    return validate_install_document(isolated, for_apply=True)["repositories"][0]


def _reserved_snapshot(
    base: dict[str, Any], reserved_ids: set[str] | frozenset[str] | None
) -> set[str] | frozenset[str]:
    """Check only caller-declared reservations; NEVER assert ledger authority."""
    if type(reserved_ids) not in (set, frozenset) or len(reserved_ids) > 10000:
        raise RepositoryPlanError("reserved_ids: bounded snapshot required")
    # Freeze a mutable caller set, preventing later in-place changes from
    # silently changing the result *after* validation. This is not a trusted
    # atomic ledger snapshot; the real writer must hold its own state lock.
    try:
        snapshot = frozenset(reserved_ids)
    except RuntimeError:
        raise RepositoryPlanError("reserved_ids: concurrent input mutation") from None
    # The caller may modify a mutable set after the first len() check.
    # Validate the *copied* cardinality; this is still not a trusted ledger.
    if len(snapshot) > 10000:
        raise RepositoryPlanError("reserved_ids: bounded snapshot required")
    if any(type(item) is not str or ID.fullmatch(item) is None
           for item in snapshot):
        raise RepositoryPlanError("reserved_ids: invalid ID")
    if not {item["id"] for item in base["repositories"]} <= snapshot:
        raise RepositoryPlanError("reserved_ids: live repository not reserved")
    return snapshot


def _effective_configuration(repo: dict[str, Any]) -> str:
    """Normalize the complete validated configuration, not just identity.

    Layout lists and upstream.allowed_hosts are semantically unordered.
    The upstream URL host/default HTTPS port are canonical; repository tokens,
    URL path, desired_state and cache policy remain significant.
    Missing cache_overrides and an empty object are the same v1 policy.
    """
    return json.dumps(
        {
            "identity": _canonical_identity(repo),
            "trust_key_refs": sorted(
                repo["layout"][
                    "release_key_refs" if repo["kind"] == "apt" else "gpg_key_refs"
                ]
            ),
            "allowed_hosts": sorted(
                _host(host, "upstream.allowed_hosts")
                for host in repo["upstream"]["allowed_hosts"]
            ),
            "desired_state": repo["desired_state"],
            "cache_overrides": repo.get("cache_overrides", {}),
        },
        sort_keys=True, separators=(",", ":"),
    )


def plan_repository_change(
    current_document: dict[str, Any],
    *,
    current_generation: int,
    operation: str,
    repository_id: str | None = None,
    proposed_repository: dict[str, Any] | None = None,
    reserved_ids: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    """Build a non-authoritative change intent from a fully IDed v1 snapshot.

    Explicit adds REQUIRE a caller-provided all-time reservation/tombstone
    snapshot. It is neither authenticated nor locked by this pure planner.
    A successful plan never certifies a free ID, current state generation,
    durable ownership, permission, active NGINX route or safe cache reuse.
    The future writer MUST recheck these against trusted durable state while
    holding an exclusive transaction lock, before any commit.
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
    if operation == "add":
        reservations = _reserved_snapshot(base, reserved_ids)
    elif reserved_ids is not None:
        raise RepositoryPlanError("reserved_ids: accepted only for add")

    draft = copy.deepcopy(base)
    repos = draft["repositories"]
    positions = {item["id"]: i for i, item in enumerate(repos)}
    target: str

    if operation == "add":
        if repository_id is not None or type(proposed_repository) is not dict:
            raise RepositoryPlanError("add: explicit-ID repository object required")
        target = _id(proposed_repository.get("id"))
        # The proposed object is validated and bounded before any deep copy.
        value = _validated_candidate(base, proposed_repository)
        position = positions.get(target)
        if position is not None:
            if _effective_configuration(repos[position]) != _effective_configuration(value):
                raise RepositoryPlanError("add: repository ID already in use")
        elif target in reservations:
            raise RepositoryPlanError("add: repository ID historically reserved")
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
        value = _validated_candidate(base, proposed_repository)
        # Same effective semantics should not produce a spurious transaction.
        if _effective_configuration(repos[positions[target]]) != _effective_configuration(value):
            repos[positions[target]] = value
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

    # All changes re-enter the same strict #18/#25 validator; even an
    # "active" desired_state is not evidence of a verified active route.
    validated = validate_install_document(draft, for_apply=True)
    result = {
        "schema_version": 1,
        "operation": operation,
        "repository_id": target,
        "changed": validated != base,
        "status": "PLAN_ONLY",
        "candidate_document": validated,
    }
    if operation == "add":
        result["id_eligibility"] = "CALLER_SNAPSHOT_ONLY"
    return result


def _canonical_identity(repo: dict[str, Any]) -> str:
    """Match the strict v1 validator's identity, ignoring administrative state."""
    host, port, path = _upstream(repo["upstream"]["base_url"])
    return _repository_identity(
        repo["kind"], (host, port, path), repo["layout"]
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
    if type(proposed_repository) is not dict or "id" in proposed_repository:
        raise RepositoryPlanError("automatic ID: ID must be omitted")
    existing = validate_install_document(current_document, for_apply=True)
    if existing["expected_state_generation"] != current_generation:
        raise RepositoryPlanError("expected_state_generation: stale candidate")
    if any("id" not in item for item in existing["repositories"]):
        raise RepositoryPlanError("repositories: durable identifiers required")
    reservations = _reserved_snapshot(existing, reserved_ids)

    # Reuse the *same strict input validator* for future candidate identity;
    # never generate IDs based on unvalidated, ambiguous attacker input.
    candidate = _validated_candidate(existing, proposed_repository)
    canonical = _canonical_identity(candidate)
    for present in existing["repositories"]:
        if _canonical_identity(present) == canonical:
            if _effective_configuration(present) != _effective_configuration(candidate):
                raise RepositoryPlanError(
                    "automatic ID: matching identity has different configuration; use update"
                )
            return {"schema_version": 1, "status": "PLAN_ONLY",
                    "repository_id": present["id"], "existing": True,
                    "id_eligibility": "CALLER_SNAPSHOT_ONLY"}

    # Hash the canonical identity rather than an input-supplied display name.
    # Tombstones prevent reuse, even when the same upstream is added later.
    for nonce in range(256):
        digest = hashlib.sha256(
            (canonical + "#" + str(nonce)).encode("utf-8")
        ).hexdigest()
        identifier = "repo-" + digest[:32]
        if identifier not in reservations:
            return {"schema_version": 1, "status": "PLAN_ONLY",
                    "repository_id": identifier, "existing": False,
                    "id_eligibility": "CALLER_SNAPSHOT_ONLY"}
    raise RepositoryPlanError("automatic ID: reservation conflict")
