"""Read-only reconciliation preview for the proposed server installation v1 schema.

This pure planner is NOT a trusted state reader, authorization mechanism, NGINX
renderer or commit engine. No caller-provided JSON, expected generation or
preview may authorize a file write, service reload or catalog publication.
The future #95/#28/#31 owner must re-read protected state under the native
transaction lock, verify provenance/ownership and repeat validation.
"""
from __future__ import annotations

import copy
from typing import Any

from repocache.server_install_v1 import (
    MAX_INT, validate_install_document,
)
from repocache.server_repository_plan_v1 import _effective_configuration


class ReconciliationPlanError(ValueError):
    """Reject an unsupported preview without echoing input values."""


_POLICY_FIELDS = ("inactive_seconds", "max_size_bytes")


def _effective_policy(repo: dict[str, Any], global_policy: dict[str, Any]) -> dict[str, Any]:
    overrides = repo.get("cache_overrides", {})
    return {
        field: {
            "value": overrides.get(field, global_policy[field]),
            "source": "repository" if field in overrides else "global",
        }
        for field in _POLICY_FIELDS
    }


def plan_declarative_reconciliation(
    current_document: dict[str, Any],
    proposed_document: dict[str, Any],
    *,
    current_generation: int,
) -> dict[str, Any]:
    """Preview an explicit update, preserving EVERY omitted repository.

    Both documents are untrusted snapshots. New IDs are intentionally refused:
    allocation and tombstone reservations require the future authoritative
    locked state engine, not guesswork by this pure planner. Omitted entries
    survive even when the submitted repositories array is empty. Global
    defaults are applied to *all* stored entries, including omitted entries.
    """
    if type(current_generation) is not int or not 0 <= current_generation <= MAX_INT:
        raise ReconciliationPlanError("current_generation: invalid")
    current = validate_install_document(current_document, for_apply=True)
    proposed = validate_install_document(proposed_document, for_apply=True)

    if (current["expected_state_generation"] != current_generation
            or proposed["expected_state_generation"] != current_generation):
        raise ReconciliationPlanError("expected_state_generation: stale preview")

    existing = current["repositories"]
    incoming = proposed["repositories"]
    if any("id" not in repo for repo in existing + incoming):
        raise ReconciliationPlanError("repositories: durable IDs required")
    by_id = {repo["id"]: repo for repo in existing}
    updates = {repo["id"]: repo for repo in incoming}
    if set(updates) - set(by_id):
        raise ReconciliationPlanError(
            "repositories: new IDs require the authoritative reservation engine"
        )

    # A submitted document is not a replace-all request. It cannot remove,
    # disable or silently reauthorize any repository absent from its list.
    candidate = copy.deepcopy(current)
    candidate["deployment"] = copy.deepcopy(proposed["deployment"])
    candidate["repositories"] = [
        (copy.deepcopy(repo)
         if repo["id"] not in updates
         or _effective_configuration(updates[repo["id"]])
            == _effective_configuration(repo)
         else copy.deepcopy(updates[repo["id"]]))
        for repo in existing
    ]
    # Validate the combined result: an individually valid partial document
    # may collide with a preserved repository's canonical upstream identity.
    candidate = validate_install_document(candidate, for_apply=True)
    final_by_id = {repo["id"]: repo for repo in candidate["repositories"]}

    old_global = current["deployment"]["cache_policy"]["global"]
    new_global = candidate["deployment"]["cache_policy"]["global"]
    changes = []
    implicit_policy_ids = []
    explicit_changed_ids = []
    preserved_ids = sorted(set(by_id) - set(updates))

    for identifier in sorted(by_id):
        before = by_id[identifier]
        after = final_by_id[identifier]
        before_policy = _effective_policy(before, old_global)
        after_policy = _effective_policy(after, new_global)
        changed_fields = [
            key for key in _POLICY_FIELDS if before_policy[key] != after_policy[key]
        ]
        if identifier in updates and before != after:
            explicit_changed_ids.append(identifier)
        if changed_fields:
            changes.append({
                "repository_id": identifier,
                "fields": changed_fields,
                "before": {key: before_policy[key] for key in changed_fields},
                "after": {key: after_policy[key] for key in changed_fields},
                "explicitly_listed": identifier in updates,
            })
            if identifier not in updates:
                implicit_policy_ids.append(identifier)

    return {
        "schema_version": 1,
        "status": "PLAN_ONLY",
        "authorizes_installation": False,
        "state_generation": current_generation,
        "changed": candidate != current,
        "explicit_changed_ids": sorted(explicit_changed_ids),
        "preserved_ids": preserved_ids,
        "implicit_policy_ids": sorted(implicit_policy_ids),
        "effective_policy_changes": changes,
        "candidate_document": candidate,
    }
