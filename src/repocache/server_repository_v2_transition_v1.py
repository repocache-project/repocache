"""Pure v2 repository lifecycle transition shared by future native owners (#95).

This is a deterministic, non-authorizing *builder*, not the protected state
reader, administrator authenticator, native activation or catalog publisher.
An installed owner must obtain the previous canonical snapshot under its
authenticated root lock, independently re-read/revalidate it at commit,
and use the separately reviewed native v2 WAL (#31/#64).
"""
from __future__ import annotations

import base64
import copy
import hashlib
from typing import Any

from repocache.server_install_v1 import (
    MAX_DOCUMENT_BYTES, MAX_INT, parse_install_bytes,
    validate_install_document,
)
from repocache.server_locked_manifest_reconcile_v1 import (
    _validate_proposed_v2_snapshot, preview_proposed_v2_state_transition,
)
from repocache.server_proposed_state_v2_store import MAX_V2_STATE_BYTES
from repocache.server_protected_state_store_v1 import _canonical, _json
from repocache.server_repository_plan_v1 import (
    _canonical_identity, plan_repository_change,
    propose_automatic_repository_id, plan_batch_repository_additions,
    plan_batch_repository_updates, plan_batch_repository_removals,
)


class RepositoryV2TransitionError(ValueError):
    """Stable error codes only, without configuration or upstream values."""


def _deny(code: str) -> None:
    raise RepositoryV2TransitionError("REPOSITORY_V2_TRANSITION_" + code)


def _hex(value: Any) -> bool:
    return (type(value) is str and len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value))


def _next_snapshot(
    previous: dict[str, Any], document: dict[str, Any], *,
    decision_sha256: str,
) -> dict[str, Any]:
    generation = previous["state_generation"] + 1
    rebased = copy.deepcopy(document)
    rebased["expected_state_generation"] = generation
    rebased = validate_install_document(rebased, for_apply=True)
    raw = _canonical(rebased, limit=MAX_DOCUMENT_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    records = [{
        "id": row["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(row).encode("utf-8")
        ).hexdigest(),
        "desired_state": row["desired_state"],
        "observed_state": "not-activated",
    } for row in rebased["repositories"]]
    historical = {
        item["id"]: copy.deepcopy(item)
        for item in previous["id_reservations"]
    }
    present = {row["id"] for row in records}
    for identifier, old in historical.items():
        if identifier not in present:
            old["status"] = "retired"
    for item in records:
        identifier = item["id"]
        if identifier not in historical:
            historical[identifier] = {
                "id": identifier,
                "canonical_identity_sha256": item["canonical_identity_sha256"],
                "status": "allocated",
            }
    return {
        "state_schema_version": 2,
        "state_generation": generation,
        "configuration_base64": base64.b64encode(raw).decode("ascii"),
        "configuration_sha256": digest,
        "repository_records": records,
        "id_reservations": [historical[rid] for rid in sorted(historical)],
        "approval_reference": {
            "source": "operator",
            "decision_sha256": decision_sha256,
            "configuration_sha256": digest,
            "expected_generation": generation - 1,
        },
    }


def plan_repository_v2_transition(
    previous_snapshot: Any, *,
    expected_generation: int,
    expected_previous_state_sha256: str,
    operation: str,
    decision_sha256: str,
    repository_id: str | None = None,
    proposed_repository: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct an exact complete v2 state from a prior canonical snapshot.

    The digest prevents accidentally constructing a proposed transition from
    the wrong predecessor; it is NOT a provenance attestation, authorization,
    durable reservation or lease. The caller MUST recheck a real protected
    state and all foreign/NGINX/cache files under its own lock before apply.
    No schema, persisted ID, native service or client source is modified.
    """
    if (type(expected_generation) is not int
            or not 1 <= expected_generation < MAX_INT
            or not _hex(expected_previous_state_sha256)
            or not _hex(decision_sha256)):
        _deny("ARGUMENT_INVALID")
    try:
        # Bounded deep freeze before reading caller-owned nested input.
        previous_raw = _canonical(
            previous_snapshot, limit=MAX_V2_STATE_BYTES,
        )
        previous = _json(previous_raw, limit=MAX_V2_STATE_BYTES)
        _validate_proposed_v2_snapshot(previous)
        if (previous["state_generation"] != expected_generation
                or hashlib.sha256(previous_raw).hexdigest()
                   != expected_previous_state_sha256):
            _deny("PREDECESSOR_MISMATCH")
        doc = parse_install_bytes(
            base64.b64decode(previous["configuration_base64"], validate=True),
            for_apply=True,
        )
        reserved = frozenset(
            record["id"] for record in previous["id_reservations"]
        )
        proposal = proposed_repository
        if operation == "add" and type(proposal) is dict and "id" not in proposal:
            suggested = propose_automatic_repository_id(
                doc, proposal,
                current_generation=expected_generation,
                reserved_ids=reserved,
            )
            proposal = {**proposal, "id": suggested["repository_id"]}
        plan = plan_repository_change(
            doc, current_generation=expected_generation,
            operation=operation, repository_id=repository_id,
            proposed_repository=proposal,
            reserved_ids=reserved if operation == "add" else None,
        )
        if not plan["changed"]:
            return {
                "schema_version": 1,
                "status": "NO_CHANGE_V2_CANDIDATE_ONLY",
                "changed": False,
                "repository_id": plan["repository_id"],
                "expected_generation": expected_generation,
                "proposed_snapshot": None,
                "authorizes_state_write": False,
                "authorizes_nginx_activation": False,
                "authorizes_catalog_publication": False,
            }
        next_snapshot = _next_snapshot(
            previous, plan["candidate_document"],
            decision_sha256=decision_sha256,
        )
        preview_proposed_v2_state_transition(
            next_snapshot, expected_generation=expected_generation,
            previous_snapshot=previous,
        )
        return {
            "schema_version": 1,
            "status": "V2_REPOSITORY_LIFECYCLE_CANDIDATE_ONLY",
            "changed": True,
            "repository_id": plan["repository_id"],
            "expected_generation": expected_generation,
            "proposed_snapshot": next_snapshot,
            "authorizes_state_write": False,
            "authorizes_nginx_activation": False,
            "authorizes_catalog_publication": False,
        }
    except RepositoryV2TransitionError:
        raise
    except (ValueError, TypeError, OverflowError, OSError,
            UnicodeError, RecursionError):
        _deny("CANDIDATE_INVALID")


def plan_repository_v2_batch_transition(
    previous_snapshot: Any, *,
    expected_generation: int,
    expected_previous_state_sha256: str,
    operation: str,
    decision_sha256: str,
    proposed_repositories: tuple[dict[str, Any], ...] = (),
    repository_ids: tuple[str, ...] = (),
    all_repositories: bool = False,
) -> dict[str, Any]:
    """Compose frozen #95 batch operations as ONE complete state-v2 generation.

    A pure, non-authorizing projection. Both the full predecessor and the
    all-time ID/identity reservation ledger are supplied by the caller,
    compared to the exact expected SHA-256, and revalidated in the adopted
    v2 transition contract. A true installed writer must re-read under its
    independently authenticated root lock and atomically apply one
    state/NGINX/catalog generation through the native #31 WAL.
    """
    if (type(expected_generation) is not int
            or not 1 <= expected_generation < MAX_INT
            or not _hex(expected_previous_state_sha256)
            or not _hex(decision_sha256)
            or type(operation) is not str
            or operation not in ("add", "update", "enable", "disable", "remove")
            or type(proposed_repositories) is not tuple
            or type(repository_ids) is not tuple
            or type(all_repositories) is not bool):
        _deny("BATCH_ARGUMENT_INVALID")
    if operation in ("add", "update"):
        if repository_ids or all_repositories:
            _deny("BATCH_SELECTORS_INVALID")
    elif operation in ("enable", "disable"):
        if proposed_repositories or all_repositories:
            _deny("BATCH_SELECTORS_INVALID")
    elif proposed_repositories:
        _deny("BATCH_SELECTORS_INVALID")

    try:
        raw = _canonical(previous_snapshot, limit=MAX_V2_STATE_BYTES)
        previous = _json(raw, limit=MAX_V2_STATE_BYTES)
        _validate_proposed_v2_snapshot(previous)
        if (previous["state_generation"] != expected_generation
                or hashlib.sha256(raw).hexdigest()
                   != expected_previous_state_sha256):
            _deny("BATCH_PREDECESSOR_MISMATCH")
        document = parse_install_bytes(
            base64.b64decode(previous["configuration_base64"], validate=True),
            for_apply=True,
        )
        if operation == "add":
            # Always use ALL historic reservations, including retired IDs,
            # never the current active subset or an external caller list.
            plan = plan_batch_repository_additions(
                document, current_generation=expected_generation,
                proposed_repositories=proposed_repositories,
                reserved_ids=frozenset(
                    row["id"] for row in previous["id_reservations"]
                ),
            )
        elif operation == "update":
            plan = plan_batch_repository_updates(
                document, current_generation=expected_generation,
                proposed_repositories=proposed_repositories,
            )
        elif operation == "remove":
            plan = plan_batch_repository_removals(
                document, current_generation=expected_generation,
                repository_ids=repository_ids,
                all_repositories=all_repositories,
            )
        else:
            # The batch desired-state planner lives in the v1 reconciliation
            # module, which already imports this v2 builder to encode the
            # fixed native candidate envelope (#411). Defer only this
            # pure module import to avoid a circular module initialization;
            # there is no runtime plugin/extension or dynamic host action.
            from repocache.server_repository_reconcile_v1 import (
                plan_batch_repository_states,
            )
            plan = plan_batch_repository_states(
                document, current_generation=expected_generation,
                operation=operation, repository_ids=repository_ids,
            )
        if plan["authorizes_state_write"] is not False:
            _deny("BATCH_PLAN_UNSAFE")
        if plan["changed"] is False:
            return {
                "schema_version": 1,
                "status": "NO_CHANGE_V2_BATCH_CANDIDATE_ONLY",
                "operation": operation,
                "changed": False,
                "expected_generation": expected_generation,
                "proposed_state_generation": expected_generation,
                "per_repository": plan["per_repository"],
                "proposed_snapshot": None,
                "operator_authorization_verified": False,
                "native_nginx_exposure_verified": False,
                "authorizes_state_write": False,
                "authorizes_nginx_activation": False,
                "authorizes_catalog_publication": False,
                "authorizes_cache_cleanup": False,
            }
        next_snapshot = _next_snapshot(
            previous, plan["candidate_document"],
            decision_sha256=decision_sha256,
        )
        preview_proposed_v2_state_transition(
            next_snapshot, expected_generation=expected_generation,
            previous_snapshot=previous,
        )
        removed_ids = sorted(
            {row["id"] for row in previous["repository_records"]}
            - {row["id"] for row in next_snapshot["repository_records"]}
        )
        return {
            "schema_version": 1,
            "status": "V2_ATOMIC_BATCH_REPOSITORY_CANDIDATE_ONLY",
            "operation": operation,
            "changed": True,
            "expected_generation": expected_generation,
            "proposed_state_generation": expected_generation + 1,
            "per_repository": plan["per_repository"],
            "retired_ids_proposed": removed_ids,
            "proposed_snapshot": next_snapshot,
            "operator_authorization_verified": False,
            "native_nginx_exposure_verified": False,
            "authorizes_state_write": False,
            "authorizes_nginx_activation": False,
            "authorizes_catalog_publication": False,
            "authorizes_cache_cleanup": False,
        }
    except RepositoryV2TransitionError:
        raise
    except (ValueError, TypeError, OSError, OverflowError, RecursionError,
            UnicodeError):
        _deny("BATCH_CANDIDATE_INVALID")
