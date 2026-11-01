"""Inert #95 repository-planning regressions: no host or catalog writes."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_install_v1 import InstallInputError
from repocache.server_repository_plan_v1 import (
    RepositoryPlanError,
    plan_repository_change,
    propose_automatic_repository_id,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document() -> dict:
    source = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    # This intent fixture deliberately omits one ID. The state planner only
    # accepts fully identified snapshots, pending a durable auto-ID allocator.
    source["repositories"][1]["id"] = "almalinux-baseos"
    return source


def plan(source: dict, operation: str, **kwargs) -> dict:
    if operation == "add" and "reserved_ids" not in kwargs:
        # Tests simulate a complete reservation snapshot containing live IDs.
        # Unlike the future state engine, this helper has NO trusted ledger.
        kwargs["reserved_ids"] = {repo["id"] for repo in source["repositories"]}
    return plan_repository_change(
        source, current_generation=0, operation=operation, **kwargs
    )


def new_apt(source: dict, name: str = "debian-extra") -> dict:
    result = copy.deepcopy(source["repositories"][0])
    result["id"] = name
    result["upstream"]["base_url"] = "https://mirror.example.invalid/other/"
    return result


def test_add_explicit_id_is_validated_inert_and_does_not_mutate_source():
    before = document()
    original = copy.deepcopy(before)
    proposed = new_apt(before)
    proposed_copy = copy.deepcopy(proposed)
    result = plan(before, "add", proposed_repository=proposed)
    assert result["status"] == "PLAN_ONLY"
    assert result["changed"] is True
    assert result["repository_id"] == "debian-extra"
    assert len(result["candidate_document"]["repositories"]) == 3
    assert before == original
    assert proposed == proposed_copy
    assert result["candidate_document"]["expected_state_generation"] == 0


def test_repeated_add_same_complete_definition_is_a_noop():
    before = document()
    result = plan(before, "add", proposed_repository=copy.deepcopy(before["repositories"][0]))
    assert result["changed"] is False
    assert result["candidate_document"] == before


def test_changed_existing_id_must_use_update_not_add():
    before = document()
    changed = copy.deepcopy(before["repositories"][0])
    changed["upstream"]["base_url"] = "https://mirror.example.invalid/other/"
    with pytest.raises(RepositoryPlanError, match="already in use"):
        plan(before, "add", proposed_repository=changed)


def test_duplicate_canonical_repository_identity_fails_closed():
    before = document()
    duplicate = copy.deepcopy(before["repositories"][0])
    duplicate["id"] = "another-name"
    with pytest.raises(InstallInputError, match="duplicate canonical"):
        plan(before, "add", proposed_repository=duplicate)


def test_update_validates_conflicts_and_preserves_stable_id():
    before = document()
    changed = new_apt(before, "debian-trixie-main")
    result = plan(before, "update", repository_id="debian-trixie-main",
                  proposed_repository=changed)
    assert result["changed"] is True
    assert result["candidate_document"]["repositories"][0] == changed
    assert before["repositories"][0]["upstream"]["base_url"] != changed["upstream"]["base_url"]
    with pytest.raises(RepositoryPlanError, match="remain stable"):
        plan(before, "update", repository_id="debian-trixie-main",
             proposed_repository=new_apt(before))


def test_enable_disable_only_change_desired_state_not_exposure():
    before = document()
    enabled = plan(before, "enable", repository_id="debian-trixie-main")
    assert enabled["changed"] is True
    assert enabled["status"] == "PLAN_ONLY"
    assert enabled["candidate_document"]["repositories"][0]["desired_state"] == "active"
    assert before["repositories"][0]["desired_state"] == "disabled"
    again = plan(enabled["candidate_document"], "enable", repository_id="debian-trixie-main")
    assert again["changed"] is False
    disabled = plan(enabled["candidate_document"], "disable", repository_id="debian-trixie-main")
    assert disabled["changed"] is True
    assert disabled["candidate_document"] == before


def test_remove_never_purges_and_absent_remove_is_noop():
    before = document()
    removed = plan(before, "remove", repository_id="almalinux-baseos")
    assert removed["changed"] is True
    assert len(removed["candidate_document"]["repositories"]) == 1
    assert len(before["repositories"]) == 2
    noop = plan(removed["candidate_document"], "remove", repository_id="almalinux-baseos")
    assert noop["changed"] is False


@pytest.mark.parametrize("invalid", [None, "", "../escape", "A", "a_b", "ä", "a" * 49])
def test_invalid_or_missing_id_rejected_without_candidate(invalid):
    before = document()
    with pytest.raises(RepositoryPlanError):
        plan(before, "remove", repository_id=invalid)


def test_auto_id_is_not_guessed_from_incomplete_installer_input():
    with pytest.raises(RepositoryPlanError, match="durable identifiers"):
        plan(json.loads(EXAMPLE.read_text(encoding="utf-8")), "remove",
             repository_id="debian-trixie-main")
    candidate = new_apt(document())
    del candidate["id"]
    with pytest.raises(RepositoryPlanError, match="explicit ID"):
        plan(document(), "add", proposed_repository=candidate)


@pytest.mark.parametrize("generation", [True, -1, 1, 2**63, "0", None])
def test_stale_or_invalid_generation_rejected(generation):
    with pytest.raises(RepositoryPlanError):
        plan_repository_change(document(), current_generation=generation,
                               operation="disable", repository_id="debian-trixie-main")


@pytest.mark.parametrize("operation", ["", "publish", "purge", "apply", None])
def test_unsafe_operations_never_enter_the_planner(operation):
    with pytest.raises(RepositoryPlanError, match="unsupported"):
        plan(document(), operation, repository_id="debian-trixie-main")


def test_unexpected_payloads_and_missing_targets_fail():
    before = document()
    with pytest.raises(RepositoryPlanError):
        plan(before, "enable", repository_id="missing")
    with pytest.raises(RepositoryPlanError):
        plan(before, "update", repository_id="missing",
             proposed_repository=new_apt(before, "missing"))
    with pytest.raises(RepositoryPlanError):
        plan(before, "enable", repository_id="debian-trixie-main",
             proposed_repository=before["repositories"][0])
    with pytest.raises(RepositoryPlanError):
        plan(before, "add", repository_id="debian-extra",
             proposed_repository=new_apt(before))


def test_writes_and_network_calls_are_never_required(monkeypatch):
    before = document()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("planner attempted an external side effect")

    import os
    import socket
    import subprocess

    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert plan(before, "disable", repository_id="debian-trixie-main")["changed"] is False
    assert plan(before, "add", proposed_repository=new_apt(before))["changed"] is True


def test_auto_id_is_stable_for_same_validated_identity():
    source = document()
    candidate = new_apt(source)
    del candidate["id"]
    original = copy.deepcopy(candidate)
    reserved = {repo["id"] for repo in source["repositories"]}
    first = propose_automatic_repository_id(
        source, candidate, current_generation=0, reserved_ids=reserved)
    second = propose_automatic_repository_id(
        source, candidate, current_generation=0, reserved_ids=frozenset(reserved))
    assert first == second
    assert first["status"] == "PLAN_ONLY" and first["existing"] is False
    assert first["repository_id"].startswith("repo-")
    assert len(first["repository_id"]) <= 48
    assert first["repository_id"] not in reserved
    assert candidate == original


def test_auto_id_matches_existing_canonical_repository():
    source = document()
    candidate = copy.deepcopy(source["repositories"][0])
    del candidate["id"]
    result = propose_automatic_repository_id(
        source, candidate, current_generation=0,
        reserved_ids={repo["id"] for repo in source["repositories"]})
    assert result["repository_id"] == "debian-trixie-main"
    assert result["existing"] is True


def test_auto_id_tombstone_prevents_reusing_removed_identity():
    source = document()
    candidate = new_apt(source)
    del candidate["id"]
    reservations = {repo["id"] for repo in source["repositories"]}
    first = propose_automatic_repository_id(
        source, candidate, current_generation=0, reserved_ids=reservations)
    reservations.add(first["repository_id"])  # reserved even after deletion
    later = propose_automatic_repository_id(
        source, candidate, current_generation=0, reserved_ids=reservations)
    assert later["repository_id"] not in reservations
    assert later["repository_id"] != first["repository_id"]


def test_auto_id_requires_all_existing_repositories_reserved():
    source = document()
    candidate = new_apt(source)
    del candidate["id"]
    with pytest.raises(RepositoryPlanError, match="live repository not reserved"):
        propose_automatic_repository_id(
            source, candidate, current_generation=0, reserved_ids=set())


@pytest.mark.parametrize("reservations", [None, [], {}, {"../bad"}, {"a" * 49}, {"ok", 2}])
def test_auto_id_refuses_ambiguous_reservation_input(reservations):
    source = document()
    candidate = new_apt(source)
    del candidate["id"]
    with pytest.raises(RepositoryPlanError):
        propose_automatic_repository_id(
            source, candidate, current_generation=0,
            reserved_ids=reservations)


def test_auto_id_rejects_unvalidated_and_stale_candidates():
    source = document()
    candidate = new_apt(source)
    del candidate["id"]
    reservations = {repo["id"] for repo in source["repositories"]}
    candidate["upstream"]["base_url"] = "http://127.0.0.1/"
    with pytest.raises(InstallInputError):
        propose_automatic_repository_id(
            source, candidate, current_generation=0, reserved_ids=reservations)
    del candidate["upstream"]["base_url"]
    with pytest.raises(RepositoryPlanError, match="stale"):
        propose_automatic_repository_id(
            source, candidate, current_generation=1, reserved_ids=reservations)


def test_auto_id_does_not_accept_explicit_identifier():
    source = document()
    candidate = new_apt(source)
    with pytest.raises(RepositoryPlanError, match="must be omitted"):
        propose_automatic_repository_id(
            source, candidate, current_generation=0,
            reserved_ids={repo["id"] for repo in source["repositories"]})


def test_explicit_add_requires_reservation_snapshot():
    before = document()
    candidate = new_apt(before)
    with pytest.raises(RepositoryPlanError, match="snapshot required"):
        plan_repository_change(before, current_generation=0,
                               operation="add", proposed_repository=candidate)
    with pytest.raises(RepositoryPlanError, match="live repository not reserved"):
        plan(before, "add", proposed_repository=candidate, reserved_ids=set())


def test_explicit_add_rejects_historical_id_after_removal():
    before = document()
    old_id = before["repositories"][0]["id"]
    removed = plan(before, "remove", repository_id=old_id)["candidate_document"]
    reserved = {repo["id"] for repo in before["repositories"]}
    with pytest.raises(RepositoryPlanError, match="historically reserved"):
        plan(removed, "add", proposed_repository=copy.deepcopy(before["repositories"][0]),
             reserved_ids=reserved)
    changed = copy.deepcopy(before["repositories"][0])
    changed["upstream"]["base_url"] = "https://mirror.example.invalid/other/"
    with pytest.raises(RepositoryPlanError, match="historically reserved"):
        plan(removed, "add", proposed_repository=changed, reserved_ids=reserved)
    added = new_apt(removed)
    outcome = plan(removed, "add", proposed_repository=added, reserved_ids=reserved)
    assert outcome["status"] == "PLAN_ONLY"
    assert outcome["id_eligibility"] == "CALLER_SNAPSHOT_ONLY"
    assert outcome["changed"] is True


@pytest.mark.parametrize("field", ["allowed_hosts", "cache_overrides", "desired_state"])
def test_auto_id_matching_identity_different_configuration_must_conflict(field):
    before = document()
    proposal = copy.deepcopy(before["repositories"][0])
    del proposal["id"]
    if field == "allowed_hosts":
        proposal["upstream"]["allowed_hosts"].append("extra.example.invalid")
    elif field == "cache_overrides":
        proposal["cache_overrides"]["inactive_seconds"] = 60
    else:
        proposal["desired_state"] = "active"
    with pytest.raises(RepositoryPlanError, match="matching identity has different configuration"):
        propose_automatic_repository_id(
            before, proposal, current_generation=0,
            reserved_ids={repo["id"] for repo in before["repositories"]})


@pytest.mark.parametrize("field", ["allowed_hosts", "cache_overrides", "desired_state"])
def test_explicit_add_matching_id_different_configuration_must_conflict(field):
    before = document()
    proposal = copy.deepcopy(before["repositories"][0])
    if field == "allowed_hosts":
        proposal["upstream"]["allowed_hosts"].append("extra.example.invalid")
    elif field == "cache_overrides":
        proposal["cache_overrides"]["inactive_seconds"] = 60
    else:
        proposal["desired_state"] = "active"
    with pytest.raises(RepositoryPlanError, match="already in use"):
        plan(before, "add", proposed_repository=proposal)


def test_semantically_equal_reordered_sets_are_idempotent():
    before = document()
    current = before["repositories"][0]
    current["layout"]["architectures"].append("arm64")
    current["upstream"]["allowed_hosts"].append("extra.example.invalid")
    proposed = copy.deepcopy(current)
    proposed["layout"]["architectures"].reverse()
    proposed["upstream"]["allowed_hosts"].reverse()
    proposed["upstream"]["allowed_hosts"][0] = "EXTRA.EXAMPLE.INVALID"
    proposed["upstream"]["base_url"] = "https://MIRROR.EXAMPLE.INVALID:443/debian/"
    proposed.pop("cache_overrides")
    assert plan(before, "add", proposed_repository=proposed)["changed"] is False
    assert plan(before, "update", repository_id=current["id"],
                proposed_repository=proposed)["changed"] is False
    del proposed["id"]
    outcome = propose_automatic_repository_id(
        before, proposed, current_generation=0,
        reserved_ids={repo["id"] for repo in before["repositories"]})
    assert outcome["existing"] is True
    assert outcome["repository_id"] == current["id"]


@pytest.mark.parametrize("operation", ["add", "update", "automatic"])
def test_malformed_proposals_rejected_before_deepcopy(operation):
    before = document()
    candidate = new_apt(before, "debian-extra" if operation != "update"
                        else "debian-trixie-main")
    if operation == "automatic":
        candidate.pop("id")
    current = candidate["layout"]
    for _ in range(100):
        current = current.setdefault("malformed", {})
    if operation == "automatic":
        execute = lambda: propose_automatic_repository_id(
            before, candidate, current_generation=0,
            reserved_ids={repo["id"] for repo in before["repositories"]})
    elif operation == "update":
        execute = lambda: plan(before, "update",
                               repository_id="debian-trixie-main",
                               proposed_repository=candidate)
    else:
        execute = lambda: plan(before, "add", proposed_repository=candidate)
    with pytest.raises(InstallInputError, match="nesting"):
        execute()


@pytest.mark.parametrize("operation", ["add", "update", "automatic"])
def test_oversized_proposals_rejected_without_copying(operation):
    before = document()
    candidate = new_apt(before, "debian-extra" if operation != "update"
                        else "debian-trixie-main")
    if operation == "automatic":
        candidate.pop("id")
    candidate["layout"]["suites"] = ["x" * (1024 * 1024)]
    if operation == "automatic":
        execute = lambda: propose_automatic_repository_id(
            before, candidate, current_generation=0,
            reserved_ids={repo["id"] for repo in before["repositories"]})
    elif operation == "update":
        execute = lambda: plan(before, "update",
                               repository_id="debian-trixie-main",
                               proposed_repository=candidate)
    else:
        execute = lambda: plan(before, "add", proposed_repository=candidate)
    with pytest.raises(InstallInputError, match="1 MiB"):
        execute()


def test_auto_id_duplicate_semantic_inputs_differ_only_on_whitelisted_policy():
    before = document()
    existing = before["repositories"][0]
    candidate = copy.deepcopy(existing)
    del candidate["id"]
    candidate["cache_overrides"] = {}
    assert propose_automatic_repository_id(
        before, candidate, current_generation=0,
        reserved_ids={repo["id"] for repo in before["repositories"]})["existing"] is True
    candidate["cache_overrides"] = {"inactive_seconds": 100}
    with pytest.raises(RepositoryPlanError, match="use update"):
        propose_automatic_repository_id(
            before, candidate, current_generation=0,
            reserved_ids={repo["id"] for repo in before["repositories"]})


def test_all_add_operations_report_non_authoritative_id_eligibility():
    before = document()
    for candidate in (new_apt(before), copy.deepcopy(before["repositories"][0])):
        outcome = plan(before, "add", proposed_repository=candidate)
        assert outcome["id_eligibility"] == "CALLER_SNAPSHOT_ONLY"
        assert outcome["status"] == "PLAN_ONLY"


def test_reservations_for_non_add_are_rejected_not_treated_as_authority():
    before = document()
    with pytest.raises(RepositoryPlanError, match="accepted only for add"):
        plan(before, "remove", repository_id="debian-trixie-main",
             reserved_ids={repo["id"] for repo in before["repositories"]})


@pytest.mark.parametrize("kind,field", [
    ("apt", "release_key_refs"), ("dnf", "gpg_key_refs"),
])
def test_trust_reference_rotation_is_an_update_not_new_identity(kind, field):
    before = document()
    current = next(repo for repo in before["repositories"] if repo["kind"] == kind)
    rotated = copy.deepcopy(current)
    rotated["layout"][field] = [
        "file:/etc/repocache/keys/rotated-public.gpg"
    ]
    old_id = current["id"]
    proposal = copy.deepcopy(rotated)
    del proposal["id"]
    reserved = {repo["id"] for repo in before["repositories"]}

    # Changing trust policy must NOT mint an unrelated source identity.
    with pytest.raises(RepositoryPlanError, match="matching identity has different configuration"):
        propose_automatic_repository_id(
            before, proposal, current_generation=0, reserved_ids=reserved)
    with pytest.raises(RepositoryPlanError, match="already in use"):
        plan(before, "add", proposed_repository=rotated)

    updated = plan(before, "update", repository_id=old_id,
                   proposed_repository=rotated)
    assert updated["changed"] is True
    assert updated["repository_id"] == old_id
    effective = next(repo for repo in updated["candidate_document"]["repositories"]
                     if repo["id"] == old_id)
    assert effective["layout"][field] == rotated["layout"][field]
    assert current["layout"][field] != effective["layout"][field]


@pytest.mark.parametrize("kind,field", [
    ("apt", "release_key_refs"), ("dnf", "gpg_key_refs"),
])
def test_reordering_public_signing_key_set_is_idempotent(kind, field):
    before = document()
    current = next(repo for repo in before["repositories"] if repo["kind"] == kind)
    current["layout"][field].append("file:/etc/repocache/keys/second-public.gpg")
    proposed = copy.deepcopy(current)
    proposed["layout"][field].reverse()
    assert plan(before, "add", proposed_repository=proposed)["changed"] is False
    assert plan(before, "update", repository_id=current["id"],
                proposed_repository=proposed)["changed"] is False
    del proposed["id"]
    result = propose_automatic_repository_id(
        before, proposed, current_generation=0,
        reserved_ids={repo["id"] for repo in before["repositories"]})
    assert result["existing"] is True
    assert result["repository_id"] == current["id"]


@pytest.mark.parametrize("field,second", [
    ("suites", "bookworm"), ("components", "contrib"),
    ("architectures", "arm64"),
])
def test_reordering_apt_routing_sets_is_idempotent(field, second):
    before = document()
    current = before["repositories"][0]
    current["layout"][field].append(second)
    proposed = copy.deepcopy(current)
    proposed["layout"][field].reverse()
    assert plan(before, "add", proposed_repository=proposed)["changed"] is False
    assert plan(before, "update", repository_id=current["id"],
                proposed_repository=proposed)["changed"] is False


@pytest.mark.parametrize("kind,field", [
    ("apt", "release_key_refs"), ("dnf", "gpg_key_refs"),
])
def test_auto_generated_identity_does_not_change_on_trust_rotation(kind, field):
    before = document()
    proposal = copy.deepcopy(
        next(repo for repo in before["repositories"] if repo["kind"] == kind))
    proposal.pop("id")
    proposal["upstream"]["base_url"] = "https://fresh.example.invalid/new-source/"
    proposal["upstream"]["allowed_hosts"] = ["fresh.example.invalid"]
    reserved = {repo["id"] for repo in before["repositories"]}
    first = propose_automatic_repository_id(
        before, proposal, current_generation=0, reserved_ids=reserved)
    proposal["layout"][field] = ["file:/etc/repocache/keys/rotated-public.gpg"]
    second = propose_automatic_repository_id(
        before, proposal, current_generation=0, reserved_ids=reserved)
    assert first["repository_id"] == second["repository_id"]
    assert first["existing"] is second["existing"] is False


def test_mutable_reservation_input_is_snapshotted():
    from repocache.server_repository_plan_v1 import _reserved_snapshot

    before = document()
    original = {repo["id"] for repo in before["repositories"]}
    snapshot = _reserved_snapshot(before, original)
    assert type(snapshot) is frozenset
    original.add("new-id")
    assert "new-id" not in snapshot
    original.clear()
    assert snapshot == {repo["id"] for repo in before["repositories"]}


def test_cache_maximum_size_is_a_material_configuration_difference():
    before = document()
    candidate = copy.deepcopy(before["repositories"][0])
    candidate["cache_overrides"]["max_size_bytes"] = 4096
    with pytest.raises(RepositoryPlanError, match="already in use"):
        plan(before, "add", proposed_repository=candidate)
    del candidate["id"]
    with pytest.raises(RepositoryPlanError, match="use update"):
        propose_automatic_repository_id(
            before, candidate, current_generation=0,
            reserved_ids={repo["id"] for repo in before["repositories"]})


def test_reservation_cardinality_rechecked_after_copy_interleaving(monkeypatch):
    """Model caller-set growth strictly between the first length check and copy.

    The injectable frozenset constructor is a deterministic interleaving hook;
    this is not a production-thread or trusted-ledger integration test.
    """
    import repocache.server_repository_plan_v1 as planner

    before = document()
    reservations = {repo["id"] for repo in before["repositories"]}
    original_count = len(reservations)

    class GrowingFrozenSet(frozenset):
        def __new__(cls, iterable):
            iterable.update(f"historical-{i}" for i in range(10000))
            return super().__new__(cls, iterable)

    monkeypatch.setattr(planner, "frozenset", GrowingFrozenSet, raising=False)
    with pytest.raises(RepositoryPlanError, match="bounded snapshot"):
        planner._reserved_snapshot(before, reservations)
    assert original_count == len(before["repositories"])
    assert len(reservations) > 10000
