"""Single-generation #95 batch lifecycle on canonical protected v2 input."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from repocache.server_fixture_multi_resource_wal_v1 import (
    _commit_fixture_multi_resource_under_root as commit_multi,
    CATALOG,
)
from repocache.server_install_v1 import validate_install_document
from repocache.server_proposed_state_v2_store import V2_STATE
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_repository_v2_transition_v1 import (
    RepositoryV2TransitionError, plan_repository_v2_batch_transition,
)
from repocache.server_repository_reconcile_v1 import (
    ReconciliationPlanError, render_fixed_native_repository_batch_envelope,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
APT = "debian-trixie-main"
DNF = "almalinux-baseos"
DECISION = "b" * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def initial():
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc["expected_state_generation"] = 1
    doc["repositories"][1]["id"] = DNF
    doc = validate_install_document(doc, for_apply=True)
    payload = canonical(doc)
    digest = hashlib.sha256(payload).hexdigest()
    rows = [{
        "id": repo["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(repo).encode("utf-8"),
        ).hexdigest(),
        "desired_state": repo["desired_state"],
        "observed_state": "not-activated",
    } for repo in doc["repositories"]]
    return {
        "state_schema_version": 2,
        "state_generation": 1,
        "configuration_base64": base64.b64encode(payload).decode("ascii"),
        "configuration_sha256": digest,
        "repository_records": rows,
        "id_reservations": [{
            "id": row["id"],
            "canonical_identity_sha256": row["canonical_identity_sha256"],
            "status": "allocated",
        } for row in rows],
        "approval_reference": {
            "source": "operator",
            "decision_sha256": "a" * 64,
            "configuration_sha256": digest,
            "expected_generation": 0,
        },
    }


def plan(previous, *, generation=None, operation, **kwargs):
    if generation is None:
        generation = previous["state_generation"]
    return plan_repository_v2_batch_transition(
        previous, expected_generation=generation,
        expected_previous_state_sha256=hashlib.sha256(
            canonical(previous)
        ).hexdigest(),
        decision_sha256=DECISION, operation=operation, **kwargs,
    )


def proposals():
    original = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    apt = copy.deepcopy(original["repositories"][0])
    apt.pop("id")
    apt["upstream"]["base_url"] = "https://auto-apt.example.invalid/debian/"
    apt["upstream"]["allowed_hosts"] = ["auto-apt.example.invalid"]
    dnf = copy.deepcopy(original["repositories"][1])
    # The canonical install-v1 sample already leaves the DNF ID for
    # automatic allocation; an absent optional field is expected.
    dnf.pop("id", None)
    dnf["upstream"]["base_url"] = (
        "https://auto-dnf.example.invalid/almalinux/10/BaseOS/x86_64/os/"
    )
    dnf["upstream"]["allowed_hosts"] = ["auto-dnf.example.invalid"]
    return apt, dnf


def test_multi_add_allocates_from_all_time_history_in_one_generation():
    before = initial()
    first, second = proposals()
    prior = copy.deepcopy(before)
    outcome = plan(
        before, operation="add", proposed_repositories=(first, second),
    )
    assert outcome["status"] == "V2_ATOMIC_BATCH_REPOSITORY_CANDIDATE_ONLY"
    assert outcome["expected_generation"] == 1
    assert outcome["proposed_state_generation"] == 2
    after = outcome["proposed_snapshot"]
    assert after["state_generation"] == 2
    assert len(after["repository_records"]) == 4
    assigned = [row["repository_id"] for row in outcome["per_repository"]]
    assert len(set(assigned)) == 2
    assert all(x.startswith("repo-") for x in assigned)
    assert set(assigned) <= {r["id"] for r in after["id_reservations"]}
    assert {r["id"] for r in before["id_reservations"]} <= {
        r["id"] for r in after["id_reservations"]
    }
    assert all(row["id_assignment"] == "AUTO_SUGGESTED"
               for row in outcome["per_repository"])
    assert outcome["retired_ids_proposed"] == []
    assert before == prior
    assert "id" not in first and "id" not in second
    assert plan(before, operation="add", proposed_repositories=(first, second))[
        "proposed_snapshot"
    ] == after
    for key, value in outcome.items():
        if key.startswith("authorizes_") or key.endswith("_verified"):
            assert value is False


def test_batch_enable_disable_and_idempotence_uses_only_one_v2_generation():
    old = initial()
    enabled = plan(
        old, operation="enable", repository_ids=(DNF, APT),
    )
    assert enabled["proposed_snapshot"]["state_generation"] == 2
    assert {r["id"] for r in enabled["proposed_snapshot"]["repository_records"]
            if r["desired_state"] == "active"} == {APT, DNF}
    assert [row["repository_id"] for row in enabled["per_repository"]] == [
        DNF, APT,
    ]
    no_op = plan(
        enabled["proposed_snapshot"], operation="enable",
        repository_ids=(APT, DNF),
    )
    assert no_op["status"] == "NO_CHANGE_V2_BATCH_CANDIDATE_ONLY"
    assert no_op["proposed_snapshot"] is None
    assert no_op["proposed_state_generation"] == 2
    assert no_op["authorizes_state_write"] is False

    disabled = plan(
        enabled["proposed_snapshot"], operation="disable",
        repository_ids=(APT, DNF),
    )
    assert disabled["proposed_snapshot"]["state_generation"] == 3
    assert all(r["desired_state"] == "disabled"
               for r in disabled["proposed_snapshot"]["repository_records"])

    # Missing but syntactically valid IDs remain explicit per-ID no-ops.
    missing = plan(
        disabled["proposed_snapshot"], operation="enable",
        repository_ids=("not-found-repo",),
    )
    assert missing["changed"] is False
    assert missing["per_repository"] == [
        {"repository_id": "not-found-repo", "result": "NOT_FOUND"},
    ]


def test_batch_update_keeps_cache_identity_and_rejects_rebinding():
    previous = initial()
    doc = json.loads(base64.b64decode(previous["configuration_base64"]))
    changed = []
    for row in doc["repositories"]:
        item = copy.deepcopy(row)
        trust_field = ("release_key_refs" if item["kind"] == "apt"
                       else "gpg_key_refs")
        item["layout"][trust_field] = [
            "file:/etc/repocache/keys/rotated-" + item["kind"] + ".gpg",
        ]
        changed.append(item)
    updated = plan(
        previous, operation="update",
        proposed_repositories=tuple(changed),
    )
    assert updated["proposed_snapshot"]["state_generation"] == 2
    old_ids = {r["id"]: r["canonical_identity_sha256"]
               for r in previous["repository_records"]}
    assert {r["id"]: r["canonical_identity_sha256"]
            for r in updated["proposed_snapshot"]["repository_records"]} == old_ids
    repeat = plan(
        updated["proposed_snapshot"], operation="update",
        proposed_repositories=tuple(changed),
    )
    assert repeat["changed"] is False

    replacement = copy.deepcopy(changed[0])
    replacement["upstream"]["base_url"] = "https://attacker.example.invalid/apt/"
    replacement["upstream"]["allowed_hosts"] = ["attacker.example.invalid"]
    with pytest.raises(RepositoryV2TransitionError, match="BATCH_CANDIDATE_INVALID"):
        plan(
            previous, operation="update",
            proposed_repositories=(replacement,),
        )


def test_batch_remove_preserves_permanent_id_and_identity_history():
    old = initial()
    report = plan(
        old, operation="remove",
        repository_ids=(APT, "not-found-repo", DNF),
    )
    assert report["proposed_snapshot"]["state_generation"] == 2
    assert report["retired_ids_proposed"] == sorted((APT, DNF))
    assert report["per_repository"] == [
        {"repository_id": APT, "result": "REMOVE_CANDIDATE"},
        {"repository_id": "not-found-repo", "result": "ALREADY_ABSENT"},
        {"repository_id": DNF, "result": "REMOVE_CANDIDATE"},
    ]
    after = report["proposed_snapshot"]
    assert after["repository_records"] == []
    assert {r["id"] for r in after["id_reservations"]} == {APT, DNF}
    assert all(r["status"] == "retired" for r in after["id_reservations"])
    already = plan(
        after, operation="remove",
        repository_ids=(APT, DNF),
    )
    assert already["changed"] is False
    assert already["proposed_snapshot"] is None

    # The historical ledger refuses re-adding a previous source, regardless
    # of whether a different ID is supplied by an untrusted caller.
    one = json.loads(base64.b64decode(old["configuration_base64"]))[
        "repositories"
    ][0]
    with pytest.raises(RepositoryV2TransitionError, match="BATCH_CANDIDATE_INVALID"):
        plan(
            after, operation="add",
            proposed_repositories=({**one, "id": "other-identifier"},),
        )


def test_batch_remove_all_is_single_generation_without_cache_purge():
    old = initial()
    out = plan(old, operation="remove", all_repositories=True)
    assert out["proposed_state_generation"] == 2
    assert out["retired_ids_proposed"] == sorted([APT, DNF])
    assert len(out["per_repository"]) == 2
    assert out["authorizes_cache_cleanup"] is False
    assert out["proposed_snapshot"]["repository_records"] == []


@pytest.mark.parametrize("operation,kwargs", [
    ("add", {"repository_ids": (APT,), "proposed_repositories": ()}),
    ("update", {"all_repositories": True}),
    ("enable", {"proposed_repositories": ({},), "repository_ids": (APT,)}),
    ("disable", {"all_repositories": True, "repository_ids": (APT,)}),
    ("remove", {"proposed_repositories": ({},), "repository_ids": (APT,)}),
    ("remove", {"repository_ids": (APT, APT)}),
    ("enable", {"repository_ids": ("../foreign",)}),
    ("unknown", {"repository_ids": (APT,)}),
])
def test_unapproved_batch_selectors_fail_before_any_v2_candidate(operation, kwargs):
    with pytest.raises(RepositoryV2TransitionError):
        plan(initial(), operation=operation, **kwargs)


def test_batch_duplicate_and_historic_explicit_id_fail_closed():
    before = initial()
    apt, dnf = proposals()
    explicit = {**apt, "id": "brand-new-id"}
    with pytest.raises(RepositoryV2TransitionError):
        plan(
            before, operation="add",
            proposed_repositories=(explicit, explicit),
        )
    with pytest.raises(RepositoryV2TransitionError):
        plan(
            before, operation="add",
            proposed_repositories=({**apt, "id": APT},),
        )
    # All-or-nothing: one valid proposal does not permit a second invalid.
    with pytest.raises(RepositoryV2TransitionError):
        plan(
            before, operation="add",
            proposed_repositories=(apt, {**dnf, "id": "../secret"}),
        )


def test_batch_requires_exact_protected_predecessor_digest_and_generation():
    old = initial()
    with pytest.raises(RepositoryV2TransitionError, match="BATCH_PREDECESSOR_MISMATCH"):
        plan_repository_v2_batch_transition(
            old, expected_generation=1,
            expected_previous_state_sha256="0" * 64,
            decision_sha256=DECISION, operation="enable",
            repository_ids=(APT,),
        )
    with pytest.raises(RepositoryV2TransitionError, match="BATCH_PREDECESSOR_MISMATCH"):
        plan(old, generation=2, operation="enable", repository_ids=(APT,))
    with pytest.raises(RepositoryV2TransitionError, match="BATCH_ARGUMENT_INVALID"):
        plan(old, generation=True, operation="enable", repository_ids=(APT,))


@pytest.fixture
def protected_root(tmp_path):
    root = tmp_path / "detached"
    root.mkdir(mode=0o700)
    path = root
    for segment in ("var", "lib", "repocache", "server"):
        path /= segment
        path.mkdir(mode=0o700)
    lock = path / LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd, path, os.geteuid()
    finally:
        os.close(fd)


def test_batch_exercises_one_durable_state_include_catalog_wal_per_operation(
    protected_root,
):
    fd, directory, uid = protected_root
    current = initial()
    def catalog(ids):
        return canonical({
            "schema_version": 1,
            "status": "fixture-only-observed-candidate",
            "active_ids": sorted(ids),
        })
    def persist(state, *, previous_generation, catalog_ids, label):
        expected_sha = (None if previous_generation == 0
                        else hashlib.sha256(
                            (directory / V2_STATE).read_bytes()
                        ).hexdigest())
        report = commit_multi(
            fd, state, owner_uid=uid,
            expected_generation=previous_generation,
            expected_previous_state_sha256=expected_sha,
            include_bytes=("# batch " + label + "\n").encode(),
            catalog_bytes=catalog(catalog_ids),
        )
        assert report["state_generation"] == previous_generation + 1
    persist(current, previous_generation=0, catalog_ids=[], label="initial")
    original_sha = hashlib.sha256(
        (directory / V2_STATE).read_bytes()
    ).hexdigest()

    enabled = plan(
        current, operation="enable", repository_ids=(APT, DNF),
    )["proposed_snapshot"]
    persist(enabled, previous_generation=1, catalog_ids=(APT, DNF), label="enable-two")
    assert json.loads((directory / CATALOG).read_bytes())[
        "active_ids"
    ] == sorted((APT, DNF))
    assert json.loads((directory / V2_STATE).read_bytes())[
        "state_generation"
    ] == 2
    assert hashlib.sha256((directory / V2_STATE).read_bytes()).hexdigest() != original_sha

    removed = plan(
        enabled, operation="remove", repository_ids=(APT, DNF),
    )["proposed_snapshot"]
    persist(removed, previous_generation=2, catalog_ids=[], label="remove-two")
    assert json.loads((directory / CATALOG).read_bytes())["active_ids"] == []
    assert json.loads((directory / V2_STATE).read_bytes())[
        "state_generation"
    ] == 3
    assert all(item["status"] == "retired"
               for item in removed["id_reservations"])
    assert not (directory / ".state-v2-multi.pending").exists()


def test_batch_fixed_native_candidate_intake_is_one_exact_wire_message():
    old = initial()
    raw = canonical(old)
    report = render_fixed_native_repository_batch_envelope(
        raw, expected_generation=1,
        expected_previous_state_sha256=hashlib.sha256(raw).hexdigest(),
        operation="enable", repository_ids=(APT, DNF),
        decision_sha256=DECISION,
    )
    assert report["status"] == "FIXED_V2_ATOMIC_BATCH_ENVELOPE_ONLY"
    assert report["changed"] is True
    assert len(report["per_repository"]) == 2
    assert report["requires_native_locked_recheck"] is True
    wire = json.loads(report["envelope_bytes"])
    assert set(wire) == {
        "request_schema_version", "expected_generation",
        "expected_state_sha256", "next_state_base64", "next_state_sha256",
    }
    assert wire["request_schema_version"] == 1
    assert wire["expected_generation"] == 1
    assert wire["expected_state_sha256"] == hashlib.sha256(raw).hexdigest()
    next_raw = base64.b64decode(wire["next_state_base64"], validate=True)
    assert hashlib.sha256(next_raw).hexdigest() == wire["next_state_sha256"]
    assert next_raw == canonical(json.loads(next_raw))
    state = json.loads(next_raw)
    assert state["state_generation"] == 2
    assert {r["id"] for r in state["repository_records"]
            if r["desired_state"] == "active"} == {APT, DNF}
    assert report["envelope_bytes"] == canonical(wire)
    for field in ("operator_approval_verified",
                  "persisted_predecessor_provenance_verified",
                  "native_state_lock_held",
                  "authorizes_state_write", "authorizes_nginx_reload",
                  "authorizes_catalog_publication", "authorizes_cache_cleanup"):
        assert report[field] is False

    noop = render_fixed_native_repository_batch_envelope(
        next_raw, expected_generation=2,
        expected_previous_state_sha256=hashlib.sha256(next_raw).hexdigest(),
        operation="enable", repository_ids=(DNF, APT),
        decision_sha256=DECISION,
    )
    assert noop["status"] == "NO_CHANGE_FIXED_V2_BATCH_CANDIDATE_ONLY"
    assert noop["changed"] is False
    assert noop["envelope_bytes"] is None
    assert noop["authorizes_state_write"] is False

    removed = render_fixed_native_repository_batch_envelope(
        next_raw, expected_generation=2,
        expected_previous_state_sha256=hashlib.sha256(next_raw).hexdigest(),
        operation="remove", repository_ids=(APT, DNF),
        decision_sha256=DECISION,
    )
    assert removed["retired_ids_proposed"] == sorted((APT, DNF))
    successor = json.loads(base64.b64decode(
        json.loads(removed["envelope_bytes"])["next_state_base64"],
        validate=True,
    ))
    assert successor["state_generation"] == 3
    assert all(r["status"] == "retired" for r in successor["id_reservations"])


def test_batch_fixed_native_candidate_rejects_forged_previous_bytes_and_selector():
    old = initial()
    raw = canonical(old)
    with pytest.raises(ReconciliationPlanError, match="fixed batch: candidate rejected"):
        render_fixed_native_repository_batch_envelope(
            raw, expected_generation=1,
            expected_previous_state_sha256="0" * 64,
            operation="enable", repository_ids=(APT,),
            decision_sha256=DECISION,
        )
    with pytest.raises(ReconciliationPlanError, match="fixed batch: candidate rejected"):
        render_fixed_native_repository_batch_envelope(
            raw, expected_generation=1,
            expected_previous_state_sha256=hashlib.sha256(raw).hexdigest(),
            operation="enable", repository_ids=("../foreign",),
            decision_sha256=DECISION,
        )
    with pytest.raises(ReconciliationPlanError, match="fixed batch: predecessor invalid"):
        render_fixed_native_repository_batch_envelope(
            b"", expected_generation=1,
            expected_previous_state_sha256="a" * 64,
            operation="enable", repository_ids=(APT,),
            decision_sha256=DECISION,
        )


def test_batch_native_envelope_and_builder_never_contact_os_or_modify_input(
    monkeypatch,
):
    import socket
    import subprocess

    before = initial()
    previous = copy.deepcopy(before)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("batch wire and planner cannot mutate the host")
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(os, "unlink", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)

    result = render_fixed_native_repository_batch_envelope(
        canonical(before), expected_generation=1,
        expected_previous_state_sha256=hashlib.sha256(canonical(before)).hexdigest(),
        operation="enable", repository_ids=(APT, DNF),
        decision_sha256=DECISION,
    )
    assert result["envelope_bytes"]
    assert before == previous


def test_mixed_states_v2_one_generation_and_exact_fixed_native_envelope():
    original = initial()
    enabled = plan(
        original, operation="enable", repository_ids=(APT,),
    )["proposed_snapshot"]
    assert enabled["state_generation"] == 2
    assert [r["desired_state"] for r in enabled["repository_records"]] == [
        "active", "disabled",
    ]
    prior = copy.deepcopy(enabled)
    changes = ((APT, "disabled"), (DNF, "active"))
    mixed = plan(
        enabled, operation="set-states", state_changes=changes,
    )
    assert mixed["status"] == "V2_ATOMIC_BATCH_REPOSITORY_CANDIDATE_ONLY"
    assert mixed["operation"] == "set-states"
    assert mixed["proposed_state_generation"] == 3
    assert mixed["retired_ids_proposed"] == []
    assert [x["result"] for x in mixed["per_repository"]] == [
        "STATE_CHANGE_CANDIDATE", "STATE_CHANGE_CANDIDATE",
    ]
    updated = mixed["proposed_snapshot"]
    assert updated["state_generation"] == 3
    assert [(r["id"], r["desired_state"]) for r in updated["repository_records"]] == [
        (APT, "disabled"), (DNF, "active"),
    ]
    assert {r["id"]: r for r in updated["id_reservations"]} == {
        r["id"]: r for r in original["id_reservations"]
    }
    assert enabled == prior
    for key, value in mixed.items():
        if key.startswith("authorizes_") or key.endswith("_verified"):
            assert value is False
    raw = canonical(enabled)
    envelope = render_fixed_native_repository_batch_envelope(
        raw, expected_generation=2,
        expected_previous_state_sha256=hashlib.sha256(raw).hexdigest(),
        decision_sha256=DECISION, operation="set-states",
        state_changes=changes,
    )
    wire = json.loads(envelope["envelope_bytes"])
    assert envelope["changed"] is True
    assert envelope["operator_approval_verified"] is False
    assert envelope["authorizes_state_write"] is False
    assert envelope["authorizes_nginx_reload"] is False
    assert envelope["authorizes_catalog_publication"] is False
    assert wire["expected_generation"] == 2
    assert wire["expected_state_sha256"] == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(wire["next_state_base64"], validate=True) == canonical(updated)
    assert wire["next_state_sha256"] == hashlib.sha256(canonical(updated)).hexdigest()
    assert plan(updated, operation="set-states", state_changes=changes)[
        "proposed_snapshot"
    ] is None
    no_op = render_fixed_native_repository_batch_envelope(
        canonical(updated), expected_generation=3,
        expected_previous_state_sha256=hashlib.sha256(canonical(updated)).hexdigest(),
        decision_sha256=DECISION, operation="set-states", state_changes=changes,
    )
    assert no_op["changed"] is False and no_op["envelope_bytes"] is None
    assert no_op["authorizes_state_write"] is False


@pytest.mark.parametrize("changes", [
    (),
    [],
    ((APT, "active"), (APT, "disabled")),
    ((APT, "active"), ("unknown-repository", "disabled")),
    ((APT, "active"), ("../etc/passwd", "disabled")),
    ((APT, "approved"),),
    ((APT, True),),
    ((APT, "active", "unexpected"),),
    ([APT, "active"],),
    ((APT, "active"),) * 65,
])
def test_mixed_states_v2_refuses_invalid_selectors_atomically(changes):
    before = initial()
    original = copy.deepcopy(before)
    with pytest.raises(RepositoryV2TransitionError, match="REPOSITORY_V2_TRANSITION_"):
        plan(before, operation="set-states", state_changes=changes)
    assert before == original


@pytest.mark.parametrize("unexpected", [
    {"repository_ids": (APT,)},
    {"proposed_repositories": ({},)},
    {"all_repositories": True},
])
def test_mixed_states_v2_refuses_cross_operation_selectors(unexpected):
    with pytest.raises(RepositoryV2TransitionError, match="BATCH_SELECTORS_INVALID"):
        plan(initial(), operation="set-states",
             state_changes=((APT, "active"),), **unexpected)


def test_mixed_states_v2_rejects_stale_digest_before_proposing_next_state():
    old = initial()
    with pytest.raises(RepositoryV2TransitionError, match="BATCH_PREDECESSOR_MISMATCH"):
        plan_repository_v2_batch_transition(
            old, expected_generation=1,
            expected_previous_state_sha256="0" * 64,
            decision_sha256=DECISION, operation="set-states",
            state_changes=((APT, "active"),),
        )
    with pytest.raises(RepositoryV2TransitionError, match="BATCH_PREDECESSOR_MISMATCH"):
        plan(old, generation=2, operation="set-states",
             state_changes=((APT, "active"),))
    with pytest.raises(ReconciliationPlanError, match="fixed batch:"):
        render_fixed_native_repository_batch_envelope(
            canonical(old), expected_generation=1,
            expected_previous_state_sha256="0" * 64,
            decision_sha256=DECISION, operation="set-states",
            state_changes=((APT, "active"),),
        )
