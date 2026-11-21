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
    dnf.pop("id")
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
