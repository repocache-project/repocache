"""#95: a batch state intent cannot activate real NGINX or mutate the host."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_repository_batch_states_v1 import (
    BatchRepositoryStateError, plan_batch_repository_states,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document():
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    data["repositories"][1]["id"] = "almalinux-baseos"
    return data


def plan(data, action, targets, generation=0):
    return plan_batch_repository_states(
        data, current_generation=generation,
        operation=action, repository_ids=targets,
    )


def assert_inert(value):
    assert value["status"] == "BATCH_STATE_PLAN_ONLY"
    assert all(value[name] is False for name in (
        "operator_authorization_verified", "native_nginx_routes_reconciled",
        "active_catalog_reconciled", "authorizes_nginx_activation",
        "authorizes_catalog_publication", "authorizes_state_write",
        "authorizes_cache_cleanup",
    ))


def test_atomic_batch_enable_then_repeat_then_disable():
    before = document()
    saved = copy.deepcopy(before)
    enabled = plan(before, "enable", ("almalinux-baseos", "debian-trixie-main"))
    assert_inert(enabled)
    assert enabled["changed"]
    assert [row["result"] for row in enabled["per_repository"]] == [
        "ACTIVE_CANDIDATE", "ACTIVE_CANDIDATE",
    ]
    assert {r["desired_state"] for r in enabled["candidate_document"]["repositories"]} == {"active"}
    assert before == saved
    repeat = plan(enabled["candidate_document"], "enable",
                  ("debian-trixie-main", "almalinux-baseos"))
    assert_inert(repeat)
    assert not repeat["changed"]
    assert [row["result"] for row in repeat["per_repository"]] == [
        "ALREADY_ACTIVE", "ALREADY_ACTIVE",
    ]
    disabled = plan(repeat["candidate_document"], "disable",
                    ("debian-trixie-main", "almalinux-baseos"))
    assert disabled["changed"]
    assert disabled["candidate_document"] == before


def test_target_local_missing_does_not_block_present_target():
    source = document()
    outcome = plan(source, "enable", ("not-present", "almalinux-baseos"))
    assert [r["result"] for r in outcome["per_repository"]] == [
        "NOT_FOUND", "ACTIVE_CANDIDATE",
    ]
    assert outcome["candidate_document"]["repositories"][0]["desired_state"] == "disabled"
    assert outcome["candidate_document"]["repositories"][1]["desired_state"] == "active"
    assert_inert(outcome)


def test_all_valid_but_missing_is_idempotent_inert_candidate():
    source = document()
    result = plan(source, "disable", ("absent-repository",))
    assert result["changed"] is False
    assert result["per_repository"][0]["result"] == "NOT_FOUND"
    assert result["candidate_document"] == source
    assert_inert(result)


@pytest.mark.parametrize("operation,ids", [
    ("publish", ("debian-trixie-main",)),
    ("remove", ("debian-trixie-main",)),
    (None, ("debian-trixie-main",)),
    ("enable", ()),
    ("enable", ["debian-trixie-main"]),
    ("enable", ("debian-trixie-main", "debian-trixie-main")),
    ("enable", ("../escape",)),
    ("enable", ("Ä",)),
    ("enable", ("a" * 49,)),
    ("enable", (True,)),
    ("enable", tuple("r" + str(x) for x in range(501))),
])
def test_malformed_or_unsafe_batch_refused_before_candidate(operation, ids):
    before = document()
    saved = copy.deepcopy(before)
    with pytest.raises(BatchRepositoryStateError, match="^BATCH_STATE_"):
        plan(before, operation, ids)
    assert before == saved


@pytest.mark.parametrize("generation", [-1, True, "0", None, 1, 2**63])
def test_untrusted_generation_never_authorizes_change(generation):
    with pytest.raises(BatchRepositoryStateError):
        plan(document(), "enable", ("debian-trixie-main",), generation)


def test_partial_unallocated_state_refused_even_for_known_target():
    source = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    with pytest.raises(BatchRepositoryStateError, match="UNALLOCATED_ID"):
        plan(source, "enable", ("debian-trixie-main",))


def test_unknown_document_fields_fail_closed_without_mutation():
    source = document()
    source["deployment"]["nginx"]["adopt_foreign"] = True
    previous = copy.deepcopy(source)
    with pytest.raises(BatchRepositoryStateError, match="DOCUMENT_INVALID"):
        plan(source, "enable", ("debian-trixie-main",))
    assert source == previous


def test_no_shell_network_or_host_persistence(monkeypatch):
    import os
    import socket
    import subprocess

    def deny(*_a, **_kw):
        pytest.fail("batch state planner attempted host mutation")
    monkeypatch.setattr(os, "replace", deny)
    monkeypatch.setattr(os, "unlink", deny)
    monkeypatch.setattr(subprocess, "run", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    result = plan(document(), "enable", ("debian-trixie-main",))
    assert_inert(result)
