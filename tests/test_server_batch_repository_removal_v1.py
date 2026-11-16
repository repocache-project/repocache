"""Safe all-or-nothing batch removal intents for managed repositories (#95)."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_repository_plan_v1 import (
    RepositoryPlanError, plan_batch_repository_removals,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document():
    obj = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    obj["repositories"][1]["id"] = "almalinux-baseos"
    return obj


def remove(obj=None, *, ids=(), all=False, generation=0):
    return plan_batch_repository_removals(
        document() if obj is None else obj,
        repository_ids=ids,
        all_repositories=all,
        current_generation=generation,
    )


def assert_inert(result):
    assert result["status"] == "BATCH_REMOVE_PLAN_ONLY"
    assert result["operation"] == "remove"
    assert result["cache_retained"] is True
    assert all(result[key] is False for key in (
        "retirement_ledger_persisted",
        "operator_authorization_verified",
        "native_nginx_routes_reconciled",
        "active_catalog_reconciled",
        "authorizes_nginx_activation",
        "authorizes_catalog_publication",
        "authorizes_cache_purge",
        "authorizes_state_write",
    ))


def test_multi_target_removal_is_one_validated_document_and_preserves_cache():
    source = document()
    before = copy.deepcopy(source)
    result = remove(source, ids=("almalinux-baseos","debian-trixie-main"))
    assert_inert(result)
    assert result["changed"] is True
    assert result["candidate_document"]["repositories"] == []
    assert result["candidate_document"]["expected_state_generation"] == 0
    assert result["candidate_document"]["deployment"] == before["deployment"]
    assert result["retired_ids_proposed"] == [
        "almalinux-baseos","debian-trixie-main",
    ]
    assert result["per_repository"] == [
        {"repository_id":"almalinux-baseos","result":"REMOVE_CANDIDATE"},
        {"repository_id":"debian-trixie-main","result":"REMOVE_CANDIDATE"},
    ]
    assert source == before


def test_valid_absent_target_is_idempotent_noop_and_never_purges():
    source = document()
    result = remove(source, ids=("absent-repo",))
    assert_inert(result)
    assert result["changed"] is False
    assert result["candidate_document"] == source
    assert result["retired_ids_proposed"] == []
    assert result["per_repository"] == [
        {"repository_id":"absent-repo","result":"ALREADY_ABSENT"},
    ]
    once = remove(source, ids=("almalinux-baseos",))
    again = remove(once["candidate_document"], ids=("almalinux-baseos",))
    assert_inert(again)
    assert again["changed"] is False
    assert again["candidate_document"] == once["candidate_document"]


def test_missing_and_present_targets_get_individual_outcomes():
    result = remove(ids=(
        "missing-a","debian-trixie-main","missing-b",
    ))
    assert result["per_repository"] == [
        {"repository_id":"missing-a","result":"ALREADY_ABSENT"},
        {"repository_id":"debian-trixie-main","result":"REMOVE_CANDIDATE"},
        {"repository_id":"missing-b","result":"ALREADY_ABSENT"},
    ]
    assert result["retired_ids_proposed"] == ["debian-trixie-main"]
    assert len(result["candidate_document"]["repositories"]) == 1


def test_all_selector_chooses_only_current_managed_ids():
    first = remove(all=True)
    assert_inert(first)
    assert first["selected_all"] is True
    assert first["candidate_document"]["repositories"] == []
    again = remove(first["candidate_document"], all=True)
    assert_inert(again)
    assert again["per_repository"] == []
    assert again["changed"] is False
    assert again["retired_ids_proposed"] == []


@pytest.mark.parametrize("ids,all_flag", [
    ((),False),
    (("debian-trixie-main",),True),
    (["debian-trixie-main"],False),
    (("debian-trixie-main","debian-trixie-main"),False),
    ((None,),False), ((True,),False),
    (("../foreign",),False), (("BadUppercase",),False),
    (("a"*49,),False),
    (tuple(f"repo-{i}" for i in range(501)),False),
    ((),None), ((),1),
])
def test_invalid_batch_selector_fails_before_creating_candidate(ids,all_flag):
    source = document()
    saved = copy.deepcopy(source)
    with pytest.raises(RepositoryPlanError):
        remove(source,ids=ids,all=all_flag)
    assert source == saved


@pytest.mark.parametrize("generation", [True,-1,1,"0",None,2**63])
def test_stale_or_unbounded_generation_refused(generation):
    with pytest.raises(RepositoryPlanError):
        remove(ids=("almalinux-baseos",), generation=generation)


def test_unallocated_ids_are_not_silently_removed():
    source = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    with pytest.raises(RepositoryPlanError,
                       match="durable identifiers"):
        remove(source, ids=("debian-trixie-main",))


def test_no_network_host_write_or_command_invocation(monkeypatch):
    obj = document()
    import os
    import socket
    import subprocess

    def forbidden(*_a, **_k):
        pytest.fail("Inert batch planner attempted host I/O")
    monkeypatch.setattr(os,"replace",forbidden)
    monkeypatch.setattr(os,"unlink",forbidden)
    monkeypatch.setattr(subprocess,"run",forbidden)
    monkeypatch.setattr(socket,"getaddrinfo",forbidden)
    assert remove(obj,all=True)["authorizes_state_write"] is False
    assert len(obj["repositories"]) == 2
