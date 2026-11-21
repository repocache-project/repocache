"""#95: protected ID uniqueness and immutable batch-add proposals."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_repository_plan_v1 import (
    BatchRepositoryAddError, plan_batch_repository_additions,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document():
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    data["repositories"][1]["id"] = "almalinux-baseos"
    return data


def explicit(source):
    data = copy.deepcopy(source["repositories"][0])
    data["id"] = "debian-custom"
    data["upstream"]["base_url"] = "https://mirror.example.invalid/custom/"
    return data


def automatic(source):
    data = copy.deepcopy(source["repositories"][1])
    del data["id"]
    data["upstream"]["base_url"] = "https://mirror.example.invalid/almalinux/10/AppStream/x86_64/os/"
    return data


def plan(source, changes, *, reserved=None):
    if reserved is None:
        reserved = {row["id"] for row in source["repositories"]}
    return plan_batch_repository_additions(
        source, current_generation=0,
        proposed_repositories=changes, reserved_ids=reserved,
    )


def assert_non_authorizing(value):
    assert value["status"] == "BATCH_ADD_PLAN_ONLY"
    assert value["id_eligibility"] == "CALLER_SNAPSHOT_ONLY"
    assert all(value[key] is False for key in (
        "all_time_reservation_ledger_persisted",
        "operator_authorization_verified", "native_nginx_routes_reconciled",
        "active_catalog_reconciled", "authorizes_state_write",
        "authorizes_nginx_activation", "authorizes_catalog_publication",
        "authorizes_cache_cleanup",
    ))


def test_explicit_and_automatic_add_in_one_validated_nonmutating_plan():
    source = document()
    originals = copy.deepcopy(source)
    proposals = (explicit(source), automatic(source))
    saved = copy.deepcopy(proposals)
    result = plan(source, proposals)
    assert_non_authorizing(result)
    assert result["changed"] is True
    assert len(result["candidate_document"]["repositories"]) == 4
    rows = result["per_repository"]
    assert [v["result"] for v in rows] == ["ADD_CANDIDATE", "ADD_CANDIDATE"]
    assert rows[0]["repository_id"] == "debian-custom"
    assert rows[0]["id_assignment"] == "EXPLICIT"
    assert rows[1]["repository_id"].startswith("repo-")
    assert rows[1]["id_assignment"] == "AUTO_SUGGESTED"
    assert rows[0]["repository_id"] != rows[1]["repository_id"]
    assert source == originals and proposals == saved


def test_repeating_a_batch_is_idempotent_and_auto_id_stable():
    source = document()
    requests = (explicit(source), automatic(source))
    first = plan(source, requests)
    after = first["candidate_document"]
    reservation = {row["id"] for row in after["repositories"]}
    repeat = plan(after, requests, reserved=reservation)
    assert_non_authorizing(repeat)
    assert repeat["changed"] is False
    assert repeat["candidate_document"] == after
    assert [r["result"] for r in repeat["per_repository"]] == [
        "ALREADY_PRESENT", "ALREADY_PRESENT",
    ]
    assert repeat["per_repository"][1]["repository_id"] == (
        first["per_repository"][1]["repository_id"]
    )


def test_retired_auto_id_gets_new_unreserved_candidate():
    source = document()
    wanted = automatic(source)
    first = plan(source, (wanted,))
    retired = first["per_repository"][0]["repository_id"]
    reserved = {r["id"] for r in source["repositories"]} | {retired}
    second = plan(source, (wanted,), reserved=reserved)
    assert second["per_repository"][0]["repository_id"] != retired
    assert second["per_repository"][0]["repository_id"] not in reserved
    assert second["changed"]


def test_second_invalid_target_refuses_whole_batch_without_partial_effect():
    source = document()
    saved = copy.deepcopy(source)
    other = copy.deepcopy(explicit(source))
    other["id"] = source["repositories"][0]["id"]
    with pytest.raises(BatchRepositoryAddError, match="REPOSITORY_INVALID"):
        plan(source, (explicit(source), other))
    assert source == saved


def test_same_target_repeated_is_rejected_even_if_idempotent():
    source = document()
    candidate = explicit(source)
    with pytest.raises(BatchRepositoryAddError, match="REPOSITORY_INVALID"):
        plan(source, (candidate, copy.deepcopy(candidate)))


def test_historical_explicit_id_is_not_silently_reallocated():
    source = document()
    request = explicit(source)
    with pytest.raises(BatchRepositoryAddError, match="REPOSITORY_INVALID"):
        plan(source, (request,), reserved={r["id"] for r in source["repositories"]} | {"debian-custom"})


def test_duplicate_identity_with_different_explicit_id_denied():
    source = document()
    other = copy.deepcopy(source["repositories"][0])
    other["id"] = "another-identical"
    with pytest.raises(BatchRepositoryAddError, match="REPOSITORY_INVALID"):
        plan(source, (other,))


@pytest.mark.parametrize("proposals", [
    [], (), [dict()], (None,), ("text",), ({"id": "invalid"},) * 65,
])
def test_unbounded_or_bad_structures_rejected(proposals):
    source = document()
    saved = copy.deepcopy(source)
    with pytest.raises(BatchRepositoryAddError, match="^BATCH_ADD_"):
        plan(source, proposals)
    assert source == saved


def test_missing_reservations_and_partial_allocated_snapshot_fail_closed():
    source = document()
    with pytest.raises(BatchRepositoryAddError, match="BASE_INVALID"):
        plan(source, (explicit(source),), reserved=set())
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    with pytest.raises(BatchRepositoryAddError, match="UNALLOCATED_ID"):
        plan(raw, (explicit(source),))


def test_unknown_generation_is_not_an_id_allocation_authorization():
    source = document()
    for invalid in (-1, True, "0", None, 1, 2**63):
        with pytest.raises(BatchRepositoryAddError):
            plan_batch_repository_additions(
                source, current_generation=invalid,
                proposed_repositories=(explicit(source),),
                reserved_ids={r["id"] for r in source["repositories"]},
            )


def test_no_host_io_or_privileged_side_effects(monkeypatch):
    import os
    import socket
    import subprocess

    def deny(*_a, **_kw):
        pytest.fail("unexpected side effect from candidate planner")
    monkeypatch.setattr(os, "replace", deny)
    monkeypatch.setattr(os, "unlink", deny)
    monkeypatch.setattr(subprocess, "run", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    assert_non_authorizing(plan(document(), (explicit(document()),)))
