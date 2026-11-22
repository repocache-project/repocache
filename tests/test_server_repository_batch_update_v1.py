"""#95 — atomic same-identity config/trust updates must not adopt cache."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_repository_plan_v1 import (
    BatchRepositoryUpdateError, plan_batch_repository_updates,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def base():
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    data["repositories"][1]["id"] = "almalinux-baseos"
    return data


def plan(source, changes, generation=0):
    return plan_batch_repository_updates(
        source, current_generation=generation,
        proposed_repositories=changes,
    )


def assert_inert(result):
    assert result["status"] == "BATCH_UPDATE_PLAN_ONLY"
    assert result["identity_preserved_for_all_updated_repositories"] is True
    for key in (
        "authorizes_existing_cache_reuse", "operator_authorization_verified",
        "protected_state_generation_verified",
        "upstream_signing_trust_verified",
        "native_nginx_routes_reconciled", "active_catalog_reconciled",
        "authorizes_nginx_activation", "authorizes_catalog_publication",
        "authorizes_state_write", "authorizes_cache_cleanup",
    ):
        assert result[key] is False


def test_two_distinct_trust_and_policy_updates_one_atomic_candidate():
    before = base()
    before["repositories"][0]["desired_state"] = "active"
    saved = copy.deepcopy(before)
    apt = copy.deepcopy(before["repositories"][0])
    dnf = copy.deepcopy(before["repositories"][1])
    apt["layout"]["release_key_refs"] = [
        "file:/etc/repocache/keys/rotated-public.gpg",
    ]
    dnf["cache_overrides"]["inactive_seconds"] = 7200
    result = plan(before, (dnf, apt))
    assert_inert(result)
    assert result["changed"] is True
    assert [row["repository_id"] for row in result["per_repository"]] == [
        "almalinux-baseos", "debian-trixie-main",
    ]
    assert [row["result"] for row in result["per_repository"]] == [
        "UPDATE_CANDIDATE", "UPDATE_CANDIDATE",
    ]
    assert result["active_route_reconciliation_candidate_ids"] == [
        "debian-trixie-main",
    ]
    assert result["candidate_document"]["repositories"][0]["layout"][
        "release_key_refs"
    ] == apt["layout"]["release_key_refs"]
    assert result["candidate_document"]["repositories"][1][
        "cache_overrides"
    ]["inactive_seconds"] == 7200
    assert before == saved


def test_repeat_is_stable_noop_and_does_not_claim_route_reconciliation():
    source = base()
    changes = tuple(copy.deepcopy(item) for item in source["repositories"])
    first = plan(source, changes)
    assert_inert(first)
    assert first["changed"] is False
    assert first["candidate_document"] == source
    assert first["active_route_reconciliation_candidate_ids"] == []
    assert [r["result"] for r in first["per_repository"]] == [
        "ALREADY_CURRENT", "ALREADY_CURRENT",
    ]


def test_upstream_change_cannot_reuse_existing_cache_namespace():
    source = base()
    proposal = copy.deepcopy(source["repositories"][0])
    proposal["upstream"]["base_url"] = "https://mirror.example.invalid/foreign/"
    with pytest.raises(BatchRepositoryUpdateError,
                       match="BATCH_UPDATE_REPOSITORY_INVALID"):
        plan(source, (proposal,))


@pytest.mark.parametrize("field", ["suites", "components", "architectures"])
def test_apt_layout_change_cannot_alias_persisted_cache(field):
    source = base()
    proposal = copy.deepcopy(source["repositories"][0])
    proposal["layout"][field] = ["different"]
    with pytest.raises(BatchRepositoryUpdateError,
                       match="BATCH_UPDATE_REPOSITORY_INVALID"):
        plan(source, (proposal,))


def test_second_invalid_proposal_refuses_whole_atomic_update():
    source = base()
    saved = copy.deepcopy(source)
    valid = copy.deepcopy(source["repositories"][0])
    valid["cache_overrides"]["inactive_seconds"] = 300
    foreign = copy.deepcopy(source["repositories"][1])
    foreign["upstream"]["base_url"] = "https://mirror.example.invalid/other/"
    with pytest.raises(BatchRepositoryUpdateError,
                       match="BATCH_UPDATE_REPOSITORY_INVALID"):
        plan(source, (valid, foreign))
    assert source == saved


def test_enable_and_disable_also_require_route_reconciliation():
    source = base()
    source["repositories"][0]["desired_state"] = "active"
    change = copy.deepcopy(source["repositories"][0])
    change["desired_state"] = "disabled"
    result = plan(source, (change,))
    assert_inert(result)
    assert result["active_route_reconciliation_candidate_ids"] == [
        "debian-trixie-main",
    ]
    assert result["candidate_document"]["repositories"][0][
        "desired_state"
    ] == "disabled"


@pytest.mark.parametrize("changes", [
    (), [], (None,), ("not-an-object",),
    tuple({} for _ in range(65)),
])
def test_untrusted_update_batch_shape_denied(changes):
    with pytest.raises(BatchRepositoryUpdateError,
                       match="BATCH_UPDATE_SELECTOR_INVALID"):
        plan(base(), changes)


@pytest.mark.parametrize("generation", [-1, True, "0", None, 1, 2**63])
def test_stale_or_ambiguous_generation_denied(generation):
    source = base()
    with pytest.raises(BatchRepositoryUpdateError):
        plan(source, (source["repositories"][0],), generation)


def test_duplicate_id_and_unknown_id_refused_without_partial():
    source = base()
    item = copy.deepcopy(source["repositories"][0])
    with pytest.raises(BatchRepositoryUpdateError,
                       match="BATCH_UPDATE_REPOSITORY_INVALID"):
        plan(source, (item, copy.deepcopy(item)))
    unknown = copy.deepcopy(item)
    unknown["id"] = "unowned-repository"
    with pytest.raises(BatchRepositoryUpdateError,
                       match="BATCH_UPDATE_REPOSITORY_INVALID"):
        plan(source, (unknown,))


def test_durable_ids_required_before_batch_preview():
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    with pytest.raises(BatchRepositoryUpdateError, match="UNALLOCATED_ID"):
        plan(raw, (copy.deepcopy(base()["repositories"][0]),))


def test_no_shell_disk_writes_or_network_calls(monkeypatch):
    import os
    import socket
    import subprocess

    def deny(*_args, **_kw):
        pytest.fail("batch update attempted native authority or side effects")

    monkeypatch.setattr(os, "replace", deny)
    monkeypatch.setattr(os, "unlink", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(subprocess, "run", deny)
    assert_inert(plan(base(), tuple(copy.deepcopy(r) for r in base()["repositories"])))
