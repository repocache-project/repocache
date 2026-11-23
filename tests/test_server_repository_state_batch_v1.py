"""Issue #95 batch state preview: no host mutation, no partial acceptance."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_repository_state_batch_v1 import (
    BatchRepositoryStateError, plan_batch_repository_states,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document():
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc["repositories"][1]["id"] = "almalinux-baseos"
    return doc


def preview(doc, changes, generation=0):
    return plan_batch_repository_states(doc, current_generation=generation, changes=changes)


def test_two_repository_changes_are_ordered_inert_and_atomic():
    original = document()
    before = copy.deepcopy(original)
    result = preview(original, (
        ("almalinux-baseos", "active"), ("debian-trixie-main", "active"),
    ))
    assert original == before
    assert result["status"] == "BATCH_STATE_PLAN_ONLY"
    assert result["changed"] is True
    assert all(r["desired_state"] == "active"
               for r in result["candidate_document"]["repositories"])
    assert [x["repository_id"] for x in result["per_repository"]] == [
        "almalinux-baseos", "debian-trixie-main",
    ]
    assert all(x["result"] == "STATE_CHANGE_CANDIDATE" for x in result["per_repository"])
    for key in (
        "operator_authorization_verified", "trusted_state_generation_verified",
        "native_nginx_routes_reconciled", "active_catalog_reconciled",
        "authorizes_state_write", "authorizes_nginx_activation",
        "authorizes_catalog_publication", "authorizes_cache_cleanup",
    ):
        assert result[key] is False


def test_idempotence_of_existing_and_repeated_states():
    doc = document()
    assert preview(doc, (("debian-trixie-main", "disabled"),))["changed"] is False
    enabled = preview(doc, (("debian-trixie-main", "active"),))
    again = preview(enabled["candidate_document"], (("debian-trixie-main", "active"),))
    assert again["changed"] is False
    assert again["per_repository"][0]["result"] == "ALREADY_CURRENT"


@pytest.mark.parametrize("changes", [
    (), [], (("debian-trixie-main", "active"), ("debian-trixie-main", "disabled")),
    (("missing", "active"),), (("../unsafe", "active"),),
    (("debian-trixie-main", "approved"),), (("debian-trixie-main", True),),
    (("debian-trixie-main", "active", "extra"),),
    (["debian-trixie-main", "active"],),
    (("debian-trixie-main", "active"),) * 65,
])
def test_invalid_selection_refuses_without_partial_output(changes):
    doc = document()
    before = copy.deepcopy(doc)
    with pytest.raises(BatchRepositoryStateError, match=r"^BATCH_STATE_"):
        preview(doc, changes)
    assert doc == before


def test_late_invalid_target_refuses_whole_batch():
    doc = document()
    with pytest.raises(BatchRepositoryStateError, match="TARGET_INVALID"):
        preview(doc, (("debian-trixie-main", "active"), ("absent", "disabled")))
    assert doc["repositories"][0]["desired_state"] == "disabled"


@pytest.mark.parametrize("generation", [True, -1, 1, "0"])
def test_invalid_or_stale_generation(generation):
    with pytest.raises(BatchRepositoryStateError):
        preview(document(), (("debian-trixie-main", "active"),), generation)


def test_unallocated_ids_and_invalid_base_refuse():
    doc = document()
    del doc["repositories"][1]["id"]
    with pytest.raises(BatchRepositoryStateError, match="UNALLOCATED_ID"):
        preview(doc, (("debian-trixie-main", "active"),))
    doc = document()
    doc["repositories"][0]["upstream"]["base_url"] = "http://127.0.0.1/"
    with pytest.raises(BatchRepositoryStateError, match="DOCUMENT_INVALID"):
        preview(doc, (("debian-trixie-main", "active"),))


def test_preview_never_performs_host_actions(monkeypatch):
    import os
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("pure planner attempted a host operation")

    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert preview(document(), (("debian-trixie-main", "active"),))["changed"]
