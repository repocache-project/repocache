"""No-effect v1 declarative reconciliation tests for #95 / #18."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_install_v1 import InstallInputError
from repocache.server_repository_reconcile_v1 import (
    ReconciliationPlanError,
    plan_declarative_reconciliation,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document() -> dict:
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    data["repositories"][1]["id"] = "almalinux-baseos"
    return data


def preview(current: dict, proposed: dict) -> dict:
    return plan_declarative_reconciliation(
        current, proposed, current_generation=0
    )


def test_empty_submission_preserves_repositories_and_does_not_write():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    old_current, old_proposed = copy.deepcopy(current), copy.deepcopy(proposed)
    result = preview(current, proposed)
    assert result["status"] == "PLAN_ONLY"
    assert result["authorizes_installation"] is False
    assert result["changed"] is False
    assert result["candidate_document"] == current
    assert result["preserved_ids"] == ["almalinux-baseos", "debian-trixie-main"]
    assert result["implicit_policy_ids"] == []
    assert current == old_current
    assert proposed == old_proposed


def test_global_policy_change_affects_omitted_repositories():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    old_max = current["deployment"]["cache_policy"]["global"]["max_size_bytes"]
    proposed["deployment"]["cache_policy"]["global"]["max_size_bytes"] = old_max + 1024
    result = preview(current, proposed)
    assert result["changed"] is True
    assert result["explicit_changed_ids"] == []
    assert result["implicit_policy_ids"] == ["almalinux-baseos", "debian-trixie-main"]
    for change in result["effective_policy_changes"]:
        assert change["fields"] == ["max_size_bytes"]
        assert change["before"]["max_size_bytes"]["value"] == old_max
        assert change["after"]["max_size_bytes"]["value"] == old_max + 1024
        assert change["explicitly_listed"] is False
    assert result["candidate_document"]["repositories"] == current["repositories"]
    assert current["deployment"]["cache_policy"]["global"]["max_size_bytes"] == old_max


def test_per_repository_override_prevents_inherited_implicit_change():
    current = document()
    current["repositories"][0]["cache_overrides"] = {"max_size_bytes": 12345}
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    proposed["deployment"]["cache_policy"]["global"]["max_size_bytes"] += 1024
    result = preview(current, proposed)
    assert result["implicit_policy_ids"] == ["almalinux-baseos"]
    assert result["candidate_document"]["repositories"][0]["cache_overrides"] == {
        "max_size_bytes": 12345
    }


def test_explicit_update_preserves_other_repository_and_identity():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(current["repositories"][0])]
    proposed["repositories"][0]["desired_state"] = "active"
    result = preview(current, proposed)
    assert result["explicit_changed_ids"] == ["debian-trixie-main"]
    assert result["preserved_ids"] == ["almalinux-baseos"]
    assert result["candidate_document"]["repositories"][1] == current["repositories"][1]
    assert result["authorizes_installation"] is False
    assert result["status"] == "PLAN_ONLY"


def test_new_repository_and_missing_durable_ids_refused():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"][0]["id"] = "new-identifier"
    with pytest.raises(ReconciliationPlanError, match="reservation"):
        preview(current, proposed)
    del current["repositories"][0]["id"]
    with pytest.raises(ReconciliationPlanError, match="durable IDs"):
        preview(current, copy.deepcopy(current))


@pytest.mark.parametrize("generation", [None, True, -1, 1, 2**63, "0"])
def test_generation_must_match_both_documents(generation):
    current = document()
    proposed = copy.deepcopy(current)
    with pytest.raises(ReconciliationPlanError):
        plan_declarative_reconciliation(
            current, proposed, current_generation=generation
        )
    proposed["expected_state_generation"] = 1
    with pytest.raises(ReconciliationPlanError, match="stale"):
        preview(current, proposed)


def test_partial_submission_cannot_collide_with_preserved_identity():
    current = document()
    proposed = copy.deepcopy(current)
    duplicate = copy.deepcopy(current["repositories"][0])
    duplicate["id"] = "almalinux-baseos"
    proposed["repositories"] = [duplicate]
    with pytest.raises(InstallInputError, match="duplicate canonical"):
        preview(current, proposed)


def test_invalid_nested_policy_is_refused_before_preview():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    proposed["deployment"]["cache_policy"]["global"]["extra"] = "private-token"
    with pytest.raises(InstallInputError) as exc:
        preview(current, proposed)
    assert "private-token" not in str(exc.value)


def test_no_network_process_or_host_writes(monkeypatch):
    import os
    import socket
    import subprocess
    def forbidden(*_args, **_kwargs):
        raise AssertionError("no external effects permitted")
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    result = preview(current, proposed)
    assert result["status"] == "PLAN_ONLY"


def test_semantically_equivalent_list_order_is_a_true_noop():
    """Unordered lists cannot trigger generation churn or policy changes."""
    current = document()
    repo = current["repositories"][0]
    repo["layout"]["suites"] = ["trixie", "bookworm"]
    repo["layout"]["components"] = ["main", "contrib"]
    repo["upstream"]["allowed_hosts"] = [
        "mirror.example.invalid", "backup.example.invalid"
    ]
    repo["layout"]["release_key_refs"] = [
        "file:/etc/repocache/keys/a.gpg",
        "file:/etc/repocache/keys/b.gpg",
    ]
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(repo)]
    for key in ("suites", "components", "release_key_refs"):
        proposed["repositories"][0]["layout"][key].reverse()
    proposed["repositories"][0]["upstream"]["allowed_hosts"].reverse()
    del proposed["repositories"][0]["cache_overrides"]
    result = preview(current, proposed)
    assert result["changed"] is False
    assert result["explicit_changed_ids"] == []
    assert result["implicit_policy_ids"] == []
    assert result["candidate_document"] == current


def test_explicit_change_of_trust_policy_is_not_silenced_by_identity():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(current["repositories"][0])]
    proposed["repositories"][0]["layout"]["release_key_refs"] = [
        "file:/etc/repocache/keys/other.gpg"
    ]
    result = preview(current, proposed)
    assert result["changed"] is True
    assert result["explicit_changed_ids"] == ["debian-trixie-main"]
    assert result["candidate_document"]["repositories"][0]["layout"]["release_key_refs"] == [
        "file:/etc/repocache/keys/other.gpg"
    ]
