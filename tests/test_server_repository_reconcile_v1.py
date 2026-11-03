"""No-effect v1 declarative reconciliation tests for #95 / #18."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from repocache.server_install_v1 import InstallInputError
from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_repository_reconcile_v1 import (
    ReconciliationPlanError,
    plan_declarative_reconciliation,
    preview_declarative_state_alignment,
    plan_inert_persistence_transition,
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


def _inert_state_snapshot(config: dict, *, generation: int = 1) -> dict:
    return {
        "state_schema_version": 1,
        "state_generation": generation,
        # The inert state schema only checks the digest's shape. There is NO
        # accepted config-byte binding or provenance in this pure preview.
        "configuration_sha256": "a" * 64,
        "repositories": [
            {
                "id": repo["id"],
                "canonical_identity_sha256": hashlib.sha256(
                    _canonical_identity(repo).encode("utf-8")
                ).hexdigest(),
                "approval": {"source": "operator", "decision_sha256": "b" * 64},
                "desired_state": repo["desired_state"],
                "observed_state": "not-activated",
            }
            for repo in config["repositories"]
        ],
        "ownership_manifest": [],
    }


def test_untrusted_state_alignment_is_never_authorization():
    config = document()
    config["expected_state_generation"] = 1
    config["repositories"][0]["desired_state"] = "active"
    state = _inert_state_snapshot(config)
    before = copy.deepcopy(state)
    result = preview_declarative_state_alignment(
        config, state, current_generation=1
    )
    assert result["status"] == "UNTRUSTED_ALIGNMENT_ONLY"
    assert result["aligned_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main"
    ]
    assert result["requires_trusted_locked_recheck"] is True
    for field in (
        "configuration_digest_verified", "approval_provenance_verified",
        "observed_exposure_verified", "reservation_history_verified",
        "authorizes_installation", "authorizes_nginx_reload",
        "authorizes_catalog_publication", "authorizes_cache_cleanup",
    ):
        assert result[field] is False
    assert state == before


@pytest.mark.parametrize("which", [
    "missing", "extra", "duplicate", "identity", "intent", "invalid_schema",
])
def test_untrusted_state_alignment_refuses_drift(which):
    config = document()
    config["expected_state_generation"] = 1
    state = _inert_state_snapshot(config)
    if which == "missing":
        state["repositories"].pop()
    elif which == "extra":
        state["repositories"].append({
            **copy.deepcopy(state["repositories"][0]), "id": "extraneous"
        })
    elif which == "duplicate":
        state["repositories"][1]["id"] = state["repositories"][0]["id"]
    elif which == "identity":
        state["repositories"][0]["canonical_identity_sha256"] = "f" * 64
    elif which == "intent":
        state["repositories"][0]["desired_state"] = "active"
    else:
        state["repositories"][0]["observed_state"] = "active"
    with pytest.raises(ReconciliationPlanError, match="state alignment"):
        preview_declarative_state_alignment(
            config, state, current_generation=1
        )


@pytest.mark.parametrize("generation", [-1, 0, True, "1", 2**63])
def test_untrusted_state_alignment_refuses_invalid_generation(generation):
    config = document()
    config["expected_state_generation"] = 1
    with pytest.raises(ReconciliationPlanError):
        preview_declarative_state_alignment(
            config, _inert_state_snapshot(config), current_generation=generation
        )


def test_untrusted_state_alignment_detects_stale_snapshots_and_missing_ids():
    config = document()
    config["expected_state_generation"] = 1
    state = _inert_state_snapshot(config)
    state["state_generation"] = 2
    with pytest.raises(ReconciliationPlanError, match="stale state"):
        preview_declarative_state_alignment(config, state, current_generation=1)
    state["state_generation"] = 1
    config["expected_state_generation"] = 2
    with pytest.raises(ReconciliationPlanError, match="stale configuration"):
        preview_declarative_state_alignment(config, state, current_generation=1)
    config["expected_state_generation"] = 1
    del config["repositories"][0]["id"]
    with pytest.raises(ReconciliationPlanError, match="durable IDs"):
        preview_declarative_state_alignment(config, state, current_generation=1)


def test_untrusted_state_alignment_never_promises_a_config_digest():
    config = document()
    config["expected_state_generation"] = 1
    state = _inert_state_snapshot(config)
    # An untrusted shape-valid digest is not evidence of the actual config.
    state["configuration_sha256"] = "f" * 64
    result = preview_declarative_state_alignment(
        config, state, current_generation=1
    )
    assert result["configuration_digest_verified"] is False
    assert result["authorizes_catalog_publication"] is False


def test_untrusted_state_alignment_is_immutable_and_has_no_host_effects(monkeypatch):
    import os
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("host effects are forbidden")

    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    config = document()
    config["expected_state_generation"] = 1
    state = _inert_state_snapshot(config)
    old_config = copy.deepcopy(config)
    old_state = copy.deepcopy(state)
    preview_declarative_state_alignment(config, state, current_generation=1)
    assert config == old_config
    assert state == old_state


def test_inert_persistence_intent_for_one_explicit_state_change():
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = [copy.deepcopy(config["repositories"][0])]
    proposed["repositories"][0]["desired_state"] = "active"
    state = _inert_state_snapshot(config)
    original = copy.deepcopy(state)

    result = plan_inert_persistence_transition(
        config, proposed, state, current_generation=1
    )
    assert result["status"] == "PLAN_ONLY"
    assert result["changed"] is True
    assert result["expected_state_generation"] == 1
    assert result["proposed_state_generation"] == 2
    assert result["fresh_approval_required_ids"] == ["debian-trixie-main"]
    assert result["deployment_approval_required"] is False
    assert {item["id"] for item in result["repository_intents"]} == {
        "debian-trixie-main", "almalinux-baseos"
    }
    assert result["repository_intents"][1]["desired_state"] == "active"
    assert result["repository_intents"][1]["observed_state"] == "not-activated"
    for field in (
        "authorizes_state_commit", "authorizes_nginx_reload",
        "authorizes_catalog_publication", "authorizes_cache_cleanup",
        "configuration_digest_binding_verified",
        "reservation_history_verified", "approval_provenance_verified",
    ):
        assert result[field] is False
    assert result["requires_trusted_locked_recheck"] is True
    assert state == original
    assert config["repositories"][0]["desired_state"] == "disabled"
    # This preview is NOT a complete candidate accepted by #31's writer.
    from repocache.server_protected_state_store_v1 import (
        ProtectedStateStoreError, validate_protected_state,
    )
    with pytest.raises(ProtectedStateStoreError):
        validate_protected_state(result)


def test_inert_persistence_preserves_unmentioned_and_noop_generation():
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = []
    result = plan_inert_persistence_transition(
        config, proposed, _inert_state_snapshot(config), current_generation=1
    )
    assert not result["changed"]
    assert result["proposed_state_generation"] == 1
    assert result["fresh_approval_required_ids"] == []
    assert len(result["repository_intents"]) == 2


def test_inert_persistence_global_policy_change_requires_broad_approval():
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = []
    proposed["deployment"]["cache_policy"]["global"]["max_size_bytes"] += 1024
    result = plan_inert_persistence_transition(
        config, proposed, _inert_state_snapshot(config), current_generation=1
    )
    assert result["deployment_approval_required"] is True
    assert result["fresh_approval_required_ids"] == [
        "almalinux-baseos", "debian-trixie-main"
    ]
    assert result["authorizes_state_commit"] is False


@pytest.mark.parametrize("mutation", ["host", "path", "layout"])
def test_inert_persistence_refuses_reassigning_stable_identity(mutation):
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = [copy.deepcopy(config["repositories"][0])]
    repo = proposed["repositories"][0]
    if mutation == "host":
        repo["upstream"]["base_url"] = "https://new.example.invalid/debian/"
        repo["upstream"]["allowed_hosts"] = ["new.example.invalid"]
    elif mutation == "path":
        repo["upstream"]["base_url"] = "https://mirror.example.invalid/other/"
    else:
        repo["layout"]["suites"] = ["bookworm"]
    with pytest.raises(ReconciliationPlanError, match="identity reassignment"):
        plan_inert_persistence_transition(
            config, proposed, _inert_state_snapshot(config), current_generation=1
        )


def test_inert_persistence_detects_drift_before_persisting_anything():
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    state = _inert_state_snapshot(config)
    state["repositories"][0]["desired_state"] = "active"
    with pytest.raises(ReconciliationPlanError, match="identity or intent mismatch"):
        plan_inert_persistence_transition(
            config, proposed, state, current_generation=1
        )


def test_inert_persistence_rejects_exhausted_generation():
    config = document()
    config["expected_state_generation"] = (2**63 - 1)
    with pytest.raises(ReconciliationPlanError, match="generation exhausted"):
        plan_inert_persistence_transition(
            config, copy.deepcopy(config),
            _inert_state_snapshot(config, generation=2**63 - 1),
            current_generation=2**63 - 1,
        )


def test_inert_persistence_fixture_only_transaction_and_stale_cas(tmp_path):
    """Prove interoperability with #31's PRIVATE fixture writer only.

    A test explicitly invents approval/config-hash values; these are not
    authenticated, safe production provenance or an operator permission API.
    """
    import os
    from repocache.server_protected_state_store_v1 import (
        LOCK_NAME, STATE_NAME, ProtectedStateStoreError,
        _commit_under_root, _recover_under_root,
    )
    root = tmp_path / "mock-root"
    root.mkdir(mode=0o700)
    folder = root
    for part in ("var", "lib", "repocache", "server"):
        folder = folder / part
        folder.mkdir(mode=0o700)
    (folder / LOCK_NAME).write_bytes(b"")
    (folder / LOCK_NAME).chmod(0o600)

    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = [copy.deepcopy(config["repositories"][0])]
    proposed["repositories"][0]["desired_state"] = "active"
    initial = _inert_state_snapshot(config)
    intent = plan_inert_persistence_transition(
        config, proposed, initial, current_generation=1
    )
    # Fixture-only synthetic provenance, NOT supplied by this module/API.
    candidate = copy.deepcopy(initial)
    candidate["state_generation"] = 2
    candidate["configuration_sha256"] = "c" * 64
    for projection in intent["repository_intents"]:
        row = next(r for r in candidate["repositories"] if r["id"] == projection["id"])
        row["desired_state"] = projection["desired_state"]
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        uid = os.geteuid()
        assert _commit_under_root(
            fd, initial, expected_generation=0, owner_uid=uid
        )["status"] == "COMMITTED_INERT_STATE"
        assert _commit_under_root(
            fd, candidate, expected_generation=1, owner_uid=uid
        )["status"] == "COMMITTED_INERT_STATE"
        saved = json.loads((folder / STATE_NAME).read_bytes())
        assert saved == candidate
        assert (folder / STATE_NAME).stat().st_mode & 0o777 == 0o600
        assert _recover_under_root(fd, owner_uid=uid)["status"] == "CLEAN"
        with pytest.raises(ProtectedStateStoreError, match="STALE_GENERATION"):
            _commit_under_root(
                fd, candidate, expected_generation=1, owner_uid=uid
            )
    finally:
        os.close(fd)


def test_inert_persistence_preview_does_not_call_writer(monkeypatch):
    import repocache.server_protected_state_store_v1 as store
    def forbidden(*args, **kwargs):
        raise AssertionError("fixture writer must never be invoked by a preview")
    monkeypatch.setattr(store, "_commit_under_root", forbidden)
    config = document()
    config["expected_state_generation"] = 1
    result = plan_inert_persistence_transition(
        config, copy.deepcopy(config),
        _inert_state_snapshot(config), current_generation=1,
    )
    assert result["authorizes_state_commit"] is False
