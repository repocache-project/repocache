"""Durable, read-only repository inventory from the protected v2 fixture WAL."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from repocache import server_fixture_repository_inventory_v1 as inventory
from repocache.server_fixture_multi_resource_wal_v1 import (
    CATALOG, INCLUDE, JOURNAL_TMP, MANIFEST,
    _commit_fixture_multi_resource_under_root as commit,
)
from repocache.server_install_v1 import validate_install_document
from repocache.server_proposed_state_v2_store import V2_JOURNAL_TMP, V2_STATE
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_repository_v2_transition_v1 import (
    plan_repository_v2_transition,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
ID = "debian-trixie-main"


def canon(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("ascii")


@pytest.fixture
def roots(tmp_path):
    root = tmp_path / "owned-test-root"
    root.mkdir(mode=0o700)
    parent = root
    for name in ("var", "lib", "repocache", "server"):
        parent /= name
        parent.mkdir(mode=0o700)
    lock = parent / LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd, parent, os.geteuid(), root
    finally:
        os.close(fd)


def initial() -> dict:
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    data["expected_state_generation"] = 1
    data["repositories"][1]["id"] = "almalinux-baseos"
    data = validate_install_document(data, for_apply=True)
    encoded = canon(data)
    digest = hashlib.sha256(encoded).hexdigest()
    records = [{
        "id": row["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(row).encode("utf-8")
        ).hexdigest(),
        "desired_state": row["desired_state"],
        "observed_state": "not-activated",
    } for row in data["repositories"]]
    return {
        "state_schema_version": 2,
        "state_generation": 1,
        "configuration_base64": base64.b64encode(encoded).decode("ascii"),
        "configuration_sha256": digest,
        "repository_records": records,
        "id_reservations": [{
            "id": item["id"],
            "canonical_identity_sha256": item["canonical_identity_sha256"],
            "status": "allocated",
        } for item in records],
        "approval_reference": {
            "source": "operator",
            "decision_sha256": "a" * 64,
            "configuration_sha256": digest,
            "expected_generation": 0,
        },
    }


def catalog(ids) -> bytes:
    return canon({
        "schema_version": 1,
        "status": "fixture-only-observed-candidate",
        "active_ids": sorted(ids),
    })


def bootstrap(roots) -> dict:
    fd, _, uid, _ = roots
    snapshot = initial()
    outcome = commit(
        fd, snapshot, owner_uid=uid, expected_generation=0,
        include_bytes=b"# fixture root only\n", catalog_bytes=catalog([]),
    )
    assert outcome["state_generation"] == 1
    return snapshot


def advance(roots, prior, *, operation, generation, repository_id=ID):
    fd, parent, uid, _ = roots
    previous_sha256 = hashlib.sha256(
        (parent / V2_STATE).read_bytes(),
    ).hexdigest()
    change = plan_repository_v2_transition(
        prior, expected_generation=generation,
        expected_previous_state_sha256=previous_sha256,
        operation=operation,
        repository_id=repository_id,
        decision_sha256="b" * 64,
    )
    snapshot = change["proposed_snapshot"]
    assert snapshot is not None
    active = [
        row["id"] for row in snapshot["repository_records"]
        if row["desired_state"] == "active"
    ]
    outcome = commit(
        fd, snapshot, owner_uid=uid,
        expected_generation=generation,
        expected_previous_state_sha256=previous_sha256,
        include_bytes=("# fixture state " + str(generation + 1) + "\n").encode(),
        catalog_bytes=catalog(active),
    )
    assert outcome["state_generation"] == generation + 1
    return snapshot


def inspect(roots, generation):
    fd, parent, uid, _ = roots
    return inventory.inspect_locked_fixture_repository_inventory_under_root(
        fd, owner_uid=uid, expected_generation=generation,
        expected_state_sha256=hashlib.sha256(
            (parent / V2_STATE).read_bytes()
        ).hexdigest(),
    )


def test_inventory_from_persisted_lock_tracks_enable_disable_and_retirement(roots):
    previous = bootstrap(roots)
    first = inspect(roots, 1)
    assert first["status"] == "FIXTURE_LOCKED_REPOSITORY_INVENTORY_ONLY"
    assert first["state_generation"] == 1
    assert first["present_repository_count"] == 2
    assert first["retired_repository_count"] == 0
    assert first["retired_repository_ids"] == []
    assert first["shadow_catalog_entry_count"] == 0
    assert [row["id"] for row in first["repositories"]] == sorted([
        "almalinux-baseos", ID
    ])
    assert all(row["shadow_catalog_intent"] == "withdrawn"
               for row in first["repositories"])

    previous = advance(roots, previous, operation="enable", generation=1)
    enabled = inspect(roots, 2)
    assert enabled["shadow_catalog_entry_count"] == 1
    active = next(r for r in enabled["repositories"] if r["id"] == ID)
    assert active["desired_state"] == "active"
    assert active["shadow_catalog_intent"] == "fixture-included"
    assert active["observed_state"] == "not-activated"
    assert active["real_nginx_exposure_verified"] is False

    previous = advance(roots, previous, operation="disable", generation=2)
    disabled = inspect(roots, 3)
    assert disabled["shadow_catalog_entry_count"] == 0
    assert next(r for r in disabled["repositories"]
                if r["id"] == ID)["shadow_catalog_intent"] == "withdrawn"

    previous = advance(roots, previous, operation="remove", generation=3)
    retired = inspect(roots, 4)
    assert retired["present_repository_count"] == 1
    assert retired["retired_repository_ids"] == [ID]
    assert retired["retired_repository_count"] == 1
    assert all(row["id"] != ID for row in retired["repositories"])
    assert not retired["operator_authorization_verified"]
    assert not retired["real_nginx_exposure_verified"]
    assert not retired["published_client_catalog_verified"]
    assert not retired["preflight_remains_valid_after_return"]
    for key, val in retired.items():
        if key.startswith("authorizes_"):
            assert val is False

    private = json.dumps(retired, sort_keys=True)
    assert "mirror.example.invalid" not in private
    assert "release_key_refs" not in private
    assert "configuration_base64" not in private
    assert "canonical_identity_sha256" not in private
    assert "decision_sha256" not in private


def test_reopened_independent_descriptor_reads_same_committed_history(roots):
    previous = bootstrap(roots)
    advance(roots, previous, operation="remove", generation=1)
    fd, _, uid, root = roots
    another_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        report = inspect(roots, 2)
        direct = inventory.inspect_locked_fixture_repository_inventory_under_root(
            another_fd, owner_uid=uid,
            expected_generation=2,
            expected_state_sha256=report["whole_state_sha256"],
        )
        assert direct == report
    finally:
        os.close(another_fd)
    assert fd >= 0


@pytest.mark.parametrize("name", [CATALOG, INCLUDE, MANIFEST])
def test_modified_owned_resource_is_refused_instead_of_trusting_shadow(name, roots):
    bootstrap(roots)
    _, parent, _, _ = roots
    private = parent / name
    raw = private.read_bytes()
    private.write_bytes(raw + b"tampered")
    with pytest.raises(inventory.FixtureRepositoryInventoryError,
                       match="PROTECTED_RESOURCES_UNVERIFIED"):
        inspect(roots, 1)


@pytest.mark.parametrize("name", [JOURNAL_TMP, V2_JOURNAL_TMP])
def test_pending_wal_prevents_inventory_until_explicit_recovery(roots, name):
    bootstrap(roots)
    _, parent, _, _ = roots
    pending = parent / name
    pending.write_bytes(b"pending-transaction-marker")
    pending.chmod(0o600)
    with pytest.raises(inventory.FixtureRepositoryInventoryError,
                       match="PROTECTED_RESOURCES_UNVERIFIED"):
        inspect(roots, 1)
    assert pending.read_bytes() == b"pending-transaction-marker"


def test_missing_or_noncanonical_catalog_fails_closed(roots):
    bootstrap(roots)
    _, parent, _, _ = roots
    owned_catalog = parent / CATALOG
    owned_catalog.unlink()
    with pytest.raises(inventory.FixtureRepositoryInventoryError):
        inspect(roots, 1)
    owned_catalog.write_bytes(
        b'{"schema_version":1,"active_ids":[],"active_ids":[]}'
    )
    owned_catalog.chmod(0o600)
    with pytest.raises(inventory.FixtureRepositoryInventoryError):
        inspect(roots, 1)


def test_exact_digest_and_generation_guard_stale_read(roots):
    bootstrap(roots)
    fd, parent, uid, _ = roots
    digest = hashlib.sha256((parent / V2_STATE).read_bytes()).hexdigest()
    for gen, sha in ((2, digest), (1, "0" * 64)):
        with pytest.raises(inventory.FixtureRepositoryInventoryError,
                           match="STALE_OR_SUBSTITUTED_STATE"):
            inventory.inspect_locked_fixture_repository_inventory_under_root(
                fd, owner_uid=uid, expected_generation=gen,
                expected_state_sha256=sha,
            )


def test_live_root_rejected_before_any_state_lock(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("root descriptor was opened under state lock")
    monkeypatch.setattr(inventory, "_locked", forbidden)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(inventory.FixtureRepositoryInventoryError,
                           match="FIXTURE_ROOT_REFUSED"):
            inventory.inspect_locked_fixture_repository_inventory_under_root(
                fd, owner_uid=os.geteuid(), expected_generation=1,
                expected_state_sha256="a" * 64,
            )
    finally:
        os.close(fd)


def test_inventory_never_mutates_files_or_invokes_network(monkeypatch, roots):
    import socket
    import subprocess
    bootstrap(roots)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("inventory must remain read only")
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(os, "unlink", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert inspect(roots, 1)["present_repository_count"] == 2


def test_invalid_types_rejected_before_any_locked_read(monkeypatch, roots):
    fd, _, uid, _ = roots
    def forbidden(*_args, **_kwargs):
        raise AssertionError("invalid arguments must not lock")
    monkeypatch.setattr(inventory, "_locked", forbidden)
    for generation, digest in (
        (False, "a" * 64), ("1", "a" * 64), (1, "A" * 64),
        (1, "a"), (1, None), (0, "a" * 64),
    ):
        with pytest.raises(inventory.FixtureRepositoryInventoryError,
                           match="ARGUMENT_INVALID"):
            inventory.inspect_locked_fixture_repository_inventory_under_root(
                fd, owner_uid=uid, expected_generation=generation,
                expected_state_sha256=digest,
            )
