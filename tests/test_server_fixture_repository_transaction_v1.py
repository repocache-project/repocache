"""#95 lifecycle changes are durably bound to the protected v2 fixture WAL.

Tests intentionally exercise state/include/catalog *writes*, not isolated
planner decisions. No production NGINX or host-root authority is inferred.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from repocache.server_fixture_multi_resource_wal_v1 import (
    CATALOG, INCLUDE, JOURNAL, MANIFEST,
    _commit_fixture_multi_resource_under_root as commit_multi,
    _recover_fixture_multi_resource_under_root as recover_multi,
)
from repocache.server_fixture_repository_transaction_v1 import (
    FixtureRepositoryTransactionError,
    commit_fixture_repository_change_under_root as change,
)
from repocache.server_install_v1 import validate_install_document
from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_proposed_state_v2_store import V2_STATE

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
HOST = "mirror.example.invalid"
CA = "/etc/ssl/certs/ca-certificates.crt"
DECISION = "a" * 64


@pytest.fixture
def protected_fixture(tmp_path):
    root = tmp_path / "mock-root"
    root.mkdir(mode=0o700)
    path = root
    for part in ("var", "lib", "repocache", "server"):
        path = path / part
        path.mkdir(mode=0o700)
    (path / LOCK_NAME).write_bytes(b"")
    (path / LOCK_NAME).chmod(0o600)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield root_fd, path, os.geteuid()
    finally:
        os.close(root_fd)


def original_document():
    document = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    document["expected_state_generation"] = 1
    document["repositories"][1]["id"] = "almalinux-baseos"
    return validate_install_document(document, for_apply=True)


def original_snapshot(doc):
    raw = json.dumps(
        doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    records = [{
        "id": item["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(item).encode("utf-8")
        ).hexdigest(),
        "desired_state": item["desired_state"],
        "observed_state": "not-activated",
    } for item in doc["repositories"]]
    return {
        "state_schema_version": 2,
        "state_generation": 1,
        "configuration_base64": base64.b64encode(raw).decode("ascii"),
        "configuration_sha256": hashlib.sha256(raw).hexdigest(),
        "repository_records": records,
        "id_reservations": [{
            "id": item["id"],
            "canonical_identity_sha256": item["canonical_identity_sha256"],
            "status": "allocated",
        } for item in records],
        "approval_reference": {
            "source": "operator",
            "decision_sha256": DECISION,
            "configuration_sha256": hashlib.sha256(raw).hexdigest(),
            "expected_generation": 0,
        },
    }


def read_state(directory):
    return json.loads((directory / V2_STATE).read_bytes())


def read_catalog(directory):
    return json.loads((directory / CATALOG).read_bytes())


def bootstrap(layout):
    fd, directory, uid = layout
    doc = original_document()
    old = original_snapshot(doc)
    catalog = json.dumps(
        {"schema_version": 1, "status": "fixture-only-observed-candidate",
         "active_ids": []}, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    result = commit_multi(
        fd, old, owner_uid=uid, expected_generation=0,
        include_bytes=b"# initial fixture include\n",
        catalog_bytes=catalog,
    )
    assert result["status"] == "COMMITTED_INERT_FIXTURE_MULTI_RESOURCE"
    assert read_state(directory) == old
    return doc


def update(layout, *, operation, expected, pins=None,
           repository_id="debian-trixie-main", proposed=None,
           probe=None, fault=None):
    fd, _, uid = layout
    return change(
        fd, owner_uid=uid, expected_generation=expected,
        operation=operation, repository_id=repository_id,
        proposed_repository=proposed,
        candidate_pins_by_repository={} if pins is None else pins,
        ca_bundle_path=CA, fixture_decision_sha256=DECISION,
        verify_fixture_exposure_before_publish=(
            (lambda: None) if probe is None else probe
        ),
        inject_fault=fault,
    )


def test_enable_disable_remove_are_real_state_include_catalog_fixture_transactions(
    protected_fixture, tmp_path,
):
    _, directory, _ = protected_fixture
    bootstrap(protected_fixture)
    before = read_state(directory)
    old_catalog = (directory / CATALOG).read_bytes()
    during = []

    def barrier():
        # The state and managed include are durable before publication;
        # readers must still see the OLD catalog while the WAL is pending.
        during.append((
            read_state(directory)["state_generation"],
            (directory / CATALOG).read_bytes(),
            (directory / JOURNAL).is_file(),
            (directory / INCLUDE).read_bytes(),
        ))

    active = update(
        protected_fixture, operation="enable", expected=1,
        pins={"debian-trixie-main": {HOST: ["8.8.8.8"]}}, probe=barrier,
    )
    assert active["status"] == "COMMITTED_INERT_FIXTURE_MULTI_RESOURCE"
    assert active["state_generation"] == 2
    assert active["durable_shadow_wal_exercised"] is True
    assert active["fixture_only"] is True
    assert all(active[field] is False for field in (
        "host_activation_verified", "operator_authorization_verified",
        "authorizes_nginx_reload", "authorizes_catalog_publication",
        "authorizes_cache_cleanup",
    ))
    assert len(during) == 1
    assert during[0][0:3] == (2, old_catalog, True)
    assert b"location ^~ /__repocache/repos/debian-trixie-main/" in during[0][3]
    assert read_catalog(directory)["active_ids"] == ["debian-trixie-main"]
    assert not (directory / JOURNAL).exists()
    assert (directory / MANIFEST).is_file()

    # Idempotent state setting must not mint a new generation or inode.
    state_inode = (directory / V2_STATE).stat().st_ino
    noop = update(protected_fixture, operation="enable", expected=2)
    assert noop["status"] == "NO_CHANGE_INERT_FIXTURE_REPOSITORY"
    assert read_state(directory)["state_generation"] == 2
    assert (directory / V2_STATE).stat().st_ino == state_inode

    # A repository's cached bytes are deliberately outside the protected
    # config writer; normal removal never attempts a cache cleanup.
    cache = tmp_path / "retained-cache-object"
    cache.write_bytes(b"signed-package-cache-bytes")
    inode = cache.stat().st_ino

    off = update(protected_fixture, operation="disable", expected=2)
    assert off["state_generation"] == 3
    assert read_catalog(directory)["active_ids"] == []
    assert b"repocache_pin_debian_trixie_main" not in (
        directory / INCLUDE
    ).read_bytes()
    removed = update(
        protected_fixture, operation="remove", expected=3,
    )
    assert removed["state_generation"] == 4
    assert cache.read_bytes() == b"signed-package-cache-bytes"
    assert cache.stat().st_ino == inode
    state = read_state(directory)
    reservations = {r["id"]: r for r in state["id_reservations"]}
    assert reservations["debian-trixie-main"]["status"] == "retired"
    assert {r["id"] for r in state["repository_records"]} == {"almalinux-baseos"}
    with pytest.raises(FixtureRepositoryTransactionError, match="PREPARE_REFUSED"):
        update(
            protected_fixture, operation="add", expected=4,
            repository_id=None, proposed=before_document_repository(before),
        )
    assert read_state(directory) == state


def before_document_repository(snapshot):
    return json.loads(
        base64.b64decode(snapshot["configuration_base64"])
    )["repositories"][0]


def test_auto_id_uses_protected_all_time_ledger_and_is_restart_stable(
    protected_fixture,
):
    _, directory, _ = protected_fixture
    doc = bootstrap(protected_fixture)
    candidate = copy.deepcopy(doc["repositories"][0])
    candidate.pop("id")
    candidate["upstream"]["base_url"] = "https://mirror2.example.invalid/debian/"
    candidate["upstream"]["allowed_hosts"] = ["mirror2.example.invalid"]
    result = update(
        protected_fixture, operation="add", expected=1,
        repository_id=None, proposed=candidate,
    )
    assert result["state_generation"] == 2
    assert result["repository_id"].startswith("repo-")
    first_id = result["repository_id"]
    state = read_state(directory)
    assert first_id in {row["id"] for row in state["repository_records"]}
    assert first_id in {row["id"] for row in state["id_reservations"]}
    # A fresh open and repeat is an idempotent existing identity, not reuse.
    again = update(
        protected_fixture, operation="add", expected=2,
        repository_id=None, proposed=candidate,
    )
    assert again["status"] == "NO_CHANGE_INERT_FIXTURE_REPOSITORY"
    assert again["repository_id"] == first_id
    assert read_state(directory) == state
    update(
        protected_fixture, operation="remove", expected=2,
        repository_id=first_id,
    )
    reserved = read_state(directory)
    assert next(x for x in reserved["id_reservations"] if x["id"] == first_id)[
        "status"
    ] == "retired"
    # The adopted v2 schema also reserves historical identity digests:
    # a tombstoned publisher identity cannot be silently rebound to a new
    # ID/cache namespace. A separately approved recovery policy is needed.
    with pytest.raises(FixtureRepositoryTransactionError, match="PREPARE_REFUSED"):
        update(
            protected_fixture, operation="add", expected=3,
            repository_id=None, proposed=candidate,
        )
    assert read_state(directory) == reserved


def test_failed_prepublication_barrier_leaves_pending_wal_for_recovery(
    protected_fixture,
):
    _, directory, uid = protected_fixture
    bootstrap(protected_fixture)
    baseline = {
        name: (directory / name).read_bytes()
        for name in (V2_STATE, INCLUDE, CATALOG, MANIFEST)
    }

    def refused():
        raise OSError("untrusted fixture exposure")

    with pytest.raises(FixtureRepositoryTransactionError, match="COMMIT_REFUSED"):
        update(
            protected_fixture, operation="enable", expected=1,
            pins={"debian-trixie-main": {HOST: ["8.8.8.8"]}},
            probe=refused,
        )
    assert (directory / JOURNAL).is_file()
    assert (directory / CATALOG).read_bytes() == baseline[CATALOG]
    with pytest.raises(FixtureRepositoryTransactionError, match="PREPARE_REFUSED"):
        update(protected_fixture, operation="disable", expected=1)
    restored = recover_multi(protected_fixture[0], owner_uid=uid)
    assert restored["status"] == "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE"
    assert all((directory / name).read_bytes() == raw
               for name, raw in baseline.items())
    assert not (directory / JOURNAL).exists()
    assert update(
        protected_fixture, operation="enable", expected=1,
        pins={"debian-trixie-main": {HOST: ["8.8.8.8"]}},
    )["state_generation"] == 2


def test_crash_after_state_install_cannot_publish_unverified_catalog(
    protected_fixture,
):
    _, directory, uid = protected_fixture
    bootstrap(protected_fixture)
    old = (directory / CATALOG).read_bytes()

    def interrupted(phase):
        if phase == "state_durable":
            raise RuntimeError("fixture process interruption")

    with pytest.raises(RuntimeError, match="fixture process interruption"):
        update(
            protected_fixture, operation="enable", expected=1,
            pins={"debian-trixie-main": {HOST: ["8.8.8.8"]}},
            fault=interrupted,
        )
    assert (directory / JOURNAL).is_file()
    assert (directory / CATALOG).read_bytes() == old
    assert read_state(directory)["state_generation"] == 2
    assert recover_multi(protected_fixture[0], owner_uid=uid)[
        "status"
    ] == "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE"
    assert read_state(directory)["state_generation"] == 1
    assert (directory / CATALOG).read_bytes() == old


def test_stale_identity_rebinding_and_pin_errors_have_no_mutation(
    protected_fixture,
):
    _, directory, _ = protected_fixture
    doc = bootstrap(protected_fixture)
    originals = {
        name: (directory / name).read_bytes()
        for name in (V2_STATE, INCLUDE, CATALOG, MANIFEST)
    }
    with pytest.raises(FixtureRepositoryTransactionError, match="STALE_GENERATION"):
        update(protected_fixture, operation="disable", expected=2)
    with pytest.raises(FixtureRepositoryTransactionError, match="PREPARE_REFUSED"):
        update(
            protected_fixture, operation="enable", expected=1,
            pins={"debian-trixie-main": {HOST: ["127.0.0.1"]}},
        )
    altered = copy.deepcopy(doc["repositories"][0])
    altered["upstream"]["base_url"] = "https://foreign.example.invalid/debian/"
    altered["upstream"]["allowed_hosts"] = ["foreign.example.invalid"]
    with pytest.raises(FixtureRepositoryTransactionError, match="PREPARE_REFUSED"):
        update(
            protected_fixture, operation="update", expected=1,
            proposed=altered,
        )
    assert all((directory / name).read_bytes() == raw
               for name, raw in originals.items())
    assert not (directory / JOURNAL).exists()
    assert recover_multi(protected_fixture[0], owner_uid=protected_fixture[2])[
        "status"
    ] == "CLEAN_INERT_FIXTURE"
