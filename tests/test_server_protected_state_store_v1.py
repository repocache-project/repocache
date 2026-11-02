"""Linux inode/lock/fsync/recovery fixture tests for the inert #31 state store."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME, JOURNAL_TMP_NAME, LOCK_NAME, ROLLBACK_NAME, STAGE_NAME, STATE_NAME,
    ProtectedStateStoreError, _commit_under_root, _locked,
    _recover_under_root, validate_protected_state,
)


@pytest.fixture
def protected_root(tmp_path):
    owner = os.geteuid()
    root = tmp_path / "mock-root"
    root.mkdir(mode=0o700)
    folder = root
    for segment in ("var", "lib", "repocache", "server"):
        folder = folder / segment
        folder.mkdir(mode=0o700)
    lock = folder / LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd, folder, owner
    finally:
        os.close(fd)


def candidate(generation=1, *, with_repo=False):
    repos = []
    if with_repo:
        repos = [{
            "id": "debian-trixie-main",
            "canonical_identity_sha256": "b" * 64,
            "approval": {"source": "operator", "decision_sha256": "c" * 64},
            "desired_state": "active",
            "observed_state": "not-activated",
        }]
    return {
        "state_schema_version": 1,
        "state_generation": generation,
        "configuration_sha256": "a" * 64,
        "repositories": repos,
        "ownership_manifest": [],
    }


def save(root, state, expected):
    fd, _, uid = root
    return _commit_under_root(fd, state, expected_generation=expected,
                              owner_uid=uid)


def recover(root):
    fd, _, uid = root
    return _recover_under_root(fd, owner_uid=uid)


def test_bootstrap_persists_and_reloads_canonical_state(protected_root):
    result = save(protected_root, candidate(with_repo=True), 0)
    assert result["status"] == "COMMITTED_INERT_STATE"
    assert result["state_generation"] == 1
    assert result["authorizes_nginx_reload"] is False
    assert result["authorizes_catalog_publication"] is False
    _, folder, _ = protected_root
    actual = json.loads((folder / STATE_NAME).read_bytes())
    assert actual == candidate(with_repo=True)
    assert (folder / STATE_NAME).stat().st_mode & 0o777 == 0o600
    assert not (folder / JOURNAL_NAME).exists()
    assert recover(protected_root)["status"] == "CLEAN"


def test_idempotent_reapply_without_increment_or_new_files(protected_root):
    state = candidate()
    save(protected_root, state, 0)
    next_state = candidate(2)
    _, folder, _ = protected_root
    before = (folder / STATE_NAME).stat()
    assert save(protected_root, next_state, 1)["status"] == "NO_CHANGE"
    assert (folder / STATE_NAME).stat().st_ino == before.st_ino
    assert json.loads((folder / STATE_NAME).read_bytes())["state_generation"] == 1
    assert not (folder / JOURNAL_NAME).exists()


def test_commit_update_increments_once(protected_root):
    save(protected_root, candidate(with_repo=True), 0)
    next_state = candidate(2, with_repo=True)
    next_state["configuration_sha256"] = "d" * 64
    assert save(protected_root, next_state, 1)["state_generation"] == 2
    assert recover(protected_root)["state_generation"] == 2
    with pytest.raises(ProtectedStateStoreError, match="STALE_GENERATION"):
        save(protected_root, candidate(3, with_repo=True), 1)


@pytest.mark.parametrize("point", ["journal_durable", "stage_durable", "replace_durable"])
def test_fault_injection_rolls_back_to_exact_old_bytes(protected_root, point):
    original = candidate(with_repo=True)
    save(protected_root, original, 0)
    _, folder, uid = protected_root
    old = (folder / STATE_NAME).read_bytes()
    proposed = candidate(2, with_repo=True)
    proposed["configuration_sha256"] = "d" * 64

    def fault(phase):
        if phase == point:
            raise RuntimeError("synthetic power interruption")

    with pytest.raises(RuntimeError, match="synthetic"):
        _commit_under_root(protected_root[0], proposed, owner_uid=uid,
                           expected_generation=1, inject_fault=fault)
    with pytest.raises(ProtectedStateStoreError, match="RECOVERY_REQUIRED"):
        save(protected_root, proposed, 1)
    result = recover(protected_root)
    assert result["status"] == "ROLLED_BACK"
    assert result["state_generation"] == 1
    assert (folder / STATE_NAME).read_bytes() == old
    assert not (folder / JOURNAL_NAME).exists()
    assert not (folder / STAGE_NAME).exists()
    assert recover(protected_root)["status"] == "CLEAN"
    assert save(protected_root, proposed, 1)["state_generation"] == 2


@pytest.mark.parametrize("point", ["journal_durable", "stage_durable", "replace_durable"])
def test_failed_first_install_recovers_to_no_state(protected_root, point):
    _, folder, uid = protected_root

    def fault(phase):
        if phase == point:
            raise RuntimeError()

    with pytest.raises(RuntimeError):
        _commit_under_root(protected_root[0], candidate(), owner_uid=uid,
                           expected_generation=0, inject_fault=fault)
    assert recover(protected_root)["status"] == "ROLLED_BACK"
    assert not (folder / STATE_NAME).exists()
    assert recover(protected_root)["status"] == "CLEAN"


def test_recovery_refuses_external_state_drift(protected_root):
    save(protected_root, candidate(), 0)
    _, folder, uid = protected_root
    changed = candidate(2)
    changed["configuration_sha256"] = "b" * 64

    def fault(phase):
        if phase == "replace_durable":
            raise RuntimeError()

    with pytest.raises(RuntimeError):
        _commit_under_root(protected_root[0], changed, expected_generation=1,
                           owner_uid=uid, inject_fault=fault)
    (folder / STATE_NAME).write_bytes(b"tampering")
    with pytest.raises(ProtectedStateStoreError, match="RECOVERY_DRIFT"):
        recover(protected_root)
    assert (folder / JOURNAL_NAME).exists()


def test_refuse_parallel_lock_holder(protected_root):
    rootfd, _, uid = protected_root
    with _locked(rootfd, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            _commit_under_root(rootfd, candidate(), expected_generation=0,
                               owner_uid=uid)


@pytest.mark.parametrize("filename", [LOCK_NAME, STATE_NAME])
def test_file_symlink_refused(protected_root, filename):
    fd, folder, uid = protected_root
    if filename == LOCK_NAME:
        (folder / LOCK_NAME).unlink()
        (folder / LOCK_NAME).symlink_to("/etc/passwd")
        with pytest.raises(ProtectedStateStoreError):
            _recover_under_root(fd, owner_uid=uid)
    else:
        (folder / STATE_NAME).symlink_to("/etc/passwd")
        with pytest.raises(ProtectedStateStoreError):
            _commit_under_root(fd, candidate(), expected_generation=0,
                               owner_uid=uid)
    assert (folder / filename).is_symlink()


def test_hardlink_lock_refused(protected_root):
    _, folder, _ = protected_root
    os.link(folder / LOCK_NAME, folder / "foreign")
    with pytest.raises(ProtectedStateStoreError, match="FILE_UNSAFE"):
        recover(protected_root)


def test_unsafe_state_metadata_refused(protected_root):
    _, folder, _ = protected_root
    (folder / STATE_NAME).write_text("{}", encoding="utf-8")
    (folder / STATE_NAME).chmod(0o644)
    with pytest.raises(ProtectedStateStoreError, match="FILE_UNSAFE"):
        recover(protected_root)


def test_unknown_schema_and_noncanonical_json_refused(protected_root):
    _, folder, _ = protected_root
    state = candidate()
    state["state_schema_version"] = 2
    with pytest.raises(ProtectedStateStoreError, match="SCHEMA"):
        validate_protected_state(state)
    file = folder / STATE_NAME
    file.write_bytes(json.dumps(candidate()).encode())
    file.chmod(0o600)
    with pytest.raises(ProtectedStateStoreError, match="NONCANONICAL"):
        recover(protected_root)


@pytest.mark.parametrize("bad", [
    {"state_generation": True},
    {"configuration_sha256": "0" * 63},
    {"repositories": [{"id": "bad"}]},
    {"ownership_manifest": [{"schema_version": 99}]},
])
def test_invalid_state_has_zero_persistent_effects(protected_root, bad):
    state = candidate()
    state.update(bad)
    _, folder, _ = protected_root
    with pytest.raises(ProtectedStateStoreError):
        save(protected_root, state, 0)
    assert sorted(p.name for p in folder.iterdir()) == [LOCK_NAME]


def test_duplicate_id_canonical_identity_and_forged_approval_flag_refused():
    state = candidate(with_repo=True)
    state["repositories"].append(copy.deepcopy(state["repositories"][0]))
    with pytest.raises(ProtectedStateStoreError):
        validate_protected_state(state)
    state = candidate(with_repo=True)
    state["repositories"][0]["approval"]["authorized"] = True
    with pytest.raises(ProtectedStateStoreError):
        validate_protected_state(state)


def test_cannot_remove_or_reassign_persisted_ids(protected_root):
    save(protected_root, candidate(with_repo=True), 0)
    with pytest.raises(ProtectedStateStoreError, match="REASSIGNMENT_OR_REMOVAL"):
        save(protected_root, candidate(2), 1)
    state = candidate(2, with_repo=True)
    state["repositories"][0]["canonical_identity_sha256"] = "e" * 64
    with pytest.raises(ProtectedStateStoreError, match="REASSIGNMENT_OR_REMOVAL"):
        save(protected_root, state, 1)


def test_ownership_manifest_strict_v1_record():
    state = candidate()
    state["ownership_manifest"] = [{
        "schema_version": 1, "generation": 1,
        "path": "/etc/nginx/conf.d/repocache-managed.conf",
        "sha256": "f" * 64, "uid": 0, "gid": 0,
        "mode": 0o640, "dev": 1, "ino": 2,
    }]
    assert validate_protected_state(state) == state
    state["ownership_manifest"][0]["path"] = "/etc/nginx/nginx.conf"
    with pytest.raises(ProtectedStateStoreError, match="MANIFEST"):
        validate_protected_state(state)


def test_orphan_stage_and_unknown_journal_fail_closed(protected_root):
    _, folder, _ = protected_root
    (folder / STAGE_NAME).write_bytes(b"unrecognized")
    (folder / STAGE_NAME).chmod(0o600)
    with pytest.raises(ProtectedStateStoreError, match="ORPHAN"):
        recover(protected_root)
    (folder / STAGE_NAME).unlink()
    (folder / JOURNAL_NAME).write_bytes(b"{}")
    (folder / JOURNAL_NAME).chmod(0o600)
    with pytest.raises(ProtectedStateStoreError):
        recover(protected_root)


def test_unsafe_directory_refused_without_mutation(protected_root):
    fd, folder, uid = protected_root
    folder.chmod(0o777)
    with pytest.raises(ValueError):
        _commit_under_root(fd, candidate(), expected_generation=0, owner_uid=uid)
    assert not (folder / STATE_NAME).exists()


@pytest.mark.parametrize("already_initialized", [False, True])
def test_interrupted_journal_creation_never_changes_state(protected_root, already_initialized):
    if already_initialized:
        save(protected_root, candidate(), 0)
    _, folder, uid = protected_root
    previous = (folder / STATE_NAME).read_bytes() if already_initialized else None
    proposal = candidate(2 if already_initialized else 1)
    proposal["configuration_sha256"] = "e" * 64

    def fault(phase):
        if phase == "journal_tmp_durable":
            raise RuntimeError("injected before journal publish")

    with pytest.raises(RuntimeError, match="injected"):
        _commit_under_root(protected_root[0], proposal, owner_uid=uid,
                           expected_generation=1 if already_initialized else 0,
                           inject_fault=fault)
    assert (folder / JOURNAL_TMP_NAME).exists()
    assert not (folder / JOURNAL_NAME).exists()
    assert ((folder / STATE_NAME).read_bytes()
            if already_initialized else None) == previous
    assert recover(protected_root)["status"] == "DISCARDED_UNPUBLISHED_JOURNAL"
    assert not (folder / JOURNAL_TMP_NAME).exists()
    assert recover(protected_root)["status"] == "CLEAN"
    assert save(protected_root, proposal, 1 if already_initialized else 0)[
        "status"] == "COMMITTED_INERT_STATE"


def test_partially_written_stage_is_recovered_without_losing_old_state(protected_root):
    save(protected_root, candidate(), 0)
    _, folder, uid = protected_root
    original = (folder / STATE_NAME).read_bytes()
    next_state = candidate(2)
    next_state["configuration_sha256"] = "c" * 64

    def fault(phase):
        if phase == "journal_durable":
            raise RuntimeError("crash while starting stage")

    with pytest.raises(RuntimeError):
        _commit_under_root(protected_root[0], next_state, expected_generation=1,
                           owner_uid=uid, inject_fault=fault)
    partial = folder / STAGE_NAME
    partial.write_bytes(b"incomplete")
    partial.chmod(0o600)
    assert recover(protected_root)["status"] == "ROLLED_BACK"
    assert (folder / STATE_NAME).read_bytes() == original
    assert not partial.exists()
    assert recover(protected_root)["status"] == "CLEAN"


def test_partially_written_rollback_can_be_retried(protected_root):
    save(protected_root, candidate(), 0)
    _, folder, uid = protected_root
    original = (folder / STATE_NAME).read_bytes()
    next_state = candidate(2)
    next_state["configuration_sha256"] = "d" * 64

    def fault(phase):
        if phase == "replace_durable":
            raise RuntimeError("crash before recovery")

    with pytest.raises(RuntimeError):
        _commit_under_root(protected_root[0], next_state, expected_generation=1,
                           owner_uid=uid, inject_fault=fault)
    partial = folder / ROLLBACK_NAME
    partial.write_bytes(b"partial rollback write")
    partial.chmod(0o600)
    assert recover(protected_root)["status"] == "ROLLED_BACK"
    assert (folder / STATE_NAME).read_bytes() == original
    assert recover(protected_root)["status"] == "CLEAN"


@pytest.mark.parametrize("identical_candidate", [False, True])
def test_unexpected_stage_after_replacement_is_refused(
        protected_root, identical_candidate):
    save(protected_root, candidate(), 0)
    _, folder, uid = protected_root
    next_state = candidate(2)
    next_state["configuration_sha256"] = "d" * 64

    def fault(phase):
        if phase == "replace_durable":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError):
        _commit_under_root(protected_root[0], next_state, expected_generation=1,
                           owner_uid=uid, inject_fault=fault)
    unexpected = folder / STAGE_NAME
    # A forged duplicate stage with the *same* digest must also fail closed.
    # Renaming a durable stage into the new state consumes its inode, so a
    # remaining stage after replacement cannot be a legitimate crash state.
    expected_state_bytes = (folder / STATE_NAME).read_bytes()
    unexpected.write_bytes(
        expected_state_bytes if identical_candidate else b"unexpected")
    unexpected.chmod(0o600)
    with pytest.raises(ProtectedStateStoreError, match="RECOVERY_DRIFT"):
        recover(protected_root)
    assert (folder / JOURNAL_NAME).exists()
    assert (folder / STAGE_NAME).read_bytes() == (
        expected_state_bytes if identical_candidate else b"unexpected")
    assert (folder / STATE_NAME).read_bytes() == expected_state_bytes
