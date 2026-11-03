"""Real disposable Linux inode/fsync and fail-closed native package journal tests."""
from __future__ import annotations

import json
import os

import pytest

from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, NATIVE_TMP_NAME, NativePackageJournalError,
    _prepare_native_journal_under_root,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME, STATE_NAME, _locked


@pytest.fixture
def protected_root(tmp_path):
    owner = os.geteuid()
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    folder = root
    for name in ("var", "lib", "repocache", "server"):
        folder = folder / name
        folder.mkdir(mode=0o700)
    (folder / LOCK_NAME).write_bytes(b"")
    (folder / LOCK_NAME).chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd, folder, owner
    finally:
        os.close(fd)


@pytest.mark.parametrize("distribution,manager", [
    ("debian", "apt"), ("almalinux", "dnf"),
])
def test_durable_pending_marker_is_mode_0600_and_blocks_reentry(
    protected_root, distribution, manager,
):
    fd, folder, uid = protected_root
    result = _prepare_native_journal_under_root(
        fd, owner_uid=uid, distribution=distribution,
    )
    assert result["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
    assert result["package_transaction_executed"] is False
    assert result["operator_authorization_authenticated"] is False
    assert result["native_package_signature_verified"] is False
    assert result["native_package_effects_reconciled"] is False
    assert result["authorizes_package_installation"] is False
    assert result["authorizes_nginx_reload"] is False
    pending = folder / NATIVE_PENDING_NAME
    assert pending.exists()
    assert (pending.stat().st_mode & 0o777) == 0o600
    assert pending.stat().st_nlink == 1
    assert not (folder / NATIVE_TMP_NAME).exists()
    doc = json.loads(pending.read_bytes())
    assert doc == {
        "journal_schema_version": 1,
        "operation": "fresh-native-nginx-package-install",
        "distribution": distribution,
        "manager": manager,
        "package": "nginx",
        "expected_state_generation": 0,
        "native_package_effects": "REQUIRES_EXPLICIT_RECONCILIATION",
    }
    assert not (folder / STATE_NAME).exists()
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED$"):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution=distribution,
        )
    assert json.loads(pending.read_bytes()) == doc


@pytest.mark.parametrize("point", [
    "native_journal_temp_durable",
    "native_journal_link_durable",
    "native_journal_published",
])
def test_injected_crash_never_leaves_clean_reentry(protected_root, point):
    fd, folder, uid = protected_root

    def fail(phase):
        if phase == point:
            raise RuntimeError("simulated interruption")

    with pytest.raises(RuntimeError, match="simulated interruption"):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution="debian", inject_fault=fail,
        )
    assert ((folder / NATIVE_TMP_NAME).exists()
            or (folder / NATIVE_PENDING_NAME).exists())
    with pytest.raises(NativePackageJournalError):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution="debian",
        )


def test_existing_native_marker_refused_without_modification(protected_root):
    fd, folder, uid = protected_root
    marker = folder / NATIVE_PENDING_NAME
    marker.write_bytes(b"foreign")
    marker.chmod(0o600)
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED$"):
        _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    assert marker.read_bytes() == b"foreign"
    assert not (folder / NATIVE_TMP_NAME).exists()


def test_unsafe_symlinked_native_marker_refuses_closed(protected_root):
    fd, folder, uid = protected_root
    (folder / NATIVE_PENDING_NAME).symlink_to("/etc/passwd")
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_JOURNAL_STATE_UNVERIFIED$"):
        _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    assert not (folder / NATIVE_TMP_NAME).exists()


def test_existing_protected_state_never_adopted_as_fresh(protected_root):
    fd, folder, uid = protected_root
    document = {
        "state_schema_version": 1,
        "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [],
        "ownership_manifest": [],
    }
    state = folder / STATE_NAME
    # #31 accepts only its canonical sorted/compact JSON encoding. A
    # noncanonical fixture is refused *before* the existing-generation gate.
    state.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    state.chmod(0o600)
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_EXISTING_STATE_REFUSED$"):
        _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    assert not (folder / NATIVE_PENDING_NAME).exists()


def test_noncanonical_existing_state_fails_closed(protected_root):
    fd, folder, uid = protected_root
    state = folder / STATE_NAME
    state.write_text(json.dumps({
        "state_schema_version": 1,
        "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [],
        "ownership_manifest": [],
    }), encoding="ascii")
    state.chmod(0o600)
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_JOURNAL_STATE_UNVERIFIED$"):
        _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    assert not (folder / NATIVE_PENDING_NAME).exists()


def test_invalid_inputs_rejected_before_lock_and_write(protected_root):
    fd, folder, uid = protected_root
    for distribution in ("ubuntu", "debian-12", None, True):
        with pytest.raises(NativePackageJournalError,
                           match="^NATIVE_JOURNAL_ARGUMENT_INVALID$"):
            _prepare_native_journal_under_root(
                fd, owner_uid=uid, distribution=distribution
            )
    assert not (folder / NATIVE_PENDING_NAME).exists()


def test_no_native_process_invoked_by_journal_writer(protected_root, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k:
                        pytest.fail("journal never invokes native package manager"))
    fd, _, uid = protected_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="almalinux")


def test_concurrent_state_lock_prevents_second_journal_writer(protected_root):
    fd, folder, uid = protected_root
    from repocache.server_protected_state_store_v1 import ProtectedStateStoreError
    with _locked(fd, uid):
        with pytest.raises(NativePackageJournalError,
                           match="^NATIVE_JOURNAL_STATE_UNVERIFIED$"):
            _prepare_native_journal_under_root(
                fd, owner_uid=uid, distribution="debian",
            )
    assert not (folder / NATIVE_PENDING_NAME).exists()
