"""Read-only native NGINX APT/DNF effects journal evidence on Linux inodes."""
from __future__ import annotations

import json
import os

import pytest

from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, NATIVE_TMP_NAME,
    _prepare_native_journal_under_root,
)
from repocache.server_native_package_effects_observe_v1 import (
    NativeEffectsReconciliationError,
    inspect_native_package_effects_under_root as inspect,
)
from repocache.server_protected_state_store_v1 import (
    JOURNAL_TMP_NAME, LOCK_NAME, STATE_NAME, _locked,
)


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "detached"
    root.mkdir(mode=0o700)
    folder = root
    for part in ("var", "lib", "repocache", "server"):
        folder = folder / part
        folder.mkdir(mode=0o700)
    (folder / LOCK_NAME).write_bytes(b"")
    (folder / LOCK_NAME).chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd, folder, os.geteuid()
    finally:
        os.close(fd)


@pytest.mark.parametrize("distribution,manager", [
    ("debian", "apt"), ("almalinux", "dnf"),
])
def test_real_pending_marker_is_read_only_and_keeps_reentry_blocked(
    fixture, distribution, manager,
):
    fd, folder, uid = fixture
    _prepare_native_journal_under_root(
        fd, owner_uid=uid, distribution=distribution,
    )
    marker = folder / NATIVE_PENDING_NAME
    prior = marker.read_bytes()
    inode = marker.stat().st_ino
    result = inspect(fd, owner_uid=uid, distribution=distribution)
    assert result["status"] == "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION"
    assert result["distribution"] == distribution
    assert result["manager"] == manager
    assert result["journal_identity_verified"] is True
    assert result["pending_native_effects_block_reentry"] is True
    assert result["native_package_effects_reconciled"] is False
    for name, value in result.items():
        if (name.startswith("authorizes_") or name.endswith("_verified")
                and name != "journal_identity_verified"):
            assert value is False, name
    assert marker.read_bytes() == prior
    assert marker.stat().st_ino == inode
    assert not (folder / NATIVE_TMP_NAME).exists()
    assert inspect(fd, owner_uid=uid, distribution=distribution) == result


@pytest.mark.parametrize("invalid", [
    "debian-12", "ubuntu", "alma", "AlmaLinux", True, None, 10,
])
def test_invalid_distro_refused_before_read_or_mutation(fixture, invalid):
    fd, folder, uid = fixture
    before = sorted(p.name for p in folder.iterdir())
    with pytest.raises(NativeEffectsReconciliationError,
                       match="^NATIVE_EFFECTS_ARGUMENT_INVALID$"):
        inspect(fd, owner_uid=uid, distribution=invalid)
    assert sorted(p.name for p in folder.iterdir()) == before


def test_no_marker_is_not_reported_as_a_clean_native_transaction(fixture):
    fd, _, uid = fixture
    with pytest.raises(NativeEffectsReconciliationError,
                       match="^NATIVE_EFFECTS_PENDING_MARKER_MISSING$"):
        inspect(fd, owner_uid=uid, distribution="debian")


def test_other_distro_pending_marker_is_not_adopted(fixture):
    fd, folder, uid = fixture
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    before = (folder / NATIVE_PENDING_NAME).read_bytes()
    with pytest.raises(NativeEffectsReconciliationError,
                       match="^NATIVE_EFFECTS_PENDING_MARKER_IDENTITY_INVALID$"):
        inspect(fd, owner_uid=uid, distribution="almalinux")
    assert (folder / NATIVE_PENDING_NAME).read_bytes() == before


@pytest.mark.parametrize("mutation", [
    "foreign-package", "forged-generation", "duplicate-fields",
    "noncanonical", "nonjson",
])
def test_forged_or_corrupt_marker_never_authorizes_recovery(
    fixture, mutation,
):
    fd, folder, uid = fixture
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    marker = folder / NATIVE_PENDING_NAME
    value = json.loads(marker.read_bytes())
    if mutation == "foreign-package":
        value["package"] = "foreign"
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    elif mutation == "forged-generation":
        value["expected_state_generation"] = 1
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    elif mutation == "duplicate-fields":
        raw = b'{"manager":"apt","manager":"dnf"}'
    elif mutation == "noncanonical":
        raw = json.dumps(value, indent=1).encode()
    else:
        raw = b'opaque binary \x00 status'
    marker.write_bytes(raw)
    with pytest.raises(NativeEffectsReconciliationError):
        inspect(fd, owner_uid=uid, distribution="debian")
    assert marker.read_bytes() == raw


@pytest.mark.parametrize("mutation", [
    "symlink", "unsafe-mode", "orphan-temp", "pending-and-temp",
    "pending-with-state-tmp", "unexpected-state",
])
def test_ambiguous_native_or_state_transaction_is_never_clean(
    fixture, mutation,
):
    fd, folder, uid = fixture
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    marker = folder / NATIVE_PENDING_NAME
    if mutation == "symlink":
        marker.unlink()
        marker.symlink_to("/etc/passwd")
    elif mutation == "unsafe-mode":
        marker.chmod(0o644)
    elif mutation == "orphan-temp":
        marker.rename(folder / NATIVE_TMP_NAME)
    elif mutation == "pending-and-temp":
        (folder / NATIVE_TMP_NAME).write_bytes(marker.read_bytes())
        (folder / NATIVE_TMP_NAME).chmod(0o600)
    elif mutation == "pending-with-state-tmp":
        (folder / JOURNAL_TMP_NAME).write_bytes(b"foreign state")
        (folder / JOURNAL_TMP_NAME).chmod(0o600)
    else:
        (folder / STATE_NAME).write_bytes(b"foreign generation")
        (folder / STATE_NAME).chmod(0o600)
    with pytest.raises(NativeEffectsReconciliationError):
        inspect(fd, owner_uid=uid, distribution="debian")
    assert marker.exists() or marker.is_symlink() or (
        folder / NATIVE_TMP_NAME).exists()


def test_concurrent_protected_state_transaction_blocks_observer(fixture):
    fd, _, uid = fixture
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="almalinux")
    with _locked(fd, uid):
        with pytest.raises(NativeEffectsReconciliationError,
                           match="^NATIVE_EFFECTS_PROTECTED_STATE_UNVERIFIED$"):
            inspect(fd, owner_uid=uid, distribution="almalinux")


def test_real_mount_namespace_root_is_not_an_injected_fixture():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(NativeEffectsReconciliationError,
                       match="^NATIVE_EFFECTS_LIVE_ROOT_REQUIRES_CURRENT_NAMESPACE_OBSERVER$"):
            inspect(fd, owner_uid=0, distribution="debian")
    finally:
        os.close(fd)


def test_observation_does_not_invoke_package_manager_or_process(monkeypatch, fixture):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k:
                        pytest.fail("journal inspection never invokes subprocess"))
    fd, folder, uid = fixture
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    assert inspect(fd, owner_uid=uid, distribution="debian")[
        "authorizes_package_installation"
    ] is False
    assert (folder / NATIVE_PENDING_NAME).is_file()
