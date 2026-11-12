"""Native package parent-churn lock checks on real disposable Linux FDs (#27)."""
from __future__ import annotations

import os
import pytest

from repocache.server_protected_state_store_v1 import (
    LOCK_NAME, ProtectedStateStoreError, _locked,
)
from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, NativePackageJournalError,
    _prepare_native_journal_under_root,
    _retain_native_package_journal_lock_under_root,
)


@pytest.fixture
def root_fixture(tmp_path):
    root = tmp_path / "namespace"
    root.mkdir(mode=0o700)
    current = root
    for name in ("var", "lib", "repocache", "server"):
        current = current / name
        current.mkdir(mode=0o700)
    lock = current / LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd, root, os.geteuid()
    finally:
        os.close(fd)


def test_default_lock_keeps_strict_shared_parent_identity(root_fixture):
    fd, root, uid = root_fixture
    with pytest.raises(ValueError, match="MANAGED_DIRECTORY_CHANGED"):
        with _locked(fd, uid):
            (root / "var/lib/native-owned").mkdir(mode=0o700)


def test_native_lock_tolerates_unrelated_parent_changes(root_fixture):
    fd, root, uid = root_fixture
    lock = root / "var/lib/repocache/server" / LOCK_NAME
    before = (lock.stat().st_dev, lock.stat().st_ino)
    with _locked(fd, uid, allow_native_package_parent_changes=True):
        (root / "var/lib/native-owned").mkdir(mode=0o700)
        (root / "var/cache").mkdir(mode=0o700)
    assert (lock.stat().st_dev, lock.stat().st_ino) == before
    with _locked(fd, uid, allow_native_package_parent_changes=True):
        pass


def test_native_lock_refuses_owned_subtree_change(root_fixture):
    fd, root, uid = root_fixture
    with pytest.raises(ProtectedStateStoreError,
                       match="PROTECTED_DIRECTORY_CHANGED"):
        with _locked(fd, uid, allow_native_package_parent_changes=True):
            (root / "var/lib/repocache/foreign").mkdir(mode=0o700)


def test_native_lock_refuses_parent_symlink_replacement(root_fixture):
    fd, root, uid = root_fixture
    parent = root / "var"
    with pytest.raises(ProtectedStateStoreError,
                       match="PROTECTED_DIRECTORY_CHANGED"):
        with _locked(fd, uid, allow_native_package_parent_changes=True):
            (parent / "lib").rename(parent / "lib-old")
            (parent / "lib").symlink_to(
                parent / "lib-old", target_is_directory=True,
            )


def test_native_lock_refuses_permission_drift(root_fixture):
    fd, root, uid = root_fixture
    with pytest.raises(ProtectedStateStoreError,
                       match="PROTECTED_DIRECTORY_CHANGED"):
        with _locked(fd, uid, allow_native_package_parent_changes=True):
            (root / "var/lib").chmod(0o777)


def test_native_lock_refuses_state_leaf_replacement(root_fixture):
    fd, root, uid = root_fixture
    parent = root / "var/lib/repocache"
    with pytest.raises(ProtectedStateStoreError,
                       match="PROTECTED_DIRECTORY_CHANGED"):
        with _locked(fd, uid, allow_native_package_parent_changes=True):
            (parent / "server").rename(parent / "server-old")
            (parent / "server").symlink_to(
                parent / "server-old", target_is_directory=True,
            )


def test_native_relaxation_is_boolean_only(root_fixture):
    fd, root, uid = root_fixture
    for invalid in (1, "true", None, [], {}):
        with pytest.raises(ProtectedStateStoreError,
                           match="PROTECTED_ROOT_INVALID"):
            with _locked(fd, uid,
                         allow_native_package_parent_changes=invalid):
                pytest.fail("invalid flag admitted")


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_native_journal_retained_lock_accepts_shared_churn_and_blocks_reentry(
    root_fixture, distribution,
):
    fd, root, uid = root_fixture
    state = root / "var/lib/repocache/server"
    with _retain_native_package_journal_lock_under_root(
        fd, owner_uid=uid, distribution=distribution,
        allow_native_package_parent_changes=True,
    ) as status:
        assert status["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
        assert not status["authorizes_package_installation"]
        (root / "var/lib/native-nginx").mkdir(mode=0o700)
        with pytest.raises(ProtectedStateStoreError,
                           match="PROTECTED_LOCK_UNAVAILABLE"):
            with _locked(fd, uid):
                pytest.fail("concurrent state lock admitted")
    assert (state / NATIVE_PENDING_NAME).exists()
    with pytest.raises(NativePackageJournalError,
                       match="NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED"):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution=distribution,
        )


def test_prepare_only_remains_strict(root_fixture):
    fd, _, uid = root_fixture
    report = _prepare_native_journal_under_root(
        fd, owner_uid=uid, distribution="debian",
    )
    assert report["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
    assert not report["authorizes_package_installation"]


def test_native_scope_invalid_flag_refused_before_journal(root_fixture):
    fd, root, uid = root_fixture
    with pytest.raises(NativePackageJournalError,
                       match="NATIVE_JOURNAL_ARGUMENT_INVALID"):
        with _retain_native_package_journal_lock_under_root(
            fd, owner_uid=uid, distribution="debian",
            allow_native_package_parent_changes=1,
        ):
            pytest.fail("invalid flag admitted")
    assert not (root / "var/lib/repocache/server" / NATIVE_PENDING_NAME).exists()
