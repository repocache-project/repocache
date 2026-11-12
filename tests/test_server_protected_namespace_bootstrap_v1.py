"""Durable fixed protected namespace bootstrap in disposable Linux roots (#31)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from repocache.server_protected_namespace_bootstrap_v1 import (
    ProtectedBootstrapError, bootstrap_protected_namespace_under_root,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME, _locked


@pytest.fixture
def isolated_root(tmp_path):
    root = tmp_path / "isolated"
    root.mkdir(mode=0o700)
    var = root / "var"
    lib = var / "lib"
    var.mkdir(mode=0o755)
    lib.mkdir(mode=0o755)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd, root, lib, os.geteuid()
    finally:
        os.close(fd)


def provision(root, uid, **kw):
    return bootstrap_protected_namespace_under_root(root, owner_uid=uid, **kw)


def test_first_provision_creates_only_fixed_protected_state(isolated_root):
    root_fd, root, lib, uid = isolated_root
    before = {x.name for x in lib.iterdir()}
    assert before == set()
    result = provision(root_fd, uid)
    assert result["status"] == "FRESH_PROTECTED_LOCK_DURABLE"
    assert result["state_directory_created"] is True
    assert result["state_lock_validated"] is True
    assert not any(value for key, value in result.items()
                   if key.startswith("authorizes_")
                   or key.endswith("_authenticated"))
    state = lib / "repocache" / "server"
    for path in (state.parent, state):
        info = path.stat()
        assert info.st_uid == uid
        assert info.st_mode & 0o777 == 0o700
        assert not path.is_symlink()
    lock = state / LOCK_NAME
    info = lock.stat()
    assert info.st_uid == uid and info.st_nlink == 1
    assert info.st_size == 0 and info.st_mode & 0o777 == 0o600
    with _locked(root_fd, uid):
        pass
    assert {x.name for x in lib.iterdir()} == {"repocache"}
    assert {x.name for x in state.iterdir()} == {LOCK_NAME}
    assert not (root / "etc").exists()


def test_idempotent_repeated_provision_preserves_lock_and_state(isolated_root):
    root_fd, _, lib, uid = isolated_root
    provision(root_fd, uid)
    state = lib / "repocache" / "server"
    lock = state / LOCK_NAME
    ident = (lock.stat().st_dev, lock.stat().st_ino)
    managed = state / "state-v2.json"
    managed.write_bytes(b"immutable-foreign-test-state")
    managed.chmod(0o600)
    before = managed.read_bytes()
    for _ in range(3):
        result = provision(root_fd, uid)
        assert result["status"] == "EXISTING_PROTECTED_LOCK_VALIDATED"
        assert result["state_directory_created"] is False
        assert (lock.stat().st_dev, lock.stat().st_ino) == ident
        assert managed.read_bytes() == before
    assert set(x.name for x in state.iterdir()) == {LOCK_NAME, "state-v2.json"}


@pytest.mark.parametrize("breakpoint", ["root_dir_durable", "state_dir_durable"])
def test_interrupted_initial_provision_never_adopts_or_replaces(
    isolated_root, breakpoint,
):
    root_fd, _, lib, uid = isolated_root
    def interrupt(step):
        if step == breakpoint:
            raise RuntimeError("injected power loss")
    with pytest.raises(RuntimeError, match="injected power loss"):
        provision(root_fd, uid, inject_fault=interrupt)
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)
    assert (lib / "repocache").is_dir()
    assert not (lib / "repocache" / "server" / LOCK_NAME).exists()


def test_after_durable_lock_interruption_is_safe_idempotent_retry(isolated_root):
    root_fd, _, lib, uid = isolated_root
    def interrupt(step):
        if step == "lock_durable":
            raise RuntimeError("after durable lock")
    with pytest.raises(RuntimeError, match="after durable lock"):
        provision(root_fd, uid, inject_fault=interrupt)
    lock = lib / "repocache" / "server" / LOCK_NAME
    before = lock.stat().st_ino
    result = provision(root_fd, uid)
    assert result["status"] == "EXISTING_PROTECTED_LOCK_VALIDATED"
    assert lock.stat().st_ino == before


def test_unowned_foreign_repocache_state_is_never_adopted(isolated_root):
    root_fd, _, lib, uid = isolated_root
    existing = lib / "repocache"
    existing.mkdir(mode=0o700)
    token = existing / "foreign-private"
    token.write_bytes(b"preserve")
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)
    assert token.read_bytes() == b"preserve"
    assert not (existing / "server").exists()


def test_foreign_leaf_or_lock_is_never_modified(isolated_root):
    root_fd, _, lib, uid = isolated_root
    provision(root_fd, uid)
    state = lib / "repocache" / "server"
    lock = state / LOCK_NAME
    lock.unlink()
    other = state / "opaque"
    other.write_bytes(b"other")
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)
    assert other.read_bytes() == b"other"
    assert not lock.exists()


def test_symlinked_existing_ancestor_or_leaf_refused(isolated_root, tmp_path):
    root_fd, _, lib, uid = isolated_root
    (lib / "repocache").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)
    (lib / "repocache").unlink()
    (lib / "repocache").mkdir(mode=0o700)
    (lib / "repocache" / "server").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)
    assert not (tmp_path / LOCK_NAME).exists()


def test_writable_ancestor_or_invalid_modes_refused(isolated_root):
    root_fd, _, lib, uid = isolated_root
    lib.chmod(0o777)
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)
    assert not (lib / "repocache").exists()
    lib.chmod(0o755)
    provision(root_fd, uid)
    (lib / "repocache").chmod(0o755)
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)


def test_lock_symlink_hardlink_wrong_mode_and_nonempty_refused(isolated_root):
    root_fd, _, lib, uid = isolated_root
    provision(root_fd, uid)
    state = lib / "repocache" / "server"
    lock = state / LOCK_NAME
    lock.unlink()
    lock.symlink_to("/etc/passwd")
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)
    assert lock.is_symlink()
    lock.unlink()
    lock.write_bytes(b"")
    lock.chmod(0o600)
    outside = state / "other-hardlink"
    os.link(lock, outside)
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)
    outside.unlink()
    lock.chmod(0o644)
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)
    lock.chmod(0o600)
    lock.write_bytes(b"not-empty")
    with pytest.raises(ProtectedBootstrapError):
        provision(root_fd, uid)


def test_root_uid_argument_and_fd_rejected_before_write(isolated_root):
    root_fd, root, lib, uid = isolated_root
    for kwargs in ({"owner_uid": -1}, {"owner_uid": True},
                   {"owner_uid": 2**33}, {"owner_uid": "root"}):
        with pytest.raises(ProtectedBootstrapError,
                           match="PROTECTED_BOOTSTRAP_ARGUMENT_INVALID"):
            bootstrap_protected_namespace_under_root(root_fd, **kwargs)
    with pytest.raises(ProtectedBootstrapError,
                       match="PROTECTED_BOOTSTRAP_ARGUMENT_INVALID"):
        bootstrap_protected_namespace_under_root(-1, owner_uid=uid)
    assert not (lib / "repocache").exists()


def test_no_package_nginx_or_privileged_host_interface():
    source = (Path(__file__).resolve().parents[1]
              / "src/repocache/server_protected_namespace_bootstrap_v1.py").read_text()
    for prohibited in ("subprocess", "systemctl", "apt-get", "dnf install",
                       "nginx -t", 'os.open("/",', "os.chown("):
        assert prohibited not in source
    assert 'authorizes_installation": False' in source
    assert 'authorizes_state_write": False' in source
