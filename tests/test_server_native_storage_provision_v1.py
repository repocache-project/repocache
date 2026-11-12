"""Real filesystem storage creation, preservation and security refusals (#29)."""
from __future__ import annotations

import os
import stat

import pytest

from repocache.server_native_storage_provision_v1 import (
    NativeStorageProvisionError, provision_native_storage_under_root,
)


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "isolated"
    root.mkdir(mode=0o700)
    for parent in ("var/cache/nginx", "var/log/nginx"):
        (root / parent).mkdir(parents=True, mode=0o755)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd, root, os.geteuid()
    finally:
        os.close(fd)


def call(fixture, **kw):
    fd, root, uid = fixture
    args = dict(root_uid=uid, cache_uid=uid)
    args.update(kw)
    return provision_native_storage_under_root(fd, **args)


def leaves(root):
    return [root / "var/cache/nginx/repocache-managed",
            root / "var/log/nginx/repocache-managed"]


def test_actual_fsync_created_leaves_and_idempotent_retention(fixture):
    _, root, uid = fixture
    new = call(fixture)
    assert new["status"] == "FRESH_STORAGE_CREATED"
    assert new["operator_authorization_verified"] is False
    assert new["host_root_authenticated"] is False
    assert not new["authorizes_host_installation"]
    assert not new["authorizes_cache_cleanup"]
    for label, leaf in zip(("cache", "logs"), leaves(root)):
        st = leaf.stat()
        assert st.st_uid == uid
        assert stat.S_IMODE(st.st_mode) == 0o700
        assert (st.st_dev, st.st_ino) == (
            new["directory_identities"][label]["dev"],
            new["directory_identities"][label]["ino"],
        )
        (leaf / "retained-private-package").write_bytes(b"retained")
    for _ in range(3):
        again = call(fixture, existing=new["directory_identities"])
        assert again["status"] == "EXISTING_STORAGE_VALIDATED"
        assert again["existing_data_retained"]
    assert all((p / "retained-private-package").read_bytes() == b"retained"
               for p in leaves(root))


@pytest.mark.parametrize("target", ("cache", "logs"))
def test_existing_foreign_leaf_never_adopted_or_mutated(fixture, target):
    _, root, uid = fixture
    leaf = leaves(root)[0 if target == "cache" else 1]
    leaf.mkdir(mode=0o700)
    token = leaf / "foreign"
    token.write_bytes(b"preserve")
    with pytest.raises(NativeStorageProvisionError,
                       match="UNOWNED_OR_PARTIAL_NAMESPACE"):
        call(fixture)
    assert token.read_bytes() == b"preserve"
    assert not leaves(root)[1 if target == "cache" else 0].exists()


def test_crash_after_cache_creation_never_adopts_or_cleans(fixture):
    _, root, uid = fixture
    def fail(step):
        if step == "cache_durable":
            raise RuntimeError("simulated power failure")
    with pytest.raises(RuntimeError, match="power failure"):
        call(fixture, inject_fault=fail)
    assert leaves(root)[0].is_dir()
    with pytest.raises(NativeStorageProvisionError,
                       match="UNOWNED_OR_PARTIAL_NAMESPACE"):
        call(fixture)
    assert not leaves(root)[1].exists()


def test_manifest_inode_change_refused_without_writes(fixture):
    _, root, uid = fixture
    result = call(fixture)
    expected = result["directory_identities"]
    leaf = leaves(root)[0]
    leaf.rename(leaf.parent / "old-owned-cache")
    leaf.mkdir(mode=0o700)
    with pytest.raises(NativeStorageProvisionError,
                       match="MANIFEST_INODE_DRIFT"):
        call(fixture, existing=expected)
    assert (leaf.parent / "old-owned-cache").is_dir()


def test_symlink_leaf_refused(fixture, tmp_path):
    _, root, uid = fixture
    leaves(root)[0].symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(NativeStorageProvisionError):
        call(fixture)
    assert leaves(root)[0].is_symlink()
    assert not leaves(root)[1].exists()


def test_unsafe_parent_mode_refused_before_first_write(fixture):
    _, root, uid = fixture
    (root / "var/cache/nginx").chmod(0o777)
    with pytest.raises(NativeStorageProvisionError):
        call(fixture)
    assert not any(p.exists() for p in leaves(root))


def test_invalid_manifest_does_not_touch_fs(fixture):
    _, root, uid = fixture
    for x in ({}, {"cache": {}, "logs": {}},
              {"cache": {"dev": True}, "logs": {}}, True):
        with pytest.raises(NativeStorageProvisionError,
                           match="EXPECTED_MANIFEST_INVALID"):
            call(fixture, existing=x)
    assert not any(p.exists() for p in leaves(root))


def test_existing_leaf_mode_or_ownership_drift_refused(fixture):
    _, root, uid = fixture
    manifest = call(fixture)["directory_identities"]
    leaf = leaves(root)[0]
    leaf.chmod(0o777)
    with pytest.raises(NativeStorageProvisionError):
        call(fixture, existing=manifest)


def test_uid_parameters_validate_before_mutating(fixture):
    _, root, uid = fixture
    for bad in (-1, True, "root", 2**33):
        with pytest.raises(NativeStorageProvisionError,
                           match="ARGUMENT_INVALID"):
            call(fixture, cache_uid=bad)
    assert not any(p.exists() for p in leaves(root))


def test_disabled_mutation_or_privilege_sources():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1]
           / "src/repocache/server_native_storage_provision_v1.py").read_text()
    assert "subprocess" not in src
    assert 'os.open("/",' not in src
    assert "os.unlink(" not in src
    assert "os.rmdir(" not in src
    assert "os.chmod(" not in src
    assert '"authorizes_host_installation": False' in src
