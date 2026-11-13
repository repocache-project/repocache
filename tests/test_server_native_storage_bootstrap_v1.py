"""Actual Linux FD/fsync owner-marked native cache+log bootstrap regressions (#29)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

from repocache.server_native_storage_bootstrap_v1 import (
    NativeStorageBootstrapError, bootstrap_native_nginx_storage_under_root,
)

MARKER = ".repocache-managed.owner-v1"
LEAF = "repocache-managed"


@pytest.fixture
def storage_root(tmp_path):
    root = tmp_path / "isolated"
    root.mkdir(mode=0o700)
    for rel in ("var", "var/cache", "var/cache/nginx",
                "var/log", "var/log/nginx"):
        (root / rel).mkdir(mode=0o755)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd, root, os.geteuid(), os.getegid()
    finally:
        os.close(fd)


def provision(item, **kwargs):
    fd, _, uid, gid = item
    return bootstrap_native_nginx_storage_under_root(
        fd, root_uid=uid, cache_uid=uid, cache_gid=gid, **kwargs,
    )


def paths(root):
    return (root / "var/cache/nginx" / LEAF,
            root / "var/log/nginx" / LEAF)


def test_new_roots_are_real_durable_and_marked_outside_worker_tree(storage_root):
    fd, root, uid, gid = storage_root
    result = provision(storage_root)
    assert result["status"] == "FIXED_NATIVE_STORAGE_FIXTURE_VERIFIED"
    assert result["cache_directory_created"] is True
    assert result["log_directory_created"] is True
    for key in result:
        if key.startswith("authorizes_") or key.endswith("_verified"):
            assert result[key] is False
    cache, logs = paths(root)
    for name, directory, mode, owner, group in (
        ("cache", cache, 0o700, uid, gid),
        ("log", logs, 0o750, uid, gid),
    ):
        info = directory.stat()
        assert info.st_uid == owner and info.st_gid == group
        assert stat.S_IMODE(info.st_mode) == mode
        marker = directory.parent / MARKER
        mark = marker.stat()
        assert mark.st_uid == uid and mark.st_nlink == 1
        assert stat.S_IMODE(mark.st_mode) == 0o600
        assert not (directory / MARKER).exists()
        recorded = json.loads(marker.read_bytes())
        assert recorded == {
            "schema": 1, "kind": name,
            "dev": info.st_dev, "ino": info.st_ino,
            "uid": owner, "gid": group, "mode": mode,
        }
    assert sorted(x.name for x in (root / "var/cache/nginx").iterdir()) == [
        MARKER, LEAF,
    ]
    assert sorted(x.name for x in (root / "var/log/nginx").iterdir()) == [
        MARKER, LEAF,
    ]


def test_repeat_preserves_cache_and_historical_log_bytes(storage_root):
    fd, root, _, _ = storage_root
    provision(storage_root)
    cache, logs = paths(root)
    cached = cache / "foreign-immutable-package.deb"
    historical = logs / "existing-metrics.jsonl"
    cached.write_bytes(b"persisted-cache-package")
    historical.write_bytes(b"no private payloads")
    snapshot = (cached.stat().st_ino, historical.stat().st_ino)
    for _ in range(3):
        report = provision(storage_root)
        assert not report["cache_directory_created"]
        assert not report["log_directory_created"]
        assert report["existing_cache_contents_preserved"]
        assert report["existing_log_contents_preserved"]
        assert cached.read_bytes() == b"persisted-cache-package"
        assert historical.read_bytes() == b"no private payloads"
        assert (cached.stat().st_ino, historical.stat().st_ino) == snapshot


@pytest.mark.parametrize("point", [
    "cache_directory_durable", "cache_ownership_durable",
    "log_directory_durable", "log_ownership_durable",
])
def test_interrupted_creation_refuses_unmarked_partial_reentry(
    storage_root, point,
):
    def power_loss(name):
        if name == point:
            raise RuntimeError("simulated power loss")
    with pytest.raises(RuntimeError, match="simulated power loss"):
        provision(storage_root, inject_fault=power_loss)
    with pytest.raises(NativeStorageBootstrapError):
        provision(storage_root)


def test_completed_durable_marker_then_interruption_can_resume(storage_root):
    def crash(name):
        if name == "cache_marker_durable":
            raise RuntimeError("crash after durable owner mark")
    with pytest.raises(RuntimeError, match="crash after durable owner mark"):
        provision(storage_root, inject_fault=crash)
    fd, root, _, _ = storage_root
    cache, _ = paths(root)
    cached = cache / "unrelated.package"
    cached.write_bytes(b"keep")
    report = provision(storage_root)
    assert report["cache_directory_created"] is False
    assert report["log_directory_created"] is True
    assert cached.read_bytes() == b"keep"


@pytest.mark.parametrize("which", ["cache", "log"])
def test_preexisting_unmarked_root_is_not_silently_adopted(storage_root, which):
    fd, root, _, _ = storage_root
    cache, logs = paths(root)
    parent = cache if which == "cache" else logs
    parent.mkdir(mode=0o700)
    foreign = parent / "operator.data"
    foreign.write_bytes(b"preserve")
    with pytest.raises(NativeStorageBootstrapError,
                       match="NATIVE_STORAGE_PARTIAL_OR_FOREIGN_ROOT"):
        provision(storage_root)
    assert foreign.read_bytes() == b"preserve"


@pytest.mark.parametrize("which", ["cache", "log"])
def test_existing_owner_marker_missing_or_modified_is_refused(storage_root, which):
    fd, root, _, _ = storage_root
    provision(storage_root)
    cache, logs = paths(root)
    parent = cache.parent if which == "cache" else logs.parent
    marker = parent / MARKER
    marker.write_bytes(b'{"schema":1}')
    with pytest.raises(NativeStorageBootstrapError):
        provision(storage_root)
    assert marker.read_bytes() == b'{"schema":1}'


@pytest.mark.parametrize("which", ["cache", "log"])
def test_hardlinked_marker_and_symlink_leaf_fail_closed(storage_root, which):
    fd, root, _, _ = storage_root
    provision(storage_root)
    cache, logs = paths(root)
    leaf = cache if which == "cache" else logs
    marker = leaf.parent / MARKER
    foreign = leaf.parent / "linked-foreign"
    os.link(marker, foreign)
    with pytest.raises(NativeStorageBootstrapError):
        provision(storage_root)
    foreign.unlink()
    leaf.rmdir()
    leaf.symlink_to(root, target_is_directory=True)
    with pytest.raises(NativeStorageBootstrapError):
        provision(storage_root)
    assert marker.is_file()


def test_invalid_mode_and_parent_symlink_refused(storage_root):
    fd, root, _, _ = storage_root
    provision(storage_root)
    cache, _ = paths(root)
    cache.chmod(0o777)
    with pytest.raises(NativeStorageBootstrapError):
        provision(storage_root)
    cache.chmod(0o700)
    nginx = root / "var/cache/nginx"
    marker = nginx / MARKER
    cache.rmdir()
    marker.unlink()
    nginx.rmdir()
    nginx.symlink_to(root, target_is_directory=True)
    with pytest.raises(NativeStorageBootstrapError):
        provision(storage_root)


def test_unknown_xattrs_are_refused_not_dropped(storage_root):
    fd, root, _, _ = storage_root
    provision(storage_root)
    cache, _ = paths(root)
    try:
        os.setxattr(cache, "user.unreviewed", b"foreign")
    except OSError:
        pytest.skip("fixture filesystem lacks user xattr")
    with pytest.raises(NativeStorageBootstrapError,
                       match="NATIVE_STORAGE_XATTR_OR_SELINUX_UNVERIFIED"):
        provision(storage_root)
    assert os.getxattr(cache, "user.unreviewed") == b"foreign"


@pytest.mark.parametrize("invalid", [
    {"root_uid": -1}, {"cache_uid": True}, {"cache_gid": 2**40},
    {"cache_uid": "www-data"}, {"inject_fault": object()},
])
def test_invalid_uid_arguments_refused_before_writes(storage_root, invalid):
    fd, root, uid, gid = storage_root
    opts = {"root_uid": uid, "cache_uid": uid, "cache_gid": gid}
    opts.update(invalid)
    with pytest.raises(NativeStorageBootstrapError,
                       match="NATIVE_STORAGE_ARGUMENT_INVALID"):
        bootstrap_native_nginx_storage_under_root(fd, **opts)
    assert not paths(root)[0].exists()


def test_true_live_namespace_root_is_never_writable_via_fixture_api():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(NativeStorageBootstrapError,
                           match="NATIVE_STORAGE_LIVE_ROOT_FORBIDDEN"):
            bootstrap_native_nginx_storage_under_root(
                fd, root_uid=os.geteuid(), cache_uid=os.geteuid(),
                cache_gid=os.getegid(),
            )
    finally:
        os.close(fd)


def test_no_public_installer_or_arbitrary_target_arguments():
    source = (Path(__file__).resolve().parents[1]
              / "src/repocache/server_native_storage_bootstrap_v1.py").read_text()
    assert '("var", "cache", "nginx")' in source
    assert '("var", "log", "nginx")' in source
    for forbidden in ("subprocess", "systemctl", "apt-get", "dnf install",
                      "rmtree(", "shutil.rmtree", 'os.open("/",'):
        assert forbidden not in source



def test_foreign_log_root_never_creates_other_cache_root(storage_root):
    fd, root, _, _ = storage_root
    cache, logs = paths(root)
    logs.mkdir(mode=0o750)
    foreign = logs / "unrelated-operator-log"
    foreign.write_bytes(b"preserve-owned-log")
    before = (foreign.stat().st_ino, foreign.read_bytes())
    with pytest.raises(
        NativeStorageBootstrapError, match="NATIVE_STORAGE_PARTIAL_OR_FOREIGN_ROOT",
    ):
        provision(storage_root)
    assert not cache.exists()
    assert not (cache.parent / MARKER).exists()
    assert (foreign.stat().st_ino, foreign.read_bytes()) == before


@pytest.mark.parametrize("corruption", ["invalid-json", "wrong-uid", "symlink"])
def test_preexisting_untrusted_log_marker_refuses_before_cache_creation(
    storage_root, corruption,
):
    fd, root, uid, gid = storage_root
    cache, logs = paths(root)
    logs.mkdir(mode=0o750)
    info = logs.stat()
    marker = logs.parent / MARKER
    recorded = {
        "schema": 1, "kind": "log",
        "dev": info.st_dev, "ino": info.st_ino,
        "uid": uid, "gid": gid, "mode": 0o750,
    }
    marker.write_text(json.dumps(recorded, sort_keys=True, separators=(",", ":")),
                      encoding="ascii")
    marker.chmod(0o600)
    if corruption == "invalid-json":
        marker.write_bytes(b"unexpected prior ownership")
    elif corruption == "wrong-uid":
        recorded["uid"] = uid + 1
        marker.write_text(json.dumps(recorded, sort_keys=True, separators=(",", ":")),
                          encoding="ascii")
    else:
        marker.unlink()
        marker.symlink_to(root / "foreign-marker")
    original = marker.lstat()
    with pytest.raises(NativeStorageBootstrapError):
        provision(storage_root)
    assert not cache.exists()
    assert not (cache.parent / MARKER).exists()
    assert marker.lstat().st_ino == original.st_ino


def test_existing_cache_bytes_untouched_when_log_marker_becomes_foreign(storage_root):
    fd, root, uid, gid = storage_root
    provision(storage_root)
    cache, logs = paths(root)
    retained = cache / "retain-original-artifact.rpm"
    retained.write_bytes(b"trusted-retained-fixture")
    before = (retained.stat().st_ino, retained.read_bytes())
    (logs.parent / MARKER).write_bytes(b"foreign")
    with pytest.raises(NativeStorageBootstrapError):
        provision(storage_root)
    assert (retained.stat().st_ino, retained.read_bytes()) == before
    assert logs.exists()
    assert cache.exists()
