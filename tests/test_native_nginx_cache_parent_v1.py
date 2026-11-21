"""Fixed native systemd nginx cache parent: owner, no-follow and idempotency.

These exercises use an isolated root FD, never the real /var/cache.
The private fixture accepts the current fixture UID; the actual signed native
installer always uses uid 0 while its durable package lock is held.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from scripts import install_native_root_worker as install
from scripts import stage_native_root_worker as stage


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "var" / "cache").mkdir(parents=True)
    return root


def _verify(root: Path) -> None:
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        install._ensure_fixed_nginx_cache_parent_under_root(fd, owner_uid=os.getuid())
    finally:
        os.close(fd)


def test_native_nginx_cache_parent_is_durable_strict_and_idempotent(tmp_path):
    root = _root(tmp_path)
    cache = root / "var" / "cache" / "nginx"
    _verify(root)
    assert cache.is_dir()
    before = cache.lstat()
    assert (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (
        os.getuid(), os.getgid(), 0o755,
    )
    assert cache.parent.stat().st_uid == os.getuid()
    _verify(root)
    after = cache.lstat()
    assert (after.st_ino, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_ino, before.st_mtime_ns, before.st_ctime_ns
    )


def test_native_nginx_cache_parent_preserves_existing_owned_contents(tmp_path):
    root = _root(tmp_path)
    cache = root / "var" / "cache" / "nginx"
    cache.mkdir(mode=0o755)
    # A strict CI umask must not accidentally turn an otherwise safe
    # existing-owned-directory preservation fixture into mode 0700.
    cache.chmod(0o755)
    record = cache / "foreign-package-cache-not-to-be-deleted"
    record.write_bytes(b"unchanged")
    prior = (cache.stat().st_ino, record.stat().st_ino, record.read_bytes())
    _verify(root)
    assert (cache.stat().st_ino, record.stat().st_ino, record.read_bytes()) == prior


@pytest.mark.parametrize("foreign", ["symlink", "file", "world-writable", "wrong-mode"])
def test_native_nginx_cache_parent_refuses_foreign_leaf_without_mutation(tmp_path, foreign):
    root = _root(tmp_path)
    leaf = root / "var" / "cache" / "nginx"
    if foreign == "symlink":
        leaf.symlink_to(tmp_path, target_is_directory=True)
    elif foreign == "file":
        leaf.write_text("foreign")
    else:
        leaf.mkdir(mode=0o755)
        leaf.chmod(0o777 if foreign == "world-writable" else 0o700)
    info = leaf.lstat()
    with pytest.raises(stage.WorkerStageError, match=r"WORKER_PLACEMENT_NATIVE_CACHE_PARENT_"):
        _verify(root)
    after = leaf.lstat()
    assert (after.st_ino, after.st_mode, after.st_mtime_ns) == (
        info.st_ino, info.st_mode, info.st_mtime_ns,
    )


@pytest.mark.parametrize("unsafe", ["var-symlink", "cache-symlink", "var-writable", "cache-writable"])
def test_native_nginx_cache_parent_refuses_unsafe_ancestor_before_create(tmp_path, unsafe):
    root = _root(tmp_path)
    var = root / "var"
    parent = var / "cache"
    if unsafe == "var-symlink":
        parent.rmdir()
        var.rmdir()
        var.symlink_to(tmp_path, target_is_directory=True)
    elif unsafe == "cache-symlink":
        parent.rmdir()
        parent.symlink_to(tmp_path, target_is_directory=True)
    elif unsafe == "var-writable":
        var.chmod(0o777)
    else:
        parent.chmod(0o777)
    with pytest.raises(stage.WorkerStageError, match=r"WORKER_PLACEMENT_NATIVE_CACHE_PARENT_"):
        _verify(root)
    assert not (tmp_path / "nginx").exists()
    if unsafe not in ("var-symlink", "cache-symlink"):
        assert not (parent / "nginx").exists()
