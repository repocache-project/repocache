"""Fixture-only native cache cleanup preflight: real inode and adversarial tests."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from repocache import server_repository_cache_cleanup_preview_v1 as preview
from repocache.server_native_repository_cache_v1 import (
    bootstrap_repository_cache_under_root,
)
from repocache.server_native_storage_bootstrap_v1 import (
    bootstrap_native_nginx_storage_under_root,
)

RID = "debian-trixie-main"
DIGEST1 = "0123456789abcdef0123456789abcdef"
DIGEST2 = "fedcba9876543210fedcba9876543210"


@pytest.fixture
def owned(tmp_path):
    root = tmp_path / "detached"
    root.mkdir(mode=0o700)
    for parent in ("var", "var/cache", "var/cache/nginx",
                   "var/log", "var/log/nginx"):
        (root / parent).mkdir(mode=0o700)
    uid, gid = os.geteuid(), os.getegid()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        bootstrap_native_nginx_storage_under_root(
            fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        )
        bootstrap_repository_cache_under_root(
            fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
            repository_id=RID,
        )
        cache = root / "var/cache/nginx/repocache-managed"
        yield fd, uid, gid, cache / RID, cache, root
    finally:
        os.close(fd)


def inspect(owned, rid=RID):
    fd, uid, gid, *_ = owned
    return preview.preview_repository_cache_cleanup_under_root(
        fd, root_uid=uid, cache_uid=uid,
        cache_gid=gid, repository_id=rid,
    )


def populate(owned):
    directory = owned[3] / "a" / "bc"
    directory.mkdir(parents=True, mode=0o700)
    (directory / DIGEST1).write_bytes(b"immutable-cached-package" * 10)
    (directory / DIGEST2).write_bytes(b"some-more-payload")
    return directory


def test_empty_repository_is_observed_but_never_authorized(owned):
    result = inspect(owned)
    assert result["status"] == "FIXTURE_CACHE_CLEANUP_PREVIEW_ONLY"
    assert result["cache_files_observed"] == 0
    assert result["cache_directories_observed"] == 0
    assert result["apparent_file_bytes_observed"] == 0
    assert result["allocated_file_bytes_observed"] == 0
    assert result["bounded_layout_and_marker_observed"] is True
    for key in ("trusted_repository_deletion_approval_verified",
                "nginx_quiescence_verified", "installed_root_provenance_verified",
                "selinux_enforcing_verified", "actual_reclaimable_space_verified",
                "authorizes_cache_cleanup", "authorizes_repository_removal",
                "authorizes_nginx_reload"):
        assert result[key] is False


def test_real_cache_file_counts_size_and_preservation(owned):
    directory = populate(owned)
    files = sorted(directory.iterdir())
    original = [(p.name, p.stat().st_ino, p.read_bytes()) for p in files]
    a = inspect(owned)
    b = inspect(owned)
    assert a == b
    assert a["cache_files_observed"] == 2
    assert a["cache_directories_observed"] == 2
    assert a["apparent_file_bytes_observed"] == sum(
        p.stat().st_size for p in files
    )
    assert a["allocated_file_bytes_observed"] == sum(
        p.stat().st_blocks * 512 for p in files
    )
    assert [(p.name, p.stat().st_ino, p.read_bytes()) for p in files] == original
    assert not a["authorizes_cache_cleanup"]


@pytest.mark.parametrize("untrusted", [
    "ordinary-file", "wrong-hex", "unexpected-topfile", "extra-depth",
    "symlink-leaf", "symlink-dir", "hardlink", "fifo", "world-write-file",
    "world-write-dir",
])
def test_foreign_cache_contents_refused_without_touching_outside(
    owned, tmp_path, untrusted,
):
    directory = populate(owned)
    original = (directory / DIGEST1).read_bytes()
    outside = tmp_path / "outside"
    outside.write_bytes(b"do-not-touch")
    if untrusted == "ordinary-file":
        (directory / "not-a-hash").write_bytes(b"foreign")
    elif untrusted == "wrong-hex":
        (directory / ("g" * 32)).write_bytes(b"foreign")
    elif untrusted == "unexpected-topfile":
        (owned[3] / DIGEST1).write_bytes(b"foreign")
    elif untrusted == "extra-depth":
        (directory / DIGEST1).unlink()
        (directory / DIGEST1).mkdir()
    elif untrusted == "symlink-leaf":
        (directory / DIGEST1).unlink()
        (directory / DIGEST1).symlink_to(outside)
    elif untrusted == "symlink-dir":
        (directory / DIGEST1).unlink()
        (owned[3] / "a" / "bc" / DIGEST2).unlink()
        directory.rmdir()
        directory.symlink_to(tmp_path, target_is_directory=True)
    elif untrusted == "hardlink":
        os.link(directory / DIGEST1, tmp_path / "another-hardlink")
    elif untrusted == "fifo":
        (directory / DIGEST1).unlink()
        os.mkfifo(directory / DIGEST1, 0o600)
    elif untrusted == "world-write-file":
        (directory / DIGEST1).chmod(0o666)
    else:
        directory.chmod(0o777)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="^CACHE_CLEANUP_"):
        inspect(owned)
    assert outside.read_bytes() in (b"do-not-touch", original)


def test_partial_or_forged_repository_owner_marker_refused(owned):
    cache = owned[4]
    marker = cache.parent / (".repocache-repository-" + RID + ".owner-v1")
    original = marker.read_bytes()
    marker.unlink()
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError):
        inspect(owned)
    marker.write_bytes(original)
    marker.chmod(0o644)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError):
        inspect(owned)


def test_preflight_refuses_foreign_or_untracked_repository(owned):
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="CACHE_CLEANUP_REPOSITORY_UNTRACKED"):
        inspect(owned, "almalinux-baseos")


@pytest.mark.parametrize("bad", [None, True, 1, "", ".", "../tmp",
                                  "BAD", "non ascii", "z" * 70])
def test_bad_repo_ids_never_traverse(owned, bad):
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="CACHE_CLEANUP_ARGUMENT_INVALID"):
        inspect(owned, bad)


def test_real_root_fd_is_never_accepted():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                           match="CACHE_CLEANUP_LIVE_ROOT_FORBIDDEN"):
            preview.preview_repository_cache_cleanup_under_root(
                fd, root_uid=0, cache_uid=0, cache_gid=0,
                repository_id=RID,
            )
    finally:
        os.close(fd)


def test_bool_uid_and_bad_fd_denied(owned):
    fd, uid, gid, *_ = owned
    for changes in ({"root_fd": True}, {"root_fd": -1},
                    {"root_uid": True}, {"cache_gid": -1}):
        args = dict(root_fd=fd, root_uid=uid, cache_uid=uid,
                    cache_gid=gid, repository_id=RID)
        args.update(changes)
        with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                           match="CACHE_CLEANUP_ARGUMENT_INVALID"):
            preview.preview_repository_cache_cleanup_under_root(**args)


def test_large_directory_count_is_fail_closed(owned, monkeypatch):
    populate(owned)
    monkeypatch.setattr(preview, "_MAX_ENTRIES", 1)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="CACHE_CLEANUP_ENTRY_LIMIT_EXCEEDED"):
        inspect(owned)


def test_concurrent_cache_mutation_refused_not_claimed(owned, monkeypatch):
    populate(owned)
    original = preview._scan

    def mutating_scan(*args, **kwargs):
        result = original(*args, **kwargs)
        (owned[3] / "foreign").write_bytes(b"concurrent")
        return result

    monkeypatch.setattr(preview, "_scan", mutating_scan)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="CACHE_CLEANUP_"):
        inspect(owned)
    assert (owned[3] / "foreign").read_bytes() == b"concurrent"


def test_preview_has_no_cache_write_delete_or_subprocess_boundary():
    source = (Path(__file__).resolve().parents[1]
              / "src/repocache/server_repository_cache_cleanup_preview_v1.py"
              ).read_text(encoding="utf-8")
    for disallowed in (
        "os.unlink(", "os.remove(", "os.rmdir(", "os.mkdir(",
        "os.chown(", "os.chmod(", "os.rename(", "subprocess",
        "shutil.rmtree", "shell=True",
    ):
        assert disallowed not in source
    assert "authorizes_cache_cleanup" in source
