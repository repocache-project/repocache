"""Native inode-backed per-repository cache retention and refusal regressions."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from repocache.server_native_storage_bootstrap_v1 import (
    bootstrap_native_nginx_storage_under_root,
)
from repocache.server_native_repository_cache_v1 import (
    RepositoryCacheBootstrapError,
    bootstrap_repository_cache_under_root,
)

RID = "debian-trixie-main"


@pytest.fixture
def fixture_root(tmp_path):
    root = tmp_path / "detached"
    root.mkdir(mode=0o700)
    for name in ("var", "var/cache", "var/cache/nginx",
                 "var/log", "var/log/nginx"):
        (root / name).mkdir(mode=0o700)
    owner = os.geteuid()
    group = os.getegid()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        bootstrap_native_nginx_storage_under_root(
            fd, root_uid=owner, cache_uid=owner, cache_gid=group,
        )
        yield root, fd, owner, group
    finally:
        os.close(fd)


def operate(fixture_root, repo=RID, *, fault=None):
    _, fd, owner, group = fixture_root
    return bootstrap_repository_cache_under_root(
        fd, root_uid=owner, cache_uid=owner, cache_gid=group,
        repository_id=repo, inject_fault=fault,
    )


def locations(root: Path, repo=RID):
    parent = root / "var/cache/nginx"
    return (
        parent / "repocache-managed" / repo,
        parent / (".repocache-repository-" + repo + ".owner-v1"),
    )


def test_fresh_and_repeat_preserve_inode_and_actual_cached_packages(fixture_root):
    root, _, _, _ = fixture_root
    first = operate(fixture_root)
    directory, marker = locations(root)
    assert first["status"] == "FIXTURE_REPOSITORY_CACHE_VERIFIED"
    assert first["directory_created"] is True
    assert first["authorizes_cache_cleanup"] is False
    assert not first["trusted_repository_approval_verified"]
    assert marker.stat().st_mode & 0o777 == 0o600
    assert directory.stat().st_mode & 0o777 == 0o700
    record = json.loads(marker.read_bytes())
    assert record["repository_id"] == RID
    assert record["ino"] == directory.stat().st_ino
    prior_inode = directory.stat().st_ino
    nested = directory / "1"
    nested.mkdir()
    cached = nested / "package-payload"
    cached.write_bytes(b"preserve-authenticated-native-cache-bytes")
    second = operate(fixture_root)
    assert second["directory_created"] is False
    assert second["existing_cache_contents_preserved"] is True
    assert directory.stat().st_ino == prior_inode
    assert cached.read_bytes() == b"preserve-authenticated-native-cache-bytes"
    assert not second["authorizes_host_installation"]
    assert not second["signed_nginx_package_identity_verified"]


def test_distinct_repository_directories_and_no_implicit_cleanup(fixture_root):
    root, _, _, _ = fixture_root
    for repo in (RID, "almalinux-baseos", "third-party-operator"):
        assert operate(fixture_root, repo)["directory_created"] is True
    for repo in (RID, "almalinux-baseos", "third-party-operator"):
        directory, marker = locations(root, repo)
        assert directory.is_dir()
        assert marker.is_file()
        assert operate(fixture_root, repo)["directory_created"] is False


@pytest.mark.parametrize("bad", [
    "", ".", "..", "../nginx", "bad/name", "Uppercase", "foo..bar",
    "naïve", "x" * 50, True, 123, None,
])
def test_unsafe_repo_id_refused_before_any_mutation(fixture_root, bad):
    root, _, _, _ = fixture_root
    parent = root / "var/cache/nginx"
    before = sorted(x.name for x in parent.iterdir())
    with pytest.raises(RepositoryCacheBootstrapError,
                       match="^REPOSITORY_CACHE_ARGUMENT_INVALID$"):
        operate(fixture_root, bad)
    assert sorted(x.name for x in parent.iterdir()) == before


def test_foreign_existing_directory_never_adopted_or_cleaned(fixture_root):
    root, _, _, _ = fixture_root
    directory, marker = locations(root)
    directory.mkdir(mode=0o700)
    data = directory / "foreign-cache"
    data.write_bytes(b"private-foreign-bytes")
    with pytest.raises(RepositoryCacheBootstrapError,
                       match="^REPOSITORY_CACHE_PARTIAL_OR_FOREIGN_DIRECTORY$"):
        operate(fixture_root)
    assert data.read_bytes() == b"private-foreign-bytes"
    assert not marker.exists()


def test_foreign_marker_without_directory_refuses_before_creation(fixture_root):
    root, _, _, _ = fixture_root
    directory, marker = locations(root)
    marker.write_bytes(b"foreign")
    marker.chmod(0o600)
    with pytest.raises(RepositoryCacheBootstrapError,
                       match="^REPOSITORY_CACHE_PARTIAL_OR_FOREIGN_DIRECTORY$"):
        operate(fixture_root)
    assert not directory.exists()
    assert marker.read_bytes() == b"foreign"


@pytest.mark.parametrize("attack", [
    "marker-symlink", "directory-symlink", "marker-corrupt",
    "marker-weak-mode", "directory-weak-mode", "marker-misbound",
])
def test_foreign_or_changed_inode_marker_refuses_without_deletion(
    fixture_root, attack,
):
    root, _, _, _ = fixture_root
    operate(fixture_root)
    directory, marker = locations(root)
    preserved = b"independent-retained-cache"
    (directory / "payload").write_bytes(preserved)
    if attack == "marker-symlink":
        marker.unlink()
        marker.symlink_to("/etc/passwd")
    elif attack == "directory-symlink":
        (directory / "payload").unlink()
        directory.rmdir()
        directory.symlink_to("/etc/passwd")
    elif attack == "marker-corrupt":
        marker.write_bytes(b'{"schema":1,"schema":1}')
    elif attack == "marker-weak-mode":
        marker.chmod(0o644)
    elif attack == "directory-weak-mode":
        directory.chmod(0o777)
    else:
        record = json.loads(marker.read_bytes())
        record["repository_id"] = "other-repository"
        marker.write_text(json.dumps(record, sort_keys=True,
                                     separators=(",", ":")), encoding="ascii")
    with pytest.raises(RepositoryCacheBootstrapError):
        operate(fixture_root)
    if attack != "directory-symlink":
        assert (directory / "payload").read_bytes() == preserved
    assert marker.is_symlink() if attack == "marker-symlink" else marker.exists()


@pytest.mark.parametrize("phase", [
    "directory_durable", "ownership_durable",
])
def test_interrupted_bootstrap_leaves_no_false_ownership_proof(
    fixture_root, phase,
):
    root, _, _, _ = fixture_root
    def crash(point):
        if point == phase:
            raise RuntimeError("deliberate interruption")
    with pytest.raises(RuntimeError, match="deliberate interruption"):
        operate(fixture_root, fault=crash)
    directory, marker = locations(root)
    assert directory.exists()
    assert not marker.exists()
    with pytest.raises(RepositoryCacheBootstrapError,
                       match="^REPOSITORY_CACHE_PARTIAL_OR_FOREIGN_DIRECTORY$"):
        operate(fixture_root)
    assert directory.exists()
    assert not marker.exists()


def test_marker_durable_crash_is_replayable_and_non_destructive(fixture_root):
    root, _, _, _ = fixture_root
    def crash(phase):
        if phase == "marker_durable":
            raise RuntimeError("after durable marker")
    with pytest.raises(RuntimeError):
        operate(fixture_root, fault=crash)
    directory, marker = locations(root)
    assert directory.is_dir()
    assert marker.is_file()
    assert operate(fixture_root)["directory_created"] is False


def test_actual_namespace_root_is_forbidden_before_any_write():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(RepositoryCacheBootstrapError,
                           match="^REPOSITORY_CACHE_LIVE_ROOT_FORBIDDEN$"):
            bootstrap_repository_cache_under_root(
                fd, root_uid=0, cache_uid=0, cache_gid=0,
                repository_id=RID,
            )
    finally:
        os.close(fd)


def test_unknown_or_replaced_cache_root_owner_marker_is_not_adopted(fixture_root):
    root, _, _, _ = fixture_root
    cache_parent = root / "var/cache/nginx"
    root_marker = cache_parent / ".repocache-managed.owner-v1"
    before = root_marker.read_bytes()
    root_marker.unlink()
    root_marker.write_bytes(before.replace(b'"kind":"cache"',
                                          b'"kind":"foreign"'))
    root_marker.chmod(0o600)
    with pytest.raises(RepositoryCacheBootstrapError):
        operate(fixture_root)
    directory, marker = locations(root)
    assert not directory.exists()
    assert not marker.exists()
