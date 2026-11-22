"""Native inode-backed per-repository cache retention and refusal regressions."""
from __future__ import annotations

import base64
import hashlib
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
    preview_locked_active_repository_cache_roots_under_root,
)
from repocache.server_fixture_multi_resource_wal_v1 import (
    _commit_fixture_multi_resource_under_root as commit_multi,
    JOURNAL_TMP,
)
from repocache.server_proposed_state_v2_store import V2_STATE
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_repository_v2_transition_v1 import (
    plan_repository_v2_transition,
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


def _v2_fixture_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _v2_state_fixture():
    sample = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
    from repocache.server_install_v1 import validate_install_document
    config = json.loads(sample.read_text(encoding="utf-8"))
    config["repositories"][1]["id"] = "almalinux-baseos"
    config["expected_state_generation"] = 1
    config = validate_install_document(config, for_apply=True)
    content = _v2_fixture_bytes(config)
    digest = hashlib.sha256(content).hexdigest()
    records = [{
        "id": repo["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(repo).encode("utf-8"),
        ).hexdigest(),
        "desired_state": repo["desired_state"],
        "observed_state": "not-activated",
    } for repo in config["repositories"]]
    return {
        "state_schema_version": 2,
        "state_generation": 1,
        "configuration_base64": base64.b64encode(content).decode("ascii"),
        "configuration_sha256": digest,
        "repository_records": records,
        "id_reservations": [{
            "id": row["id"],
            "canonical_identity_sha256": row["canonical_identity_sha256"],
            "status": "allocated",
        } for row in records],
        "approval_reference": {
            "source": "operator",
            "decision_sha256": "a" * 64,
            "configuration_sha256": digest,
            "expected_generation": 0,
        },
    }


@pytest.fixture
def active_cache_state(fixture_root):
    root, fd, uid, gid = fixture_root
    for path in ("var/lib", "var/lib/repocache", "var/lib/repocache/server"):
        (root / path).mkdir(mode=0o700)
    target = root / "var/lib/repocache/server"
    lock = target / LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o600)
    initial = _v2_state_fixture()
    result = commit_multi(
        fd, initial, owner_uid=uid, expected_generation=0,
        include_bytes=b"# no active fixture routes\n",
        catalog_bytes=_v2_fixture_bytes({
            "schema_version": 1,
            "status": "fixture-only-observed-candidate",
            "active_ids": [],
        }),
    )
    assert result["state_generation"] == 1
    return fixture_root, initial, target


def _v2_active_preview(active_cache_state, *, generation=None, digest=None):
    (root, fd, uid, gid), state, target = active_cache_state
    if generation is None:
        generation = state["state_generation"]
    if digest is None:
        digest = hashlib.sha256((target / V2_STATE).read_bytes()).hexdigest()
    return preview_locked_active_repository_cache_roots_under_root(
        fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        expected_state_generation=generation,
        expected_state_sha256=digest,
    )


def _next_active_v2(active_cache_state, *, generation, operation, rid=RID):
    fixture, previous, target = active_cache_state
    _, fd, uid, gid = fixture
    previous_digest = hashlib.sha256((target / V2_STATE).read_bytes()).hexdigest()
    plan = plan_repository_v2_transition(
        previous, expected_generation=generation,
        expected_previous_state_sha256=previous_digest,
        operation=operation, repository_id=rid,
        decision_sha256="b" * 64,
    )
    next_state = plan["proposed_snapshot"]
    active_ids = sorted(x["id"] for x in next_state["repository_records"]
                        if x["desired_state"] == "active")
    result = commit_multi(
        fd, next_state, owner_uid=uid,
        expected_generation=generation,
        expected_previous_state_sha256=previous_digest,
        include_bytes=("# fixture generation " + str(generation + 1) + "\n").encode(),
        catalog_bytes=_v2_fixture_bytes({
            "schema_version": 1,
            "status": "fixture-only-observed-candidate",
            "active_ids": active_ids,
        }),
    )
    assert result["state_generation"] == generation + 1
    return fixture, next_state, target


def test_locked_active_cache_roots_refuse_missing_marker_before_exposure(
    active_cache_state,
):
    original = _v2_active_preview(active_cache_state)
    assert original["active_repository_count"] == 0
    fixture, state, target = _next_active_v2(
        active_cache_state, generation=1, operation="enable",
    )
    current = (fixture, state, target)
    with pytest.raises(RepositoryCacheBootstrapError,
                       match="ACTIVE_REPOSITORY_CACHE_UNOWNED"):
        _v2_active_preview(current)
    assert operate(fixture)["directory_created"] is True
    verified = _v2_active_preview(current)
    assert verified["status"] == "FIXTURE_ACTIVE_REPOSITORY_CACHE_ROOTS_ONLY"
    assert verified["state_generation"] == 2
    assert verified["desired_active_repository_ids"] == [RID]
    assert verified["active_repository_count"] == 1
    assert verified["all_active_cache_root_markers_verified"] is True
    assert verified["complete_fixture_state_and_catalog_owned"] is True
    for k,v in verified.items():
        if k.startswith("authorizes_") or k.endswith("_verified") and (
            k not in ("all_active_cache_root_markers_verified",)
        ):
            assert v is False


def test_locked_active_cache_refuses_second_missing_repository_then_recovers(
    active_cache_state,
):
    fixture, previous, target = _next_active_v2(
        active_cache_state, generation=1, operation="enable",
    )
    first = (fixture, previous, target)
    operate(fixture)
    second_fixture, second_state, second_target = _next_active_v2(
        first, generation=2, operation="enable", rid="almalinux-baseos",
    )
    together = (second_fixture, second_state, second_target)
    with pytest.raises(RepositoryCacheBootstrapError,
                       match="ACTIVE_REPOSITORY_CACHE_UNOWNED"):
        _v2_active_preview(together)
    assert operate(fixture, "almalinux-baseos")["directory_created"]
    report = _v2_active_preview(together)
    assert report["desired_active_repository_ids"] == [
        "almalinux-baseos", RID,
    ]


def test_locked_active_cache_default_removal_leaves_cache_inode_and_bytes(
    active_cache_state,
):
    fixture, enabled, target = _next_active_v2(
        active_cache_state, generation=1, operation="enable",
    )
    active = (fixture, enabled, target)
    operate(fixture)
    directory, marker = locations(fixture[0])
    cached = directory / "package-payload"
    cached.write_bytes(b"retained-signed-artifact")
    before = cached.stat().st_ino
    assert _v2_active_preview(active)["active_repository_count"] == 1
    _, disabled, target = _next_active_v2(
        active, generation=2, operation="disable",
    )
    _, removed, target = _next_active_v2(
        (fixture, disabled, target), generation=3, operation="remove",
    )
    report = _v2_active_preview((fixture, removed, target))
    assert report["desired_active_repository_ids"] == []
    assert report["active_repository_count"] == 0
    assert cached.read_bytes() == b"retained-signed-artifact"
    assert cached.stat().st_ino == before
    assert marker.is_file()


def test_active_cache_owner_marker_and_symlink_refused_without_mutation(
    active_cache_state, tmp_path,
):
    fixture, state, target = _next_active_v2(
        active_cache_state, generation=1, operation="enable",
    )
    current = (fixture, state, target)
    operate(fixture)
    directory, marker = locations(fixture[0])
    marker.write_bytes(b"forged-owner")
    with pytest.raises(RepositoryCacheBootstrapError):
        _v2_active_preview(current)
    assert directory.is_dir()

    # An attacker cannot substitute a different cache directory via symlink.
    # The root-level marker is now deliberately untrusted; that never
    # authorizes adopt/delete of the symlink or of a foreign target.
    outside = tmp_path / "unrelated"
    outside.mkdir()
    directory.rename(directory.with_name("original-cache"))
    directory.symlink_to(outside)
    with pytest.raises(RepositoryCacheBootstrapError):
        _v2_active_preview(current)
    assert outside.is_dir()


def test_active_cache_cas_and_pending_multi_journal_refused(active_cache_state):
    fixture, state, target = _next_active_v2(
        active_cache_state, generation=1, operation="enable",
    )
    operate(fixture)
    current = (fixture, state, target)
    with pytest.raises(RepositoryCacheBootstrapError, match="ACTIVE_STATE_CHANGED"):
        _v2_active_preview(current, digest="0" * 64)
    with pytest.raises(RepositoryCacheBootstrapError, match="ACTIVE_STATE_CHANGED"):
        _v2_active_preview(current, generation=1)
    wal_tmp = target / JOURNAL_TMP
    wal_tmp.write_bytes(b"unpublished-multi-WAL")
    wal_tmp.chmod(0o600)
    with pytest.raises(RepositoryCacheBootstrapError,
                       match="ACTIVE_OWNERSHIP_UNVERIFIED"):
        _v2_active_preview(current)
    assert wal_tmp.read_bytes() == b"unpublished-multi-WAL"


def test_active_cache_live_root_refused_before_state_lock(monkeypatch):
    from repocache import server_native_repository_cache_v1 as module
    def forbidden(*_args, **_kwargs):
        raise AssertionError("no state lock on installed host")
    monkeypatch.setattr(module, "_locked", forbidden)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(RepositoryCacheBootstrapError,
                           match="ACTIVE_LIVE_ROOT_REFUSED"):
            preview_locked_active_repository_cache_roots_under_root(
                fd, root_uid=os.geteuid(), cache_uid=os.geteuid(),
                cache_gid=os.getegid(), expected_state_generation=1,
                expected_state_sha256="a" * 64,
            )
    finally:
        os.close(fd)


def test_active_cache_does_not_write_reconfigure_or_delete( monkeypatch,
    active_cache_state,
):
    import socket
    import subprocess
    fixture, state, target = _next_active_v2(
        active_cache_state, generation=1, operation="enable",
    )
    operate(fixture)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("active cache inspection is read-only")
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(os, "unlink", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert _v2_active_preview((fixture, state, target))[
        "all_active_cache_root_markers_verified"
    ] is True
