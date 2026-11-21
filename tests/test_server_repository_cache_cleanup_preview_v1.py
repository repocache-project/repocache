"""Fixture-only native cache cleanup preflight: real inode and adversarial tests."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
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
from repocache.server_proposed_state_v2_store import (
    V2_JOURNAL, V2_STATE,
    _commit_proposed_v2_under_root as commit_v2,
)
from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_repository_v2_transition_v1 import plan_repository_v2_transition
from repocache.server_protected_state_store_v1 import LOCK_NAME, _locked

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

@pytest.mark.parametrize("kind", ["fifo", "symlink", "world-write", "directory"])
def test_untrusted_leaf_is_refused_before_any_file_open(owned, tmp_path,
                                                         monkeypatch, kind):
    """A special cache leaf must never be opened even with O_NONBLOCK."""
    target = populate(owned) / DIGEST1
    external = tmp_path / "external"
    external.write_bytes(b"foreign-private-payload")
    target.unlink()
    if kind == "fifo":
        os.mkfifo(target, mode=0o600)
    elif kind == "symlink":
        target.symlink_to(external)
    elif kind == "world-write":
        target.write_bytes(b"unsafe")
        target.chmod(0o666)
    else:
        target.mkdir(mode=0o700)

    original_open = preview.os.open
    attempted = []

    def observe_open(path, flags, *args, **kwargs):
        if path == DIGEST1:
            attempted.append(flags)
            pytest.fail("untrusted leaf reached os.open before stat refusal")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(preview.os, "open", observe_open)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="CACHE_CLEANUP_CONTENT_UNTRUSTED"):
        inspect(owned)
    assert attempted == []
    assert external.read_bytes() == b"foreign-private-payload"


def test_untrusted_directory_is_refused_before_open(owned, tmp_path,
                                                     monkeypatch):
    populate(owned)
    first = owned[3] / "a"
    foreign = tmp_path / "foreign-directory"
    foreign.mkdir()
    # Replace a known cache directory with a symlink, preserving foreign
    # contents and ensuring the descriptor scanner never dereferences it.
    (first / "bc" / DIGEST1).unlink()
    (first / "bc" / DIGEST2).unlink()
    (first / "bc").rmdir()
    first.rmdir()
    first.symlink_to(foreign, target_is_directory=True)

    original = preview.os.open

    def deny_bad_directory_open(name, flags, *args, **kwargs):
        if name == "a":
            pytest.fail("foreign cache directory reached os.open")
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(preview.os, "open", deny_bad_directory_open)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="CACHE_CLEANUP_CONTENT_UNTRUSTED"):
        inspect(owned)


def _canonical_state_bytes(payload):
    return json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")


def _initial_cache_v2_state():
    source = Path(__file__).resolve().parents[1] / (
        "docs/examples/server-install-v1.json"
    )
    config = json.loads(source.read_text(encoding="utf-8"))
    config["expected_state_generation"] = 1
    config["repositories"][1]["id"] = "almalinux-baseos"
    raw = _canonical_state_bytes(config)
    digest = hashlib.sha256(raw).hexdigest()
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
        "configuration_base64": base64.b64encode(raw).decode("ascii"),
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
def owned_with_locked_state(owned):
    fd, uid, gid, cache_root, cache, root = owned
    for segment in (
        "var/lib", "var/lib/repocache", "var/lib/repocache/server",
    ):
        (root / segment).mkdir(mode=0o700)
    lock = root / "var/lib/repocache/server" / LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o600)
    initial = _initial_cache_v2_state()
    initial_report = commit_v2(fd, initial, owner_uid=uid, expected_generation=0)
    assert initial_report["state_generation"] == 1
    state_file = root / "var/lib/repocache/server" / V2_STATE
    return owned, initial, state_file


def _locked_cleanup_preview(owned_with_state, *, generation, digest,
                            rid=RID):
    layout, _, _ = owned_with_state
    fd, uid, gid, *_ = layout
    return preview.preview_locked_retired_repository_cache_cleanup_under_root(
        fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        repository_id=rid,
        expected_state_generation=generation,
        expected_state_sha256=digest,
    )


def _retire_owned_repo(owned_with_state):
    layout, initial, state_file = owned_with_state
    fd, uid, _, *_ = layout
    original = state_file.read_bytes()
    next_plan = plan_repository_v2_transition(
        initial, expected_generation=1,
        expected_previous_state_sha256=hashlib.sha256(original).hexdigest(),
        operation="remove", repository_id=RID,
        decision_sha256="b" * 64,
    )
    next_state = next_plan["proposed_snapshot"]
    assert next_state["state_generation"] == 2
    report = commit_v2(fd, next_state, owner_uid=uid, expected_generation=1)
    assert report["state_generation"] == 2
    return hashlib.sha256(state_file.read_bytes()).hexdigest()


def test_locked_cleanup_preflight_refuses_allocated_repository_before_cache_scan(
    owned_with_locked_state, monkeypatch,
):
    owned, _, state_file = owned_with_locked_state
    digest = hashlib.sha256(state_file.read_bytes()).hexdigest()
    def forbidden(*_args, **_kwargs):
        raise AssertionError("active repository must never reach cache scan")
    monkeypatch.setattr(preview, "preview_repository_cache_cleanup_under_root",
                        forbidden)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="LOCKED_REPOSITORY_NOT_RETIRED"):
        _locked_cleanup_preview(
            owned_with_locked_state, generation=1, digest=digest,
        )


def test_locked_retired_cache_preflight_checks_persisted_ledger_and_cache(
    owned_with_locked_state,
):
    layout, initial, state_file = owned_with_locked_state
    original = populate(layout)
    cache_file = original / DIGEST1
    before = (cache_file.read_bytes(), cache_file.stat().st_ino)
    digest = _retire_owned_repo(owned_with_locked_state)
    report = _locked_cleanup_preview(
        owned_with_locked_state, generation=2, digest=digest,
    )
    assert report["status"] == "LOCKED_RETIRED_CACHE_PREVIEW_ONLY"
    assert report["repository_id"] == RID
    assert report["state_generation"] == 2
    assert report["protected_state_sha256"] == digest
    assert report["fixture_retirement_and_cache_correspondence_observed"] is True
    assert report["state_lock_held_during_inspection"] is True
    assert report["state_lock_still_held_after_return"] is False
    assert report["cache_files_observed"] == 2
    assert report["cache_directories_observed"] == 2
    assert report["apparent_file_bytes_observed"] > 0
    for flag in (
        "trusted_repository_deletion_approval_verified",
        "nginx_quiescence_verified", "installed_root_provenance_verified",
        "installed_nginx_quiescence_verified",
        "signed_operator_force_cleanup_verified",
        "authorizes_cache_cleanup", "authorizes_repository_removal",
        "authorizes_nginx_reload",
    ):
        assert report[flag] is False
    assert (cache_file.read_bytes(), cache_file.stat().st_ino) == before
    assert state_file.is_file()
    # The other active DNF state remains present, with no implicit cleanup.
    assert [r["id"] for r in initial["repository_records"]] == [
        "debian-trixie-main", "almalinux-baseos"
    ]


def test_locked_retired_cache_preflight_refuses_stale_digest_or_generation(
    owned_with_locked_state,
):
    _retire_owned_repo(owned_with_locked_state)
    _, _, state_file = owned_with_locked_state
    digest = hashlib.sha256(state_file.read_bytes()).hexdigest()
    for generation, claimed in (
        (1, digest), (2, "0" * 64), (3, digest),
    ):
        with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                           match="LOCKED_STATE_CHANGED"):
            _locked_cleanup_preview(
                owned_with_locked_state, generation=generation,
                digest=claimed,
            )
    for rid in ("almalinux-baseos", "unknown-repo"):
        with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                           match="LOCKED_REPOSITORY_NOT_RETIRED"):
            _locked_cleanup_preview(
                owned_with_locked_state, generation=2,
                digest=digest, rid=rid,
            )
    assert state_file.is_file()


def test_locked_retired_cleanup_refuses_pending_state_wal_without_scanning(
    owned_with_locked_state,
):
    _retire_owned_repo(owned_with_locked_state)
    layout, _, state_file = owned_with_locked_state
    digest = hashlib.sha256(state_file.read_bytes()).hexdigest()
    pending = state_file.with_name(V2_JOURNAL)
    pending.write_bytes(b'not-a-clean-recovery-journal')
    pending.chmod(0o600)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="LOCKED_RECOVERY_REQUIRED"):
        _locked_cleanup_preview(
            owned_with_locked_state, generation=2, digest=digest,
        )
    assert pending.read_bytes() == b'not-a-clean-recovery-journal'


def test_locked_retired_cleanup_unsafe_cache_objects_and_lock_contention(
    owned_with_locked_state, tmp_path,
):
    layout, _, state_file = owned_with_locked_state
    digest = _retire_owned_repo(owned_with_locked_state)
    _, uid, _, directory, *_ = layout
    external = tmp_path / "foreign"
    external.write_bytes(b"foreign-immutable")
    (directory / "a").mkdir(mode=0o700)
    (directory / "a" / "bc").mkdir(mode=0o700)
    (directory / "a" / "bc" / DIGEST1).symlink_to(external)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError):
        _locked_cleanup_preview(
            owned_with_locked_state, generation=2, digest=digest,
        )
    assert external.read_bytes() == b"foreign-immutable"
    (directory / "a" / "bc" / DIGEST1).unlink()

    with _locked(layout[0], uid):
        with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                           match="LOCKED_PROTECTED_UNVERIFIED"):
            _locked_cleanup_preview(
                owned_with_locked_state, generation=2, digest=digest,
            )
    assert state_file.is_file()
