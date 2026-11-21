"""Fixture-only native cache cleanup preflight: real inode and adversarial tests."""
from __future__ import annotations

import base64
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
from repocache.server_fixture_multi_resource_wal_v1 import (
    MANIFEST as MULTI_MANIFEST,
    JOURNAL_TMP as MULTI_PENDING_TMP,
    _commit_fixture_multi_resource_under_root as commit_multi,
)
from repocache.server_proposed_state_v2_store import (
    V2_JOURNAL, V2_JOURNAL_TMP, V2_STATE,
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
    # An unpublished temporary WAL marker is a genuine pending-recovery
    # interlock without any parsed published journal body.
    pending = state_file.with_name(V2_JOURNAL_TMP)
    pending.write_bytes(b'not-a-clean-recovery-journal')
    pending.chmod(0o600)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="LOCKED_RECOVERY_REQUIRED"):
        _locked_cleanup_preview(
            owned_with_locked_state, generation=2, digest=digest,
        )
    assert pending.read_bytes() == b'not-a-clean-recovery-journal'
    pending.unlink()
    # A malformed *published* WAL cannot be trusted enough to classify its
    # contents as an ordinary pending transaction, but still fails closed
    # without touching the cached data.
    corrupted = state_file.with_name(V2_JOURNAL)
    corrupted.write_bytes(b'not-a-canonical-journal')
    corrupted.chmod(0o600)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="LOCKED_PROTECTED_UNVERIFIED"):
        _locked_cleanup_preview(
            owned_with_locked_state, generation=2, digest=digest,
        )
    assert corrupted.read_bytes() == b'not-a-canonical-journal'


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


def test_locked_retired_preview_accepts_completed_multi_resource_owner(owned):
    """Join the already-integrated #410 WAL with the real owned cache."""
    fd, uid, gid, directory, cache_root, root = owned
    for segment in ("var/lib", "var/lib/repocache", "var/lib/repocache/server"):
        (root / segment).mkdir(mode=0o700)
    lock = root / "var/lib/repocache/server" / LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o600)
    state_file = root / "var/lib/repocache/server" / V2_STATE
    initial = _initial_cache_v2_state()
    catalog = _canonical_state_bytes({
        "schema_version": 1,
        "status": "fixture-only-observed-candidate",
        "active_ids": [],
    })
    first = commit_multi(
        fd, initial, owner_uid=uid, expected_generation=0,
        include_bytes=b"# fixed fixture include: generation 1\n",
        catalog_bytes=catalog,
    )
    assert first["state_generation"] == 1

    previous = state_file.read_bytes()
    plan = plan_repository_v2_transition(
        initial, expected_generation=1,
        expected_previous_state_sha256=hashlib.sha256(previous).hexdigest(),
        operation="remove", repository_id=RID,
        decision_sha256="b" * 64,
    )
    committed = commit_multi(
        fd, plan["proposed_snapshot"], owner_uid=uid,
        expected_generation=1,
        include_bytes=b"# fixed fixture include: generation 2\n",
        catalog_bytes=catalog,
    )
    assert committed["state_generation"] == 2

    cached = directory / "a" / "bc"
    cached.mkdir(parents=True, mode=0o700)
    package = cached / DIGEST1
    package.write_bytes(b"intact-retired-cache")
    observed = (package.stat().st_ino, package.read_bytes())
    digest = hashlib.sha256(state_file.read_bytes()).hexdigest()
    result = preview.preview_locked_retired_repository_cache_cleanup_under_root(
        fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        repository_id=RID, expected_state_generation=2,
        expected_state_sha256=digest,
    )
    assert result["status"] == "LOCKED_RETIRED_CACHE_PREVIEW_ONLY"
    assert result["cache_files_observed"] == 1
    assert result["state_lock_held_during_inspection"] is True
    assert result["authorizes_cache_cleanup"] is False
    assert (package.stat().st_ino, package.read_bytes()) == observed

    # A tampered committed multi-resource manifest must not be mistaken for
    # a clean state-only fixture. The cache and report stay inert.
    marker = state_file.with_name(MULTI_MANIFEST)
    marker.write_bytes(b"tampered")
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="LOCKED_PROTECTED_UNVERIFIED"):
        preview.preview_locked_retired_repository_cache_cleanup_under_root(
            fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
            repository_id=RID, expected_state_generation=2,
            expected_state_sha256=digest,
        )
    assert (package.stat().st_ino, package.read_bytes()) == observed


def test_locked_retired_preview_refuses_multi_resource_pending_marker(owned):
    fd, uid, gid, directory, cache_root, root = owned
    for segment in ("var/lib", "var/lib/repocache", "var/lib/repocache/server"):
        (root / segment).mkdir(mode=0o700)
    lock = root / "var/lib/repocache/server" / LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o600)
    initial = _initial_cache_v2_state()
    catalog = _canonical_state_bytes({
        "schema_version": 1,
        "status": "fixture-only-observed-candidate",
        "active_ids": [],
    })
    commit_multi(
        fd, initial, owner_uid=uid, expected_generation=0,
        include_bytes=b"# fixed fixture include\n",
        catalog_bytes=catalog,
    )
    state_file = root / "var/lib/repocache/server" / V2_STATE
    pending = state_file.with_name(MULTI_PENDING_TMP)
    pending.write_bytes(b"interrupted-unpublished-multi-resource")
    pending.chmod(0o600)
    with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                       match="LOCKED_PROTECTED_UNVERIFIED"):
        preview.preview_locked_retired_repository_cache_cleanup_under_root(
            fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
            repository_id=RID, expected_state_generation=1,
            expected_state_sha256=hashlib.sha256(
                state_file.read_bytes()
            ).hexdigest(),
        )
    assert pending.read_bytes() == b"interrupted-unpublished-multi-resource"


def test_locked_retired_cache_preview_rejects_actual_root_before_state_lock(
    monkeypatch,
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("cannot acquire lock on the installed host")
    monkeypatch.setattr(preview, "_locked", forbidden)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(preview.RepositoryCacheCleanupPreviewError,
                           match="LIVE_ROOT_FORBIDDEN"):
            preview.preview_locked_retired_repository_cache_cleanup_under_root(
                fd, root_uid=os.geteuid(), cache_uid=os.geteuid(),
                cache_gid=os.getegid(), repository_id=RID,
                expected_state_generation=1,
                expected_state_sha256="0" * 64,
            )
    finally:
        os.close(fd)



# The actual object-deletion rehearsal is intentionally in a DIFFERENT,
# fixture-only module. The public preflight module above stays read-only.
def _fixture_purge(layout, *, generation, digest, files, allocated,
                   probe=None, fault=None, rid=RID):
    from repocache.server_fixture_retired_cache_cleanup_v1 import (
        purge_fixture_retired_repository_cache_objects_under_root,
    )
    fd, uid, gid, *_ = layout
    return purge_fixture_retired_repository_cache_objects_under_root(
        fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        repository_id=rid, expected_state_generation=generation,
        expected_state_sha256=digest,
        expected_cache_files=files,
        expected_allocated_file_bytes=allocated,
        assert_fixture_quiescent=(lambda: None) if probe is None else probe,
        inject_fixture_fault=fault,
    )


def test_explicit_fixture_purge_is_retired_only_and_preserves_other_cache(
    owned_with_locked_state,
):
    layout, _, state_file = owned_with_locked_state
    fd, uid, gid, retired_root, cache_root, root = layout
    populate(layout)
    from repocache.server_fixture_retired_cache_cleanup_v1 import (
        FixtureRetiredCacheCleanupError,
    )
    # A syntactically valid request is not sufficient to purge an
    # allocated/disabled repository before it is persistently retired.
    initial = hashlib.sha256(state_file.read_bytes()).hexdigest()
    original_payload = (retired_root / "a/bc" / DIGEST1).read_bytes()
    with pytest.raises(FixtureRetiredCacheCleanupError,
                       match="REPOSITORY_NOT_RETIRED"):
        _fixture_purge(
            layout, generation=1, digest=initial, files=2,
            allocated=inspect(layout)["allocated_file_bytes_observed"],
        )
    assert (retired_root / "a/bc" / DIGEST1).read_bytes() == original_payload

    bootstrap_repository_cache_under_root(
        fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        repository_id="almalinux-baseos",
    )
    other_root = cache_root / "almalinux-baseos"
    other_file = other_root / "b" / "cd" / DIGEST1
    other_file.parent.mkdir(parents=True, mode=0o700)
    other_file.write_bytes(b"signed-dnf-cache-must-survive")
    other_inode = other_file.stat().st_ino

    digest = _retire_owned_repo(owned_with_locked_state)
    sample = _locked_cleanup_preview(
        owned_with_locked_state, generation=2, digest=digest,
    )
    before_state = state_file.read_bytes()
    expected = [
        (p.name, p.stat().st_ino)
        for p in (retired_root / "a" / "bc").iterdir()
    ]
    assert len(expected) == 2
    observed = []
    result = _fixture_purge(
        layout, generation=2, digest=digest,
        files=sample["cache_files_observed"],
        allocated=sample["allocated_file_bytes_observed"],
        probe=lambda: observed.append("fixture-drained") or None,
    )
    assert observed == ["fixture-drained"]
    assert result["status"] == "PURGED_DETACHED_FIXTURE_CACHE_OBJECTS_ONLY"
    assert result["verified_cache_files_removed"] == 2
    assert result["repository_cache_marker_preserved"] is True
    assert result["retirement_ledger_preserved"] is True
    assert result["fixture_only"] is True
    assert result["actual_host_transfer_quiescence_verified"] is False
    assert result["authorizes_installed_cache_cleanup"] is False
    assert list(retired_root.iterdir()) == []
    assert retired_root.is_dir()
    assert (cache_root.parent / (
        ".repocache-repository-" + RID + ".owner-v1"
    )).is_file()
    assert other_file.read_bytes() == b"signed-dnf-cache-must-survive"
    assert other_file.stat().st_ino == other_inode
    assert state_file.read_bytes() == before_state

    # Explicit cleanup is idempotent: a second full preflight reports zero,
    # then an accepted empty purge touches no selected cache objects.
    after = _locked_cleanup_preview(
        owned_with_locked_state, generation=2, digest=digest,
    )
    assert after["cache_files_observed"] == 0
    again = _fixture_purge(
        layout, generation=2, digest=digest,
        files=0, allocated=0,
    )
    assert again["verified_cache_files_removed"] == 0
    assert other_file.read_bytes() == b"signed-dnf-cache-must-survive"


def test_fixture_purge_refuses_stale_or_unapproved_scope_without_deletion(
    owned_with_locked_state,
):
    from repocache.server_fixture_retired_cache_cleanup_v1 import (
        FixtureRetiredCacheCleanupError,
    )
    layout, _, state_file = owned_with_locked_state
    files = populate(layout)
    digest = _retire_owned_repo(owned_with_locked_state)
    sample = _locked_cleanup_preview(
        owned_with_locked_state, generation=2, digest=digest,
    )
    args = dict(
        generation=2, digest=digest,
        files=sample["cache_files_observed"],
        allocated=sample["allocated_file_bytes_observed"],
    )
    bad = (
        {"generation": 1},
        {"digest": "0" * 64},
        {"files": 1},
        {"allocated": sample["allocated_file_bytes_observed"] + 4096},
        {"rid": "almalinux-baseos"},
        {"rid": "../not-safe"},
        {"probe": lambda: False},
        {"probe": lambda: (_ for _ in ()).throw(
            RuntimeError("synthetic active transfer")
        )},
    )
    before = sorted((p.name, p.read_bytes()) for p in files.iterdir())
    for override in bad:
        with pytest.raises(FixtureRetiredCacheCleanupError):
            _fixture_purge(layout, **{**args, **override})
        assert sorted((p.name, p.read_bytes())
                      for p in files.iterdir()) == before
        assert not (state_file.with_name(".state-v2-multi.pending")).exists()
    assert hashlib.sha256(state_file.read_bytes()).hexdigest() == digest


def test_fixture_purge_detects_payload_changing_during_quiescence_check(
    owned_with_locked_state,
):
    from repocache.server_fixture_retired_cache_cleanup_v1 import (
        FixtureRetiredCacheCleanupError,
    )
    layout, _, _ = owned_with_locked_state
    directory = populate(layout)
    digest = _retire_owned_repo(owned_with_locked_state)
    report = _locked_cleanup_preview(
        owned_with_locked_state, generation=2, digest=digest,
    )
    target = directory / DIGEST1
    baseline = (directory / DIGEST2).read_bytes()

    def tamper():
        # Even when file count and allocated size are unchanged, the
        # complete inode/mtime fingerprint must block deletion.
        target.write_bytes(b"x" * target.stat().st_size)

    with pytest.raises(FixtureRetiredCacheCleanupError,
                       match="CONTENT_CHANGED"):
        _fixture_purge(
            layout, generation=2, digest=digest,
            files=report["cache_files_observed"],
            allocated=report["allocated_file_bytes_observed"],
            probe=tamper,
        )
    assert (directory / DIGEST2).read_bytes() == baseline
    assert target.is_file()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "extra-file"])
def test_fixture_purge_foreign_objects_fail_before_unlink(
    owned_with_locked_state, tmp_path, kind,
):
    from repocache.server_fixture_retired_cache_cleanup_v1 import (
        FixtureRetiredCacheCleanupError,
    )
    layout, _, _ = owned_with_locked_state
    directory = populate(layout)
    digest = _retire_owned_repo(owned_with_locked_state)
    outside = tmp_path / "outside-package"
    outside.write_bytes(b"critical-other-repo")
    if kind == "symlink":
        (directory / DIGEST1).unlink()
        (directory / DIGEST1).symlink_to(outside)
    elif kind == "hardlink":
        os.link(directory / DIGEST1, outside, follow_symlinks=False)
    else:
        (directory / "not-a-digest").write_bytes(b"not-owned")
    with pytest.raises(FixtureRetiredCacheCleanupError):
        _fixture_purge(
            layout, generation=2, digest=digest,
            files=2, allocated=0,
        )
    assert outside.read_bytes() in (b"critical-other-repo",
                                    b"immutable-cached-package" * 10)
    assert (directory / DIGEST2).read_bytes() == b"some-more-payload"


def test_fixture_purge_fault_after_unlink_has_explicit_resumable_partial_state(
    owned_with_locked_state,
):
    layout, _, state_file = owned_with_locked_state
    directory = populate(layout)
    digest = _retire_owned_repo(owned_with_locked_state)
    report = _locked_cleanup_preview(
        owned_with_locked_state, generation=2, digest=digest,
    )

    def crash(phase):
        assert phase == "entry_removed"
        raise RuntimeError("fixture-only kill after first unlink")

    with pytest.raises(RuntimeError, match="fixture-only kill"):
        _fixture_purge(
            layout, generation=2, digest=digest,
            files=report["cache_files_observed"],
            allocated=report["allocated_file_bytes_observed"],
            fault=crash,
        )
    assert state_file.is_file()
    # Non-atomic cache deletion must not be misreported as complete.
    remaining = _locked_cleanup_preview(
        owned_with_locked_state, generation=2, digest=digest,
    )
    assert remaining["cache_files_observed"] == 1
    result = _fixture_purge(
        layout, generation=2, digest=digest,
        files=remaining["cache_files_observed"],
        allocated=remaining["allocated_file_bytes_observed"],
    )
    assert result["verified_cache_files_removed"] == 1
    assert list(layout[3].iterdir()) == []


def test_fixture_purge_rejects_actual_root_before_lock(monkeypatch):
    from repocache import server_fixture_retired_cache_cleanup_v1 as module
    monkeypatch.setattr(
        module, "_locked",
        lambda *_args, **_kwargs: pytest.fail("real host lock must not be read"),
    )
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(module.FixtureRetiredCacheCleanupError,
                           match="LIVE_ROOT_FORBIDDEN"):
            module.purge_fixture_retired_repository_cache_objects_under_root(
                fd, root_uid=os.geteuid(), cache_uid=os.geteuid(),
                cache_gid=os.getegid(), repository_id=RID,
                expected_state_generation=2,
                expected_state_sha256="0" * 64,
                expected_cache_files=0, expected_allocated_file_bytes=0,
                assert_fixture_quiescent=lambda: None,
            )
    finally:
        os.close(fd)
