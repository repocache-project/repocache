"""Actual Linux FD regression for bounded multi-repository cache usage (#29/#97)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from repocache import server_repository_cache_usage_v1 as usage
from repocache.server_native_repository_cache_v1 import (
    bootstrap_repository_cache_under_root,
)
from repocache.server_native_storage_bootstrap_v1 import (
    bootstrap_native_nginx_storage_under_root,
)

APT = "debian-trixie-main"
DNF = "almalinux-baseos"
DIGEST = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def owned(tmp_path):
    root = tmp_path / "detached"
    root.mkdir(mode=0o700)
    for p in ("var", "var/cache", "var/cache/nginx",
              "var/log", "var/log/nginx"):
        (root / p).mkdir(mode=0o700)
    uid, gid = os.geteuid(), os.getegid()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        bootstrap_native_nginx_storage_under_root(
            fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        )
        for rid in (APT, DNF):
            bootstrap_repository_cache_under_root(
                fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
                repository_id=rid,
            )
        yield fd, uid, gid, root
    finally:
        os.close(fd)


def check(owned, ids=(APT, DNF), **overrides):
    fd, uid, gid, _ = owned
    args = dict(root_fd=fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
                repository_ids=ids)
    args.update(overrides)
    return usage.preview_owned_repository_cache_usage_under_root(**args)


def cache_file(owned, rid, data: bytes):
    base = owned[3] / "var/cache/nginx/repocache-managed" / rid / "a" / "bc"
    base.mkdir(mode=0o700, parents=True)
    dest = base / DIGEST
    dest.write_bytes(data)
    return dest


def test_two_verified_repositories_aggregate_real_allocated_bytes_without_writes(owned):
    apt = cache_file(owned, APT, b"apt-signed-shape" * 17)
    dnf = cache_file(owned, DNF, b"rpm-signed-shape" * 23)
    before = [(f.stat().st_ino, f.read_bytes()) for f in (apt, dnf)]
    result = check(owned, ids=(DNF, APT))
    assert result == check(owned, ids=(APT, DNF))
    assert result["status"] == "SELECTED_CACHE_USAGE_OBSERVATION_ONLY"
    assert result["repository_ids_observed"] == [DNF, APT]
    assert result["selected_repository_count"] == 2
    assert result["cache_files_observed"] == 2
    assert result["cache_directories_observed"] == 4
    assert result["apparent_file_bytes_observed"] == sum(
        f.stat().st_size for f in (apt, dnf)
    )
    assert result["allocated_file_bytes_observed"] == sum(
        f.stat().st_blocks * 512 for f in (apt, dnf)
    )
    assert [(f.stat().st_ino, f.read_bytes()) for f in (apt, dnf)] == before
    for field in (
        "all_repository_ids_authenticated", "full_cache_inventory_verified",
        "multi_repository_snapshot_atomic", "nginx_cache_manager_verified",
        "selinux_enforcing_verified", "actual_reclaimable_space_verified",
        "authorizes_cache_cleanup", "authorizes_nginx_reload",
        "authorizes_state_commit", "authorizes_operator_alert_publish",
    ):
        assert result[field] is False


def test_one_selected_repository_cannot_claim_total_cache_usage(owned):
    cache_file(owned, APT, b"apt")
    cache_file(owned, DNF, b"dnf-is-not-listed")
    result = check(owned, ids=(APT,))
    assert result["repository_ids_observed"] == [APT]
    assert result["cache_files_observed"] == 1
    assert result["full_cache_inventory_verified"] is False


@pytest.mark.parametrize("ids", [
    (), (APT, APT), (APT, "../etc"), (APT, None),
    [APT, DNF], (True,), (APT,) * 501,
])
def test_invalid_lists_denied_before_any_repository_read(owned, monkeypatch, ids):
    def forbidden(*_a, **_kw):
        pytest.fail("invalid selectors attempted native inspection")
    monkeypatch.setattr(usage, "preview_repository_cache_cleanup_under_root", forbidden)
    with pytest.raises(usage.CacheUsageObservationError,
                       match="^CACHE_USAGE_ARGUMENT_INVALID$"):
        check(owned, ids=ids)


def test_missing_or_unmarked_repository_aborts_without_partial_totals(owned):
    cache_file(owned, APT, b"keep-apt")
    with pytest.raises(usage.CacheUsageObservationError,
                       match="^CACHE_USAGE_OBSERVATION_UNVERIFIED$"):
        check(owned, ids=(APT, "not-owned"))
    assert (owned[3] / "var/cache/nginx/repocache-managed" / APT /
            "a" / "bc" / DIGEST).read_bytes() == b"keep-apt"


def test_foreign_second_repository_file_refuses_whole_aggregate(owned):
    cache_file(owned, APT, b"good")
    cache_file(owned, DNF, b"good")
    second = owned[3] / "var/cache/nginx/repocache-managed" / DNF / "a" / "bc"
    (second / "not-a-cache-hash").write_bytes(b"foreign")
    with pytest.raises(usage.CacheUsageObservationError,
                       match="^CACHE_USAGE_OBSERVATION_UNVERIFIED$"):
        check(owned)
    assert (second / "not-a-cache-hash").read_bytes() == b"foreign"


def test_live_host_root_is_never_an_acceptable_aggregate_source():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(usage.CacheUsageObservationError,
                           match="^CACHE_USAGE_OBSERVATION_UNVERIFIED$"):
            usage.preview_owned_repository_cache_usage_under_root(
                fd, root_uid=0, cache_uid=0, cache_gid=0,
                repository_ids=(APT,),
            )
    finally:
        os.close(fd)


@pytest.mark.parametrize("value", [
    {"root_fd": True}, {"root_uid": True}, {"cache_uid": -1},
    {"cache_gid": None}, {"root_fd": -1},
])
def test_invalid_descriptor_or_credential_arguments_refused(owned, value):
    with pytest.raises(usage.CacheUsageObservationError,
                       match="^CACHE_USAGE_ARGUMENT_INVALID$"):
        check(owned, **value)


def test_large_cumulative_selection_fails_closed(owned, monkeypatch):
    cache_file(owned, APT, b"one")
    monkeypatch.setattr(usage, "_MAX_OBSERVED_ENTRIES", 1)
    with pytest.raises(usage.CacheUsageObservationError,
                       match="^CACHE_USAGE_"):
        check(owned, ids=(APT,))


def test_unverified_or_authorizing_underlying_result_is_not_promoted(owned, monkeypatch):
    real = usage.preview_repository_cache_cleanup_under_root

    def tampered(*args, **kwargs):
        item = real(*args, **kwargs)
        item["authorizes_cache_cleanup"] = True
        return item

    monkeypatch.setattr(usage, "preview_repository_cache_cleanup_under_root", tampered)
    with pytest.raises(usage.CacheUsageObservationError,
                       match="^CACHE_USAGE_"):
        check(owned, ids=(APT,))


def test_aggregate_has_no_own_mutating_primitive():
    source = (Path(__file__).resolve().parents[1] /
              "src/repocache/server_repository_cache_usage_v1.py"
              ).read_text(encoding="utf-8")
    for forbidden in (
        "os.unlink(", "os.remove(", "os.rmdir(", "os.mkdir(",
        "os.chown(", "os.chmod(", "os.rename(", "subprocess.run(",
        "shutil.rmtree", "shell=True",
    ):
        assert forbidden not in source
    assert "authorizes_cache_cleanup" in source



def _create_locked_v2_usage_state(owned, *, active=()):
    """Bind the already-bootstrap-owned cache roots to a real v2 state FD."""
    import base64
    import hashlib
    import json
    from repocache.server_repository_plan_v1 import _canonical_identity
    from repocache.server_protected_state_store_v1 import LOCK_NAME
    from repocache.server_proposed_state_v2_store import (
        V2_STATE, _commit_proposed_v2_under_root,
    )
    fd, uid, gid, root = owned
    directory = root / "var/lib/repocache/server"
    directory.mkdir(parents=True, mode=0o700)
    (directory / LOCK_NAME).write_bytes(b"")
    (directory / LOCK_NAME).chmod(0o600)
    doc = json.loads((
        Path(__file__).resolve().parents[1]
        / "docs/examples/server-install-v1.json"
    ).read_text(encoding="utf-8"))
    doc["expected_state_generation"] = 1
    doc["repositories"][1]["id"] = DNF
    for item in doc["repositories"]:
        item["desired_state"] = (
            "active" if item["id"] in active else "disabled"
        )
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    records = [{
        "id": item["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(item).encode("utf-8")
        ).hexdigest(),
        "desired_state": item["desired_state"],
        "observed_state": "not-activated",
    } for item in doc["repositories"]]
    state = {
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
    result = _commit_proposed_v2_under_root(
        fd, state, owner_uid=uid, expected_generation=0,
    )
    assert result["state_generation"] == 1
    return directory / V2_STATE, state


def _locked_usage(owned, state_file, **override):
    import hashlib
    fd, uid, gid, _ = owned
    args = dict(
        root_fd=fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        expected_state_generation=2,
        expected_state_sha256=hashlib.sha256(
            state_file.read_bytes()
        ).hexdigest(),
    )
    args.update(override)
    return usage.preview_locked_v2_repository_cache_usage_under_root(**args)


def _retire_apt_usage(owned, state_file, initial):
    import hashlib
    from repocache.server_proposed_state_v2_store import (
        _commit_proposed_v2_under_root,
    )
    from repocache.server_repository_v2_transition_v1 import (
        plan_repository_v2_transition,
    )
    fd, uid, _, _ = owned
    old = state_file.read_bytes()
    changed = plan_repository_v2_transition(
        initial, expected_generation=1,
        expected_previous_state_sha256=hashlib.sha256(old).hexdigest(),
        operation="remove", repository_id=APT,
        decision_sha256="b" * 64,
    )["proposed_snapshot"]
    report = _commit_proposed_v2_under_root(
        fd, changed, owner_uid=uid, expected_generation=1,
    )
    assert report["state_generation"] == 2
    return changed


def test_locked_v2_history_usage_includes_retired_cache_without_deletion(owned):
    apt = cache_file(owned, APT, b"retired apt signed payload" * 8)
    dnf = cache_file(owned, DNF, b"active DNF signed payload" * 12)
    state_file, initial = _create_locked_v2_usage_state(owned, active=(DNF,))
    _retire_apt_usage(owned, state_file, initial)
    original_state = state_file.read_bytes()
    original_objects = (
        (apt.stat().st_ino, apt.read_bytes()),
        (dnf.stat().st_ino, dnf.read_bytes()),
    )

    result = _locked_usage(owned, state_file)
    assert result == _locked_usage(owned, state_file)
    assert result["status"] == "LOCKED_V2_MARKED_CACHE_USAGE_FIXTURE_ONLY"
    assert result["state_generation"] == 2
    assert result["protected_historic_repository_count"] == 2
    assert result["marked_cache_root_count"] == 2
    assert result["cache_files_observed"] == 2
    assert result["cache_directories_observed"] == 4
    assert result["apparent_file_bytes_observed"] == (
        apt.stat().st_size + dnf.stat().st_size
    )
    by_id = {
        row["repository_id"]: row
        for row in result["protected_history_rows"]
    }
    assert by_id[APT]["history_status"] == "retired"
    assert by_id[APT]["desired_state"] == "removed"
    assert by_id[APT]["owned_cache_root_present"] is True
    assert by_id[APT]["cache_files_observed"] == 1
    assert by_id[DNF]["history_status"] == "allocated"
    assert by_id[DNF]["desired_state"] == "active"
    assert by_id[DNF]["cache_files_observed"] == 1
    assert result["fixture_all_ids_from_committed_v2_ledger"] is True
    assert result["full_cache_inventory_verified"] is False
    assert result["multi_repository_snapshot_atomic"] is False
    assert result["actual_reclaimable_space_verified"] is False
    assert all(v is False for k, v in result.items()
               if k.startswith("authorizes_") or k.endswith("_verified"))
    assert state_file.read_bytes() == original_state
    assert (
        (apt.stat().st_ino, apt.read_bytes()),
        (dnf.stat().st_ino, dnf.read_bytes()),
    ) == original_objects


@pytest.mark.parametrize("foreign", ["directory", "marker", "symlink"])
def test_locked_v2_history_refuses_foreign_cache_names_before_any_report(
    owned, foreign, tmp_path,
):
    apt = cache_file(owned, APT, b"untouched-apt")
    state_file, initial = _create_locked_v2_usage_state(owned)
    _retire_apt_usage(owned, state_file, initial)
    _, _, _, root = owned
    cache_root = root / "var/cache/nginx/repocache-managed"
    if foreign == "directory":
        (cache_root / "foreign-id").mkdir(mode=0o700)
    elif foreign == "marker":
        marker = root / "var/cache/nginx/.repocache-repository-foreign-id.owner-v1"
        marker.write_bytes(b"unknown")
        marker.chmod(0o600)
    else:
        dnf = cache_root / DNF
        # The corresponding root-owned marker is untouched; a symlink is
        # always refused instead of following an outside repository path.
        dnf.rmdir()
        dnf.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(usage.CacheUsageObservationError, match="LOCKED_"):
        _locked_usage(owned, state_file)
    assert apt.read_bytes() == b"untouched-apt"


def test_locked_v2_usage_reports_missing_disabled_cache_root_as_zero(owned):
    state_file, initial = _create_locked_v2_usage_state(owned)
    _retire_apt_usage(owned, state_file, initial)
    fd, uid, gid, root = owned
    missing = root / "var/cache/nginx/repocache-managed" / DNF
    missing.rmdir()
    marker = (root / "var/cache/nginx" /
              (".repocache-repository-" + DNF + ".owner-v1"))
    marker.unlink()
    result = _locked_usage(owned, state_file)
    by_id = {
        item["repository_id"]: item
        for item in result["protected_history_rows"]
    }
    assert by_id[DNF]["owned_cache_root_present"] is False
    assert by_id[DNF]["cache_files_observed"] == 0
    assert by_id[DNF]["desired_state"] == "disabled"
    assert by_id[APT]["history_status"] == "retired"
    assert by_id[APT]["owned_cache_root_present"] is True


def test_locked_v2_active_repository_without_owned_cache_fails_closed(owned):
    state_file, initial = _create_locked_v2_usage_state(owned, active=(DNF,))
    # Remove only the detached DNF cache root and marker, never a live path.
    root = owned[3]
    (root / "var/cache/nginx/repocache-managed" / DNF).rmdir()
    (root / "var/cache/nginx" /
     (".repocache-repository-" + DNF + ".owner-v1")).unlink()
    import hashlib
    with pytest.raises(usage.CacheUsageObservationError,
                       match="LOCKED_ACTIVE_CACHE_ROOT_MISSING"):
        usage.preview_locked_v2_repository_cache_usage_under_root(
            owned[0], root_uid=owned[1],
            cache_uid=owned[1], cache_gid=owned[2],
            expected_state_generation=1,
            expected_state_sha256=hashlib.sha256(
                state_file.read_bytes()
            ).hexdigest(),
        )


def test_locked_v2_usage_stale_state_pending_wal_or_host_root_refused(owned):
    state_file, initial = _create_locked_v2_usage_state(owned)
    _retire_apt_usage(owned, state_file, initial)
    for change in (
        {"expected_state_generation": 1},
        {"expected_state_sha256": "0" * 64},
        {"expected_state_generation": True},
        {"root_uid": True},
    ):
        with pytest.raises(usage.CacheUsageObservationError):
            _locked_usage(owned, state_file, **change)
    pending = state_file.with_name(".state-v2-multi.pending-tmp")
    pending.write_bytes(b"unknown-wal")
    pending.chmod(0o600)
    with pytest.raises(usage.CacheUsageObservationError):
        _locked_usage(owned, state_file)
    assert pending.read_bytes() == b"unknown-wal"
    pending.unlink()

    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(usage.CacheUsageObservationError,
                           match="LOCKED_LIVE_ROOT_FORBIDDEN"):
            usage.preview_locked_v2_repository_cache_usage_under_root(
                fd, root_uid=os.geteuid(), cache_uid=os.geteuid(),
                cache_gid=os.getegid(),
                expected_state_generation=1,
                expected_state_sha256="0" * 64,
            )
    finally:
        os.close(fd)
