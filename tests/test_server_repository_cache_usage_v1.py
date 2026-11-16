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
