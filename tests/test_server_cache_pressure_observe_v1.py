"""Actual Linux descriptor and synthetic error tests for cache pressure (#97)."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from repocache import server_cache_pressure_observe_v1 as obs


@pytest.fixture
def cache_tree(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir(mode=0o700)
    current = root
    for name in ("var", "cache", "nginx", "repocache-managed"):
        current = current / name
        current.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd, root, current
    finally:
        os.close(fd)


def sample(fd, **overrides):
    args = dict(
        root_uid=os.geteuid(), cache_uid=os.geteuid(),
        warning_free_bytes=10, critical_free_bytes=5,
        recovery_margin_bytes=2, previous_level="unknown",
    )
    args.update(overrides)
    return obs.observe_cache_pressure_under_root(fd, **args)


def test_actual_fd_statvfs_observed_without_changes(cache_tree):
    fd, root, cache = cache_tree
    before = sorted((str(p.relative_to(root)), p.stat().st_mode)
                    for p in root.rglob("*"))
    result = sample(fd)
    assert result["status"] == "READ_ONLY_CACHE_PRESSURE_PARTIAL"
    assert result["observation_code"] == "FIXED_CACHE_FREE_SPACE_OBSERVED"
    assert result["cache_root_ownership_observed"] is True
    assert result["free_bytes_observed"] >= 0
    assert result["free_inodes_observed"] >= 0
    # Large free-space alone is never an invented NORMAL or writable result.
    assert result["pressure_level"] in ("unknown", "critical")
    assert result["measurements_complete"] is False
    assert result["disk_writable_observed"] is None
    assert result["nginx_manager_behavior_verified"] is False
    assert result["authorizes_installation"] is False
    assert result["authorizes_cache_cleanup"] is False
    assert result == sample(fd)
    after = sorted((str(p.relative_to(root)), p.stat().st_mode)
                   for p in root.rglob("*"))
    assert after == before


def test_missing_cache_refuses_without_creating(cache_tree):
    fd, root, cache = cache_tree
    cache.rmdir()
    result = sample(fd)
    assert result["pressure_level"] == "unknown"
    assert result["free_bytes_observed"] is None
    assert result["cache_root_ownership_observed"] is False
    assert not cache.exists()


def test_symlink_leaf_and_parent_refused_without_following(cache_tree, tmp_path):
    fd, root, cache = cache_tree
    cache.rmdir()
    cache.symlink_to(tmp_path, target_is_directory=True)
    result = sample(fd)
    assert result["observation_code"] == "CACHE_ROOT_OR_CAPACITY_UNVERIFIED"
    cache.unlink()
    parent = root / "var" / "cache" / "nginx"
    parent.rmdir()
    parent.symlink_to(tmp_path, target_is_directory=True)
    assert sample(fd)["cache_root_ownership_observed"] is False
    assert not (tmp_path / "repocache-managed").exists()


def test_foreign_uid_and_writable_root_refused(cache_tree):
    fd, root, cache = cache_tree
    assert sample(fd, cache_uid=os.geteuid()+1)["cache_root_ownership_observed"] is False
    cache.chmod(0o777)
    assert sample(fd)["cache_root_ownership_observed"] is False
    cache.chmod(0o700)
    assert sample(fd, root_uid=os.geteuid()+1)["cache_root_ownership_observed"] is False


def test_real_free_space_limit_and_critical_hysteresis(cache_tree, monkeypatch):
    fd, _, _ = cache_tree
    monkeypatch.setattr(obs.os, "fstatvfs", lambda _fd: SimpleNamespace(
        f_frsize=4096, f_bavail=1, f_favail=25,
    ))
    result = sample(fd, warning_free_bytes=8192, critical_free_bytes=4096)
    assert result["free_bytes_observed"] == 4096
    assert result["pressure_level"] == "critical"
    assert result["reason_code"] == "CRITICAL_FREE_SPACE"
    result = sample(fd, warning_free_bytes=8192, critical_free_bytes=1024,
                    recovery_margin_bytes=4096, previous_level="critical")
    assert result["pressure_level"] == "critical"
    assert result["reason_code"] == "CRITICAL_RECOVERY_HYSTERESIS"


def test_zero_inodes_override_unknown_bytes_health(cache_tree, monkeypatch):
    fd, _, _ = cache_tree
    monkeypatch.setattr(obs.os, "fstatvfs", lambda _fd: SimpleNamespace(
        f_frsize=4096, f_bavail=1_000_000, f_favail=0,
    ))
    result = sample(fd)
    assert result["pressure_level"] == "critical"
    assert result["reason_code"] == "FILESYSTEM_INODES_EXHAUSTED"
    assert not result["authorizes_installation"]


@pytest.mark.parametrize("bad_capacity", [
    (0, 42, 10), (1, -1, 10), (1, 1, -1),
    (4096, 2**63, 10), (4096, 10, 2**63),
])
def test_invalid_statvfs_does_not_invent_zero(cache_tree, monkeypatch, bad_capacity):
    fd, _, _ = cache_tree
    monkeypatch.setattr(obs.os, "fstatvfs", lambda _fd: SimpleNamespace(
        f_frsize=bad_capacity[0], f_bavail=bad_capacity[1],
        f_favail=bad_capacity[2],
    ))
    report = sample(fd)
    assert report["pressure_level"] == "unknown"
    assert report["free_bytes_observed"] is None
    assert report["free_inodes_observed"] is None


def test_invalid_thresholds_refuse_before_host_observation(cache_tree, monkeypatch):
    fd, _, _ = cache_tree
    monkeypatch.setattr(obs, "_observe_under_root",
                        lambda *_a, **_k: pytest.fail("unsafe policy reached filesystem"))
    with pytest.raises(ValueError, match="CACHE_PRESSURE_THRESHOLD_ORDER_INVALID"):
        sample(fd, warning_free_bytes=1, critical_free_bytes=2)


def test_fixed_path_not_external_or_mutating():
    source = (Path(__file__).resolve().parents[1]
              / "src/repocache/server_cache_pressure_observe_v1.py").read_text()
    assert "subprocess" not in source
    assert "os.mkdir(" not in source
    assert "os.unlink(" not in source
    assert "os.remove(" not in source
    assert "os.chmod(" not in source
    assert "_CACHE_LEAF = \"repocache-managed\"" in source


def test_readonly_cache_mount_is_immediate_critical_even_with_free_bytes(cache_tree, monkeypatch):
    fd, _, _ = cache_tree
    monkeypatch.setattr(obs.os, "fstatvfs", lambda _fd: SimpleNamespace(
        f_frsize=4096, f_bavail=100000, f_favail=200,
        f_flag=getattr(os, "ST_RDONLY", 1),
    ))
    report = sample(fd)
    assert report["status"] == "READ_ONLY_CACHE_PRESSURE_PARTIAL"
    assert report["pressure_level"] == "critical"
    assert report["reason_code"] == "STORAGE_WRITE_REFUSED"
    assert report["disk_writable_observed"] is False
    assert report["free_bytes_observed"] == 4096 * 100000
    assert report["cache_root_ownership_observed"] is True
    assert report["measurements_complete"] is False
    assert not report["authorizes_cache_cleanup"]


def test_clear_mount_readonly_flag_never_claims_nginx_writable(cache_tree, monkeypatch):
    fd, _, _ = cache_tree
    monkeypatch.setattr(obs.os, "fstatvfs", lambda _fd: SimpleNamespace(
        f_frsize=4096, f_bavail=100000, f_favail=200,
        f_flag=0,
    ))
    report = sample(fd)
    assert report["pressure_level"] == "unknown"
    assert report["disk_writable_observed"] is None
    assert report["reason_code"] == "OBSERVATION_INCOMPLETE"


@pytest.mark.parametrize("bad_flag", [True, "readonly", -1, 1.5])
def test_untrusted_statvfs_mount_flags_do_not_manufacture_healthy_result(
    cache_tree, monkeypatch, bad_flag,
):
    fd, _, _ = cache_tree
    monkeypatch.setattr(obs.os, "fstatvfs", lambda _fd: SimpleNamespace(
        f_frsize=4096, f_bavail=100000, f_favail=200,
        f_flag=bad_flag,
    ))
    report = sample(fd)
    assert report["observation_code"] == "CACHE_ROOT_OR_CAPACITY_UNVERIFIED"
    assert report["pressure_level"] == "unknown"
    assert report["disk_writable_observed"] is None
    assert not report["authorizes_cache_cleanup"]
