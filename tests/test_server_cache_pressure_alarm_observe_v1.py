"""Concrete descriptor and interrupted-telemetry alarms never guess healthy."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
import pytest

from repocache import server_cache_pressure_observe_v1 as source
from repocache.server_cache_pressure_alarm_observe_v1 import (
    NativePressureAlarmObservationError,
    preview_observed_cache_pressure_alarm as inspect,
)

BASE = dict(warning_free_bytes=4096 * 100, critical_free_bytes=4096 * 10,
            recovery_margin_bytes=4096 * 2)


@pytest.fixture
def cache_root(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir(mode=0o700)
    path = root
    for item in ("var", "cache", "nginx", "repocache-managed"):
        path = path / item
        path.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd, root, path
    finally:
        os.close(fd)


def check(cache_root, previous=None, **overrides):
    fd, _, _ = cache_root
    return inspect(fd, root_uid=os.geteuid(), cache_uid=os.geteuid(),
                   previous=previous, **{**BASE, **overrides})


def state(level="critical", stale=True, sequence=1):
    return dict(schema_version=1, alarm_level=level,
                telemetry_stale=stale, sequence=sequence)


def test_actual_statvfs_from_fixed_cache_does_not_report_healthy(cache_root):
    a = check(cache_root)
    assert a["status"] == "READ_ONLY_PARTIAL_PRESSURE_ALARM_CANDIDATE"
    assert a["filesystem_observation"]["cache_root_ownership_observed"] is True
    assert a["filesystem_observation"]["free_inodes_observed"] >= 0
    assert a["alarm_candidate"]["measurements_complete"] is False
    assert a["alarm_candidate"]["next_state"]["telemetry_stale"] is True
    assert a["alarm_candidate"]["next_state"]["alarm_level"] != "normal"
    assert a["telemetry_complete"] is False
    for key in ("nginx_writability_proven", "prior_alarm_authenticated",
                "nginx_cache_manager_verified", "operator_alert_delivered",
                "authorizes_operator_alert_publish", "authorizes_nginx_cache_bypass",
                "authorizes_nginx_reload", "authorizes_cache_cleanup"):
        assert a[key] is False, key


def test_known_low_free_bytes_raise_critical_despite_missing_other_metrics(
    cache_root, monkeypatch,
):
    monkeypatch.setattr(source.os, "fstatvfs", lambda fd: SimpleNamespace(
        f_frsize=4096, f_bavail=9, f_favail=500, f_flag=0,
    ))
    a = check(cache_root)
    assert a["alarm_candidate"]["next_state"]["alarm_level"] == "critical"
    assert a["alarm_candidate"]["reason_code"] == "CRITICAL_FREE_SPACE"
    assert "CACHE_PRESSURE_CRITICAL" in a["alarm_candidate"]["event_codes"]
    assert a["alarm_candidate"]["next_state"]["telemetry_stale"] is True


def test_zero_inodes_or_readonly_mount_stays_critical(cache_root, monkeypatch):
    for readonly, inodes, reason in (
        (0, 0, "FILESYSTEM_INODES_EXHAUSTED"),
        (getattr(os, "ST_RDONLY", 1), 123, "STORAGE_WRITE_REFUSED"),
    ):
        monkeypatch.setattr(source.os, "fstatvfs", lambda fd, flag=readonly,
                            count=inodes: SimpleNamespace(
                            f_frsize=4096, f_bavail=100000, f_favail=count,
                            f_flag=flag,
                        ))
        out = check(cache_root)
        assert out["alarm_candidate"]["next_state"]["alarm_level"] == "critical"
        assert out["alarm_candidate"]["reason_code"] == reason


def test_missing_and_untrusted_cache_holds_confirmed_critical(cache_root):
    _, _, leaf = cache_root
    leaf.rmdir()
    a = check(cache_root, previous=state())
    assert a["filesystem_observation"]["cache_root_ownership_observed"] is False
    assert a["alarm_candidate"]["next_state"]["alarm_level"] == "critical"
    assert a["alarm_candidate"]["reason_code"] == (
        "ALARM_HELD_ON_INCOMPLETE_TELEMETRY"
    )
    assert not a["authorizes_operator_alert_publish"]


def test_damaged_cache_mode_does_not_replace_prior_warning_with_normal(cache_root):
    _, _, leaf = cache_root
    leaf.chmod(0o777)
    a = check(cache_root, previous=state("warning"))
    assert a["alarm_candidate"]["next_state"]["alarm_level"] == "warning"
    assert a["filesystem_observation"]["observation_code"] == (
        "CACHE_ROOT_OR_CAPACITY_UNVERIFIED"
    )


def test_recovery_is_never_proven_from_positive_statvfs_without_writability(
    cache_root, monkeypatch,
):
    monkeypatch.setattr(source.os, "fstatvfs", lambda fd: SimpleNamespace(
        f_frsize=4096, f_bavail=1_000_000, f_favail=10_000, f_flag=0,
    ))
    a = check(cache_root, previous=state())
    assert a["alarm_candidate"]["next_state"]["alarm_level"] == "critical"
    assert a["alarm_candidate"]["next_state"]["telemetry_stale"]
    assert "CACHE_PRESSURE_RECOVERED" not in a["alarm_candidate"]["event_codes"]


@pytest.mark.parametrize("previous", [
    {"schema_version": 1, "sequence": -1, "alarm_level": "warning",
     "telemetry_stale": True},
    {"schema_version": 1, "sequence": True, "alarm_level": "normal",
     "telemetry_stale": False},
    {"schema_version": 1, "sequence": 1, "alarm_level": "normal",
     "telemetry_stale": False, "unexpected": "injection"},
    {"schema_version": 1, "sequence": 1, "alarm_level": "root",
     "telemetry_stale": False},
])
def test_forged_prior_state_refused(cache_root, previous):
    with pytest.raises(NativePressureAlarmObservationError):
        check(cache_root, previous=previous)


@pytest.mark.parametrize("invalid", [
    {"warning_free_bytes": 0},
    {"critical_free_bytes": True},
    {"recovery_margin_bytes": -1},
    {"critical_free_bytes": 1000000000},
])
def test_bad_policy_rejected_before_truthful_observation(cache_root, invalid):
    with pytest.raises(NativePressureAlarmObservationError):
        check(cache_root, **invalid)


def test_pure_read_only_no_service_or_alert_side_effects():
    source_text = (Path(__file__).resolve().parents[1] /
                   "src/repocache/server_cache_pressure_alarm_observe_v1.py"
                   ).read_text()
    for forbidden in ("subprocess", "os.unlink(", "os.remove(", "os.mkdir(",
                      "os.chmod(", "systemctl", "nginx -s", "requests.post"):
        assert forbidden not in source_text
