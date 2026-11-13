"""Cache pressure alarm hysteresis and telemetry-liveness security tests."""
from __future__ import annotations

import os

import pytest

from repocache.server_cache_pressure_alarm_v1 import (
    CachePressureAlarmError, evaluate_cache_pressure_alarm,
)

DEFAULT = dict(
    warning_free_bytes=1000, critical_free_bytes=300,
    recovery_margin_bytes=100, free_inodes=100,
    disk_writable=True, measurements_complete=True,
)


def event(free, state=None, **kwargs):
    values = dict(DEFAULT)
    values.update(kwargs)
    return evaluate_cache_pressure_alarm(
        free_bytes=free, previous=state, **values,
    )


def test_normal_to_warning_to_critical_no_event_spam():
    normal = event(1500)
    assert normal["next_state"]["alarm_level"] == "normal"
    warning = event(900, normal["next_state"])
    assert warning["event_codes"] == ["CACHE_PRESSURE_WARNING"]
    repeat = event(800, warning["next_state"])
    assert repeat["event_codes"] == []
    critical = event(100, repeat["next_state"])
    assert critical["event_codes"] == ["CACHE_PRESSURE_CRITICAL"]
    assert critical["next_state"]["sequence"] == 4


def test_recovery_hysteresis_requires_full_margin():
    critical = event(100)
    held = event(330, critical["next_state"])
    assert held["next_state"]["alarm_level"] == "critical"
    assert held["event_codes"] == []
    warning = event(650, held["next_state"])
    assert warning["next_state"]["alarm_level"] == "warning"
    assert warning["event_codes"] == ["CACHE_PRESSURE_DOWNGRADED"]
    held_warning = event(1050, warning["next_state"])
    assert held_warning["next_state"]["alarm_level"] == "warning"
    recovered = event(1500, held_warning["next_state"])
    assert recovered["next_state"]["alarm_level"] == "normal"
    assert recovered["event_codes"] == ["CACHE_PRESSURE_RECOVERED"]


def test_incomplete_telemetry_never_clears_critical():
    previous = event(90)["next_state"]
    unknown = event(
        None, previous, disk_writable=None, measurements_complete=False,
        free_inodes=None,
    )
    assert unknown["next_state"]["alarm_level"] == "critical"
    assert unknown["next_state"]["telemetry_stale"]
    assert unknown["event_codes"] == ["CACHE_TELEMETRY_INCOMPLETE"]
    repeat = event(
        None, unknown["next_state"], disk_writable=None,
        measurements_complete=False, free_inodes=None,
    )
    assert repeat["event_codes"] == []
    recovered = event(1500, repeat["next_state"])
    assert recovered["event_codes"] == [
        "CACHE_TELEMETRY_RESTORED", "CACHE_PRESSURE_RECOVERED",
    ]


def test_inode_exhaustion_and_readonly_disk_escalate_immediately():
    for args, code in (
        ({"free_inodes": 0}, "FILESYSTEM_INODES_EXHAUSTED"),
        ({"disk_writable": False}, "STORAGE_WRITE_REFUSED"),
    ):
        x = event(5000, **args)
        assert x["next_state"]["alarm_level"] == "critical"
        assert x["reason_code"] == code
        assert "CACHE_PRESSURE_CRITICAL" in x["event_codes"]
        assert not x["authorizes_cache_delete"]


def test_incomplete_monitor_does_not_claim_recovery_even_if_bytes_high():
    critical = event(100)["next_state"]
    x = event(5000, critical, measurements_complete=False,
              disk_writable=None, free_inodes=None)
    assert x["next_state"]["alarm_level"] == "critical"
    assert not x["measurements_complete"]
    assert "CACHE_PRESSURE_RECOVERED" not in x["event_codes"]


@pytest.mark.parametrize("bad", [
    {}, {"schema_version": 1}, {"schema_version": True, "sequence": 1,
                              "alarm_level": "normal", "telemetry_stale": False},
    {"schema_version": 1, "sequence": -1,
     "alarm_level": "normal", "telemetry_stale": False},
    {"schema_version": 1, "sequence": 0,
     "alarm_level": "NORMAL", "telemetry_stale": False},
    {"schema_version": 1, "sequence": 0,
     "alarm_level": "normal", "telemetry_stale": 1},
])
def test_malformed_prior_state_denied(bad):
    with pytest.raises(CachePressureAlarmError,
                       match="CACHE_ALARM_PREVIOUS_STATE_INVALID"):
        event(500, bad)


@pytest.mark.parametrize("free_inodes", [-1, True, "100", 2**64])
def test_invalid_inode_measurement_refused(free_inodes):
    with pytest.raises(CachePressureAlarmError,
                       match="CACHE_ALARM_INODE_COUNT_INVALID"):
        event(500, free_inodes=free_inodes)


def test_actual_linux_statvfs_counter_feeds_non_authorizing_policy(tmp_path):
    actual = os.statvfs(tmp_path)
    free = actual.f_frsize * actual.f_bavail
    inode = actual.f_favail
    assert free >= 0 and inode >= 0
    observed = evaluate_cache_pressure_alarm(
        free_bytes=free, free_inodes=inode,
        warning_free_bytes=1000, critical_free_bytes=300,
        recovery_margin_bytes=0, disk_writable=True,
        measurements_complete=True,
    )
    assert observed["free_bytes_observed"] == free
    assert observed["free_inodes_observed"] == inode
    for field in ("last_state_authenticated","metrics_source_authenticated",
                  "authorizes_cache_delete","authorizes_operator_alert_publish"):
        assert observed[field] is False
