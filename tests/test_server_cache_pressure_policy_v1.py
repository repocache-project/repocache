"""Deterministic, pure cache-pressure policy regression tests (#97)."""
from __future__ import annotations

import copy
import os
import socket
import subprocess

import pytest

from repocache.server_cache_pressure_policy_v1 import (
    CachePressurePolicyError, preview_cache_pressure,
)


BASE = {
    "warning_free_bytes": 100,
    "critical_free_bytes": 30,
    "recovery_margin_bytes": 10,
    "previous_level": "normal",
    "measurements_complete": True,
    "disk_writable": True,
}


def preview(free, **changes):
    params = {**BASE, "free_bytes": free, **changes}
    return preview_cache_pressure(**params)


@pytest.mark.parametrize("free,level", [
    (200, "normal"), (111, "normal"), (101, "normal"),
    (100, "warning"), (31, "warning"), (30, "critical"), (0, "critical"),
])
def test_thresholds_escalate_immediately(free, level):
    report = preview(free)
    assert report["pressure_level"] == level
    assert report["free_bytes_observed"] == free


def test_critical_hysteresis_preserves_alarm_until_recovered():
    first = preview(20)["pressure_level"]
    assert first == "critical"
    assert preview(39, previous_level=first)["pressure_level"] == "critical"
    promoted = preview(41, previous_level=first)
    assert promoted["pressure_level"] == "warning"
    assert promoted["reason_code"] == "LOW_FREE_SPACE"
    assert preview(100, previous_level="critical")["pressure_level"] == "warning"
    assert preview(111, previous_level="critical")["pressure_level"] == "normal"


def test_warning_hysteresis_and_immediate_reescalation():
    assert preview(101, previous_level="warning")["pressure_level"] == "warning"
    assert preview(110, previous_level="warning")["pressure_level"] == "warning"
    assert preview(111, previous_level="warning")["pressure_level"] == "normal"
    assert preview(30, previous_level="warning")["pressure_level"] == "critical"


@pytest.mark.parametrize("previous", ["unknown", "normal", "warning", "critical"])
def test_absent_free_space_is_unknown_not_zero(previous):
    result = preview(None, previous_level=previous)
    assert result["pressure_level"] == "unknown"
    assert result["free_bytes_observed"] is None
    assert result["reason_code"] == "FREE_SPACE_UNAVAILABLE"


def test_unavailable_writability_or_incomplete_metrics_cannot_claim_normal():
    assert preview(10000, disk_writable=None)["pressure_level"] == "unknown"
    assert preview(10000, measurements_complete=False)["pressure_level"] == "unknown"
    assert preview(20, measurements_complete=False)["pressure_level"] == "critical"
    assert preview(70, measurements_complete=False)["pressure_level"] == "warning"


def test_known_read_only_storage_forces_critical_even_without_space_metric():
    report = preview(None, disk_writable=False, measurements_complete=False)
    assert report["pressure_level"] == "critical"
    assert report["reason_code"] == "STORAGE_WRITE_REFUSED"


@pytest.mark.parametrize("change", [
    {"free_bytes": -1}, {"free_bytes": True},
    {"warning_free_bytes": 0}, {"critical_free_bytes": -1},
    {"warning_free_bytes": 29}, {"recovery_margin_bytes": -1},
    {"recovery_margin_bytes": 2**63}, {"previous_level": "healthy"},
    {"previous_level": 1}, {"measurements_complete": 0},
    {"disk_writable": "true"}, {"disk_writable": 1},
])
def test_refuse_untrusted_or_ambiguous_observations(change):
    with pytest.raises(CachePressurePolicyError, match="CACHE_PRESSURE_"):
        preview(1000, **change)


def test_large_valid_values_and_no_overflow_bypass():
    report = preview(
        2**63 - 1,
        warning_free_bytes=2**63 - 10,
        critical_free_bytes=2**63 - 20,
        recovery_margin_bytes=2**63 - 1,
        previous_level="critical",
    )
    assert report["pressure_level"] == "critical"


def test_explicitly_never_claims_native_activation_recovery_or_cleanup():
    for report in (
        preview(0), preview(500), preview(None),
        preview(0, disk_writable=False),
    ):
        assert report["status"] == "POLICY_PREVIEW_ONLY"
        for key in (
            "nginx_manager_behavior_verified", "cache_occupancy_verified",
            "upstream_fallback_verified", "authorizes_nginx_policy_apply",
            "authorizes_cache_cleanup", "authorizes_source_rewrite",
        ):
            assert report[key] is False


def test_pure_repeatable_no_host_access_or_caller_mutation(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("pure pressure preview invoked host/network/subprocess")

    monkeypatch.setattr(os, "statvfs", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    settings = copy.deepcopy(BASE)
    one = preview(90, **settings)
    two = preview(90, **settings)
    assert one == two
    assert settings == BASE
