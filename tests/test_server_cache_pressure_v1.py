"""Source-only pressure/hysteresis regressions; no native service activation."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from repocache.server_cache_pressure_v1 import (
    CachePressureError, evaluate_cache_pressure,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document():
    sample = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    sample["repositories"][1]["id"] = "almalinux-baseos"
    sample["deployment"]["cache_policy"]["disk_pressure"] = {
        "warning_free_bytes": 200, "critical_free_bytes": 100,
    }
    return sample


def observe(free, *, previous="unknown", hysteresis=25, complete=True,
            total=1000, used=200, doc=None):
    return evaluate_cache_pressure(
        document() if doc is None else doc,
        filesystem_total_bytes=total,
        filesystem_free_bytes=free,
        cache_used_bytes=used,
        sample_complete=complete,
        previous_level=previous,
        recovery_hysteresis_bytes=hysteresis,
    )


@pytest.mark.parametrize("free,expected,advisory", [
    (400, "normal", "NO_PRESSURE_ALERT"),
    (200, "normal", "NO_PRESSURE_ALERT"),
    (199, "warning", "INSPECT_CACHE_CAPACITY"),
    (100, "warning", "INSPECT_CACHE_CAPACITY"),
    (99, "critical", "INSPECT_DISK_AND_UPSTREAM_FALLBACK"),
    (0, "critical", "INSPECT_DISK_AND_UPSTREAM_FALLBACK"),
])
def test_exact_warning_and_critical_boundaries(free, expected, advisory):
    result = observe(free)
    assert result["level"] == expected
    assert result["action_advisory"] == advisory
    assert result["measurement_complete"] is True
    assert result["no_pressure_in_sample"] == (expected == "normal")
    assert result["critical_free_bytes"] == 100
    assert result["warning_free_bytes"] == 200
    for key in ("native_cache_eviction_observed", "authorizes_cache_deletion",
                "authorizes_nginx_reload", "authorizes_client_source_change",
                "native_nginx_capability_verified"):
        assert result[key] is False


@pytest.mark.parametrize("previous,free,expected", [
    ("normal", 90, "critical"),
    ("normal", 150, "warning"),
    ("critical", 120, "critical"),
    ("critical", 125, "warning"),
    ("critical", 210, "warning"),
    ("critical", 225, "normal"),
    ("warning", 99, "critical"),
    ("warning", 210, "warning"),
    ("warning", 224, "warning"),
    ("warning", 225, "normal"),
    ("unknown", 300, "normal"),
])
def test_recovery_hysteresis_never_delays_escalation(previous, free, expected):
    assert observe(free, previous=previous)["level"] == expected


@pytest.mark.parametrize("kwargs", [
    {"complete": False},
    {"free": None},
    {"total": None},
    {"used": None},
    {"free": None, "used": None},
])
def test_incomplete_or_missing_observations_are_unknown(kwargs):
    inputs = {"free": 400, "total": 1000, "used": 200, "complete": True}
    inputs.update(kwargs)
    result = observe(**inputs)
    assert result["level"] == "unknown"
    assert result["action_advisory"] == "RECHECK_COMPLETE_METRICS"
    assert result["measurement_complete"] is False
    assert result["no_pressure_in_sample"] is False
    assert result["authorizes_nginx_reload"] is False


@pytest.mark.parametrize("bad", [
    {"free": -1}, {"free": True}, {"free": "100"},
    {"total": 0}, {"total": 30, "free": 35},
    {"total": 1000, "free": 900, "used": 200},
    {"used": -1}, {"used": 1.2},
    {"hysteresis": -1}, {"hysteresis": True},
    {"hysteresis": 2**63},
    {"complete": 1}, {"previous": "danger"}, {"previous": 5},
])
def test_invalid_and_inconsistent_measurements_fail_closed(bad):
    values = {"free": 300, "total": 1000, "used": 200,
              "hysteresis": 25, "complete": True, "previous": "normal"}
    values.update(bad)
    with pytest.raises(CachePressureError, match="^CACHE_PRESSURE_"):
        observe(**values)


@pytest.mark.parametrize("bad", [
    {"warning_free_bytes": 0, "critical_free_bytes": 50},
    {"warning_free_bytes": 40, "critical_free_bytes": 50},
    {"warning_free_bytes": True, "critical_free_bytes": 10},
    {"warning_free_bytes": 200, "critical_free_bytes": -1},
])
def test_reuse_strict_install_schema_and_refuse_invalid_policy(bad):
    config = document()
    config["deployment"]["cache_policy"]["disk_pressure"] = bad
    with pytest.raises(CachePressureError, match="CACHE_PRESSURE_POLICY_INVALID"):
        observe(300, doc=config)


def test_decision_is_pure_does_not_consume_cache_or_mutate_sources(monkeypatch):
    config = document()
    original = copy.deepcopy(config)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("read-only evaluator unexpectedly used host I/O")

    monkeypatch.setattr(os, "statvfs", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    assert observe(300, doc=config)["level"] == "normal"
    assert config == original


def test_fixed_redacted_output_does_not_return_filesystem_usage_or_host_paths():
    result = observe(75)
    assert "filesystem_free_bytes" not in result
    assert "filesystem_total_bytes" not in result
    assert "cache_used_bytes" not in result
    assert not any("path" in key for key in result)
    assert set(result) == {
        "schema_version", "status", "level", "measurement_complete",
        "previous_level", "warning_free_bytes", "critical_free_bytes",
        "recovery_hysteresis_bytes", "action_advisory",
        "no_pressure_in_sample", "native_cache_eviction_observed",
        "native_nginx_capability_verified", "authorizes_cache_deletion",
        "authorizes_nginx_reload", "authorizes_client_source_change",
    }
