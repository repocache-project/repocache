"""Safe, deterministic alarm-to-cache-off candidate tests (#97, Stage A)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repocache.server_cache_bypass_decision_v1 import (
    CachePressureBypassError,
    preview_cache_pressure_nginx_recovery_candidate as decide,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
HOST = "mirror.example.invalid"
CA = "/etc/ssl/certs/ca-certificates.crt"
APT = "debian-trixie-main"
DNF = "almalinux-baseos"
MARGIN = 1024


def fixture(*, disable_dnf=False):
    document = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    for entry in document["repositories"]:
        entry["desired_state"] = "active"
        if entry["kind"] == "dnf":
            entry["id"] = DNF
            if disable_dnf:
                entry["desired_state"] = "disabled"
    pins = {
        entry["id"]: {HOST: ["8.8.8.8"]}
        for entry in document["repositories"]
        if entry["desired_state"] == "active"
    }
    thresholds = document["deployment"]["cache_policy"]["disk_pressure"]
    return document, pins, thresholds["critical_free_bytes"], thresholds["warning_free_bytes"]


def proposed(document, pins, *, free_bytes, **overrides):
    settings = {
        "expected_state_generation": 0,
        "candidate_pins_by_repository": pins,
        "ca_bundle_path": CA,
        "free_bytes": free_bytes,
        "free_inodes": 100,
        "disk_writable": True,
        "measurements_complete": True,
        "recovery_margin_bytes": MARGIN,
    }
    settings.update(overrides)
    return decide(document, **settings)


def assert_no_authority(result):
    assert result["status"] == "NON_ACTIVATING_PRESSURE_BYPASS_CANDIDATE"
    for name in (
        "metrics_source_authenticated", "previous_alarm_state_authenticated",
        "previous_bypass_state_authenticated", "installed_nginx_exposure_verified",
        "host_root_authenticated", "nginx_manager_recovery_verified",
        "authorizes_nginx_policy_apply", "authorizes_nginx_reload",
        "authorizes_cache_cleanup", "authorizes_catalog_publication",
        "authorizes_client_fallback_apply",
    ):
        assert result[name] is False
    assert result["nginx_candidate"]["authorizes_nginx_activation"] is False
    assert result["nginx_candidate"]["authorizes_catalog_publication"] is False
    assert result["alarm_candidate"]["authorizes_operator_alert_publish"] is False


def test_verified_healthy_proposes_unmodified_default_nginx_candidate():
    doc, pins, _, warning = fixture()
    result = proposed(doc, pins, free_bytes=warning + MARGIN + 1)
    unchanged = render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=0,
        candidate_pins_by_repository=pins, ca_bundle_path=CA,
    )
    assert result["decision_code"] == "PROPOSE_RESTORE_AFTER_VERIFIED_RECOVERY"
    assert result["bypass_repository_ids"] == []
    assert result["nginx_candidate"] == unchanged
    assert_no_authority(result)


def test_critical_bytes_proposes_only_active_cached_routes_without_touching_tls():
    doc, pins, critical, _ = fixture()
    base = render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=0,
        candidate_pins_by_repository=pins, ca_bundle_path=CA,
    )
    result = proposed(doc, pins, free_bytes=critical)
    assert result["decision_code"] == "PROPOSE_BYPASS_ON_OBSERVED_CRITICAL"
    assert result["alarm_candidate"]["reason_code"] == "CRITICAL_FREE_SPACE"
    assert result["bypass_repository_ids"] == [DNF, APT]
    assert result["nginx_candidate"]["http_upstream_fragment"] == base[
        "http_upstream_fragment"
    ]
    assert result["nginx_candidate"]["server_location_fragment"].count(
        "    proxy_cache off;"
    ) == 2
    assert result["nginx_candidate"]["proposed_repository_ids"] == [DNF, APT]
    assert "    proxy_ssl_verify on;" in result["nginx_candidate"][
        "server_location_fragment"
    ]
    assert_no_authority(result)


@pytest.mark.parametrize("observed,reason", [
    ({"disk_writable": False}, "STORAGE_WRITE_REFUSED"),
    ({"free_inodes": 0}, "FILESYSTEM_INODES_EXHAUSTED"),
])
def test_proven_hard_failure_proposes_bypass_despite_missing_other_metrics(
    observed, reason,
):
    doc, pins, _, _ = fixture()
    result = proposed(
        doc, pins, free_bytes=None,
        **{"measurements_complete": False, "free_inodes": None,
           "disk_writable": None, **observed},
    )
    assert result["alarm_candidate"]["reason_code"] == reason
    assert not result["alarm_candidate"]["measurements_complete"]
    assert result["decision_code"] == "PROPOSE_BYPASS_ON_OBSERVED_CRITICAL"
    assert result["bypass_repository_ids"] == [DNF, APT]
    assert result["alarm_candidate"]["free_bytes_observed"] is None
    assert_no_authority(result)


def test_known_critical_bytes_are_not_hidden_by_missing_inode_metrics():
    doc, pins, critical, _ = fixture()
    result = proposed(
        doc, pins, free_bytes=critical, free_inodes=None,
        disk_writable=None, measurements_complete=False,
    )
    assert result["decision_code"] == "PROPOSE_BYPASS_ON_OBSERVED_CRITICAL"
    assert result["alarm_candidate"]["reason_code"] == "CRITICAL_FREE_SPACE"
    assert result["bypass_repository_ids"] == [DNF, APT]


def test_warning_maintains_any_existing_bypass_until_verified_normal():
    doc, pins, critical, warning = fixture()
    active = proposed(doc, pins, free_bytes=critical)
    held = proposed(
        doc, pins, free_bytes=warning,
        previous_alarm=active["alarm_candidate"]["next_state"],
        previously_bypassed_ids=tuple(active["bypass_repository_ids"]),
    )
    assert held["alarm_candidate"]["next_state"]["alarm_level"] == "warning"
    assert held["decision_code"] == "HOLD_LAST_BYPASS_WHILE_NOT_RECOVERED"
    assert held["bypass_repository_ids"] == [DNF, APT]

    still_held = proposed(
        doc, pins, free_bytes=warning + MARGIN,
        previous_alarm=held["alarm_candidate"]["next_state"],
        previously_bypassed_ids=tuple(held["bypass_repository_ids"]),
    )
    assert still_held["bypass_repository_ids"] == [DNF, APT]
    assert still_held["alarm_candidate"]["next_state"]["alarm_level"] == "warning"

    recovered = proposed(
        doc, pins, free_bytes=warning + MARGIN + 1,
        previous_alarm=still_held["alarm_candidate"]["next_state"],
        previously_bypassed_ids=tuple(still_held["bypass_repository_ids"]),
    )
    assert recovered["alarm_candidate"]["next_state"]["alarm_level"] == "normal"
    assert recovered["bypass_repository_ids"] == []
    assert recovered["decision_code"] == "PROPOSE_RESTORE_AFTER_VERIFIED_RECOVERY"
    assert "CACHE_PRESSURE_RECOVERED" in recovered["alarm_candidate"]["event_codes"]
    assert_no_authority(recovered)


def test_stale_critical_and_unknown_metric_cannot_silently_clear_bypass():
    doc, pins, critical, warning = fixture()
    prior = proposed(doc, pins, free_bytes=critical)
    stale = proposed(
        doc, pins, free_bytes=None, disk_writable=None,
        measurements_complete=False, free_inodes=None,
        previous_alarm=prior["alarm_candidate"]["next_state"],
        previously_bypassed_ids=(APT,),
    )
    assert stale["alarm_candidate"]["next_state"]["alarm_level"] == "critical"
    assert stale["alarm_candidate"]["reason_code"] == (
        "ALARM_HELD_ON_INCOMPLETE_TELEMETRY"
    )
    assert stale["bypass_repository_ids"] == [APT]
    assert stale["decision_code"] == "HOLD_LAST_BYPASS_WHILE_NOT_RECOVERED"

    unknown = proposed(
        doc, pins, free_bytes=None, disk_writable=None,
        measurements_complete=False, free_inodes=None,
        previously_bypassed_ids=(APT,),
    )
    assert unknown["alarm_candidate"]["next_state"]["alarm_level"] == "unknown"
    assert unknown["bypass_repository_ids"] == [APT]
    assert_no_authority(unknown)


def test_only_desired_active_repository_may_be_selected():
    doc, pins, critical, _ = fixture(disable_dnf=True)
    result = proposed(doc, pins, free_bytes=critical)
    assert result["bypass_repository_ids"] == [APT]
    assert result["nginx_candidate"]["proposed_repository_ids"] == [APT]
    assert result["nginx_candidate"]["server_location_fragment"].count(
        "    proxy_cache off;"
    ) == 1
    assert_no_authority(result)


def test_native_min_free_coexists_with_bypass_without_activation():
    doc, pins, critical, _ = fixture()
    result = proposed(
        doc, pins, free_bytes=critical, native_min_free_supported=True,
    )
    assert " min_free=" in result["nginx_candidate"]["http_upstream_fragment"]
    assert result["nginx_candidate"]["native_min_free_supported_verified"] is False
    assert result["nginx_candidate"]["native_min_free_candidate_emitted"] is True
    assert_no_authority(result)


@pytest.mark.parametrize("bad", [
    None, True, False, 3, "active", ["debian-trixie-main"],
    ("debian-trixie-main", "debian-trixie-main"),
    ("unknown-repository",), (True,), (APT,) * 100_000,
])
def test_invalid_previous_bypass_state_refused_before_pressure_decision(bad):
    doc, pins, critical, _ = fixture()
    with pytest.raises(CachePressureBypassError, match="^CACHE_BYPASS_PRIOR_IDS_INVALID$"):
        proposed(doc, pins, free_bytes=critical, previously_bypassed_ids=bad)


@pytest.mark.parametrize("bad", [
    {"expected_state_generation": 1}, {"candidate_pins_by_repository": {}},
    {"ca_bundle_path": "/tmp/unsafe;newline"},
    {"free_bytes": -1}, {"free_inodes": True},
    {"measurements_complete": 1}, {"disk_writable": "false"},
    {"recovery_margin_bytes": -1}, {"native_min_free_supported": 1},
    {"previous_alarm": {"alarm_level": "critical"}},
])
def test_invalid_document_pins_telemetry_and_alarm_fail_closed(bad):
    doc, pins, critical, _ = fixture()
    with pytest.raises(CachePressureBypassError, match="^CACHE_BYPASS_CANDIDATE_INVALID$"):
        proposed(doc, pins, free_bytes=critical, **bad)


def test_repeatable_pure_plan_no_host_or_network_mutation(monkeypatch):
    doc, pins, critical, _ = fixture()
    original = json.dumps(doc, sort_keys=True)
    import os
    import socket
    import subprocess

    def forbidden(*_a, **_k):
        pytest.fail("pure policy proposal attempted host/network/subprocess access")

    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(os, "statvfs", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    a = proposed(doc, pins, free_bytes=critical)
    b = proposed(doc, pins, free_bytes=critical)
    assert a == b
    assert json.dumps(doc, sort_keys=True) == original
    assert_no_authority(a)
