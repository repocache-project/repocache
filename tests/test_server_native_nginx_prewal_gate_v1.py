"""Fail-closed active vendor NGINX gate before native v2 WAL (#27).

These tests exercise a read-only unit observation, not host activation.
Actual systemd, kernel and SELinux behavior remains native guest evidence.
"""
from __future__ import annotations

import pytest

from repocache import server_native_v2_transaction_v1 as native
from repocache.server_native_nginx_effective_unit_v1 import EffectiveNginxUnitError


GOOD = {
    "status": "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION",
    "unit_name": "nginx.service",
    "main_pid_observed": 1234,
    "kernel_nginx_master_executable_inode_observed": True,
    "effective_unit_shape_observed": True,
    "vendor_unit_sha256": "a" * 64,
    "authorizes_systemctl": False,
    "authorizes_nginx_reload": False,
}


def test_matching_active_vendor_unit_allows_later_stage_only(monkeypatch):
    observed = []
    monkeypatch.setattr(
        native, "inspect_effective_native_nginx_unit",
        lambda distribution: observed.append(distribution) or dict(GOOD),
    )
    assert native._require_active_nginx_before_wal("debian") is None
    assert observed == ["debian"]


@pytest.mark.parametrize("delta", [
    {"status": "FOREIGN"},
    {"unit_name": "other.service"},
    {"main_pid_observed": 0},
    {"main_pid_observed": True},
    {"main_pid_observed": "1234"},
    {"kernel_nginx_master_executable_inode_observed": False},
    {"effective_unit_shape_observed": False},
    {"vendor_unit_sha256": "b" * 63},
    {"vendor_unit_sha256": "b" * 64 + "x"},
    {"vendor_unit_sha256": "A" * 64},
    {"authorizes_systemctl": True},
    {"authorizes_nginx_reload": True},
])
def test_foreign_or_invalid_unit_refused(monkeypatch, delta):
    monkeypatch.setattr(
        native, "inspect_effective_native_nginx_unit",
        lambda distribution: dict(GOOD, **delta),
    )
    with pytest.raises(
        native.NativeV2TransactionError,
        match="^NGINX_NOT_ACTIVE_BEFORE_WAL$",
    ):
        native._require_active_nginx_before_wal("almalinux")


@pytest.mark.parametrize("report", [None, {}, {"status": "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION"}])
def test_missing_or_incomplete_observation_refused(monkeypatch, report):
    monkeypatch.setattr(
        native, "inspect_effective_native_nginx_unit", lambda distribution: report,
    )
    with pytest.raises(
        native.NativeV2TransactionError,
        match="^NGINX_NOT_ACTIVE_BEFORE_WAL$",
    ):
        native._require_active_nginx_before_wal("debian")


def test_inactive_or_unreadable_systemd_is_redacted(monkeypatch):
    def unavailable(_distribution):
        raise EffectiveNginxUnitError("private /run/systemd inaccessible")
    monkeypatch.setattr(native, "inspect_effective_native_nginx_unit", unavailable)
    with pytest.raises(native.NativeV2TransactionError) as denied:
        native._require_active_nginx_before_wal("debian")
    assert str(denied.value) == "NGINX_NOT_ACTIVE_BEFORE_WAL"
    assert "private" not in str(denied.value)
