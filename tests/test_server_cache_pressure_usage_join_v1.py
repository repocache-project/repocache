"""Real Linux selected-cache usage + partial pressure observational join (#97)."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from repocache import server_cache_pressure_alarm_observe_v1 as joined
from repocache import server_cache_pressure_observe_v1 as pressure_source
from repocache.server_native_repository_cache_v1 import (
    bootstrap_repository_cache_under_root,
)
from repocache.server_native_storage_bootstrap_v1 import (
    bootstrap_native_nginx_storage_under_root,
)

APT = "debian-trixie-main"
DNF = "almalinux-baseos"
DIGEST = "0123456789abcdef0123456789abcdef"
THRESHOLDS = dict(warning_free_bytes=4096 * 100,
                  critical_free_bytes=4096 * 10,
                  recovery_margin_bytes=4096 * 2)


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
        for rid in (APT, DNF):
            bootstrap_repository_cache_under_root(
                fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
                repository_id=rid,
            )
        yield fd, uid, gid, root
    finally:
        os.close(fd)


def check(owned, ids=(APT, DNF), previous=None, **overrides):
    fd, uid, gid, _ = owned
    return joined.preview_observed_cache_pressure_alarm_with_selected_usage(
        fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        repository_ids=ids, previous=previous,
        **{**THRESHOLDS, **overrides},
    )


def put(owned, rid, body):
    path = (owned[3] / "var/cache/nginx/repocache-managed" / rid /
            "a" / "bc")
    path.mkdir(mode=0o700, parents=True)
    target = path / DIGEST
    target.write_bytes(body)
    return target


def test_real_selected_usage_and_free_space_remain_distinct_partial_evidence(owned):
    apt = put(owned, APT, b"apt-source" * 11)
    dnf = put(owned, DNF, b"dnf-source" * 17)
    expected = (apt.stat().st_blocks + dnf.stat().st_blocks) * 512
    original = [(p.stat().st_ino, p.read_bytes()) for p in (apt, dnf)]
    result = check(owned, ids=(DNF, APT))
    assert result == check(owned, ids=(APT, DNF))
    assert result["status"] == "READ_ONLY_SELECTED_USAGE_PARTIAL_PRESSURE_CANDIDATE"
    assert result["selected_cache_usage"]["repository_ids_observed"] == [DNF, APT]
    assert result["selected_cache_usage"]["cache_files_observed"] == 2
    assert result["observed_selected_allocated_bytes"] == expected
    assert (result["observed_filesystem_free_bytes"]
            == result["partial_pressure_alarm"][
                "filesystem_observation"]["free_bytes_observed"])
    assert result["partial_pressure_alarm"]["alarm_candidate"][
        "next_state"]["telemetry_stale"] is True
    assert result["partial_pressure_alarm"]["alarm_candidate"][
        "next_state"]["alarm_level"] != "normal"
    for forbidden in (
        "selected_ids_complete_or_authenticated", "cross_sample_atomic",
        "nginx_writability_proven", "actual_reclaimable_space_verified",
        "telemetry_complete", "prior_alarm_authenticated",
        "authorizes_operator_alert_publish", "authorizes_nginx_cache_bypass",
        "authorizes_nginx_reload", "authorizes_cache_cleanup",
        "authorizes_state_commit",
    ):
        assert result[forbidden] is False
    assert [(p.stat().st_ino, p.read_bytes()) for p in (apt, dnf)] == original


def test_known_critical_free_space_remains_critical_with_actual_cache_bytes(
    owned, monkeypatch,
):
    put(owned, APT, b"persisted-fixture")
    monkeypatch.setattr(pressure_source.os, "fstatvfs",
                        lambda fd: SimpleNamespace(
                            f_frsize=4096, f_bavail=5, f_favail=500,
                            f_flag=0,
                        ))
    result = check(owned, ids=(APT,))
    state = result["partial_pressure_alarm"]["alarm_candidate"]
    assert state["next_state"]["alarm_level"] == "critical"
    assert state["next_state"]["telemetry_stale"] is True
    assert "CACHE_PRESSURE_CRITICAL" in state["event_codes"]
    assert result["observed_selected_allocated_bytes"] > 0
    assert not result["authorizes_operator_alert_publish"]


def test_only_selected_ids_cannot_claim_global_cache_zero_or_complete(owned):
    put(owned, APT, b"still-missing-DNF")
    put(owned, DNF, b"not-selected")
    result = check(owned, ids=(APT,))
    assert result["selected_cache_usage"]["cache_files_observed"] == 1
    assert result["selected_ids_complete_or_authenticated"] is False
    assert result["selected_cache_usage"]["full_cache_inventory_verified"] is False


def test_one_untracked_repository_aborts_even_if_other_cache_is_valid(owned):
    apt = put(owned, APT, b"preserved")
    with pytest.raises(joined.NativePressureAlarmObservationError,
                       match="NATIVE_PRESSURE_SELECTED_USAGE_INVALID"):
        check(owned, ids=(APT, "not-owned"))
    assert apt.read_bytes() == b"preserved"


@pytest.mark.parametrize("ids", [
    (), (APT, APT), (APT, "../escape"), (True,), [APT, DNF],
])
def test_unsafe_selected_ids_refused_without_empty_usage(owned, ids):
    with pytest.raises(joined.NativePressureAlarmObservationError,
                       match="NATIVE_PRESSURE_SELECTED_USAGE_INVALID"):
        check(owned, ids=ids)


def test_previous_alarm_forgery_never_becomes_authoritative(owned):
    with pytest.raises(joined.NativePressureAlarmObservationError,
                       match="NATIVE_PRESSURE_SELECTED_USAGE_INVALID"):
        check(owned, previous={"alarm_level": "normal", "sequence": 1})


def test_foreign_cache_file_aborts_without_partial_alarm(owned):
    good = put(owned, APT, b"keep")
    second = put(owned, DNF, b"keep2")
    (second.parent / "unexpected-file").write_bytes(b"foreign")
    with pytest.raises(joined.NativePressureAlarmObservationError,
                       match="NATIVE_PRESSURE_SELECTED_USAGE_INVALID"):
        check(owned)
    assert good.read_bytes() == b"keep"


def test_forged_selected_or_pressure_source_cannot_promote_incomplete_telemetry(
    owned, monkeypatch,
):
    original = joined.preview_owned_repository_cache_usage_under_root
    def tamper(*args, **kwargs):
        sample = original(*args, **kwargs)
        sample["full_cache_inventory_verified"] = True
        return sample
    monkeypatch.setattr(joined, "preview_owned_repository_cache_usage_under_root", tamper)
    with pytest.raises(joined.NativePressureAlarmObservationError):
        check(owned)
    monkeypatch.setattr(joined, "preview_owned_repository_cache_usage_under_root", original)

    observed = joined.preview_observed_cache_pressure_alarm
    def forged_pressure(*args, **kwargs):
        sample = observed(*args, **kwargs)
        sample["telemetry_complete"] = True
        return sample
    monkeypatch.setattr(joined, "preview_observed_cache_pressure_alarm",
                        forged_pressure)
    with pytest.raises(joined.NativePressureAlarmObservationError):
        check(owned)


def test_join_never_owns_write_delete_reload_or_alert_delivery():
    source = (Path(__file__).resolve().parents[1]
              / "src/repocache/server_cache_pressure_alarm_observe_v1.py"
              ).read_text(encoding="utf-8")
    for forbidden in (
        "os.unlink(", "os.remove(", "os.rmdir(", "os.mkdir(",
        "os.chmod(", "os.chown(", "subprocess", "systemctl",
        "shutil.rmtree", "nginx -s", "requests.post",
    ):
        assert forbidden not in source
