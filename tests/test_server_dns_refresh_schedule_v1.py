"""Fail-closed automatic DNS candidate scheduling; never authorizes NGINX."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import socket

import pytest

from repocache.server_dns_refresh_schedule_v1 import (
    INITIAL_FAILURE_BACKOFF_SECONDS,
    MAX_FAILURE_BACKOFF_SECONDS,
    RefreshSlot,
    UpstreamScheduleError,
    refresh_due,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
HOST = "mirror.example.invalid"


def document(*, generation=0, active=True):
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc["repositories"][0]["desired_state"] = "active" if active else "disabled"
    doc["expected_state_generation"] = generation
    return doc


def answer(host, port, *, family, type, proto):
    assert (host, port, family, type, proto) == (
        HOST, 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )
    return [(socket.AF_INET, socket.SOCK_STREAM,
             socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]


def tick(*, doc=None, generation=0, now=1000.0, slot=None,
         pins=None, resolver=answer):
    return refresh_due(
        document(generation=generation) if doc is None else doc,
        repository_id="debian-trixie-main",
        current_generation=generation, previous_pins_by_host=pins,
        now_monotonic=now, prior_slot=slot, resolver=resolver,
    )


def test_initial_due_tick_returns_candidate_without_authority():
    result = tick()
    assert result["status"] == "PIN_CHANGE_CANDIDATE"
    assert result["candidate"]["candidate_pins_by_host"] == {HOST: ["8.8.8.8"]}
    assert result["slot"].failures == 0
    assert 1300 <= result["slot"].next_due <= 1360
    assert result["candidate"]["automatic_scheduler_installed"] is False
    for key in ("authorizes_nginx_activation", "authorizes_catalog_publication",
                "automatic_scheduler_installed"):
        assert result[key] is False


def test_not_due_does_not_query_dns_or_stage_changes():
    first = tick()
    def unexpected(*_a, **_kw):
        pytest.fail("not-due tick must not query DNS")
    next_tick = tick(now=first["slot"].next_due - 0.01,
                     slot=first["slot"], resolver=unexpected)
    assert next_tick["status"] == "NOT_DUE"
    assert next_tick["candidate"] is None
    assert next_tick["slot"] == first["slot"]


def test_untrusted_future_slot_cannot_suspend_periodic_dns_indefinitely():
    """A forged hint is never a durable lease or a source of authorization."""
    future = RefreshSlot("debian-trixie-main", 0, 1e14, 0)
    observed = []

    def counted(*args, **kwargs):
        observed.append(True)
        return answer(*args, **kwargs)

    refresh = tick(now=1000.0, slot=future, resolver=counted)
    assert refresh["status"] == "PIN_CHANGE_CANDIDATE"
    assert observed == [True]
    assert refresh["slot"].next_due <= 1360
    assert refresh["authorizes_nginx_activation"] is False

    # A forged retry with the maximum valid failure count cannot lock out
    # periodic refresh either. It is abandoned rather than trusting a date.
    retry = RefreshSlot("debian-trixie-main", 0, 1e14, 12)
    observed.clear()
    attempted = tick(now=1000.0, slot=retry, resolver=counted)
    assert attempted["status"] == "PIN_CHANGE_CANDIDATE"
    assert attempted["slot"].failures == 0
    assert observed == [True]


def test_valid_future_retry_slot_still_defers_work():
    slot = RefreshSlot("debian-trixie-main", 0, 4600.0, 12)

    def forbidden(*_args, **_kwargs):
        pytest.fail("bounded retry deadline must be respected")

    result = tick(now=1000.0, slot=slot, resolver=forbidden)
    assert result["status"] == "NOT_DUE"
    assert result["slot"] == slot


def test_identical_pins_reset_backoff_and_skip_reactivation():
    first = tick()
    second = tick(
        now=first["slot"].next_due, slot=first["slot"],
        pins={HOST: ["8.8.8.8"]},
    )
    assert second["status"] == "PINS_UNCHANGED"
    assert second["candidate"]["changed"] is False
    assert second["candidate"]["requires_staged_nginx_activation"] is False
    assert second["slot"].failures == 0


def test_changed_public_dns_reproposes_pins_without_manual_ip_maintenance():
    result = tick(pins={HOST: ["1.1.1.1"]})
    assert result["status"] == "PIN_CHANGE_CANDIDATE"
    assert result["candidate"]["changed"] is True
    assert result["candidate"]["candidate_pins_by_host"][HOST] == ["8.8.8.8"]


def test_failure_is_redacted_and_retries_with_exponential_bounded_backoff():
    def dns_failure(*_a, **_kw):
        raise socket.gaierror("sensitive hostname or DNS response")
    current = None
    now = 0.0
    delays = []
    for _ in range(10):
        state = tick(slot=current, now=now, resolver=dns_failure)
        assert state["candidate"] is None
        assert state["status"] == "DNS_RETRY_SCHEDULED"
        assert state["authorizes_nginx_activation"] is False
        current = state["slot"]
        delay = current.next_due - now
        delays.append(delay)
        assert INITIAL_FAILURE_BACKOFF_SECONDS <= delay <= MAX_FAILURE_BACKOFF_SECONDS
        now = current.next_due
    assert delays[1] > delays[0]
    assert delays[-1] == MAX_FAILURE_BACKOFF_SECONDS
    assert current.failures == 10


def test_mixed_public_private_answer_aborts_with_no_partial_candidate():
    def malicious(host, port, **kw):
        return answer(host, port, **kw) + [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
             "", ("169.254.169.254", 443)),
        ]
    result = tick(pins={HOST: ["1.1.1.1"]}, resolver=malicious)
    assert result["status"] == "DNS_RETRY_SCHEDULED"
    assert result["candidate"] is None


def test_success_after_dns_failure_clears_retry_counter():
    failure = tick(resolver=lambda *_a, **_kw: (_ for _ in ()).throw(
        socket.gaierror("offline")
    ))
    recovered = tick(now=failure["slot"].next_due,
                     slot=failure["slot"], resolver=answer)
    assert recovered["status"] == "PIN_CHANGE_CANDIDATE"
    assert recovered["slot"].failures == 0
    assert recovered["slot"].next_due - failure["slot"].next_due >= 300


def test_new_generation_is_immediately_due_regardless_of_old_slot():
    old = tick()
    result = tick(generation=1, slot=old["slot"], now=1001)
    assert result["status"] == "PIN_CHANGE_CANDIDATE"
    assert result["slot"].generation == 1


@pytest.mark.parametrize("bad_now", [
    -1, float("nan"), float("inf"), False, "100", 1e20,
])
def test_bad_monotonic_clock_fails_closed(bad_now):
    with pytest.raises(UpstreamScheduleError, match="SCHEDULE_INPUT_INVALID"):
        tick(now=bad_now)


@pytest.mark.parametrize("bad_slot", [
    object(),
    RefreshSlot("wrong-repo", 0, 1200, 0),
    RefreshSlot("debian-trixie-main", True, 1200, 0),
    RefreshSlot("debian-trixie-main", 0, float("nan"), 0),
    RefreshSlot("debian-trixie-main", 0, 1200, True),
    RefreshSlot("debian-trixie-main", 0, 1200, 13),
])
def test_invalid_or_forged_schedule_slot_fails_closed(bad_slot):
    with pytest.raises(UpstreamScheduleError, match="SCHEDULE_SLOT_INVALID"):
        tick(slot=bad_slot)


def test_stale_generation_and_disabled_repository_refused_even_when_not_due():
    prior = tick()["slot"]
    with pytest.raises(UpstreamScheduleError, match="SCHEDULE_STALE_GENERATION"):
        tick(doc=document(generation=1), slot=prior)
    with pytest.raises(UpstreamScheduleError, match="SCHEDULE_REPOSITORY_NOT_ACTIVE"):
        tick(doc=document(active=False), slot=prior)


def test_non_authorizing_tick_has_no_fs_writes_http_or_service_commands(monkeypatch):
    import os
    import subprocess
    def forbidden(*_a, **_kw):
        pytest.fail("scheduled DNS candidate cannot write or activate")
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert tick()["status"] == "PIN_CHANGE_CANDIDATE"
