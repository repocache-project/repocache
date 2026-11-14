"""Automatic upstream DNS pin refresh candidates; never a live NGINX policy."""
from __future__ import annotations

import copy
import json
import socket
from pathlib import Path

import pytest

from repocache.server_upstream_rotation_v1 import (
    MIN_REFRESH_INTERVAL_SECONDS,
    UpstreamRotationError,
    propose_automatic_upstream_refresh,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
HOST = "mirror.example.invalid"


def document():
    value = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    value["repositories"][0]["desired_state"] = "active"
    return value


def answer(host, port, *, family, type, proto):
    assert host == HOST
    assert port == 443
    assert family == socket.AF_UNSPEC
    assert type == socket.SOCK_STREAM
    assert proto == socket.IPPROTO_TCP
    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
         "", ("8.8.8.8", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
         "", ("2001:4860:4860::8888", 443, 0, 0)),
    ]


def refresh(*, doc=None, pins=None, resolver=answer, generation=0):
    return propose_automatic_upstream_refresh(
        document() if doc is None else doc,
        repository_id="debian-trixie-main",
        current_generation=generation,
        previous_pins_by_host=pins,
        resolver=resolver,
    )


def test_initial_automatic_refresh_requires_staged_activation():
    result = refresh()
    assert result["status"] == "PIN_REFRESH_CANDIDATE"
    assert result["changed"] is True
    assert result["candidate_pins_by_host"] == {
        HOST: ["2001:4860:4860::8888", "8.8.8.8"]
    }
    assert result["requires_staged_nginx_activation"] is True
    assert result["recommended_min_refresh_seconds"] == MIN_REFRESH_INTERVAL_SECONDS
    for key in (
        "authorizes_nginx_activation", "authorizes_catalog_publication",
        "trusted_state_provenance_verified",
        "runtime_destination_enforcement_verified",
        "automatic_scheduler_installed",
    ):
        assert result[key] is False


def test_equivalent_answers_are_noop_and_do_not_require_reload():
    first = refresh()
    later = refresh(pins={HOST: list(reversed(
        first["candidate_pins_by_host"][HOST]
    ))})
    assert later["status"] == "PINS_UNCHANGED"
    assert later["changed"] is False
    assert later["requires_staged_nginx_activation"] is False


def test_address_rotation_produces_new_pins_without_manual_approval():
    old = {HOST: ["1.1.1.1"]}
    candidate = refresh(pins=old)
    assert candidate["status"] == "PIN_REFRESH_CANDIDATE"
    assert candidate["candidate_pins_by_host"][HOST] != old[HOST]
    assert old == {HOST: ["1.1.1.1"]}
    assert candidate["authorizes_nginx_activation"] is False


@pytest.mark.parametrize("unsafe", [
    "127.0.0.1", "10.5.0.1", "169.254.169.254",
    "192.168.0.1", "0.0.0.0", "255.255.255.255",
    "::1", "fc00::1", "fe80::1", "2001:db8::1", "::ffff:8.8.8.8",
    "192.0.2.12",
])
def test_mixed_public_and_non_global_dns_aborts_whole_rotation(unsafe):
    def malicious(_host, _port, **_kw):
        return [
            (socket.AF_INET, 1, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET6 if ":" in unsafe else socket.AF_INET,
             1, 6, "", (unsafe, 443, 0, 0) if ":" in unsafe
             else (unsafe, 443)),
        ]
    with pytest.raises(UpstreamRotationError, match="unsafe"):
        refresh(pins={HOST: ["1.1.1.1"]}, resolver=malicious)


def test_resolution_failure_does_not_fall_back_to_unchecked_hostname():
    def offline(*_args, **_kwargs):
        raise socket.gaierror(-2, "internal resolver detail")
    with pytest.raises(UpstreamRotationError, match="DNS lookup: failed") as exc:
        refresh(pins={HOST: ["1.1.1.1"]}, resolver=offline)
    assert "internal resolver detail" not in str(exc.value)


def test_unapproved_or_duplicate_hosts_in_prior_pins_refused_before_dns():
    def should_not_resolve(*_args, **_kwargs):
        raise AssertionError("unsafe prior pins must be refused before DNS")
    for bad in [
        {"unapproved.example.invalid": ["1.1.1.1"]},
        {HOST: ["1.1.1.1"], "MIRROR.EXAMPLE.INVALID": ["8.8.8.8"]},
        {HOST: ["10.0.0.5"]},
        {HOST: []},
    ]:
        with pytest.raises(UpstreamRotationError, match="incomplete or unsafe"):
            refresh(pins=bad, resolver=should_not_resolve)


def test_disabled_repository_and_stale_generation_do_not_query_dns():
    def forbid(*_args, **_kwargs):
        raise AssertionError("untrusted input must not query DNS")
    disabled = document()
    disabled["repositories"][0]["desired_state"] = "disabled"
    with pytest.raises(UpstreamRotationError, match="not enabled"):
        refresh(doc=disabled, resolver=forbid)
    with pytest.raises(UpstreamRotationError, match="stale"):
        refresh(generation=1, resolver=forbid)
    invalid = document()
    invalid["repositories"][0]["upstream"]["allowed_hosts"].append(
        "unapproved.example.invalid"
    )
    invalid["repositories"][0]["upstream"]["allowed_hosts"].append(
        "unapproved.example.invalid"
    )
    with pytest.raises(UpstreamRotationError, match="invalid"):
        refresh(doc=invalid, resolver=forbid)


def test_all_allowed_hosts_must_pass_and_one_failure_rejects_entire_snapshot():
    doc = document()
    doc["repositories"][0]["upstream"]["allowed_hosts"].append(
        "backup.example.invalid"
    )
    seen = []
    def multi(host, port, **_kw):
        seen.append(host)
        if host == "backup.example.invalid":
            return [(socket.AF_INET, 1, 6, "", ("10.1.1.1", 443))]
        return [(socket.AF_INET, 1, 6, "", ("1.1.1.1", 443))]
    with pytest.raises(UpstreamRotationError, match="unsafe"):
        refresh(doc=doc, resolver=multi)
    assert seen == ["backup.example.invalid", HOST]


@pytest.mark.parametrize("bad_answers", [
    [],
    [("bad",)],
    [(socket.AF_UNIX, 1, 6, "", ("1.1.1.1", 443))],
    [(socket.AF_INET, 1, 6, "", ("not-ip", 443))],
    [(socket.AF_INET, 1, 6, "", ("1.1.1.1", 443))] * 33,
    None,
])
def test_incomplete_unsupported_or_unbounded_resolver_output_refused(bad_answers):
    with pytest.raises(UpstreamRotationError):
        refresh(resolver=lambda *_args, **_kwargs: bad_answers)


def test_repeated_getaddrinfo_records_deduplicated():
    def duplicate(*_args, **_kwargs):
        records = answer(HOST, 443, family=socket.AF_UNSPEC,
                         type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        return [records[0], records[0], records[1]]
    assert refresh(resolver=duplicate)["candidate_pins_by_host"] == {
        HOST: ["2001:4860:4860::8888", "8.8.8.8"]
    }


def test_dns_lookup_has_no_http_connection_nginx_or_filesystem_mutation(monkeypatch):
    import os
    import subprocess
    def forbidden(*_args, **_kwargs):
        raise AssertionError("refresh cannot activate a service or connect HTTP")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert refresh()["authorizes_nginx_activation"] is False


def test_invalid_oversized_prior_snapshot_refused_without_mutation():
    original = document()
    before = copy.deepcopy(original)
    with pytest.raises(UpstreamRotationError):
        refresh(doc=original, pins={HOST: ["8" * 200000]})
    assert original == before


def test_explicit_https_port_is_resolved_without_silent_443_fallback():
    doc = document()
    doc["repositories"][0]["upstream"]["base_url"] = (
        "https://mirror.example.invalid:8443/debian/"
    )
    def port_checked(host, port, *, family, type, proto):
        assert host == HOST and port == 8443
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                 "", ("8.8.8.8", 8443))]
    result = refresh(doc=doc, resolver=port_checked)
    assert result["candidate_pins_by_host"] == {HOST: ["8.8.8.8"]}


@pytest.mark.parametrize("sockaddr_record", [
    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
     "", ("8.8.8.8", 8443)),
    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
     "", ("2001:4860:4860::8888", 443)),
    (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
     "", ("8.8.8.8", 443, 0, 0)),
    (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
     "", ("2001:4860:4860::8888", 443, 0, 5)),
    (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
     "", ("2001:4860:4860::8888", 443, 1, 0)),
    (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
     "", ("8.8.8.8", 443)),
    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
     "", ("8.8.8.8", False)),
])
def test_dns_sockaddr_must_match_approved_tcp_family_port_and_scope(sockaddr_record):
    with pytest.raises(UpstreamRotationError, match="mismatch"):
        refresh(resolver=lambda *_args, **_kwargs: [sockaddr_record])


def test_default_refresh_uses_killable_bounded_dns_not_blocking_libc(monkeypatch):
    from repocache import server_upstream_rotation_v1 as rotation

    called = []
    def bounded(host, port, **kwargs):
        called.append((host, port, kwargs))
        return answer(host, port, **kwargs)

    monkeypatch.setattr(rotation, "bounded_getaddrinfo", bounded)
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *_a, **_kw: pytest.fail("unbounded libc resolver used"))
    result = refresh(resolver=None)
    assert result["candidate_pins_by_host"][HOST] == [
        "2001:4860:4860::8888", "8.8.8.8",
    ]
    assert len(called) == 1
    assert called[0][0:2] == (HOST, 443)
    assert called[0][2] == {
        "family": socket.AF_UNSPEC,
        "type": socket.SOCK_STREAM,
        "proto": socket.IPPROTO_TCP,
    }
    assert not result["authorizes_nginx_activation"]


def test_default_bounded_dns_timeout_refuses_candidate_without_host_details(monkeypatch):
    from repocache import server_upstream_rotation_v1 as rotation

    def timeout(*_args, **_kwargs):
        raise socket.gaierror("internal DNS hostname/private resolver failure")

    monkeypatch.setattr(rotation, "bounded_getaddrinfo", timeout)
    with pytest.raises(UpstreamRotationError, match="^DNS lookup: failed$") as caught:
        refresh(resolver=None)
    assert "private resolver" not in str(caught.value)
