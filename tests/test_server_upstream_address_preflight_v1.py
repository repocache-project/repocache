"""Static upstream DNS refusal tests; never attest runtime NGINX routing."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repocache.server_upstream_address_preflight_v1 import (
    UpstreamAddressError,
    inspect_upstream_address_snapshot,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def inspect(addresses, *, doc=None, repo_id="debian-trixie-main"):
    return inspect_upstream_address_snapshot(
        document() if doc is None else doc,
        repository_id=repo_id,
        answers_by_host=addresses,
    )


def test_global_ipv4_ipv6_snapshot_never_authorizes_activation():
    snapshot = {"mirror.example.invalid": ["8.8.8.8", "2001:4860:4860::8888"]}
    result = inspect(snapshot)
    assert result == {
        "schema_version": 1,
        "status": "STATIC_PREFLIGHT_ONLY",
        "repository_id": "debian-trixie-main",
        "checked_hosts": 1,
        "checked_addresses": 2,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "runtime_dns_binding_verified": False,
    }


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.169.254", "0.0.0.0", "255.255.255.255",
    "224.0.0.1", "fe80::1", "fc00::1", "::",
    "192.0.2.1", "2001:db8::1", "::ffff:8.8.8.8",
])
def test_rejects_non_global_and_mapped_addresses(ip):
    with pytest.raises(UpstreamAddressError, match="non-global"):
        inspect({"mirror.example.invalid": ["8.8.8.8", ip]})


@pytest.mark.parametrize("answers", [
    {},
    {"evil.example.invalid": ["8.8.8.8"]},
    {"mirror.example.invalid": []},
    {"mirror.example.invalid": ["8.8.8.8", "8.8.8.8"]},
    {"mirror.example.invalid": ["8.8.8.8"] * 33},
    {"mirror.example.invalid": ["8.8.8.8"], "extra.example.invalid": ["1.1.1.1"]},
    {"mirror.example.invalid": ["1.2.3.4%lo"]},
    {"mirror.example.invalid": [True]},
    {"mirror.example.invalid": ["not-an-ip"]},
    {"mirror.example.invalid": ["8.8.8.8"], "MIRROR.EXAMPLE.INVALID": ["1.1.1.1"]},
])
def test_missing_overlarge_ambiguous_or_untrusted_answers_refused(answers):
    with pytest.raises(UpstreamAddressError):
        inspect(answers)


def test_requires_existing_durable_id_and_complete_allowlist():
    with pytest.raises(UpstreamAddressError):
        inspect({"mirror.example.invalid": ["1.1.1.1"]},
                repo_id="unknown-id")
    original = document()
    original["repositories"][0]["upstream"]["allowed_hosts"].append("backup.example.invalid")
    with pytest.raises(UpstreamAddressError, match="missing"):
        inspect({"mirror.example.invalid": ["1.1.1.1"]}, doc=original)


def test_two_host_snapshot_checks_all_and_rejects_mixed_private():
    source = document()
    source["repositories"][0]["upstream"]["allowed_hosts"].append("backup.example.invalid")
    valid = {"mirror.example.invalid": ["8.8.4.4"], "backup.example.invalid": ["1.1.1.1"]}
    assert inspect(valid, doc=source)["checked_hosts"] == 2
    valid["backup.example.invalid"] = ["10.1.2.3"]
    with pytest.raises(UpstreamAddressError, match="non-global"):
        inspect(valid, doc=source)


def test_does_not_write_produce_network_traffic_or_call_nginx(monkeypatch):
    import os
    import socket
    import subprocess
    def forbidden(*_args, **_kwargs):
        raise AssertionError("no system side effects permitted")
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    result = inspect({"mirror.example.invalid": ["8.8.8.8"]})
    assert result["runtime_dns_binding_verified"] is False
