"""Exact TLS + repository-route NGINX candidate, not host activation (#28/#30)."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError,
    render_repository_https_server_candidate,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)
from repocache.server_nginx_tls_listener_candidate_v1 import (
    render_native_tls_listener_candidate,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
CA = "/etc/ssl/certs/ca-certificates.crt"
HOST = "mirror.example.invalid"


def document(apt=True, dnf=True, *, generation=3):
    obj = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    obj["expected_state_generation"] = generation
    obj["repositories"][0]["desired_state"] = "active" if apt else "disabled"
    obj["repositories"][1]["id"] = "almalinux-baseos"
    obj["repositories"][1]["desired_state"] = "active" if dnf else "disabled"
    return obj


def pins(apt=True, dnf=True):
    return {
        name: {HOST: ["8.8.8.8"]}
        for name, enabled in (
            ("debian-trixie-main", apt),
            ("almalinux-baseos", dnf),
        ) if enabled
    }


def render(d=None, *, candidates=None, generation=3, **kwargs):
    return render_repository_https_server_candidate(
        document() if d is None else d,
        expected_state_generation=generation,
        candidate_pins_by_repository=pins() if candidates is None else candidates,
        ca_bundle_path=CA,
        **kwargs,
    )


def test_exact_composition_preserves_tls_routing_and_input():
    doc = document()
    before = copy.deepcopy(doc)
    candidate = render(doc)
    raw = render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=3,
        candidate_pins_by_repository=pins(), ca_bundle_path=CA,
    )
    tls = render_native_tls_listener_candidate(doc)
    assert candidate["status"] == "HTTPS_REPOSITORY_SERVER_CANDIDATE_ONLY"
    assert candidate["http_context_fragment"] == raw["http_upstream_fragment"]
    assert candidate["server_block_fragment"] == (
        "server {\n" + tls["server_context_fragment"]
        + raw["server_location_fragment"] + "}\n"
    )
    assert candidate["proposed_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main",
    ]
    assert candidate["server_block_fragment"].count(
        "location ^~ /__repocache/repos/"
    ) == 2
    assert candidate["server_block_fragment"].count("ssl_certificate_key ") == 1
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in candidate["server_block_fragment"]
    assert "default_server" not in candidate["server_block_fragment"]
    assert "proxy_pass http://" not in candidate["server_block_fragment"]
    assert "resolver " not in candidate["http_context_fragment"]
    assert doc == before
    assert all(candidate[name] is False for name in (
        "tls_material_or_hostname_verified",
        "native_nginx_syntax_verified",
        "installed_nginx_or_operator_authority_verified",
        "active_route_exposure_verified",
        "authorizes_nginx_activation",
        "authorizes_catalog_publication",
        "authorizes_firewall_change",
    ))


@pytest.mark.parametrize("apt,dnf", [(True,False),(False,True),(False,False)])
def test_disabled_repositories_never_emit_cache_or_route(apt,dnf):
    d = document(apt,dnf)
    expected = [
        name for name,enabled in (
            ("almalinux-baseos",dnf),("debian-trixie-main",apt),
        ) if enabled
    ]
    result = render(d,candidates=pins(apt,dnf))
    assert result["proposed_repository_ids"] == expected
    assert result["server_block_fragment"].count("listen ") == 1
    assert result["server_block_fragment"].count("location ^~") == len(expected)
    assert result["http_context_fragment"].count("proxy_cache_path ") == len(expected)
    assert result["authorizes_catalog_publication"] is False


def test_tls_and_route_composition_is_deterministic_across_ordering():
    d = document()
    first = render(d)
    d["repositories"].reverse()
    again = render(d, candidates={
        name: {HOST: list(reversed(addresses[HOST]))}
        for name, addresses in reversed(list(pins().items()))
    })
    assert first == again


@pytest.mark.parametrize("mutation", [
    "invalid-tls", "wildcard-host", "missing-pins", "unsafe-pins",
    "unexpected-pins", "stale-generation", "invalid-bypass",
])
def test_invalid_input_refused_without_partial_result(mutation):
    d = document()
    candidate_pins = pins()
    kwargs = {}
    generation = 3
    if mutation == "invalid-tls":
        d["deployment"]["tls"]["private_key_file"] = "/etc/nginx/key;return 200;"
    elif mutation == "wildcard-host":
        d["deployment"]["listen"]["hostname"] = "*.invalid"
    elif mutation == "missing-pins":
        candidate_pins.pop("almalinux-baseos")
    elif mutation == "unsafe-pins":
        candidate_pins["debian-trixie-main"] = {HOST: ["169.254.169.254"]}
    elif mutation == "unexpected-pins":
        candidate_pins["foreign"] = {HOST: ["8.8.8.8"]}
    elif mutation == "stale-generation":
        generation = 4
    else:
        kwargs["cache_bypass_repository_ids"] = ("disabled-route",)
    with pytest.raises(NginxRepositoryBundleError,
                       match="^NGINX_HTTPS_BUNDLE_INPUT_INVALID$"):
        render(d, candidates=candidate_pins, generation=generation, **kwargs)


def test_cache_bypass_and_firewall_request_remain_inert():
    d = document()
    d["deployment"]["firewall"]["modify"] = True
    result = render(d, cache_bypass_repository_ids=("debian-trixie-main",))
    assert result["firewall_mutation_requested"] is True
    assert result["authorizes_firewall_change"] is False
    assert result["cache_bypass_recovery_candidate_repository_ids"] == [
        "debian-trixie-main",
    ]
    assert "proxy_cache off;" in result["server_block_fragment"]
    assert result["authorizes_nginx_activation"] is False


def test_renderer_does_not_spawn_or_write_or_resolve(monkeypatch):
    import os
    import socket
    import subprocess

    def refused(*_args, **_kwargs):
        pytest.fail("Pure renderer attempted host/network mutation")
    monkeypatch.setattr(subprocess, "run", refused)
    monkeypatch.setattr(os, "system", refused)
    monkeypatch.setattr(os, "replace", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)
    assert render()["pin_count"] == 2
