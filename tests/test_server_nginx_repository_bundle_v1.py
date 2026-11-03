"""Pure declarative NGINX candidate assembly: no approval, I/O or activation."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError,
    render_repository_nginx_bundle_candidate,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
HOST = "mirror.example.invalid"
CA = "/etc/ssl/certs/ca-certificates.crt"


def document(*, apt=True, dnf=True, generation=4):
    payload = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    payload["expected_state_generation"] = generation
    payload["repositories"][0]["desired_state"] = "active" if apt else "disabled"
    payload["repositories"][1]["id"] = "almalinux-baseos"
    payload["repositories"][1]["desired_state"] = "active" if dnf else "disabled"
    return payload


def pins(*, apt=True, dnf=True):
    return {
        key: {HOST: ["8.8.8.8", "2001:4860:4860::8888"]}
        for key, enabled in (
            ("debian-trixie-main", apt), ("almalinux-baseos", dnf)
        )
        if enabled
    }


_DEFAULT_CANDIDATES = object()


def render(doc=None, candidates=_DEFAULT_CANDIDATES, generation=4, ca=CA):
    return render_repository_nginx_bundle_candidate(
        document() if doc is None else doc,
        expected_state_generation=generation,
        candidate_pins_by_repository=(
            pins() if candidates is _DEFAULT_CANDIDATES else candidates
        ),
        ca_bundle_path=ca,
    )


def test_two_supported_layouts_render_only_candidate_fragments():
    original = document()
    snapshot = copy.deepcopy(original)
    result = render(doc=original)
    assert original == snapshot
    assert result["proposed_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main"
    ]
    assert result["pin_count"] == 4
    assert result["http_upstream_fragment"].count("upstream repocache_pin_") == 2
    assert result["server_location_fragment"].count("location ^~ /__repocache/repos/") == 2
    assert "proxy_pass https://repocache_pin_debian_trixie_main/debian/;" in result["server_location_fragment"]
    assert "proxy_pass https://repocache_pin_almalinux_baseos/almalinux/10/BaseOS/x86_64/os/;" in result["server_location_fragment"]
    assert result["http_upstream_fragment"].count("server 8.8.8.8:443;") == 2
    assert "server mirror.example.invalid:" not in result["http_upstream_fragment"]
    assert "proxy_ssl_verify on;" in result["server_location_fragment"]
    assert "proxy_ssl_server_name on;" in result["server_location_fragment"]
    assert "X-Accel-Redirect;" in result["server_location_fragment"]
    assert "error_page 301 302 303 307 308 =502" in result["server_location_fragment"]
    for forbidden in ("resolver ", "proxy_pass $", "proxy_pass http://"):
        assert forbidden not in (result["http_upstream_fragment"] + result["server_location_fragment"])
    for key in (
        "trusted_state_provenance_verified", "operator_approval_verified",
        "active_exposure_verified", "authorizes_nginx_activation",
        "authorizes_catalog_publication",
    ):
        assert result[key] is False
    assert "catalog_artifact" not in result
    assert "discovery" not in result


def test_declared_disabled_repositories_have_no_route_and_no_catalog():
    result = render(doc=document(dnf=False), candidates=pins(dnf=False))
    assert result["proposed_repository_ids"] == ["debian-trixie-main"]
    assert "almalinux_baseos" not in (
        result["http_upstream_fragment"] + result["server_location_fragment"]
    )
    empty = render(doc=document(apt=False, dnf=False), candidates={})
    assert empty["proposed_repository_ids"] == []
    assert empty["http_upstream_fragment"] == ""
    assert empty["server_location_fragment"] == ""
    assert empty["authorizes_catalog_publication"] is False


def test_deterministic_for_reversed_repository_and_pin_order():
    first = render()
    doc = document()
    doc["repositories"].reverse()
    candidate = pins()
    candidate = {
        k: {HOST: list(reversed(v[HOST]))}
        for k, v in reversed(list(candidate.items()))
    }
    assert first == render(doc=doc, candidates=candidate)


@pytest.mark.parametrize("bad", [
    {"debian-trixie-main": {HOST: ["8.8.8.8"]}},
    {**pins(), "extra-repository": {HOST: ["8.8.8.8"]}},
    {**pins(), "almalinux-baseos": {HOST: ["127.0.0.1"]}},
    {**pins(), "almalinux-baseos": {HOST: ["8.8.8.8", "169.254.169.254"]}},
    {**pins(), "almalinux-baseos": {"evil.example.invalid": ["8.8.8.8"]}},
    [],
    None,
])
def test_missing_extra_or_unsafe_repository_pins_are_refused(bad):
    with pytest.raises(NginxRepositoryBundleError, match="NGINX_BUNDLE_"):
        render(candidates=bad)


@pytest.mark.parametrize("bad_generation", [True, -1, 3, 5, "4", None])
def test_untrusted_or_stale_generation_never_generates_bundle(bad_generation):
    with pytest.raises(NginxRepositoryBundleError, match="GENERATION"):
        render(generation=bad_generation)


def test_active_repository_must_have_durable_id_even_for_preview():
    doc = document()
    del doc["repositories"][1]["id"]
    with pytest.raises(NginxRepositoryBundleError, match="UNALLOCATED"):
        render(doc=doc)


@pytest.mark.parametrize("bad_ca", [
    "", "relative/ca.pem", "/etc/certs/../bad.pem",
    "/etc/ssl/cert.pem;return 200;", "/etc//ssl/ca.pem", None,
])
def test_ca_validation_cannot_be_skipped_for_empty_route_set(bad_ca):
    with pytest.raises(NginxRepositoryBundleError, match="CA_INVALID"):
        render(doc=document(apt=False, dnf=False), candidates={}, ca=bad_ca)


def test_disabled_pins_must_not_be_accepted_as_desired_active_routes():
    with pytest.raises(NginxRepositoryBundleError, match="PIN_SET_INCOMPLETE"):
        render(doc=document(dnf=False), candidates=pins())


@pytest.mark.parametrize("url", [
    "http://mirror.example.invalid/debian/",
    "https://127.0.0.1/debian/",
    "https://mirror.example.invalid/debian/;return 200;",
    "https://mirror.example.invalid/%2e%2e/",
])
def test_invalid_upstreams_never_render(url):
    doc = document()
    doc["repositories"][0]["upstream"]["base_url"] = url
    with pytest.raises(NginxRepositoryBundleError, match="DOCUMENT_INVALID"):
        render(doc=doc)


def test_redaction_and_no_filesystem_service_or_network_effects(monkeypatch):
    import os
    import socket
    def forbidden(*args, **kwargs):
        raise AssertionError("candidate renderer has side effects")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    result = render()
    assert result["status"] == "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY"
    bad = pins()
    bad["debian-trixie-main"] = {HOST: ["169.254.169.254"]}
    with pytest.raises(NginxRepositoryBundleError) as error:
        render(candidates=bad)
    assert HOST not in str(error.value)
    assert "169.254.169.254" not in str(error.value)


@pytest.mark.skipif(shutil.which("nginx") is None, reason="packaged nginx unavailable")
def test_nginx_t_accepts_composed_candidates_in_disposable_config(tmp_path):
    native_ca = next((p for p in (
        CA, "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(p).is_file()), None)
    if native_ca is None:
        pytest.skip("packaged CA bundle unavailable")
    result = render(ca=native_ca)
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'error.log'} notice;\n"
        "events {}\nhttp { access_log off;\n"
        + result["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19991;\n"
        + result["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    checked = subprocess.run(
        [shutil.which("nginx"), "-t", "-c", str(conf), "-p", str(tmp_path)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert checked.returncode == 0, checked.stderr
