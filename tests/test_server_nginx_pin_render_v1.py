"""Pure NGINX numeric-IP candidate rendering and adversarial regression tests."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from repocache.server_nginx_pin_render_v1 import (
    PinnedNginxError,
    render_pinned_upstream_fragments,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
HOST = "mirror.example.invalid"
IPS = {HOST: ["8.8.8.8", "2001:4860:4860::8888"]}
CA = "/etc/ssl/certs/ca-certificates.crt"


def document():
    value = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    value["repositories"][0]["desired_state"] = "active"
    return value


def render(*, doc=None, ips=None, ca=CA):
    return render_pinned_upstream_fragments(
        document() if doc is None else doc,
        repository_id="debian-trixie-main",
        candidate_pins_by_host=copy.deepcopy(IPS if ips is None else ips),
        ca_bundle_path=ca,
    )


def test_numeric_pins_are_only_nginx_upstream_servers():
    result = render()
    upstream = result["http_upstream_fragment"]
    loc = result["server_location_fragment"]
    assert "server 8.8.8.8:443;" in upstream
    assert "server [2001:4860:4860::8888]:443;" in upstream
    assert "server mirror.example.invalid" not in upstream
    assert "resolver " not in upstream + loc
    assert "proxy_pass https://repocache_pin_debian_trixie_main" in loc
    assert "proxy_set_header Host mirror.example.invalid;" in loc
    assert "proxy_ssl_name mirror.example.invalid;" in loc
    assert "proxy_ssl_server_name on;" in loc
    assert "proxy_ssl_verify on;" in loc
    assert f"proxy_ssl_trusted_certificate {CA};" in loc
    assert "proxy_intercept_errors on;" in loc
    assert "error_page 301 302 303 307 308 =502" in loc
    assert "proxy_redirect off;" in loc
    assert "return 502;" in loc
    assert "limit_except GET HEAD" in loc
    assert result["pin_count"] == 2
    for flag in (
        "authorizes_nginx_activation", "authorizes_catalog_publication",
        "trusted_state_provenance_verified",
        "runtime_destination_enforcement_verified",
    ):
        assert result[flag] is False


def test_deterministic_across_pin_order_and_no_input_mutation():
    original = document()
    before = copy.deepcopy(original)
    a = render(doc=original)
    b = render(doc=original, ips={HOST: list(reversed(IPS[HOST]))})
    assert a == b
    assert original == before


@pytest.mark.parametrize("bad", [
    {HOST: ["10.1.2.3"]},
    {HOST: ["8.8.8.8", "169.254.169.254"]},
    {HOST: ["8.8.8.8", "::ffff:8.8.8.8"]},
    {HOST: ["8.8.8.8", "8.8.8.8"]},
    {HOST: []},
    {"untrusted.example.invalid": ["8.8.8.8"]},
    {HOST: ["8.8.8.8"], "extra.example.invalid": ["1.1.1.1"]},
])
def test_bad_pin_sets_never_render(bad):
    with pytest.raises(PinnedNginxError):
        render(ips=bad)


@pytest.mark.parametrize("bad_ca", [
    "", "/tmp/file with space.pem", "/etc/ssl/../passwd", "/etc//ssl/ca.pem",
    "/etc/nginx/ca.pem;return 200;", "relative/path.pem", None,
])
def test_ca_bundle_cannot_inject_directives(bad_ca):
    with pytest.raises(PinnedNginxError):
        render(ca=bad_ca)


def test_disabled_repository_cannot_be_rendered():
    doc = document()
    doc["repositories"][0]["desired_state"] = "disabled"
    with pytest.raises(PinnedNginxError, match="not active"):
        render(doc=doc)


def test_extra_allowlisted_host_needs_complete_dns_pins():
    doc = document()
    doc["repositories"][0]["upstream"]["allowed_hosts"].append("backup.example.invalid")
    with pytest.raises(PinnedNginxError):
        render(doc=doc)


def test_bad_hostname_and_base_path_rejected_before_render():
    doc = document()
    doc["repositories"][0]["upstream"]["base_url"] = "https://127.0.0.1/debian/"
    with pytest.raises(PinnedNginxError):
        render(doc=doc)
    doc = document()
    doc["repositories"][0]["upstream"]["base_url"] = (
        "https://mirror.example.invalid/debian/;return 200;"
    )
    with pytest.raises(PinnedNginxError):
        render(doc=doc)


def test_no_nginx_service_or_filesystem_side_effect(monkeypatch):
    import os
    def forbidden(*_args, **_kwargs):
        raise AssertionError("pure renderer cannot execute or persist anything")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    assert render()["status"] == "RENDER_CANDIDATE_ONLY"


@pytest.mark.skipif(shutil.which("nginx") is None, reason="packaged nginx unavailable")
def test_packaged_nginx_accepts_fragments_without_activation(tmp_path):
    """Real nginx -t on an isolated disposable config; never reload/service."""
    candidate = render()
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "events {}\nhttp {\n"
        + candidate["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19991;\n"
        + candidate["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    observed = subprocess.run(
        [shutil.which("nginx"), "-t", "-c", str(conf), "-p", str(tmp_path)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert observed.returncode == 0, observed.stderr


def test_non_default_https_port_and_url_path_are_preserved():
    doc = document()
    doc["repositories"][0]["upstream"]["base_url"] = (
        "https://mirror.example.invalid:8443/repo~stable/"
    )
    result = render(doc=doc)
    assert "server 8.8.8.8:8443;" in result["http_upstream_fragment"]
    assert "server [2001:4860:4860::8888]:8443;" in result["http_upstream_fragment"]
    assert "proxy_pass https://repocache_pin_debian_trixie_main/repo~stable;" not in result["server_location_fragment"]
    assert "proxy_pass https://repocache_pin_debian_trixie_main/repo~stable/;" in result["server_location_fragment"]
    assert "proxy_set_header Host mirror.example.invalid:8443;" in result["server_location_fragment"]
    assert "proxy_ssl_name mirror.example.invalid;" in result["server_location_fragment"]


def test_safe_root_https_path_and_uppercase_hostname():
    doc = document()
    doc["repositories"][0]["upstream"]["base_url"] = "https://MIRROR.EXAMPLE.INVALID/"
    result = render(doc=doc)
    assert "proxy_pass https://repocache_pin_debian_trixie_main/;" in result["server_location_fragment"]
    assert "proxy_ssl_name mirror.example.invalid;" in result["server_location_fragment"]
