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
    assert "proxy_ignore_headers X-Accel-Redirect;" in loc
    assert "proxy_hide_header X-Accel-Redirect;" in loc
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
    native_ca = next((p for p in (
        CA, "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(p).is_file()), None)
    if native_ca is None:
        pytest.skip("packaged CA bundle unavailable")
    doc = document()
    doc["deployment"]["paths"]["cache_root"] = str(tmp_path / "candidate_cache")
    (tmp_path / "candidate_cache" / "debian-trixie-main").mkdir(
        parents=True, mode=0o700,
    )
    candidate = render(doc=doc, ca=native_ca)
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'error.log'} notice;\n"
        "events {}\nhttp { access_log off;\n"
        f"client_body_temp_path {tmp_path / 'candidate_client_temp'};\n"
        f"proxy_temp_path {tmp_path / 'candidate_proxy_temp'};\n"
        f"fastcgi_temp_path {tmp_path / 'candidate_fastcgi_temp'};\n"
        f"uwsgi_temp_path {tmp_path / 'candidate_uwsgi_temp'};\n"
        f"scgi_temp_path {tmp_path / 'candidate_scgi_temp'};\n"
        + candidate["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19991;\n"
        + candidate["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    for name in ("candidate_client_temp", "candidate_proxy_temp",
                 "candidate_fastcgi_temp", "candidate_uwsgi_temp",
                 "candidate_scgi_temp"):
        (tmp_path / name).mkdir()
    observed = subprocess.run(
        [shutil.which("nginx"), "-t", "-e", str(tmp_path / "nginx-startup.log"),
         "-c", str(conf), "-p", str(tmp_path)],
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


def test_dnf_baseos_candidate_renders_from_metadata_without_source_changes():
    doc = document()
    doc["repositories"][1]["id"] = "almalinux-baseos"
    doc["repositories"][1]["desired_state"] = "active"
    before = copy.deepcopy(doc)
    output = render_pinned_upstream_fragments(
        doc,
        repository_id="almalinux-baseos",
        candidate_pins_by_host={HOST: ["8.8.8.8"]},
        ca_bundle_path=CA,
    )
    assert "server 8.8.8.8:443;" in output["http_upstream_fragment"]
    assert (
        "proxy_pass https://repocache_pin_almalinux_baseos/"
        "almalinux/10/BaseOS/x86_64/os/;"
    ) in output["server_location_fragment"]
    assert "proxy_ssl_verify on;" in output["server_location_fragment"]
    assert output["authorizes_nginx_activation"] is False
    assert doc == before


def test_cache_zone_is_per_repository_and_sensitive_requests_bypass():
    candidate = render()
    upstream = candidate["http_upstream_fragment"]
    location = candidate["server_location_fragment"]
    assert "proxy_cache_path /var/cache/nginx/repocache-managed/debian-trixie-main " in upstream
    assert "keys_zone=repocache_cache_debian_trixie_main:1m" in upstream
    assert "inactive=604800s max_size=10737418240" in upstream
    assert "proxy_cache repocache_cache_debian_trixie_main;" in location
    assert "proxy_cache_valid 200 60s;" in location
    assert "proxy_cache_methods GET HEAD;" in location
    assert "proxy_cache_lock on;" in location
    assert 'proxy_cache_key "$scheme|$proxy_host|$request_uri";' in location
    for field in ("$http_authorization", "$http_cookie"):
        assert field in location
    assert "proxy_cache_use_stale" not in location
    assert "proxy_ignore_headers Cache-Control" not in location
    assert candidate["authorizes_nginx_activation"] is False


def test_cache_inheritance_resolves_each_local_override():
    doc = document()
    doc["deployment"]["cache_policy"]["global"].update({
        "inactive_seconds": 900, "max_size_bytes": 8192,
    })
    doc["repositories"][0]["cache_overrides"] = {
        "inactive_seconds": 120,
    }
    first = render(doc=doc)["http_upstream_fragment"]
    assert "inactive=120s max_size=8192" in first
    doc["repositories"][0]["cache_overrides"] = {
        "max_size_bytes": 4096,
    }
    second = render(doc=doc)["http_upstream_fragment"]
    assert "inactive=900s max_size=4096" in second
    assert first != second
