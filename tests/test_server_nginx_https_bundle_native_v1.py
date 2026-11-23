"""Issue #28 native stock NGINX syntax for the existing full HTTPS+APT/DNF bundle.

Rootless, disposable configuration and locally generated TLS test identity.
Neither nginx -t nor this candidate preview authorizes service activation.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError, render_repository_https_server_candidate,
)

FIXTURE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
HOST = "mirror.example.invalid"
PINS = {
    "almalinux-baseos": {HOST: ["8.8.8.8"]},
    "debian-trixie-main": {HOST: ["8.8.4.4"]},
}


def source_document():
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    doc["repositories"][0]["desired_state"] = "active"
    doc["repositories"][1]["id"] = "almalinux-baseos"
    doc["repositories"][1]["desired_state"] = "active"
    return doc


def candidate(doc, pins=None):
    return render_repository_https_server_candidate(
        doc, expected_state_generation=0,
        candidate_pins_by_repository=copy.deepcopy(PINS if pins is None else pins),
        ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
    )


def test_complete_https_candidate_includes_two_independent_routes_no_authority():
    doc = source_document()
    before = copy.deepcopy(doc)
    result = candidate(doc)
    assert doc == before
    assert result["status"] == "HTTPS_REPOSITORY_SERVER_CANDIDATE_ONLY"
    assert result["proposed_repository_ids"] == ["almalinux-baseos", "debian-trixie-main"]
    assert result["pin_count"] == 2
    assert result["http_context_fragment"].count("proxy_cache_path ") == 2
    assert result["server_block_fragment"].count("location ^~ ") == 2
    assert "listen 127.0.0.1:443 ssl;" in result["server_block_fragment"]
    assert "proxy_ssl_verify on;" in result["server_block_fragment"]
    assert "proxy_intercept_errors on;" in result["server_block_fragment"]
    for key in (
        "tls_material_or_hostname_verified", "native_nginx_syntax_verified",
        "installed_nginx_or_operator_authority_verified", "active_route_exposure_verified",
        "authorizes_nginx_activation", "authorizes_catalog_publication",
        "authorizes_firewall_change",
    ):
        assert result[key] is False


def test_late_unsafe_pin_or_inactive_repo_refuses_whole_https_candidate():
    doc = source_document()
    with pytest.raises(NginxRepositoryBundleError, match="NGINX_HTTPS_BUNDLE_INPUT_INVALID"):
        candidate(doc, {**PINS, "debian-trixie-main": {HOST: ["169.254.169.254"]}})
    doc["repositories"][1]["desired_state"] = "disabled"
    with pytest.raises(NginxRepositoryBundleError, match="NGINX_HTTPS_BUNDLE_INPUT_INVALID"):
        candidate(doc)
    allowed = candidate(doc, {"debian-trixie-main": PINS["debian-trixie-main"]})
    assert allowed["proposed_repository_ids"] == ["debian-trixie-main"]
    assert "almalinux_baseos" not in (
        allowed["http_context_fragment"] + allowed["server_block_fragment"]
    )


@pytest.mark.skipif(
    not shutil.which("nginx") or not shutil.which("openssl"),
    reason="disposable stock nginx and openssl unavailable",
)
def test_real_stock_nginx_validates_full_https_apt_dnf_candidate(tmp_path):
    """Both target OS containers run this with installed stock nginx/openssl."""
    native_ca = next((p for p in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(p).is_file()), None)
    if native_ca is None:
        pytest.skip("packaged trusted CA bundle unavailable")
    doc = source_document()
    doc["deployment"]["listen"]["https_port"] = 19994
    doc["deployment"]["paths"]["cache_root"] = str(tmp_path / "cache")
    cert = tmp_path / "test.crt"
    key = tmp_path / "test.key"
    doc["deployment"]["tls"]["certificate_file"] = str(cert)
    doc["deployment"]["tls"]["private_key_file"] = str(key)
    openssl = subprocess.run([
        shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048",
        "-noenc", "-days", "1", "-subj", "/CN=cache.example.invalid",
        "-keyout", str(key), "-out", str(cert),
    ], capture_output=True, check=False, timeout=20)
    assert openssl.returncode == 0, openssl.stderr.decode("utf-8", "replace")
    for repository in doc["repositories"]:
        (tmp_path / "cache" / repository["id"]).mkdir(parents=True)
    for name in ("client_temp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"):
        (tmp_path / name).mkdir()
    result = render_repository_https_server_candidate(
        doc, expected_state_generation=0,
        candidate_pins_by_repository=PINS, ca_bundle_path=native_ca,
    )
    assert not result["authorizes_nginx_activation"]
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'error.log'} notice;\n"
        "events {}\nhttp { access_log off;\n"
        + "".join(
            directive + " " + str(tmp_path / folder) + ";\n"
            for directive, folder in (
                ("client_body_temp_path", "client_temp"),
                ("proxy_temp_path", "proxy_temp"),
                ("fastcgi_temp_path", "fastcgi_temp"),
                ("uwsgi_temp_path", "uwsgi_temp"),
                ("scgi_temp_path", "scgi_temp"),
            )
        )
        + result["http_context_fragment"]
        + result["server_block_fragment"]
        + "}\n", encoding="utf-8",
    )
    observed = subprocess.run(
        [shutil.which("nginx"), "-t", "-e", str(tmp_path / "startup.log"),
         "-c", str(conf), "-p", str(tmp_path)],
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert observed.returncode == 0, observed.stderr
    assert result["native_nginx_syntax_verified"] is False
    assert result["active_route_exposure_verified"] is False
