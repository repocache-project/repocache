"""Issue #28: inert all-or-nothing multiple NGINX repository rendering."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from repocache.server_nginx_bundle_v1 import (
    PinnedNginxBundleError,
    render_pinned_repository_bundle,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
HOST = "mirror.example.invalid"
PINS = {
    "almalinux-baseos": {HOST: ["8.8.8.8"]},
    "debian-trixie-main": {HOST: ["8.8.4.4"]},
}
CA = "/etc/ssl/certs/ca-certificates.crt"


def document():
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc["repositories"][0]["desired_state"] = "active"
    doc["repositories"][1]["id"] = "almalinux-baseos"
    doc["repositories"][1]["desired_state"] = "active"
    return doc


def render(doc=None, pins=None, ca=CA):
    return render_pinned_repository_bundle(
        document() if doc is None else doc,
        pins_by_repository=copy.deepcopy(PINS if pins is None else pins),
        ca_bundle_path=ca,
    )


def test_active_apt_and_dnf_render_together_deterministically():
    doc = document()
    before = copy.deepcopy(doc)
    result = render(doc)
    assert doc == before
    assert result["status"] == "RENDER_BUNDLE_CANDIDATE_ONLY"
    assert result["repository_ids"] == ["almalinux-baseos", "debian-trixie-main"]
    assert result["pin_count"] == 2
    assert result["http_upstream_fragment"].count("proxy_cache_path ") == 2
    assert result["server_location_fragment"].count("location ^~ ") == 2
    assert "server 8.8.8.8:443;" in result["http_upstream_fragment"]
    assert "server 8.8.4.4:443;" in result["http_upstream_fragment"]
    assert "/__repocache/repos/almalinux-baseos/" in result["server_location_fragment"]
    assert "/__repocache/repos/debian-trixie-main/" in result["server_location_fragment"]
    assert "proxy_ssl_verify on;" in result["server_location_fragment"]
    assert "proxy_intercept_errors on;" in result["server_location_fragment"]
    reordered = dict(reversed(list(PINS.items())))
    assert result == render(doc, reordered)
    for key in (
        "native_min_free_supported_verified", "trusted_state_provenance_verified",
        "runtime_destination_enforcement_verified", "authorizes_nginx_activation",
        "authorizes_catalog_publication",
    ):
        assert result[key] is False


def test_disabled_repository_never_creates_route_and_extra_pin_refused():
    doc = document()
    doc["repositories"][1]["desired_state"] = "disabled"
    with pytest.raises(PinnedNginxBundleError, match="PIN_SET_MISMATCH"):
        render(doc)
    result = render(doc, {"debian-trixie-main": PINS["debian-trixie-main"]})
    assert result["repository_ids"] == ["debian-trixie-main"]
    assert "almalinux-baseos" not in (
        result["http_upstream_fragment"] + result["server_location_fragment"]
    )


def test_no_active_repositories_produce_no_routes():
    doc = document()
    for row in doc["repositories"]:
        row["desired_state"] = "disabled"
    result = render(doc, {})
    assert result["repository_ids"] == []
    assert result["http_upstream_fragment"] == ""
    assert result["server_location_fragment"] == ""
    assert result["pin_count"] == 0


@pytest.mark.parametrize("pins", [
    {}, {"debian-trixie-main": PINS["debian-trixie-main"]},
    {**PINS, "unapproved": {HOST: ["8.8.8.8"]}},
    {**PINS, "almalinux-baseos": {HOST: ["127.0.0.1"]}},
    {**PINS, "almalinux-baseos": {HOST: []}},
    [],
    {"bad": []},
])
def test_invalid_or_incomplete_pin_set_rejects_all_fragments(pins):
    with pytest.raises(PinnedNginxBundleError, match=r"^BUNDLE_"):
        render(pins=pins)


def test_invalid_second_repository_never_returns_partial_candidate():
    doc = document()
    doc["repositories"][1]["upstream"]["base_url"] = "http://127.0.0.1/"
    with pytest.raises(PinnedNginxBundleError, match="DOCUMENT_INVALID"):
        render(doc)


def test_options_are_boolean_and_no_side_effects(monkeypatch):
    import os

    def blocked(*args, **kwargs):
        raise AssertionError("inert renderer attempted host mutation")
    monkeypatch.setattr(os, "replace", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    assert render()["status"] == "RENDER_BUNDLE_CANDIDATE_ONLY"
    with pytest.raises(PinnedNginxBundleError, match="OPTIONS_INVALID"):
        render_pinned_repository_bundle(
            document(), pins_by_repository=PINS, ca_bundle_path=CA,
            cache_bypass_for_recovery=1,
        )


@pytest.mark.skipif(shutil.which("nginx") is None, reason="packaged nginx unavailable")
def test_packaged_nginx_accepts_two_repository_candidate_without_activation(tmp_path):
    native_ca = next((path for path in (
        CA, "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(path).is_file()), None)
    if native_ca is None:
        pytest.skip("packaged CA bundle unavailable")
    doc = document()
    doc["deployment"]["paths"]["cache_root"] = str(tmp_path / "cache")
    for rid in PINS:
        (tmp_path / "cache" / rid).mkdir(parents=True)
    rendered = render(doc, ca=native_ca)
    for name in ("client_temp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"):
        (tmp_path / name).mkdir()
    config = tmp_path / "nginx.conf"
    config.write_text(
        "worker_processes 1;\n"
        + "pid " + str(tmp_path / "nginx.pid") + ";\n"
        + "error_log " + str(tmp_path / "nginx.log") + " notice;\n"
        + "events {}\nhttp { access_log off;\n"
        + "".join(
            name + "_path " + str(tmp_path / name) + ";\n"
            for name in (
                "client_body_temp", "proxy_temp", "fastcgi_temp",
                "uwsgi_temp", "scgi_temp",
            )
        ).replace("client_body_temp_path", "client_body_temp_path")
        + rendered["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19993;\n"
        + rendered["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shutil.which("nginx"), "-t", "-e", str(tmp_path / "error.log"),
         "-c", str(config), "-p", str(tmp_path)],
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
