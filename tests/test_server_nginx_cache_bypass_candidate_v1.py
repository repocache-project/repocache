"""Pure per-repository cache-off recovery candidate contracts (#97)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repocache.server_nginx_pin_render_v1 import (
    PinnedNginxError, render_pinned_upstream_fragments,
)
from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError, render_repository_nginx_bundle_candidate,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
HOST = "mirror.example.invalid"
CA = "/etc/ssl/certs/ca-certificates.crt"


def source():
    document = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    for entry in document["repositories"]:
        entry["desired_state"] = "active"
        if entry["kind"] == "dnf":
            entry["id"] = "almalinux-baseos"
    pins = {
        entry["id"]: {HOST: ["8.8.8.8"]}
        for entry in document["repositories"]
    }
    return document, pins


def render(document, pins, **options):
    return render_repository_nginx_bundle_candidate(
        document,
        expected_state_generation=0,
        candidate_pins_by_repository=pins,
        ca_bundle_path=CA,
        **options,
    )


def test_only_one_approved_active_repository_stops_using_cache():
    document, pins = source()
    before = render(document, pins)
    recovery = render(
        document, pins,
        cache_bypass_repository_ids=("debian-trixie-main",),
    )
    exact = before["server_location_fragment"].replace(
        "    proxy_cache repocache_cache_debian_trixie_main;",
        "    proxy_cache off;",
    )
    assert recovery["server_location_fragment"] == exact
    assert recovery["http_upstream_fragment"] == before["http_upstream_fragment"]
    assert recovery["proposed_repository_ids"] == before["proposed_repository_ids"]
    assert recovery["cache_bypass_recovery_candidate_repository_ids"] == [
        "debian-trixie-main"
    ]
    assert recovery["cache_bypass_activation_verified"] is False
    assert recovery["authorizes_nginx_activation"] is False
    assert recovery["authorizes_catalog_publication"] is False
    assert "    proxy_cache repocache_cache_almalinux_baseos;" in exact
    assert exact.count("    proxy_cache off;") == 1


def test_empty_bypass_keeps_legacy_config_identical():
    document, pins = source()
    assert render(document, pins) == render(
        document, pins, cache_bypass_repository_ids=()
    )
    assert not render(document, pins)["cache_bypass_recovery_candidate_repository_ids"]


@pytest.mark.parametrize("bad", [
    None, False, True, 1, "", [], ["debian-trixie-main"],
    ("debian-trixie-main", "debian-trixie-main"),
    ("not-an-active-repository",), (1,),
    ("debian-trixie-main",) * 100_000,
])
def test_invalid_recovery_ids_are_refused_before_candidate_render(bad):
    document, pins = source()
    with pytest.raises(
        NginxRepositoryBundleError, match="NGINX_BUNDLE_BYPASS_IDS_INVALID"
    ):
        render(document, pins, cache_bypass_repository_ids=bad)


def test_disabled_repository_cannot_be_bypassed():
    document, pins = source()
    for entry in document["repositories"]:
        if entry["id"] == "debian-trixie-main":
            entry["desired_state"] = "disabled"
            pins.pop(entry["id"])
    with pytest.raises(
        NginxRepositoryBundleError, match="NGINX_BUNDLE_BYPASS_IDS_INVALID"
    ):
        render(
            document, pins,
            cache_bypass_repository_ids=("debian-trixie-main",),
        )


def test_bypass_combines_with_min_free_candidate_without_authorizing_activation():
    document, pins = source()
    result = render(
        document, pins,
        cache_bypass_repository_ids=("almalinux-baseos",),
        native_min_free_supported=True,
    )
    assert result["native_min_free_candidate_emitted"] is True
    assert result["native_min_free_supported_verified"] is False
    assert result["server_location_fragment"].count("    proxy_cache off;") == 1
    assert " min_free=" in result["http_upstream_fragment"]
    assert result["authorizes_nginx_activation"] is False


@pytest.mark.parametrize("bad", [None, 0, 1, "true", {}, [], object()])
def test_single_repository_renderer_refuses_untrusted_bypass_type(bad):
    document, pins = source()
    with pytest.raises(PinnedNginxError, match="cache bypass recovery: invalid"):
        render_pinned_upstream_fragments(
            document,
            repository_id="debian-trixie-main",
            candidate_pins_by_host=pins["debian-trixie-main"],
            ca_bundle_path=CA,
            cache_bypass_for_recovery=bad,
        )
