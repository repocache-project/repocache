"""Native NGINX min_free generated candidate contracts for issue #97."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError,
    render_repository_nginx_bundle_candidate,
)
from repocache.server_nginx_pin_render_v1 import (
    PinnedNginxError, render_pinned_upstream_fragments,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
CA = "/etc/ssl/certs/ca-certificates.crt"
HOST = "mirror.example.invalid"


def fixture():
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    for repo in doc["repositories"]:
        repo["desired_state"] = "active"
        if repo["kind"] == "dnf":
            repo["id"] = "almalinux-baseos"
    pins = {
        repo["id"]: {HOST: ["8.8.8.8"]}
        for repo in doc["repositories"]
    }
    return doc, pins


def candidate(doc, pins, **kwargs):
    return render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=0,
        candidate_pins_by_repository=pins, ca_bundle_path=CA, **kwargs,
    )


def test_legacy_default_syntax_exactly_unchanged_without_capability():
    doc, pins = fixture()
    legacy = candidate(doc, pins)
    explicit = candidate(doc, pins, native_min_free_supported=False)
    assert legacy == explicit
    assert legacy["native_min_free_candidate_emitted"] is False
    assert legacy["native_min_free_supported_verified"] is False
    assert " min_free=" not in legacy["http_upstream_fragment"]
    assert legacy["authorizes_nginx_activation"] is False
    assert legacy["authorizes_catalog_publication"] is False


def test_validated_critical_threshold_emitted_per_active_repository_only():
    doc, pins = fixture()
    snapshot = deepcopy(doc), deepcopy(pins)
    value = doc["deployment"]["cache_policy"]["disk_pressure"]["critical_free_bytes"]
    active = candidate(doc, pins, native_min_free_supported=True)
    baseline = candidate(doc, pins)
    assert active["native_min_free_candidate_emitted"] is True
    assert active["native_min_free_supported_verified"] is False
    assert active["http_upstream_fragment"].count(f" min_free={value} ") == 2
    assert active["http_upstream_fragment"].count("proxy_cache_path ") == 2
    assert " min_free=" not in baseline["http_upstream_fragment"]
    assert active["server_location_fragment"] == baseline["server_location_fragment"]
    assert active["proposed_repository_ids"] == baseline["proposed_repository_ids"]
    assert not active["authorizes_nginx_activation"]
    assert not active["authorizes_catalog_publication"]
    assert (doc, pins) == snapshot


def test_independent_cache_inheritance_and_overrides_unchanged():
    doc, pins = fixture()
    doc["repositories"][0]["cache_overrides"] = {
        "inactive_seconds": 120, "max_size_bytes": 8192,
    }
    doc["deployment"]["cache_policy"]["global"] = {
        "inactive_seconds": 600, "max_size_bytes": 65536,
    }
    enhanced = candidate(doc, pins, native_min_free_supported=True)
    http = enhanced["http_upstream_fragment"]
    assert "inactive=120s max_size=8192 min_free=" in http
    assert "inactive=600s max_size=65536 min_free=" in http


@pytest.mark.parametrize("value", [
    None, 0, 1, "supported", [], {}, object(),
])
def test_non_boolean_capability_fail_closed_without_render(value):
    doc, pins = fixture()
    with pytest.raises(NginxRepositoryBundleError,
                       match="NGINX_BUNDLE_MIN_FREE_CAPABILITY_INVALID"):
        candidate(doc, pins, native_min_free_supported=value)
    with pytest.raises(PinnedNginxError,
                       match="native min_free capability: invalid"):
        render_pinned_upstream_fragments(
            doc, repository_id="debian-trixie-main",
            candidate_pins_by_host=pins["debian-trixie-main"],
            ca_bundle_path=CA, native_min_free_supported=value,
        )


def test_disabled_repository_never_emits_directive_even_on_supported_binary():
    doc, pins = fixture()
    doc["repositories"][0]["desired_state"] = "disabled"
    doc["repositories"][1]["desired_state"] = "disabled"
    disabled = candidate(doc, {}, native_min_free_supported=True)
    assert disabled["http_upstream_fragment"] == ""
    assert disabled["native_min_free_candidate_emitted"] is False
    assert not disabled["authorizes_nginx_activation"]


def test_malformed_critical_threshold_does_not_bypass_document_validation():
    doc, pins = fixture()
    for invalid in (True, -1, 0, "0", None):
        changed = deepcopy(doc)
        changed["deployment"]["cache_policy"]["disk_pressure"][
            "critical_free_bytes"
        ] = invalid
        with pytest.raises(NginxRepositoryBundleError,
                           match="NGINX_BUNDLE_DOCUMENT_INVALID"):
            candidate(changed, pins, native_min_free_supported=True)


def test_generated_directive_has_no_unapproved_path_or_public_side_effect():
    doc, pins = fixture()
    result = candidate(doc, pins, native_min_free_supported=True)
    text = result["http_upstream_fragment"]
    assert "resolver " not in text
    assert "server 127.0.0.1" not in text
    assert "server 8.8.8.8:443;" in text
    assert "proxy_cache_path /var/cache/nginx/repocache-managed/" in text
    assert "server_location_fragment" in result
    assert "native_min_free_supported_verified" in result
