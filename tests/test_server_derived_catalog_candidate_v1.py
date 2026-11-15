"""#28 active-only discovery preview; no host write or publication claims."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_derived_catalog_candidate_v1 import (
    DerivedCatalogCandidateError, preview_derived_catalog_from_nginx_dump,
    preview_derived_https_catalog_from_nginx_dump,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
    render_repository_https_server_candidate,
)

EXAMPLE = (Path(__file__).resolve().parents[1]
           / "docs/examples/server-install-v1.json")
_CA = "/etc/ssl/certs/ca-certificates.crt"


def doc(*, active=("debian-trixie-main", "almalinux-baseos")):
    value = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    value["repositories"][1]["id"] = "almalinux-baseos"
    for row in value["repositories"]:
        row["desired_state"] = (
            "active" if row["id"] in active else "disabled"
        )
    return value


def pins(d):
    return {
        row["id"]: {"mirror.example.invalid": ["8.8.8.8"]}
        for row in d["repositories"] if row["desired_state"] == "active"
    }


def dump(d):
    bundle = render_repository_nginx_bundle_candidate(
        d, expected_state_generation=d["expected_state_generation"],
        candidate_pins_by_repository=pins(d), ca_bundle_path=_CA,
    )
    return ("worker_processes 1;\nevents {}\n"
            "http {\n" + bundle["http_upstream_fragment"]
            + "server {\n" + bundle["server_location_fragment"]
            + "}\n}\n")


_DUMP_NOT_PROVIDED = object()


def preview(d, raw=_DUMP_NOT_PROVIDED, **kwargs):
    return preview_derived_catalog_from_nginx_dump(
        d, candidate_pins_by_repository=pins(d), ca_bundle_path=_CA,
        nginx_dump_text=(dump(d) if raw is _DUMP_NOT_PROVIDED else raw),
        nginx_t_exit_code=kwargs.pop("exit_code", 0),
        **kwargs,
    )


def test_two_active_repositories_derive_exact_client_schema():
    d = doc()
    before = copy.deepcopy(d)
    result = preview(d)
    assert result["status"] == "INERT_DERIVED_CATALOG_CANDIDATE_ONLY"
    assert result["desired_active_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main",
    ]
    assert result["candidate_catalog"] == {
        "schema": 1,
        "repositories": [
            {
                "upstream": "https://mirror.example.invalid/almalinux/10/BaseOS/x86_64/os/",
                "cache": "https://cache.example.invalid/__repocache/repos/almalinux-baseos/",
            },
            {
                "upstream": "https://mirror.example.invalid/debian/",
                "cache": "https://cache.example.invalid/__repocache/repos/debian-trixie-main/",
            },
        ],
    }
    assert all(result[flag] is False for flag in (
        "root_owned_installed_nginx_verified",
        "kernel_operator_authorization_verified",
        "actual_active_exposure_verified",
        "installed_catalog_publication_verified",
        "authorizes_nginx_reload",
        "authorizes_catalog_publication",
    ))
    assert d == before


@pytest.mark.parametrize("active,expected", [
    (("debian-trixie-main",), ["debian-trixie-main"]),
    (("almalinux-baseos",), ["almalinux-baseos"]),
    ((), []),
])
def test_disabled_routes_never_appear(active, expected):
    d = doc(active=active)
    result = preview(d)
    assert result["desired_active_repository_ids"] == expected
    assert len(result["candidate_catalog"]["repositories"]) == len(expected)


def test_non_default_public_https_port_is_derived_from_validated_document():
    d = doc(active=("debian-trixie-main",))
    d["deployment"]["listen"]["https_port"] = 8443
    result = preview(d)
    assert result["candidate_catalog"]["repositories"][0]["cache"] == (
        "https://cache.example.invalid:8443/__repocache/repos/debian-trixie-main/"
    )


@pytest.mark.parametrize("bad", [True, False, 1, -1, "0", None])
def test_untrusted_nginx_exit_status_never_accepted_as_success(bad):
    with pytest.raises(DerivedCatalogCandidateError,
                       match="NGINX_SYNTAX_NOT_OBSERVED"):
        preview(doc(), exit_code=bad)


@pytest.mark.parametrize("change", [
    "duplicate-fragments", "missing-fragments", "rogue-location",
    "shadow-location", "foreign-upstream", "duplicate-location",
    "unexpected-disabled", "empty-dump",
])
def test_unapproved_or_ambiguous_nginx_dump_refused(change):
    d = doc()
    raw = dump(d)
    bundle = render_repository_nginx_bundle_candidate(
        d, expected_state_generation=0,
        candidate_pins_by_repository=pins(d), ca_bundle_path=_CA,
    )
    if change == "duplicate-fragments":
        raw += bundle["server_location_fragment"]
    elif change == "missing-fragments":
        raw = raw.replace(bundle["server_location_fragment"], "")
    elif change == "rogue-location":
        raw += "location ^~ /__repocache/repos/evil/ { return 200; }\n"
    elif change == "shadow-location":
        raw += "location = /__repocache/repos/debian-trixie-main/ { return 200; }\n"
    elif change == "foreign-upstream":
        raw += "upstream repocache_pin_fake { server 1.1.1.1:443; }\n"
    elif change == "duplicate-location":
        raw += "location ^~ /__repocache/repos/debian-trixie-main/ {\n}\n"
    elif change == "unexpected-disabled":
        raw += "location ^~ /__repocache/repos/not-active/ {\n}\n"
    else:
        raw = ""
    with pytest.raises(DerivedCatalogCandidateError):
        preview(d, raw=raw)


@pytest.mark.parametrize("bad", [
    "x" * (4 * 1024 * 1024 + 1),
    "nginx\x00conf", "nginx\rconf", b"bytes", {}, None,
])
def test_untrusted_invalid_or_oversized_nginx_dump_refused(bad):
    with pytest.raises(DerivedCatalogCandidateError,
                       match="NGINX_DUMP_INVALID"):
        preview(doc(), raw=bad)


def test_inconsistent_disabled_document_refuses_foreign_proposed_route():
    d = doc(active=())
    raw = dump(doc(active=("debian-trixie-main",)))
    with pytest.raises(DerivedCatalogCandidateError):
        preview(d, raw=raw)


def test_bad_ip_pins_fail_without_creating_any_catalog():
    d = doc()
    with pytest.raises(DerivedCatalogCandidateError,
                       match="RENDER_INVALID"):
        preview_derived_catalog_from_nginx_dump(
            d, candidate_pins_by_repository={
                "debian-trixie-main": {
                    "mirror.example.invalid": ["169.254.169.254"],
                },
            }, ca_bundle_path=_CA,
            nginx_dump_text=dump(d), nginx_t_exit_code=0,
        )


def test_preview_never_writes_or_launches_commands(monkeypatch):
    import os
    import subprocess

    def forbidden(*_args, **_kw):
        pytest.fail("catalog preview must never execute or mutate the host")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    assert preview(doc())["authorizes_catalog_publication"] is False


def test_different_managed_repository_kinds_cannot_emit_duplicate_client_origin():
    value = doc()
    # The repository identity includes the kind/layout, so the server may
    # regard these as separate managed repositories while the v1 client
    # cannot choose between two cache routes for one upstream URL.
    value["repositories"][1]["upstream"] = copy.deepcopy(
        value["repositories"][0]["upstream"]
    )
    with pytest.raises(DerivedCatalogCandidateError,
                       match="CATALOG_CANDIDATE_CLIENT_MAPPING_AMBIGUOUS"):
        preview(value)


def test_valid_distinct_client_mappings_are_stable_across_repeated_derivation():
    value = doc()
    first = preview(value)
    second = preview(copy.deepcopy(value))
    assert first["candidate_catalog"] == second["candidate_catalog"]
    assert len({row["upstream"] for row in first["candidate_catalog"]["repositories"]}) == 2
    assert len({row["cache"] for row in first["candidate_catalog"]["repositories"]}) == 2
    assert not first["authorizes_catalog_publication"]



@pytest.mark.parametrize("extra", [
    "é" * (2 * 1024 * 1024 + 10),
    "\ud800",
    "\udfff",
])
def test_catalog_dump_rejects_oversize_encoded_utf8_or_surrogate(extra):
    """Reject malformed/unbounded caller text before treating it as nginx -T."""
    with pytest.raises(DerivedCatalogCandidateError,
                       match="NGINX_DUMP_INVALID"):
        preview(doc(), raw=dump(doc()) + extra)


def test_catalog_dump_accepts_genuine_utf8_comments_without_authority():
    result = preview(doc(), raw=dump(doc()) + "# NGINX café comment\n")
    assert result["status"] == "INERT_DERIVED_CATALOG_CANDIDATE_ONLY"
    assert result["authorizes_catalog_publication"] is False



def https_dump(d):
    full = render_repository_https_server_candidate(
        d, expected_state_generation=d["expected_state_generation"],
        candidate_pins_by_repository=pins(d), ca_bundle_path=_CA,
    )
    assert full["authorizes_nginx_activation"] is False
    assert full["authorizes_catalog_publication"] is False
    return (
        "pid /tmp/nginx.pid;\nevents { worker_connections 64; }\n"
        "http {\n" + full["http_context_fragment"]
        + full["server_block_fragment"] + "}\n"
    )


def strict_preview(d, raw=None, *, exit_code=0):
    return preview_derived_https_catalog_from_nginx_dump(
        d, candidate_pins_by_repository=pins(d), ca_bundle_path=_CA,
        nginx_dump_text=https_dump(d) if raw is None else raw,
        nginx_t_exit_code=exit_code,
    )


def test_full_https_catalog_requires_single_exact_tls_listener_and_routes():
    source = doc()
    original = copy.deepcopy(source)
    ordinary = preview(source, raw=https_dump(source))
    strict = strict_preview(source)
    assert strict["status"] == "INERT_DERIVED_HTTPS_CATALOG_CANDIDATE_ONLY"
    assert strict["candidate_catalog"] == ordinary["candidate_catalog"]
    assert strict["desired_active_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main"
    ]
    assert strict["exact_https_server_context_candidate_matched"] is True
    for flag in (
        "installed_tls_certificate_verified", "real_tls_handshake_verified",
        "nginx_dump_provenance_authenticated", "kernel_listener_exposure_verified",
        "authorizes_catalog_publication", "authorizes_nginx_activation",
    ):
        assert strict[flag] is False
    assert source == original


def test_route_only_nginx_dump_is_insufficient_for_https_catalog_candidate():
    source = doc()
    assert preview(source)["candidate_catalog"]["repositories"]
    with pytest.raises(DerivedCatalogCandidateError,
                       match="HTTPS_SERVER_CONTEXT_MISSING_OR_AMBIGUOUS"):
        strict_preview(source, dump(source))


@pytest.mark.parametrize("mutation", [
    "different-sni", "different-host", "different-key", "different-port",
    "missing-server", "duplicate-server", "split-server-context",
])
def test_strict_catalog_refuses_incomplete_or_ambiguous_https_context(mutation):
    source = doc()
    full = render_repository_https_server_candidate(
        source, expected_state_generation=0,
        candidate_pins_by_repository=pins(source), ca_bundle_path=_CA,
    )
    exact = full["server_block_fragment"]
    raw = https_dump(source)
    if mutation == "different-sni":
        raw = raw.replace("$ssl_server_name", "$ssl_fake_name", 1)
    elif mutation == "different-host":
        raw = raw.replace("$http_host", "$host", 1)
    elif mutation == "different-key":
        raw = raw.replace("ssl_certificate_key ", "ssl_certificate_key /foreign-", 1)
    elif mutation == "different-port":
        raw = raw.replace("listen 127.0.0.1:443 ssl;",
                          "listen 127.0.0.1:8443 ssl;", 1)
    elif mutation == "missing-server":
        raw = raw.replace(exact, "")
    elif mutation == "duplicate-server":
        raw += exact
    else:
        raw = raw.replace("server {\n", "server {\n}\nserver {\n", 1)
    assert raw != https_dump(source)
    with pytest.raises(DerivedCatalogCandidateError):
        strict_preview(source, raw)


@pytest.mark.parametrize("active", [
    ("debian-trixie-main",), ("almalinux-baseos",), (),
])
def test_strict_https_candidate_tracks_only_desired_active_repositories(active):
    source = doc(active=active)
    result = strict_preview(source)
    assert result["desired_active_repository_ids"] == sorted(active)
    assert len(result["candidate_catalog"]["repositories"]) == len(active)
    assert result["authorizes_catalog_publication"] is False


def test_strict_https_candidate_rejects_forged_nginx_t_success():
    source = doc()
    for bad in (1, True, -1, None):
        with pytest.raises(DerivedCatalogCandidateError,
                           match="NGINX_SYNTAX_NOT_OBSERVED"):
            strict_preview(source, exit_code=bad)


def test_strict_https_preview_remains_read_only(monkeypatch):
    import os
    import subprocess
    def forbidden(*args, **kwargs):
        pytest.fail("HTTPS catalog preview attempted host mutation")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    result = strict_preview(doc())
    assert result["authorizes_nginx_activation"] is False
