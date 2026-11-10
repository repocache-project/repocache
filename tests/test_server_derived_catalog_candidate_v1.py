"""#28 active-only discovery preview; no host write or publication claims."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_derived_catalog_candidate_v1 import (
    DerivedCatalogCandidateError, preview_derived_catalog_from_nginx_dump,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
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
