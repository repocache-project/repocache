"""Future opt-in APT/DNF source route shape; never authenticates catalog (#24)."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repocache_client_native_catalog_shape",
    ROOT / "client/repocache_client.py",
)
assert SPEC is not None and SPEC.loader is not None
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)

SERVER = "https://cache.example.invalid"
APT = "https://deb.example.invalid/debian/"
DNF = "https://rpm.example.invalid/almalinux/10/"
ID_APT = "debian-main"
ID_DNF = "almalinux-baseos"


def catalog():
    return {
        "schema": 1,
        "repositories": [
            {"upstream": APT,
             "cache": SERVER + "/__repocache/repos/" + ID_APT + "/"},
            {"upstream": DNF,
             "cache": SERVER + "/__repocache/repos/" + ID_DNF + "/"},
        ],
    }


def preview(doc=None, *, source=APT, ident=ID_APT, server=SERVER):
    return client.preview_native_client_catalog_route(
        server, catalog() if doc is None else doc,
        upstream=source, repository_id=ident,
    )


def test_exact_v06_apt_and_dnf_routes_admit_non_authorizing_shape_only():
    c = catalog()
    before = copy.deepcopy(c)
    for source, ident in ((APT, ID_APT), (DNF, ID_DNF)):
        result = preview(c, source=source, ident=ident)
        assert result == {
            "schema_version": 1,
            "status": "NATIVE_CATALOG_ROUTE_SHAPE_ONLY",
            "repository_id": ident,
            "read_only_mapping_observed": True,
            "catalog_publisher_authenticated": False,
            "native_operator_approval_verified": False,
            "source_file_ownership_verified": False,
            "native_fallback_verified": False,
            "authorizes_source_write": False,
        }
    assert c == before


def test_legacy_readonly_catalog_path_not_permitted_for_native_apply_shape():
    c = catalog()
    c["repositories"][0]["cache"] = SERVER + "/debian/"
    # Historical read-only lookup remains unaffected; native source writers
    # must not treat arbitrary same-origin catalog paths as privileged routes.
    with pytest.raises(client.ClientError, match="Native catalog route"):
        preview(c)


@pytest.mark.parametrize("change", [
    "wrong-id", "foreign-origin", "foreign-id-collision", "duplicate-source",
    "duplicate-cache", "missing-target", "unknown-map-field", "untrusted-upstream",
    "escaped-route", "dotdot-route", "credentials", "http-source", "cache-query",
    "cache-fragment", "alternate-port", "numeric-leading-id", "oversize-url",
])
def test_unsafe_or_ambiguous_catalog_routes_refused(change):
    c = catalog()
    if change == "wrong-id":
        c["repositories"][0]["cache"] = SERVER + "/__repocache/repos/other/"
    elif change == "foreign-origin":
        c["repositories"][0]["cache"] = "https://evil.example/__repocache/repos/debian-main/"
    elif change == "foreign-id-collision":
        c["repositories"][1]["cache"] = SERVER + "/__repocache/repos/debian-main/"
    elif change == "duplicate-source":
        c["repositories"][1]["upstream"] = APT
    elif change == "duplicate-cache":
        c["repositories"][1]["cache"] = c["repositories"][0]["cache"]
    elif change == "missing-target":
        c["repositories"] = [c["repositories"][1]]
    elif change == "unknown-map-field":
        c["repositories"][0]["unapproved"] = True
    elif change == "untrusted-upstream":
        c["repositories"][0]["upstream"] = "https://user:secret@deb.example.invalid/debian/"
    elif change == "escaped-route":
        c["repositories"][0]["cache"] = SERVER + "/__repocache/repos/%2e%2e/"
    elif change == "dotdot-route":
        c["repositories"][0]["cache"] = SERVER + "/__repocache/repos/../"
    elif change == "credentials":
        c["repositories"][0]["cache"] = "https://u:p@cache.example.invalid/__repocache/repos/debian-main/"
    elif change == "http-source":
        c["repositories"][0]["upstream"] = "http://deb.example.invalid/debian/"
    elif change == "cache-query":
        c["repositories"][0]["cache"] += "?q=x"
    elif change == "cache-fragment":
        c["repositories"][0]["cache"] += "#foo"
    elif change == "alternate-port":
        c["repositories"][0]["cache"] = SERVER + ":8443/__repocache/repos/debian-main/"
    elif change == "numeric-leading-id":
        c["repositories"][0]["cache"] = SERVER + "/__repocache/repos/9repo/"
    else:
        c["repositories"][0]["cache"] = SERVER + "/__repocache/repos/" + "x" * 5000 + "/"
    with pytest.raises(client.ClientError, match="Native catalog"):
        preview(c)


@pytest.mark.parametrize("value", [
    None, True, 1, [], {}, "2", {"schema": 1},
    {"schema": 1, "repositories": {}},
    {"schema": True, "repositories": []},
    {"schema": 1, "repositories": [1]},
    {"schema": 1, "repositories": []},
    {"schema": 1, "repositories": [{}]},
])
def test_wrong_catalog_schema_or_missing_route_refused(value):
    with pytest.raises(client.ClientError, match="Native catalog"):
        preview(value)


@pytest.mark.parametrize("ident", [
    "", "0repo", "Uppercase", "a" * 49, "../outside", None, True, "a%2fb",
])
def test_unapproved_or_invalid_route_id_refused_before_network(ident):
    with pytest.raises(client.ClientError, match="Native catalog"):
        preview(ident=ident)


def test_server_id_grammar_agrees_with_install_v1():
    from repocache.server_install_v1 import ID
    for value in ("a", "debian-main", "a-", "a" * 48):
        assert ID.fullmatch(value) is not None
        c = catalog()
        c["repositories"][0]["cache"] = SERVER + "/__repocache/repos/" + value + "/"
        assert preview(c, ident=value)["repository_id"] == value


def test_future_native_preview_does_not_fetch_catalog_or_touch_os(monkeypatch):
    import os
    import socket
    import subprocess

    def forbidden(*_a, **_kw):
        pytest.fail("Native catalog route preview must not access the host")
    monkeypatch.setattr(client, "_fetch_json", forbidden)
    monkeypatch.setattr(client, "_catalog", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    assert preview()["authorizes_source_write"] is False


def test_large_untrusted_catalog_values_refuse_with_fixed_error():
    c = catalog()
    c["repositories"][0]["upstream"] = APT + ("secret" * 10000)
    with pytest.raises(client.ClientError) as exc:
        preview(c)
    assert "secret" not in str(exc.value)
