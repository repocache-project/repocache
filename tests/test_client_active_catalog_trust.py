"""Strict live-catalog trust contract for the v0.6.0 opt-in APT/DNF client.

The client still plans only: none of these tests authorize --apply, edit
package-manager sources, trust unsigned metadata or claim native VM support.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from urllib.request import HTTPSHandler, ProxyHandler

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "client_catalog_trust", ROOT / "client/repocache_client.py"
)
assert spec is not None and spec.loader is not None
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)

SERVER = "https://cache.example.invalid"
URL = SERVER + "/.well-known/repocache/catalog.json"
VALID = {
    "schema": 1,
    "repositories": [{
        "upstream": "https://mirror.example.invalid/debian/",
        "cache": SERVER + "/__repocache/repos/debian-main/",
    }],
}


def _catalog(monkeypatch, document):
    monkeypatch.setattr(client, "_fetch_json", lambda *_a, **_kw: document)
    return client._catalog(SERVER)


def test_exact_active_only_catalog_is_read_only_and_interoperable(monkeypatch):
    expected = _catalog(monkeypatch, VALID)
    assert expected == VALID
    assert client._mapped(
        {"urls": ["https://mirror.example.invalid/debian/dists/trixie/"]},
        expected,
    )
    assert not client._mapped(
        {"urls": ["https://foreign.example.invalid/debian/"]},
        expected,
    )
    assert _catalog(monkeypatch, {"schema": 1, "repositories": []}) == {
        "schema": 1, "repositories": [],
    }
    # Schema 1 also remains compatible with the audited legacy explicit
    # per-path NGINX approval catalog; it remains read-only here.
    legacy = {"schema": 1, "repositories": [{
        "upstream": "https://deb.debian.org/debian/",
        "cache": SERVER + "/debian/",
    }]}
    assert _catalog(monkeypatch, legacy) == legacy


@pytest.mark.parametrize("document", [
    {"schema": True, "repositories": []},
    {"schema": 1.0, "repositories": []},
    {"schema": "1", "repositories": []},
    {"schema": 2, "repositories": []},
    {"schema": 1, "repositories": {}, "extra": "ignored?"},
    {"schema": 1, "repositories": [{}]},
    {"schema": 1, "repositories": [{"upstream": "https://x.example/",
                                    "cache": SERVER + "/__repocache/repos/x/",
                                    "priority": 9}]},
    {"schema": 1, "repositories": [VALID["repositories"][0]] * 2},
    {"schema": 1, "repositories": [
        VALID["repositories"][0],
        {"upstream": "https://another.example.invalid/repository/",
         "cache": VALID["repositories"][0]["cache"]},
    ]},
    {"schema": 1, "repositories": [
        VALID["repositories"][0],
        {"upstream": VALID["repositories"][0]["upstream"],
         "cache": SERVER + "/__repocache/repos/other-id/"},
    ]},
    {"schema": 1, "repositories": [{
        **VALID["repositories"][0],
        "cache": SERVER + "/evil//repo/",
    }]},
    {"schema": 1, "repositories": [{
        **VALID["repositories"][0],
        "cache": SERVER + "/__repocache/repos/../../evil/",
    }]},
    {"schema": 1, "repositories": [{
        **VALID["repositories"][0],
        "cache": SERVER + "/__repocache/repos/%2e%2e/",
    }]},
    {"schema": 1, "repositories": [{
        **VALID["repositories"][0],
        "cache": "https://foreign.example.invalid/__repocache/repos/debian-main/",
    }]},
    {"schema": 1, "repositories": [{
        **VALID["repositories"][0],
        "upstream": "http://mirror.example.invalid/debian/",
    }]},
])
def test_unsupported_or_forged_active_catalog_fails_closed(monkeypatch, document):
    with pytest.raises(client.ClientError):
        _catalog(monkeypatch, document)


def test_duplicate_json_object_keys_are_rejected_without_last_wins():
    for body in (
        b'{"schema":1,"schema":1,"repositories":[]}',
        b'{"schema":1,"repositories":[{"upstream":"https://a.example/",'
        b'"upstream":"https://b.example/","cache":'
        b'"https://cache.example.invalid/__repocache/repos/a/"}]}',
    ):
        with pytest.raises(client.ClientError, match="Duplicate catalog"):
            json.loads(body, object_pairs_hook=client._strict_catalog_pairs)


@pytest.mark.parametrize("raw", [b'NaN', b'Infinity', b'-Infinity'])
def test_nonfinite_catalog_json_is_refused(raw, monkeypatch):
    assert len(raw) < client.MAX_CATALOG_BYTES
    with pytest.raises(client.ClientError):
        json.loads(
            raw, parse_constant=lambda _v: (_ for _ in ()).throw(
                client.ClientError("Non-finite catalog value"),
            ),
        )


class Response:
    def __init__(self, url=URL, status=200, payload=b'{"schema":1,"repositories":[]}'):
        self.url = url
        self.status = status
        self.payload = payload
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def read(self, size):
        return self.payload[:size]


@pytest.mark.parametrize("url,status", [
    (URL, 200),
    (URL + "?redirected=true", 200),
    ("https://foreign.example.invalid/steal", 200),
    (URL, 206),
])
def test_fetch_uses_verified_tls_no_ambient_proxy_and_disables_redirects(
    monkeypatch, url, status,
):
    captured = {}
    def make_opener(*handlers):
        captured["handlers"] = handlers
        class Opener:
            def open(self, request, *, timeout):
                captured["request"] = request
                captured["timeout"] = timeout
                return Response(url=url, status=status)
        return Opener()
    monkeypatch.setattr(client, "build_opener", make_opener)
    monkeypatch.setattr(client, "urlopen",
                        lambda *_a, **_kw: pytest.fail("ambient urllib forbidden"))
    if url == URL and status == 200:
        assert client._fetch_json(URL, max_bytes=client.MAX_CATALOG_BYTES) == {
            "schema": 1, "repositories": [],
        }
    else:
        with pytest.raises(client.ClientError, match="response origin or status"):
            client._fetch_json(URL, max_bytes=client.MAX_CATALOG_BYTES)
    assert captured["request"].full_url == URL
    assert captured["timeout"] == 5
    handlers = captured["handlers"]
    assert len(handlers) == 3
    assert isinstance(handlers[0], ProxyHandler)
    assert handlers[0].proxies == {}
    assert isinstance(handlers[1], client._RejectRedirects)
    assert handlers[1].redirect_request(None, None, 302, "moved", {},
                                        "https://foreign.example.invalid/") is None
    assert isinstance(handlers[2], HTTPSHandler)


def test_fetch_json_refuses_oversize_and_ambiguous_json(monkeypatch):
    bodies = [
        b'{"schema":1,"schema":1,"repositories":[]}',
        b'{"schema":NaN,"repositories":[]}',
        b'{"schema":1,"repositories":[]}' + b' ' * 600,
    ]
    for raw in bodies:
        class Opener:
            def open(self, request, *, timeout):
                return Response(payload=raw)
        monkeypatch.setattr(client, "build_opener", lambda *_: Opener())
        with pytest.raises(client.ClientError, match="|".join((
            "Duplicate catalog", "Non-finite catalog", "Catalog too large",
        ))):
            client._fetch_json(URL, max_bytes=512)


@pytest.mark.parametrize("bad", [
    "https://CACHE.example.invalid",
    "https://cache.example.invalid:0443",
    "https://cache.example.invalid:000443",
    "https://cache.example.invalid:0x1bb",
    "https://cache.example.invalid.:443",
    "https://[2001:0DB8::1]",
])
def test_explicit_or_installed_client_server_origin_refuses_noncanonical_authority(bad):
    with pytest.raises(client.ClientError, match="canonical HTTPS origin|Invalid server address"):
        client._server(bad)


@pytest.mark.parametrize("good", [
    "https://cache.example.invalid",
    "https://cache.example.invalid:443",
    "https://cache.example.invalid:18443/",
    "https://127.0.0.1:18443",
    "https://[2001:db8::1]:443",
])
def test_canonical_origin_remains_compatible_with_existing_cli_config(good):
    assert client._server(good) == good.rstrip("/")
