"""Client/derived catalog schema contract, without publication or sources edits."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from repocache.server_derived_catalog_candidate_v1 import (
    preview_derived_catalog_from_nginx_dump,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "isolated_native_client_v06_catalog", ROOT / "client/repocache_client.py"
)
assert spec and spec.loader
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def _candidate(*, disabled=()):
    doc = json.loads(
        (ROOT / "docs/examples/server-install-v1.json").read_text("utf-8")
    )
    doc["repositories"][1]["id"] = "almalinux-baseos"
    for row in doc["repositories"]:
        row["desired_state"] = (
            "disabled" if row["id"] in disabled else "active"
        )
    pins = {
        row["id"]: {"mirror.example.invalid": ["8.8.8.8"]}
        for row in doc["repositories"] if row["desired_state"] == "active"
    }
    ca = "/etc/ssl/certs/ca-certificates.crt"
    bundle = render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=0,
        candidate_pins_by_repository=pins, ca_bundle_path=ca,
    )
    nginx_text = ("http {\n" + bundle["http_upstream_fragment"]
                  + "server {\n" + bundle["server_location_fragment"]
                  + "}\n}\n")
    return preview_derived_catalog_from_nginx_dump(
        doc, candidate_pins_by_repository=pins, ca_bundle_path=ca,
        nginx_dump_text=nginx_text, nginx_t_exit_code=0,
    )


def test_derived_mapping_matches_standalone_client_contract(monkeypatch):
    preview = _candidate()
    catalog = preview["candidate_catalog"]
    monkeypatch.setattr(client, "_fetch_json", lambda *_a, **_kw: catalog)
    fetched = client._catalog("https://cache.example.invalid")
    assert fetched == catalog
    apt = fetched["repositories"][1]
    dnf = fetched["repositories"][0]
    assert client._classify_repository(
        {"urls": [apt["upstream"], apt["cache"]]}, fetched,
    ) == "supported"
    assert client._classify_repository(
        {"urls": [dnf["upstream"], dnf["cache"]]}, fetched,
    ) == "supported"
    assert client._classify_repository({
        "urls": [apt["upstream"], "https://foreign.example.invalid/"]
    }, fetched) == "unknown"
    assert preview["authorizes_catalog_publication"] is False


def test_disabled_route_is_not_usable_via_standalone_client(monkeypatch):
    preview = _candidate(disabled=("almalinux-baseos",))
    catalog = preview["candidate_catalog"]
    monkeypatch.setattr(client, "_fetch_json", lambda *_a, **_kw: catalog)
    fetched = client._catalog("https://cache.example.invalid")
    assert len(fetched["repositories"]) == 1
    assert client._classify_repository({
        "urls": ["https://mirror.example.invalid/almalinux/10/BaseOS/x86_64/os/"]
    }, fetched) == "unknown"
    assert preview["installed_catalog_publication_verified"] is False
