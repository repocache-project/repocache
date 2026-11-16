#!/usr/bin/env python3
"""Actual stock NGINX -T verifies generated active-only route/catalog removal.

Disposable nonroot userspace; candidate-only, no running managed service,
publication, package traffic, cleanup or installed host authority (#95/#28).
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from repocache.server_derived_catalog_candidate_v1 import (
    DerivedCatalogCandidateError, preview_derived_catalog_from_nginx_dump,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)

ROOT = Path(__file__).resolve().parents[1]
APT = "debian-trixie-main"
DNF = "almalinux-baseos"
HOST = "mirror.example.invalid"
CA_PATHS = ("/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt")


def inspected_candidate(document: dict, pins: dict, ca: str,
                        nginx: str, prefix: Path) -> tuple[dict, dict, str]:
    candidate = render_repository_nginx_bundle_candidate(
        document, expected_state_generation=0,
        candidate_pins_by_repository=pins, ca_bundle_path=ca,
    )
    assert candidate["authorizes_nginx_activation"] is False
    assert candidate["authorizes_catalog_publication"] is False
    for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        (prefix / name).mkdir(mode=0o700, exist_ok=True)
    config = (
        f"pid {prefix / 'nginx.pid'};\n"
        f"error_log {prefix / 'nginx-error.log'} notice;\n"
        "worker_processes 1;\nevents { worker_connections 64; }\n"
        "http {\naccess_log off;\n"
        + "".join(f"{name}_temp_path {prefix / name};\n"
                  for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        + candidate["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19317;\nlocation / { return 404; }\n"
        + candidate["server_location_fragment"]
        + "}\n}\n"
    )
    conf = prefix / "nginx.conf"
    conf.write_text(config, encoding="utf-8")
    observed = subprocess.run(
        [nginx, "-T", "-p", str(prefix), "-c", str(conf)],
        capture_output=True, text=True, check=False, timeout=12,
    )
    assert observed.returncode == 0, "STOCK_NGINX_CANDIDATE_SYNTAX_REFUSED"
    catalog = preview_derived_catalog_from_nginx_dump(
        document, candidate_pins_by_repository=pins, ca_bundle_path=ca,
        nginx_dump_text=observed.stdout, nginx_t_exit_code=observed.returncode,
    )
    assert catalog["authorizes_catalog_publication"] is False
    assert catalog["actual_active_exposure_verified"] is False
    assert catalog["inert_nginx_dump_routes_match_candidate"] is True
    return candidate, catalog, observed.stdout


def main() -> None:
    if (os.geteuid() == 0 or not Path("/.dockerenv").is_file()
            or os.environ.get("REPOCACHE_DISPOSABLE_NGINX_SMOKE") != "1"):
        raise RuntimeError("DISPOSABLE_NONROOT_NGINX_REQUIRED")
    nginx = shutil.which("nginx")
    assert nginx == "/usr/sbin/nginx", "Unexpected native binary"
    ca = next((p for p in CA_PATHS if Path(p).is_file()), None)
    assert ca, "Native CA file missing"
    doc = json.loads((ROOT / "docs/examples/server-install-v1.json").read_text())
    for item in doc["repositories"]:
        item["desired_state"] = "active"
        if item["kind"] == "dnf":
            item["id"] = DNF
    assert len(doc["repositories"]) == 2
    with tempfile.TemporaryDirectory(prefix="repocache-native-catalog-withdraw-") as temp:
        root = Path(temp)
        cache = root / "cache"
        cache.mkdir(mode=0o700)
        doc["deployment"]["paths"]["cache_root"] = str(cache)
        for item in doc["repositories"]:
            (cache / item["id"]).mkdir(mode=0o700)
        payload = cache / DNF / "fixture-retained-package"
        payload.write_bytes(b"unchanged-after-remove-and-reenable")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        original_inode = payload.stat().st_ino
        all_pins = {
            APT: {HOST: ["8.8.8.8"]},
            DNF: {HOST: ["8.8.8.8"]},
        }
        both, both_catalog, both_dump = inspected_candidate(
            doc, all_pins, ca, nginx, root,
        )
        assert both["proposed_repository_ids"] == [DNF, APT]
        assert len(both_catalog["candidate_catalog"]["repositories"]) == 2
        assert both_dump.count(f"location ^~ /__repocache/repos/{DNF}/ {{") == 1

        disabled = copy.deepcopy(doc)
        for item in disabled["repositories"]:
            if item["id"] == DNF:
                item["desired_state"] = "disabled"
        reduced, catalog, dump = inspected_candidate(
            disabled, {APT: all_pins[APT]}, ca, nginx, root,
        )
        assert reduced["proposed_repository_ids"] == [APT]
        assert len(catalog["candidate_catalog"]["repositories"]) == 1
        assert f"location ^~ /__repocache/repos/{DNF}/ {{" not in dump
        assert dump.count(f"location ^~ /__repocache/repos/{APT}/ {{") == 1
        assert hashlib.sha256(payload.read_bytes()).hexdigest() == digest
        assert payload.stat().st_ino == original_inode

        # The derived catalog must not trust a caller-supplied -T dump that
        # surreptitiously includes the route removed from desired state.
        try:
            preview_derived_catalog_from_nginx_dump(
                disabled, candidate_pins_by_repository={APT: all_pins[APT]},
                ca_bundle_path=ca,
                nginx_dump_text=(dump + f"\nlocation ^~ /__repocache/repos/{DNF}/ {{\n"),
                nginx_t_exit_code=0,
            )
        except DerivedCatalogCandidateError:
            pass
        else:
            raise AssertionError("FOREIGN_DISABLED_ROUTE_ACCEPTED")

        restored, restored_catalog, restored_dump = inspected_candidate(
            doc, all_pins, ca, nginx, root,
        )
        assert restored["proposed_repository_ids"] == [DNF, APT]
        assert len(restored_catalog["candidate_catalog"]["repositories"]) == 2
        assert restored_dump.count(f"location ^~ /__repocache/repos/{DNF}/ {{") == 1
        assert hashlib.sha256(payload.read_bytes()).hexdigest() == digest
        assert payload.stat().st_ino == original_inode

        print("PASS: stock nginx -T and derived catalog withdraw disabled route, "
              "deny forged dump, retain cache inode and re-enable candidate", flush=True)
        print("NOT VERIFIED: real NGINX reload/exposure, signed client cache, "
              "native host systemd/SELinux or actual cache loader reuse", flush=True)


if __name__ == "__main__":
    main()
