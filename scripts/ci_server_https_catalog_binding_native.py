#!/usr/bin/env python3
"""Check a complete HTTPS server context in a real stock NGINX -T dump.

#28/#95: disposable native syntax proof only; no service or catalog publish.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from repocache.server_derived_catalog_candidate_v1 import (
    DerivedCatalogCandidateError,
    preview_derived_catalog_from_nginx_dump,
    preview_derived_https_catalog_from_nginx_dump,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_https_server_candidate,
)

ROOT = Path("/repo")
HOST = "cache.example.invalid"


def main() -> None:
    if (os.geteuid() == 0 or not Path("/.dockerenv").is_file()
            or os.environ.get("REPOCACHE_DISPOSABLE_NGINX_SMOKE") != "1"):
        raise RuntimeError("DISPOSABLE_ROOTLESS_ONLY")
    nginx, openssl = shutil.which("nginx"), shutil.which("openssl")
    assert nginx and openssl, "STOCK_NGINX_AND_OPENSSL_REQUIRED"

    with tempfile.TemporaryDirectory(prefix="repocache-https-catalog-") as tmp:
        prefix = Path(tmp)
        cert, key = prefix / "synthetic.pem", prefix / "synthetic.key"
        issued = subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-keyout", str(key), "-out", str(cert),
             "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30, check=False,
        )
        assert issued.returncode == 0, "SYNTHETIC_TLS_FIXTURE_INVALID"
        key.chmod(0o600)

        doc = json.loads((ROOT / "docs/examples/server-install-v1.json").read_text())
        doc["deployment"]["listen"]["bind_address"] = "127.0.0.1"
        doc["deployment"]["listen"]["https_port"] = 18447
        doc["deployment"]["tls"]["certificate_file"] = str(cert)
        doc["deployment"]["tls"]["private_key_file"] = str(key)
        cache = prefix / "cache"
        doc["deployment"]["paths"]["cache_root"] = str(cache)
        for row in doc["repositories"]:
            row["desired_state"] = "active"
            if row["kind"] == "dnf":
                row["id"] = "almalinux-baseos"
            (cache / row["id"]).mkdir(mode=0o700, parents=True)
        original = copy.deepcopy(doc)
        pins = {
            row["id"]: {"mirror.example.invalid": ["8.8.8.8"]}
            for row in doc["repositories"]
        }
        complete = render_repository_https_server_candidate(
            doc, expected_state_generation=0,
            candidate_pins_by_repository=pins, ca_bundle_path=str(cert),
        )
        assert doc == original
        assert complete["authorizes_nginx_activation"] is False
        assert complete["authorizes_catalog_publication"] is False
        assert "$ssl_server_name" in complete["server_block_fragment"]
        assert "$http_host" in complete["server_block_fragment"]

        temp_paths = ""
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            part = prefix / name
            part.mkdir(mode=0o700)
            temp_paths += f"{name}_temp_path {part};\n"
        config = (
            f"pid {prefix / 'nginx.pid'};\n"
            f"error_log {prefix / 'nginx-error.log'} notice;\n"
            "worker_processes 1;\nevents { worker_connections 64; }\n"
            "http {\naccess_log off;\n" + temp_paths
            + complete["http_context_fragment"]
            + complete["server_block_fragment"] + "}\n"
        )
        conf = prefix / "nginx.conf"
        conf.write_text(config, encoding="ascii")
        check = subprocess.run(
            [nginx, "-T", "-p", str(prefix), "-c", str(conf)],
            capture_output=True, text=True, check=False, timeout=20,
        )
        assert check.returncode == 0, "STOCK_NGINX_HTTPS_CONFIG_REJECTED"
        result = preview_derived_https_catalog_from_nginx_dump(
            doc, candidate_pins_by_repository=pins, ca_bundle_path=str(cert),
            nginx_dump_text=check.stdout, nginx_t_exit_code=check.returncode,
        )
        assert result["status"] == "INERT_DERIVED_HTTPS_CATALOG_CANDIDATE_ONLY"
        assert len(result["candidate_catalog"]["repositories"]) == 2
        assert result["exact_https_server_context_candidate_matched"] is True
        assert result["authorizes_catalog_publication"] is False
        assert result["actual_active_exposure_verified"] is False
        assert result["real_tls_handshake_verified"] is False
        print("PASS: stock nginx -T matches exact complete HTTPS/SNI/routes "
              "and one inert APT/DNF catalog candidate", flush=True)

        # Distinguish ordinary route-only matching from strict HTTPS
        # context consistency. Mutation is textual negative test data,
        # NEVER a modified configuration used to launch a service.
        altered = check.stdout.replace("$ssl_server_name", "$ssl_fake_name", 1)
        assert altered != check.stdout
        ordinary = preview_derived_catalog_from_nginx_dump(
            doc, candidate_pins_by_repository=pins, ca_bundle_path=str(cert),
            nginx_dump_text=altered, nginx_t_exit_code=0,
        )
        assert ordinary["authorizes_catalog_publication"] is False
        try:
            preview_derived_https_catalog_from_nginx_dump(
                doc, candidate_pins_by_repository=pins, ca_bundle_path=str(cert),
                nginx_dump_text=altered, nginx_t_exit_code=0,
            )
        except DerivedCatalogCandidateError:
            pass
        else:
            raise AssertionError("FOREIGN_TLS_SNI_SERVER_CONTEXT_ACCEPTED")
        print("PASS: route-only text cannot bypass strict HTTPS/SNI binding",
              flush=True)
        print("NOT VERIFIED: installed NGINX/TLS trust, authorized activation, "
              "current live exposure or catalog publication", flush=True)


if __name__ == "__main__":
    main()
