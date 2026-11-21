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
import signal
import socket
import subprocess
import tempfile
import time

from ci_generated_nginx_route_cache_smoke import (
    nginx_master_children, await_worker_generation_drained,
)
from ci_native_nginx_cache_smoke import free_port

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



def live_lifecycle_withdrawal(
    document: dict, disabled: dict, *, all_pins: dict, ca: str,
    nginx: str, root: Path, retained: Path, initial_digest: str,
    initial_inode: int,
) -> None:
    """Exercise actual private NGINX worker generations, not only nginx -T.

    The synthetic return-204 probes are injected ONLY into a disposable
    local config after strict real-pin rendering, and the outgoing pin
    is forced to a non-serving loopback port. No external upstream is used.
    This tests runtime routing under reload, not real signed cache HITs,
    installed activation, user authority or a published catalog.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    assert 1024 < port <= 65535
    path = root / "live-route-test.conf"

    def config(doc: dict, pins: dict) -> None:
        rendered = render_repository_nginx_bundle_candidate(
            doc, expected_state_generation=0,
            candidate_pins_by_repository=pins, ca_bundle_path=ca,
        )
        active_ids = rendered["proposed_repository_ids"]
        assert not rendered["authorizes_nginx_activation"]
        assert not rendered["authorizes_catalog_publication"]
        # Substitute validated public pin AFTER generator approval, test-only;
        # if any request escapes the static route probe it still cannot
        # contact a public upstream.
        public = "server 8.8.8.8:443;"
        upstream = rendered["http_upstream_fragment"]
        assert upstream.count(public) == len(active_ids)
        upstream = upstream.replace(public, "server 127.0.0.1:65535;")
        assert "8.8.8.8" not in upstream
        locations = rendered["server_location_fragment"]
        for name in active_ids:
            needle = f"location ^~ /__repocache/repos/{name}/ {{\\n"
            assert locations.count(needle) == 1
            locations = locations.replace(
                needle, needle + "    return 204;\\n",
            )
        # The complete final config runs in a *private* process under
        # nonroot UID 65534. Injected fixture return short-circuits proxy.
        content = (
            f"pid {root / 'live-nginx.pid'};\\n"
            f"error_log {root / 'live-nginx-error.log'} notice;\\n"
            "worker_processes 1;\\nevents { worker_connections 64; }\\n"
            "http { access_log off;\\n"
            + "".join(f"{name}_temp_path {root / name};\\n"
                      for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
            + upstream
            + f"server {{ listen 127.0.0.1:{port};\\n"
            + "server_name localhost;\\n"
            + "location / { return 404; }\\n"
            + locations
            + "}\\n}\\n"
        )
        path.write_text(content, encoding="ascii")
        syntax = subprocess.run(
            [nginx, "-t", "-p", str(root), "-c", str(path)],
            capture_output=True, text=True, check=False, timeout=12,
        )
        assert syntax.returncode == 0, "LIVE_TEST_NGINX_SYNTAX_REFUSED"

    def response_code(repository_id: str) -> int:
        target = f"/__repocache/repos/{repository_id}/probe"
        assert target.isascii()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall((
                f"GET {target} HTTP/1.1\\r\\n"
                "Host: localhost\\r\\nConnection: close\\r\\n\\r\\n"
            ).encode("ascii"))
            first = sock.recv(1024).split(b"\\r\\n", 1)[0]
        assert first.startswith(b"HTTP/1."), "NATIVE_NGINX_RESPONSE_INVALID"
        return int(first.split(b" ", 2)[1])

    def expect(expected: dict[str, int], process: subprocess.Popen) -> None:
        for _ in range(80):
            assert process.poll() is None, "DISPOSABLE_NGINX_MASTER_EXITED"
            try:
                outcomes = {name: response_code(name) for name in expected}
                if outcomes == expected:
                    return
            except (OSError, ValueError, IndexError):
                pass
            time.sleep(0.05)
        raise AssertionError("LIVE_NGINX_ROUTE_WITHDRAWAL_MISMATCH")

    def preserve_payload() -> None:
        assert retained.stat().st_ino == initial_inode
        assert hashlib.sha256(retained.read_bytes()).hexdigest() == initial_digest

    config(document, all_pins)
    process = subprocess.Popen(
        [nginx, "-p", str(root), "-c", str(path),
         "-g", "daemon off;"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        expect({APT: 204, DNF: 204, "unapproved-repository": 404}, process)
        preserve_payload()

        def reload(doc: dict, pins: dict, checks: dict[str, int]) -> None:
            before = nginx_master_children(process.pid)
            assert before, "NATIVE_NGINX_WORKER_IDENTITY_MISSING"
            config(doc, pins)
            # Fixed, process-local SIGHUP; never signal the machine's NGINX.
            process.send_signal(signal.SIGHUP)
            await_worker_generation_drained(process, before)
            expect(checks, process)
            preserve_payload()

        reload(disabled, {APT: all_pins[APT]},
               {APT: 204, DNF: 404, "unapproved-repository": 404})

        removed = copy.deepcopy(disabled)
        removed["repositories"] = [
            row for row in removed["repositories"] if row["id"] != DNF
        ]
        reload(removed, {APT: all_pins[APT]},
               {APT: 204, DNF: 404})

        # Synthetic rollback of the ORIGINAL config, not permission to
        # reuse a retired ID in a durable all-time reservation ledger.
        reload(document, all_pins, {APT: 204, DNF: 204})
    finally:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=8)
    preserve_payload()
    print("PASS: real nonroot NGINX worker generations serve, withdraw, "
          "remove and restore active-only routes without cache sentinel loss",
          flush=True)
    print("NOT VERIFIED: actual signed cache HIT, protected state / catalog "
          "transaction, installed systemd / SELinux or production signing",
          flush=True)



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

        live_lifecycle_withdrawal(
            doc, disabled, all_pins=all_pins, ca=ca, nginx=nginx,
            root=root, retained=payload, initial_digest=digest,
            initial_inode=original_inode,
        )

        print("PASS: stock nginx -T and derived catalog withdraw disabled route, "
              "deny forged dump, retain cache inode and re-enable candidate", flush=True)
        print("NOT VERIFIED: installed NGINX reload/owner, signed client cache, "
              "native host systemd/SELinux or actual cache loader reuse", flush=True)


if __name__ == "__main__":
    main()
