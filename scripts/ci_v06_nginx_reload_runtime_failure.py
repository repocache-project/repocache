#!/usr/bin/env python3
"""Prove nginx -t success does not imply successful live reload (CI #27/#31).

A deliberately occupied TCP port makes a real, syntax-valid reload fail.
Only a disposable nonroot NGINX process with a private configuration is used.
"""
from __future__ import annotations

import http.client
import copy
import json

from repocache.server_derived_catalog_candidate_v1 import (
    preview_derived_catalog_from_nginx_dump,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


class ReloadSmokeError(RuntimeError):
    """Static CI failure code, never a host path or private configuration."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ReloadSmokeError(code)


def command(nginx: str, root: Path, conf: Path, *args: str) -> int:
    result = subprocess.run(
        [nginx, *args, "-p", str(root), "-c", str(conf)],
        capture_output=True, stdin=subprocess.DEVNULL, timeout=10, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    return result.returncode


def children(pid: int) -> frozenset[int]:
    raw = Path(f"/proc/{pid}/task/{pid}/children").read_text("ascii").split()
    require(0 < len(raw) <= 8 and all(item.isdecimal() and len(item) <= 10
                                     for item in raw), "NGINX_WORKERS_UNVERIFIED")
    return frozenset(int(item) for item in raw)


def fetch_health(port: int) -> bool:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/health")
        answer = connection.getresponse()
        return answer.status == 200 and answer.read() == b"repocache-safe"
    finally:
        connection.close()


def wait_health(port: int, proc: subprocess.Popen) -> None:
    for _ in range(80):
        require(proc.poll() is None, "NGINX_MASTER_EXITED")
        try:
            if fetch_health(port):
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.05)
    raise ReloadSmokeError("NGINX_OLD_LISTENER_UNAVAILABLE")



def fetch_managed_route(port: int, repo_id: str) -> int:
    """Observe a specific repository route on the active private master."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", f"/__repocache/repos/{repo_id}/probe")
        reply = connection.getresponse()
        status, body = reply.status, reply.read()
        require(body == (b"repocache-active" if status == 200 else body),
                "MANAGED_ROUTE_RESPONSE_INVALID")
        return status
    finally:
        connection.close()


def generated_fixture(root: Path, ca: str) -> tuple[str, str, dict, dict, dict]:
    """Render real active and disabled candidates; no local apply authority."""
    example = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
    doc = json.loads(example.read_text("utf-8"))
    cache = root / "repository-cache"
    for repo in doc["repositories"]:
        repo["desired_state"] = "active"
        if repo["kind"] == "dnf":
            repo["id"] = "almalinux-baseos"
        (cache / repo["id"]).mkdir(mode=0o700, parents=True, exist_ok=True)
    doc["deployment"]["paths"]["cache_root"] = str(cache)
    pins = {
        repo["id"]: {"mirror.example.invalid": ["8.8.8.8"]}
        for repo in doc["repositories"]
    }
    active = render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=0,
        candidate_pins_by_repository=pins, ca_bundle_path=ca,
    )
    inactive_doc = copy.deepcopy(doc)
    for repo in inactive_doc["repositories"]:
        if repo["id"] == "almalinux-baseos":
            repo["desired_state"] = "disabled"
    inactive_pins = {"debian-trixie-main": pins["debian-trixie-main"]}
    disabled = render_repository_nginx_bundle_candidate(
        inactive_doc, expected_state_generation=0,
        candidate_pins_by_repository=inactive_pins, ca_bundle_path=ca,
    )
    require(active["proposed_repository_ids"]
            == ["almalinux-baseos", "debian-trixie-main"]
            and disabled["proposed_repository_ids"] == ["debian-trixie-main"]
            and not active["authorizes_nginx_activation"]
            and not disabled["authorizes_nginx_activation"]
            and not disabled["authorizes_catalog_publication"],
            "REAL_REPOSITORY_RENDER_INVALID")
    def test_routes(rendered: dict) -> str:
        result = rendered["server_location_fragment"]
        for rid in rendered["proposed_repository_ids"]:
            header = f"location ^~ /__repocache/repos/{rid}/ {{\n"
            require(result.count(header) == 1,
                    "GENERATED_LOCATION_HEADER_INVALID")
            result = result.replace(
                header, header + '    return 200 "repocache-active";\n', 1,
            )
        return result
    return test_routes(active), test_routes(disabled), doc, inactive_doc, inactive_pins


def main() -> None:
    require(
        os.geteuid() != 0 and Path("/.dockerenv").is_file()
        and os.environ.get("REPOCACHE_DISPOSABLE_NGINX_RELOAD_CI") == "1"
        and Path("/proc/1/comm").read_text("ascii").strip() != "systemd",
        "DISPOSABLE_NONROOT_CONTAINER_REQUIRED",
    )
    nginx = shutil.which("nginx")
    require(nginx == "/usr/sbin/nginx", "STOCK_NGINX_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="repocache-failed-native-reload-") as temp:
        root = Path(temp)
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (root / name).mkdir(mode=0o700)
        temp_paths = "".join(
            f"{name}_temp_path {root / name};\n"
            for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
        )
        ca = next(
            (p for p in ("/etc/ssl/certs/ca-certificates.crt",
                          "/etc/pki/tls/certs/ca-bundle.crt")
             if Path(p).is_file()), None,
        )
        require(ca is not None, "STOCK_CA_BUNDLE_REQUIRED")
        live_routes, disabled_routes, source_doc, disabled_doc, inactive_pins = (
            generated_fixture(root, ca)
        )
        all_pins = {
            row["id"]: {"mirror.example.invalid": ["8.8.8.8"]}
            for row in source_doc["repositories"]
        }
        active_bundle = render_repository_nginx_bundle_candidate(
            source_doc, expected_state_generation=0,
            candidate_pins_by_repository=all_pins, ca_bundle_path=ca,
        )
        disabled_bundle = render_repository_nginx_bundle_candidate(
            disabled_doc, expected_state_generation=0,
            candidate_pins_by_repository=inactive_pins, ca_bundle_path=ca,
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as retained_socket:
            retained_socket.bind(("127.0.0.1", 0))
            retained_socket.listen(1)
            held_port = retained_socket.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                serving_port = probe.getsockname()[1]
            require(serving_port != held_port, "FIXTURE_PORTS_MUST_DIFFER")
            normal = (
                f"pid {root / 'nginx.pid'};\n"
                f"error_log {root / 'nginx-error.log'} notice;\n"
                "worker_processes 1;\n"
                "events { worker_connections 32; }\n"
                "http { access_log off;\n"
                + temp_paths
                + active_bundle["http_upstream_fragment"]
                + "server {\n"
                + f"listen 127.0.0.1:{serving_port};\n"
                + 'location = /health { return 200 "repocache-safe"; }\n'
                + "location / { return 404; }\n"
                + live_routes
                + "}\n}\n"
            )
            candidate = normal.replace(
                active_bundle["http_upstream_fragment"],
                disabled_bundle["http_upstream_fragment"], 1,
            ).replace(live_routes, disabled_routes, 1).replace(
                "location = /health",
                f"listen 127.0.0.1:{held_port};\nlocation = /health", 1,
            )
            require(
                "location ^~ /__repocache/repos/almalinux-baseos/" not in candidate
                and "repocache_cache_almalinux_baseos" not in candidate,
                "DISABLED_ROUTE_NOT_WITHDRAWN_IN_CANDIDATE",
            )
            require(candidate != normal, "FAILED_RELOAD_FIXTURE_UNCHANGED")
            conf = root / "nginx.conf"
            conf.write_text(normal, encoding="ascii")
            require(command(nginx, root, conf, "-t") == 0,
                    "INITIAL_NGINX_SYNTAX_INVALID")
            master = subprocess.Popen(
                [nginx, "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            try:
                wait_health(serving_port, master)
                require(
                    fetch_managed_route(serving_port, "almalinux-baseos") == 200
                    and fetch_managed_route(serving_port, "debian-trixie-main") == 200,
                    "INITIAL_GENERATED_ROUTES_NOT_LIVE",
                )
                original_workers = children(master.pid)
                print("PASS: packaged nonroot NGINX master serves initial loopback route", flush=True)
                conf.write_text(candidate, encoding="ascii")
                require(command(nginx, root, conf, "-t") == 0,
                        "RUNTIME_FAILURE_CANDIDATE_SYNTAX_FAILED")
                # The parser can approve a disabled-only catalog projection,
                # although live NGINX may never activate that configuration.
                # Test this mismatch instead of treating nginx -T as a
                # publication token for an inactive repository.
                catalog_conf = root / "proposed-catalog-only.conf"
                catalog_conf.write_text(
                    candidate.replace(
                        '    return 200 "repocache-active";\n', "",
                    ), encoding="ascii",
                )
                observed = subprocess.run(
                    [nginx, "-T", "-p", str(root), "-c", str(catalog_conf)],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                require(observed.returncode == 0,
                        "PROSPECTIVE_CATALOG_NGINX_SYNTAX_INVALID")
                catalog = preview_derived_catalog_from_nginx_dump(
                    disabled_doc, candidate_pins_by_repository=inactive_pins,
                    ca_bundle_path=ca, nginx_dump_text=observed.stdout,
                    nginx_t_exit_code=observed.returncode,
                )
                require(
                    catalog["desired_active_repository_ids"]
                    == ["debian-trixie-main"]
                    and len(catalog["candidate_catalog"]["repositories"]) == 1
                    and catalog["authorizes_catalog_publication"] is False
                    and catalog["actual_active_exposure_verified"] is False,
                    "UNTRUSTED_CATALOG_PROJECTION_NOT_INERT",
                )
                require(command(nginx, root, conf, "-s", "reload") == 0,
                        "NATIVE_RELOAD_SIGNAL_FAILED")
                log = root / "nginx-error.log"
                for _ in range(120):
                    require(master.poll() is None, "NGINX_MASTER_EXITED_ON_BAD_RELOAD")
                    if "still could not bind()" in log.read_text("utf-8"):
                        break
                    time.sleep(0.05)
                else:
                    raise ReloadSmokeError("RUNTIME_BIND_FAILURE_NOT_OBSERVED")
                require(
                    children(master.pid) == original_workers
                    and fetch_health(serving_port)
                    and fetch_managed_route(serving_port, "almalinux-baseos") == 200
                    and fetch_managed_route(serving_port, "debian-trixie-main") == 200,
                    "OLD_WORKER_NOT_PRESERVED_AFTER_FAILED_ACTIVATION",
                )
                print("PASS: nginx -t and reload signal succeeded but port binding failed; old worker stayed available", flush=True)
                conf.write_text(normal, encoding="ascii")
                require(command(nginx, root, conf, "-t") == 0,
                        "ROLLBACK_NGINX_SYNTAX_INVALID")
                require(command(nginx, root, conf, "-s", "reload") == 0,
                        "ROLLBACK_RELOAD_SIGNAL_FAILED")
                switched = False
                for _ in range(100):
                    require(master.poll() is None, "NGINX_MASTER_EXITED_DURING_ROLLBACK")
                    current = children(master.pid)
                    if current.isdisjoint(original_workers) and fetch_health(serving_port):
                        switched = True
                        break
                    time.sleep(0.05)
                require(
                    switched and conf.read_text("ascii") == normal
                    and fetch_managed_route(serving_port, "almalinux-baseos") == 200
                    and fetch_managed_route(serving_port, "debian-trixie-main") == 200,
                    "ROLLBACK_GENERATION_UNVERIFIED",
                )
                print(
                    "PASS: real generated DNF route remains live after syntax-valid "
                    "failed withdrawal reload; inactive-only catalog candidate "
                    "stays non-publishable and rollback retains active routes",
                    flush=True,
                )
                print("PASS: validated rollback reload replaced old worker, restored exact config and healthy listener", flush=True)
            finally:
                master.terminate()
                try:
                    master.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    master.kill()
                    master.wait(timeout=5)
    print("NOT VERIFIED: production transaction authority, installed systemd, SELinux or crash-durable native rollback", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ReloadSmokeError, OSError, ValueError, subprocess.TimeoutExpired):
        print("FAIL: disposable NGINX reload failure or rollback unverified", flush=True)
        raise SystemExit(1)
