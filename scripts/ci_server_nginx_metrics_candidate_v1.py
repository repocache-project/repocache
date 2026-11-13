#!/usr/bin/env python3
"""Actual rootless NGINX metrics emission + REPOCACHE parser interoperability.

Test-only disposable Docker, localhost-only, temporary private filesystem.
No installed NGINX config, root helper, systemd, client source or TLS touched.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.request import build_opener, ProxyHandler

from repocache.core import Settings, metrics
from repocache.server_nginx_metrics_candidate_v1 import (
    METRICS_LOG, render_nginx_metrics_candidate,
)

_ROOT = Path(__file__).resolve().parents[1]
_REPO = "debian-trixie-main"
_ROUTE = "/__repocache/repos/" + _REPO + "/"
_PRIVATE = "PRIVATE_METRIC_QUERY_VALUE_NOT_FOR_LOGS"


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise AssertionError(reason)
    print("PASS: " + reason, flush=True)


def get_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def run() -> None:
    require(
        (os.geteuid() != 0 and Path("/.dockerenv").is_file()
         and os.environ.get("REPOCACHE_DISPOSABLE_NGINX_SMOKE") == "1"),
        "disposable non-root Docker-only metrics test",
    )
    nginx = shutil.which("nginx")
    require(bool(nginx), "distribution-packaged NGINX exists")
    doc = json.loads(
        (_ROOT / "docs/examples/server-install-v1.json").read_text("utf-8")
    )
    doc["deployment"]["logging"]["metrics_opt_in"] = True
    doc["repositories"][0]["desired_state"] = "active"
    doc["repositories"][1]["desired_state"] = "disabled"
    candidate = render_nginx_metrics_candidate(doc)
    require(
        set(candidate["location_directives_by_repository"]) == {_REPO}
        and not candidate["authorizes_nginx_activation"]
        and candidate["metrics_path_candidate"] == METRICS_LOG,
        "only approved active repository gets isolated opt-in metrics candidate",
    )

    with tempfile.TemporaryDirectory(prefix="repocache-metrics-v06-") as temp:
        root = Path(temp)
        log = root / "metrics.jsonl"
        conf = root / "nginx.conf"
        # Rootless NGINX must use private writable temp directories rather
        # than native distro package defaults under /var/lib/nginx.
        for dirname in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (root / dirname).mkdir(mode=0o700)
        port = get_port()
        # Test-only substitution of the fixed production destination into a
        # private disposable path; production never accepts a path override.
        directives = candidate["location_directives_by_repository"][_REPO]
        assert directives.count(METRICS_LOG) == 1
        directives = directives.replace(METRICS_LOG, str(log))
        config = (
            f"pid {root / 'nginx.pid'};\n"
            f"error_log {root / 'nginx-error.log'} notice;\n"
            "worker_processes 1;\n"
            "events { worker_connections 64; }\n"
            "http {\n"
            + "".join(
                f"{dirname}_temp_path {root / dirname};\n"
                for dirname in ("client_body", "proxy", "fastcgi",
                                "uwsgi", "scgi")
            )
            + "access_log off;\n"
            + candidate["http_log_format_fragment"] + "\n"
            f"server {{ listen 127.0.0.1:{port};\n"
            f"location ^~ {_ROUTE} {{\n"
            + directives +
            'return 200 "OK";\n'
            "}\n"
            "location = /not-approved/ { return 404; }\n"
            "}\n}\n"
        )
        conf.write_text(config, encoding="ascii")
        syntax = subprocess.run(
            [nginx, "-t", "-p", str(root), "-c", str(conf)],
            shell=False, capture_output=True, timeout=12, check=False,
        )
        require(syntax.returncode == 0,
                "actual native NGINX accepts derived metrics directives")
        proc = subprocess.Popen(
            [nginx, "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            opener = build_opener(ProxyHandler({}))
            def get(path: str) -> tuple[int, bytes]:
                last = None
                for _ in range(35):
                    try:
                        with opener.open(
                            f"http://127.0.0.1:{port}{path}", timeout=2
                        ) as response:
                            return response.status, response.read()
                    except OSError as exc:
                        last = exc
                        time.sleep(0.05)
                raise AssertionError("Disposable NGINX loopback unavailable") from last
            status, body = get(_ROUTE + "package.deb?token=" + _PRIVATE)
            require(status == 200 and body == b"OK",
                    "real active NGINX request returned exact payload")
            try:
                get("/not-approved/")
            except Exception:
                pass
            for _ in range(35):
                if log.exists() and log.stat().st_size:
                    break
                time.sleep(0.05)
            require(log.exists() and log.stat().st_size > 0,
                    "real NGINX wrote an opt-in structured metrics record")
            lines = log.read_text("utf-8").splitlines()
            require(len(lines) == 1, "disabled location produced no metrics record")
            require(_PRIVATE not in lines[0] and "package.deb" not in lines[0],
                    "query credentials and URL path excluded from log bytes")
            record = json.loads(lines[0])
            require(
                set(record) == {
                    "time_iso8601", "repocache_repository", "status",
                    "upstream_cache_status", "body_bytes_sent", "request_time",
                }
                and record["repocache_repository"] == _ROUTE
                and record["status"] == "200"
                and record["body_bytes_sent"] == "2",
                "metric schema agrees with the existing core parser",
            )
            observed = metrics(
                Settings(metrics_log=log), hours=1, repo=_ROUTE,
                now=datetime.now(timezone.utc),
            )
            require(
                observed["available"] is True
                and observed["requests"] == 1
                and observed["statuses_observed"] == 1
                and observed["bytes_sent"] == 2
                and observed["cache_observed"] == 0
                and observed["hit_rate"] is None,
                "real NGINX measurement parsed without invented cache HIT",
            )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=6)
    print("PASS: no host logging, installation or live activation", flush=True)


if __name__ == "__main__":
    run()
