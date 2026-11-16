#!/usr/bin/env python3
"""Prove nginx -t success does not imply successful live reload (CI #27/#31).

A deliberately occupied TCP port makes a real, syntax-valid reload fail.
Only a disposable nonroot NGINX process with a private configuration is used.
"""
from __future__ import annotations

import http.client
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
                + "server {\n"
                + f"listen 127.0.0.1:{serving_port};\n"
                + 'location = /health { return 200 "repocache-safe"; }\n'
                + "location / { return 404; }\n"
                + "}\n}\n"
            )
            candidate = normal.replace(
                "location = /health",
                f"listen 127.0.0.1:{held_port};\nlocation = /health", 1,
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
                original_workers = children(master.pid)
                print("PASS: packaged nonroot NGINX master serves initial loopback route", flush=True)
                conf.write_text(candidate, encoding="ascii")
                require(command(nginx, root, conf, "-t") == 0,
                        "RUNTIME_FAILURE_CANDIDATE_SYNTAX_FAILED")
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
                    and fetch_health(serving_port),
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
                require(switched and conf.read_text("ascii") == normal,
                        "ROLLBACK_GENERATION_UNVERIFIED")
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
