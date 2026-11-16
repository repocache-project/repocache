#!/usr/bin/env python3
"""Live packaged NGINX metrics, stock logrotate and reopen in a private CI lab.

No installed host root, real systemd unit, production logging or NGINX service
is touched. This executable is guarded to disposable nonroot Docker only.
"""
from __future__ import annotations

from datetime import datetime, timezone
import gzip
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time

from repocache.core import Settings, metrics
from repocache.server_nginx_metrics_candidate_v1 import render_nginx_metrics_candidate
from repocache.server_native_metrics_logrotate_candidate_v1 import render_native_metrics_rotation_candidate

_GUARD = "REPOCACHE_DISPOSABLE_NGINX_ROTATION_CI"
_ROUTE = "/__repocache/repos/debian-trixie-main/"
_LOG = "/var/log/nginx/repocache-managed/metrics.jsonl"
_REOPEN = "/usr/bin/systemctl kill --kill-who=main --signal=USR1 nginx.service"
_SECRET = "opaque_private_query_must_not_log"


def _check(command: list[str], *, success: bool = True) -> None:
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            check=False, timeout=15)
    if (result.returncode == 0) != success:
        raise AssertionError("PRIVATE_NATIVE_COMMAND_UNEXPECTED_STATUS")


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


def _request(port: int, resource: str) -> None:
    deadline = time.monotonic() + 6
    while True:
        try:
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            client.request("GET", resource, headers={"Connection": "close"})
            response = client.getresponse()
            status = response.status
            response.read()
            client.close()
            assert status == 200, "PRIVATE_NGINX_RESPONSE_INVALID"
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def _wait_lines(path: Path, target: int) -> list[str]:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if path.is_file():
            rows = path.read_text(encoding="utf-8").splitlines()
            if len(rows) == target:
                return rows
        time.sleep(0.05)
    raise AssertionError("PRIVATE_NGINX_LOG_COUNT_MISMATCH")


def _private(path: Path) -> None:
    data = path.stat()
    assert stat.S_ISREG(data.st_mode)
    assert data.st_uid == os.geteuid()
    assert stat.S_IMODE(data.st_mode) & 0o077 == 0
    assert data.st_nlink == 1


def main() -> None:
    if (os.geteuid() == 0 or os.environ.get(_GUARD) != "1"
            or not Path("/.dockerenv").is_file()):
        raise AssertionError("DISPOSABLE_NONROOT_DOCKER_REQUIRED")
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    assert re.search(r'^ID="?(debian|almalinux)"?$', release, re.M)
    assert re.search(r'^VERSION_ID="?(13|10(?:\.[0-9]+)?)"?$', release, re.M)
    _check(["/usr/sbin/nginx", "-v"])
    _check(["/usr/sbin/logrotate", "--version"])

    doc = json.loads((
        Path(__file__).resolve().parents[1] /
        "docs/examples/server-install-v1.json"
    ).read_text(encoding="utf-8"))
    doc["deployment"]["logging"].update(metrics_opt_in=True, retention_days=3)
    doc["repositories"][0]["desired_state"] = "active"
    doc["repositories"][1]["desired_state"] = "disabled"
    metrics_candidate = render_nginx_metrics_candidate(doc)
    rotation = render_native_metrics_rotation_candidate(doc)
    assert list(metrics_candidate["location_directives_by_repository"]) == [
        "debian-trixie-main"
    ]
    assert not metrics_candidate["authorizes_nginx_activation"]
    assert not rotation["authorizes_logrotate_installation"]

    with tempfile.TemporaryDirectory(prefix="repocache-metrics-live-") as temp:
        root = Path(temp)
        for part in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (root / part).mkdir(mode=0o700)
        log, audit = root / "metrics.jsonl", root / "audit.log"
        # Native NGINX may create a first log with permissive defaults.
        # Require a managed, preprovisioned 0600 log in this fixture.
        log.touch(mode=0o600, exist_ok=False)
        _private(log)
        conf, rotate_conf = root / "nginx.conf", root / "logrotate.conf"
        state = root / "logrotate.state"
        port = _port()
        fragment = metrics_candidate["location_directives_by_repository"]["debian-trixie-main"]
        assert fragment.count(_LOG) == 1
        fragment = fragment.replace(_LOG, str(log))
        configuration = (
            f"pid {root / 'nginx.pid'};\n"
            f"error_log {root / 'error.log'} notice;\n"
            "worker_processes 1;\n"
            "events { worker_connections 32; }\n"
            "http {\n"
            + "".join(f"{part}_temp_path {root / part};\n" for part in (
                "client_body", "proxy", "fastcgi", "uwsgi", "scgi"
            ))
            + "log_format original_audit '$status';\n"
            + f"access_log {audit} original_audit;\n"
            + metrics_candidate["http_log_format_fragment"]
            + f"server {{ listen 127.0.0.1:{port};\n"
            + f"location ^~ {_ROUTE} {{\n"
            + fragment
            + f"access_log {audit} original_audit;\n"
            + "return 200 'safe-payload';\n}\n"
            + "location /unapproved/ { return 200 'not-logged'; }\n"
            + "}\n}\n"
        )
        conf.write_text(configuration, encoding="utf-8")
        _check(["/usr/sbin/nginx", "-t", "-p", str(root), "-c", str(conf)])
        invalid = root / "invalid.conf"
        invalid.write_text(configuration + "\nINVALID_CANDIDATE_DIRECTIVE;\n",
                           encoding="utf-8")
        _check(["/usr/sbin/nginx", "-t", "-p", str(root), "-c", str(invalid)],
               success=False)

        profile = rotation["rotation_candidate"]
        assert profile.count(_LOG) == profile.count(_REOPEN) == 1
        # Only this disposable fixture substitutes the production root path,
        # systemd signal and file UID. Never publish this as a host profile.
        profile = profile.replace(_LOG, str(log)).replace(
            _REOPEN, f"/usr/sbin/nginx -s reopen -p {root} -c {conf}"
        ).replace("create 0600 root root",
                  f"create 0600 {os.geteuid()} {os.getegid()}")
        rotate_conf.write_text(profile, encoding="utf-8")

        old_umask = os.umask(0o077)
        err = open(root / "nginx-stderr", "ab")
        process = subprocess.Popen(
            ["/usr/sbin/nginx", "-p", str(root), "-c", str(conf),
             "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
        )
        try:
            _request(port, _ROUTE + "first?private=" + _SECRET)
            _request(port, _ROUTE + "second")
            _request(port, "/unapproved/not-logged")
            _wait_lines(log, 2)
            _wait_lines(audit, 3)
            for index in range(2):
                _check(["/usr/sbin/logrotate", "--force", "--state",
                        str(state), str(rotate_conf)])
                # -s reopen is signalled asynchronously; allow a bounded
                # dispatch interval before issuing requests to the new inode.
                time.sleep(0.15)
                _request(port, _ROUTE + f"after-{index}-one")
                _request(port, _ROUTE + f"after-{index}-two")
                _wait_lines(log, 2)
                _wait_lines(audit, 5 + 2 * index)
                _private(log)
                _private(root / "metrics.jsonl.1")
            _private(root / "metrics.jsonl.2.gz")
            live = [json.loads(line) for line in _wait_lines(log, 2)]
            archived = [json.loads(line) for line in (
                root / "metrics.jsonl.1"
            ).read_text(encoding="utf-8").splitlines()]
            with gzip.open(root / "metrics.jsonl.2.gz", "rt", encoding="utf-8") as data:
                older = [json.loads(line) for line in data]
            observed_rows = live + archived + older
            assert len(observed_rows) == 6
            assert all(row["repocache_repository"] == _ROUTE for row in observed_rows)
            assert all(row["status"] == "200" for row in observed_rows)
            assert _SECRET not in json.dumps(observed_rows)
            assert "private" not in json.dumps(observed_rows)
            report = metrics(Settings(metrics_log=log), hours=1, repo=_ROUTE,
                             now=datetime.now(timezone.utc))
            assert report["available"] and report["requests"] == 6
            assert report["history_files_read"] == 3
            assert report["rotation_incomplete"] is False
            _wait_lines(audit, 7)
            assert process.poll() is None
            print("PASS: actual NGINX route metrics and live logrotate/reopen,"
                  " two archives, private files, retained audit and CLI history",
                  flush=True)
            print("NOT VERIFIED: installed logrotate systemd hook, real host"
                  " ownership, SELinux enforcing and signed deployment", flush=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            err.close()
            os.umask(old_umask)


if __name__ == "__main__":
    main()
