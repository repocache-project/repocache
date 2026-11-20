#!/usr/bin/env python3
"""Disposable native Linux NGINX process-footprint refusal (#27).

The script never runs a package manager or manages a systemd service.
The CI workflow installs stock packages only in fresh Docker images.
This executable runs a private stock NGINX master and checks that a
simulated missing on-disk footprint cannot bypass process-conflict refusal.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
from typing import Any

from repocache.server_install_v1 import (
    validate_os_identity, validate_server_architecture,
)
from repocache.server_native_nginx_ownership_v1 import (
    _scan_nginx_process_footprint, inspect_fresh_nginx_footprint,
    prepare_fresh_native_nginx,
)

_ROOT = Path(__file__).resolve().parents[1]
_CONTAINER_MARKER = "CONFIRMED_DISPOSABLE_DOCKER_ONLY"


class NativeProcessConflictTestError(ValueError):
    """Only fixed, redacted failure identifiers escape."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise NativeProcessConflictTestError(code)


def _missing_disk_marker(path: str):
    """Simulate deleted/inaccessible disk markers while NGINX is running."""
    raise FileNotFoundError(path)


def _forbid_network_or_install(*args: Any, **kwargs: Any):
    raise NativeProcessConflictTestError("NATIVE_MANAGER_REACHED_AFTER_PROCESS_CONFLICT")


def _guard() -> tuple[str, str]:
    _require(
        os.environ.get("REPOCACHE_NATIVE_TEST_CONTAINER") == _CONTAINER_MARKER
        and Path("/.dockerenv").is_file()
        and os.geteuid() == 0
        and Path("/proc/1/comm").read_text(encoding="ascii").strip() != "systemd"
        and not Path("/var/lib/repocache/server").exists(),
        "DISPOSABLE_DOCKER_CONTEXT_REQUIRED",
    )
    release = Path("/etc/os-release").read_text(encoding="ascii")
    distribution = validate_os_identity(
        release, (sys.version_info.major, sys.version_info.minor),
    )
    validate_server_architecture(platform.machine())
    _require(
        Path("/usr/sbin/nginx").is_file()
        and _scan_nginx_process_footprint() == "PROCESS_NGINX_NOT_OBSERVED",
        "FRESH_DOCKER_NGINX_BASELINE_UNVERIFIED",
    )
    return distribution, release


def run() -> dict[str, Any]:
    distribution, release = _guard()
    document = json.loads(
        (_ROOT / "docs/examples/server-install-v1.json").read_text("utf-8")
    )
    version = (sys.version_info.major, sys.version_info.minor)
    with tempfile.TemporaryDirectory(prefix="repocache-nginx-proc-fixture-") as tmp:
        root = Path(tmp)
        configuration = root / "nginx.conf"
        configuration.write_text(
            "worker_processes 1;\n"
            "pid " + str(root / "nginx.pid") + ";\n"
            "error_log " + str(root / "nginx-error.log") + " warn;\n"
            "events { worker_connections 32; }\n"
            "http { server { listen 127.0.0.1:18081; "
            "location /health { return 200 'repocache'; } } }\n",
            encoding="ascii",
        )
        fixed = ["/usr/sbin/nginx", "-p", str(root) + "/", "-c", str(configuration)]
        syntax = subprocess.run(
            [*fixed, "-t", "-q"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            cwd="/", timeout=10, check=False,
        )
        _require(syntax.returncode == 0, "FIXTURE_NGINX_SYNTAX_INVALID")
        nginx = subprocess.Popen(
            [*fixed, "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            cwd="/",
        )
        try:
            found = False
            for _ in range(60):
                _require(nginx.poll() is None, "NATIVE_NGINX_MASTER_EXITED")
                if _scan_nginx_process_footprint() == "PROCESS_NGINX_FOUND":
                    found = True
                    break
                time.sleep(0.05)
            _require(found, "REAL_NATIVE_NGINX_PROCESS_NOT_OBSERVED")
            # Model a disappearing package binary/configuration with the
            # filesystem callback. A live NGINX master still MUST refuse
            # the proposed *fresh* install before native metadata/network.
            footprint = inspect_fresh_nginx_footprint(
                os_release=release, python_version=version,
                document=document, lstat=_missing_disk_marker,
            )
            _require(
                footprint.code == "NGINX_RUNNING_PROCESS_REFUSED"
                and footprint.to_dict()["status"] == "FAIL"
                and footprint.to_dict()["authorizes_package_transaction"] is False,
                "PROCESS_CONFLICT_NOT_REFUSED",
            )
            preparation = prepare_fresh_native_nginx(
                os_release=release, python_version=version,
                document=document, lstat=_missing_disk_marker,
                runner=_forbid_network_or_install,
            )
            _require(
                preparation.metadata is None
                and preparation.footprint.code == "NGINX_RUNNING_PROCESS_REFUSED"
                and preparation.to_dict()["can_install"] is False,
                "NATIVE_PACKAGE_TRUST_INVOKED_ON_FOREIGN_PROCESS",
            )
        finally:
            if nginx.poll() is None:
                nginx.terminate()
            try:
                nginx.wait(timeout=8)
            except subprocess.TimeoutExpired:
                nginx.kill()
                nginx.wait(timeout=8)
    return {
        "schema_version": 1,
        "status": "CI_REAL_NGINX_PROCESS_CONFLICT_REFUSED",
        "distribution": distribution,
        "real_native_nginx_master_started_in_disposable_container": True,
        "simulated_missing_disk_markers": True,
        "process_conflict_refused_before_package_manager": True,
        "no_active_process_adopted": True,
        "native_service_start_or_reload_performed": False,
        "booted_systemd_verified": False,
        "selinux_enforcing_verified": False,
        "authorized_host_installation": False,
    }


def main() -> int:
    try:
        report = run()
    except NativeProcessConflictTestError as exc:
        report = {"schema_version": 1, "status": "FAIL", "code": str(exc),
                  "authorized_host_installation": False}
    except Exception:
        report = {"schema_version": 1, "status": "FAIL",
                  "code": "CI_NATIVE_PROCESS_CONFLICT_UNVERIFIED",
                  "authorized_host_installation": False}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return int(report["status"] != "CI_REAL_NGINX_PROCESS_CONFLICT_REFUSED")


if __name__ == "__main__":
    raise SystemExit(main())
