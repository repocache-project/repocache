"""CI-only live NGINX master /proc inode smoke, NEVER a host service test.

Runs only in a marked disposable Docker image after authenticated native
nginx installation. Uses a private config with no listener, no systemd unit,
and no persistent REPOCACHE path. This proves a kernel observation, not
installed host-root, package signing, SELinux, or an activation permission.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from repocache.server_native_nginx_effective_unit_v1 import (
    EffectiveNginxUnitError, _observe_nginx_master_kernel,
)


class DisposableProcessSmokeError(ValueError):
    """Always report fixed, redacted CI error codes."""


def run_disposable_process_smoke() -> dict[str, object]:
    if (os.environ.get("REPOCACHE_NATIVE_TEST_CONTAINER")
            != "CONFIRMED_DISPOSABLE_DOCKER_ONLY"
            or not Path("/.dockerenv").is_file()
            or os.geteuid() != 0
            or not Path("/usr/sbin/nginx").is_file()
            or Path("/proc/1/comm").read_bytes() == b"systemd\n"):
        raise DisposableProcessSmokeError("DISPOSABLE_CONTAINER_REQUIRED")

    with tempfile.TemporaryDirectory(prefix="repocache-native-master-") as dirname:
        root = Path(dirname)
        conf = root / "nginx.conf"
        conf.write_text(
            "worker_processes 1;\n"
            f"pid {root / 'nginx.pid'};\n"
            f"error_log {root / 'error.log'} notice;\n"
            "events { worker_connections 32; }\n"
            "http { }\n", encoding="ascii",
        )
        validated = subprocess.run(
            ["/usr/sbin/nginx", "-t", "-c", str(conf), "-p", dirname],
            shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False, cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        if validated.returncode != 0:
            raise DisposableProcessSmokeError("PRIVATE_NGINX_SYNTAX_FAILED")
        process = subprocess.Popen(
            ["/usr/sbin/nginx", "-c", str(conf), "-p", dirname,
             "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
            cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        try:
            # Popen owns this exact disposable child PID; never use a
            # configurable pid file, process name lookup or systemctl.
            observed = False
            for _ in range(60):
                if process.poll() is not None:
                    break
                try:
                    _observe_nginx_master_kernel(process.pid)
                except EffectiveNginxUnitError:
                    time.sleep(0.05)
                    continue
                observed = True
                break
            if not observed or process.poll() is not None:
                raise DisposableProcessSmokeError("LIVE_MASTER_INODE_UNVERIFIED")
            return {
                "status": "DISPOSABLE_NGINX_MASTER_INODE_OBSERVED",
                "kernel_process_executable_inode_matches_package_path": True,
                "booted_systemd_service_tested": False,
                "selinux_enforcing_host_tested": False,
                "installed_service_reloaded": False,
                "host_root_provenance_verified": False,
                "authorizes_nginx_reload": False,
                "authorizes_catalog_publication": False,
            }
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main() -> int:
    try:
        result = run_disposable_process_smoke()
    except (DisposableProcessSmokeError, OSError, ValueError,
            subprocess.TimeoutExpired):
        print(json.dumps({"status": "FAIL", "code": "NATIVE_MASTER_SMOKE_UNVERIFIED"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
