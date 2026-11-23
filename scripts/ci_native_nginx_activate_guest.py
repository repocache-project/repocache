#!/usr/bin/env python3
"""Disposable, booted two-distro proof of signed-worker NGINX activation.

This fixture rewrites a vendor config INSIDE A DISPOSABLE VM to constrain all
listeners to loopback. It is not a deployed REPOCACHE configuration writer,
does not prove the default vendor HTTP listener is safe, and uses only an
isolated synthetic release-signing identity.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys


ROOT = Path("/var/tmp/repocache-pr237")
STATE = Path("/var/lib/repocache/server")
CONF = Path("/etc/nginx/nginx.conf")
SOURCE = Path("/home/pr237ci/combined")


def run(*cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=45,
                          check=False)


def require_status(expected_active: bool, expected_enabled: bool) -> None:
    active = run("/usr/bin/systemctl", "is-active", "nginx.service")
    enabled = run("/usr/bin/systemctl", "is-enabled", "nginx.service")
    assert (active.returncode, active.stdout.strip()) == (
        (0, "active") if expected_active else (3, "inactive")
    ), (active.returncode, active.stdout)
    assert (enabled.returncode, enabled.stdout.strip()) == (
        (0, "enabled") if expected_enabled else (1, "disabled")
    ), (enabled.returncode, enabled.stdout)


def verify_live_loopback() -> None:
    with socket.create_connection(("127.0.0.1", 18080), timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(
            b"GET /__repocache/private HTTP/1.1\r\n"
            b"Host: localhost\r\nConnection: close\r\n\r\n"
        )
        received = connection.recv(2048)
    assert received.startswith(b"HTTP/1.1 204"), received[:70]


def verify_guest(distribution: str) -> None:
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert run("/usr/bin/systemd-detect-virt", "--vm").returncode == 0
    if distribution == "almalinux":
        assert run("/usr/sbin/getenforce").stdout.strip() == "Enforcing"
    sys.path[:0] = [str(SOURCE / "src"), str(SOURCE)]
    from scripts import install_native_root_worker as native
    from scripts import stage_native_root_worker as stage
    from repocache.server_native_nginx_effective_unit_v1 import (
        inspect_effective_native_nginx_unit,
    )
    pins = json.loads((ROOT / "pins.json").read_bytes())
    assert set(pins) == {"commit", "archive_sha256"}
    assets = ROOT / "assets"
    assert stage.verify_installed_worker(assets, **pins)[
        "status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    completion = STATE / ".native-nginx-v1.completed"
    original = completion.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    assert not (STATE / ".native-nginx-v1.pending").exists()
    assert not (STATE / ".state-v2-native.pending").exists()

    phase = sys.argv[2]
    if phase == "activate":
        require_status(False, False)
        # A stock distro service typically binds HTTP on all interfaces.
        # Explicit activation MUST first refuse without affecting service.
        try:
            native.activate_authenticated_native_nginx(assets, **pins)
        except stage.WorkerStageError as error:
            assert str(error) == "WORKER_PLACEMENT_NATIVE_LISTENERS_UNVERIFIED"
        else:
            raise AssertionError("Fresh stock HTTP listener unexpectedly activated")
        require_status(False, False)
        assert completion.read_bytes() == original
        print("PASS: signed-worker activation refused stock public/plaintext NGINX", flush=True)

        # VM-ONLY operator-controlled minimal loopback configuration. Never
        # write the vendor nginx.conf in the product's activation operation.
        before = CONF.lstat()
        assert (stat.S_ISREG(before.st_mode) and before.st_uid == 0
                and before.st_gid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o644)
        safe = (
            b"pid /run/nginx.pid;\n"
            b"events { worker_connections 128; }\n"
            b"http {\n"
            b"  server {\n"
            b"    listen 127.0.0.1:18080;\n"
            b"    location = /__repocache/private { return 204; }\n"
            b"  }\n"
            b"}\n"
        )
        CONF.write_bytes(safe)
        assert CONF.lstat().st_ino == before.st_ino
        assert run("/usr/sbin/nginx", "-t", "-q").returncode == 0

        original_command = native._nginx_activation_command
        def injected_enable_failure(action: str) -> None:
            if action == "enable":
                raise stage.WorkerStageError("WORKER_PLACEMENT_VM_ENABLE_FAULT")
            original_command(action)
        native._nginx_activation_command = injected_enable_failure
        try:
            try:
                native.activate_authenticated_native_nginx(assets, **pins)
            except stage.WorkerStageError as error:
                assert str(error) == "WORKER_PLACEMENT_NATIVE_ACTIVATION_FAILED_ROLLED_BACK"
            else:
                raise AssertionError("Injected systemd enable failure was accepted")
        finally:
            native._nginx_activation_command = original_command
        require_status(False, False)
        assert completion.read_bytes() == original
        print("PASS: actual started NGINX returned to disabled/inactive after injected enable failure", flush=True)

        activated = native.activate_authenticated_native_nginx(assets, **pins)
        assert activated["status"] == "AUTHENTICATED_NATIVE_NGINX_ACTIVE"
        verify_live_loopback()
        observed = inspect_effective_native_nginx_unit(distribution)
        assert observed["main_pid_observed"] > 1
        require_status(True, True)
        repeated = native.activate_authenticated_native_nginx(assets, **pins)
        assert repeated["status"] == "AUTHENTICATED_NATIVE_NGINX_ALREADY_ACTIVE"
        assert completion.read_bytes() == original
        (ROOT / "native-activation-receipt-sha256.txt").write_text(digest + "\n")
        print("PASS: authenticated native service started and enabled, real PID/kernel inode and loopback HTTP 204 verified", flush=True)
    elif phase == "after":
        expected = (ROOT / "native-activation-receipt-sha256.txt").read_text().strip()
        assert digest == expected
        require_status(True, True)
        observed = inspect_effective_native_nginx_unit(distribution)
        assert observed["main_pid_observed"] > 1
        verify_live_loopback()
        again = native.activate_authenticated_native_nginx(assets, **pins)
        assert again["status"] == "AUTHENTICATED_NATIVE_NGINX_ALREADY_ACTIVE"
        assert completion.read_bytes() == original
        print("PASS: operational NGINX survives native kernel reboot with enabled vendor service; no duplicate install", flush=True)
        print("NOT VERIFIED: unmodified stock HTTP exposure, managed TLS bootstrap or final publisher-signed release", flush=True)
    else:
        raise AssertionError("unsupported phase")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("debian", "almalinux") or sys.argv[2] not in ("activate", "after"):
        raise SystemExit("Usage: ci_native_nginx_activate_guest.py debian|almalinux activate|after")
    verify_guest(sys.argv[1])
