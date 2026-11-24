#!/usr/bin/env python3
"""Disposable VM evidence for the independently owned REPOCACHE NGINX unit.

This exercises real PID1, native APT/DNF, NGINX and SELinux enforcing with
test-only signed archive assets, not an authorized production deployment.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

ROOT = Path("/root/pr237-synthetic-fixture")
STATE = Path("/var/lib/repocache/server")
SOURCE = Path("/home/pr237ci/combined")
VENDOR_CONFIG = Path("/etc/nginx/nginx.conf")
OWN_CONFIG = Path("/etc/nginx/repocache.conf")
VENDOR = "nginx.service"
OWN = "repocache-nginx.service"


def run(*cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=45,
                          check=False)


def require_status(unit: str, active: bool, enabled: bool) -> None:
    state = run("/usr/bin/systemctl", "is-active", unit)
    policy = run("/usr/bin/systemctl", "is-enabled", unit)
    assert (state.returncode, state.stdout.strip()) == (
        (0, "active") if active else (3, "inactive")
    ), (unit, state.returncode, state.stdout)
    assert (policy.returncode, policy.stdout.strip()) == (
        (0, "enabled") if enabled else (1, "disabled")
    ), (unit, policy.returncode, policy.stdout)


def loopback_response() -> None:
    with socket.create_connection(("127.0.0.1", 8008), timeout=5) as client:
        client.settimeout(5)
        client.sendall(
            b"GET /__repocache/private HTTP/1.1\r\n"
            b"Host: localhost\r\nConnection: close\r\n\r\n"
        )
        response = client.recv(2048)
    assert response.startswith(b"HTTP/1.1 204"), response[:70]


def verify_signed_runtime(expected_pid: int, *, reject_mode: bool = False) -> None:
    """Run the fixed read-only probes from the actual installed signed zipapp.

    The VM has already verified the installed worker against the disposable
    signed release. A source-tree import cannot exercise its embedded unit.
    """
    code = """
import os
import sys
sys.path.insert(0, "/usr/libexec/repocache/server-control-worker")
from repocache.server_native_nginx_effective_unit_v1 import (
    EffectiveNginxUnitError, inspect_signed_owned_nginx_unit,
    require_owned_bootstrap_health,
)
from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS
from repocache.server_protected_state_store_v1 import _locked
from repocache.server_native_v2_transaction_v1 import (
    NativeV2TransactionError, _owned_live_verify_listener,
)
import socket
root = os.open("/", _DIRECTORY_FLAGS)
try:
    with _locked(root, 0):
        if sys.argv[1] == "reject":
            try:
                inspect_signed_owned_nginx_unit()
            except EffectiveNginxUnitError as exc:
                assert str(exc) == "NATIVE_NGINX_EFFECTIVE_SIGNED_OWN_UNIT_METADATA_MISMATCH"
            else:
                raise AssertionError("Unsafe installed unit mode accepted")
        else:
            result = inspect_signed_owned_nginx_unit()
            assert result["unit_name"] == "repocache-nginx.service"
            assert result["signed_worker_unit_bytes_match"] is True
            assert result["main_pid_observed"] == int(sys.argv[2])
            assert result["authorizes_nginx_reload"] is False
            assert result["authorizes_systemctl"] is False
            identity = (result["main_pid_observed"], result["private_unit_identity"])
            assert _owned_live_verify_listener(root, identity, (None, None, None)) > 0
            # Real kernel listener in this test process, not the signed NGINX
            # master. No production dispatch or alternate service is exposed.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as foreign:
                foreign.bind(("127.0.0.1", 0))
                foreign.listen(1)
                foreign_doc = {"deployment": {"listen": {
                    "bind_address": "127.0.0.1", "https_port": foreign.getsockname()[1],
                }}}
                try:
                    _owned_live_verify_listener(root, identity, (foreign_doc, 1, None))
                except NativeV2TransactionError as exc:
                    assert str(exc) == "NATIVE_V2_OWNED_LIVE_LISTENER_UNVERIFIED"
                else:
                    raise AssertionError("Foreign kernel listener adopted")
        require_owned_bootstrap_health()
finally:
    os.close(root)
"""
    result = subprocess.run(
        ["/usr/bin/python3", "-IS", "-B", "-c", code,
         "reject" if reject_mode else "accept", str(expected_pid)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        cwd="/", timeout=45, check=False,
    )
    if result.returncode:
        # Only static error types/codes from the disposable guest, never
        # raw subprocess output, private config or signed asset contents.
        import re
        for marker in re.findall(
                r"NATIVE_NGINX_EFFECTIVE_[A-Z_]+", result.stderr):
            print("SIGNED_RUNTIME_DIAGNOSTIC: " + marker, flush=True)
        raise AssertionError("Installed signed runtime probe failed")


def verify_signed_runtime_mode_refusal(expected_pid: int) -> None:
    """Change only the test guest's mode; retain the original unit inode."""
    unit = Path("/etc/systemd/system/repocache-nginx.service")
    fd = os.open(unit, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        import stat
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode)
        assert (before.st_uid, before.st_gid, before.st_nlink,
                stat.S_IMODE(before.st_mode)) == (0, 0, 1, 0o644)
        try:
            os.fchmod(fd, 0o600)
            verify_signed_runtime(expected_pid, reject_mode=True)
        finally:
            os.fchmod(fd, 0o644)
        restored = unit.lstat()
        assert (restored.st_dev, restored.st_ino, restored.st_uid,
                restored.st_gid, restored.st_mode, restored.st_mtime_ns) == (
            before.st_dev, before.st_ino, before.st_uid,
            before.st_gid, before.st_mode, before.st_mtime_ns,
        )
    finally:
        os.close(fd)
    verify_signed_runtime(expected_pid)
    print("PASS: installed signed unit mode drift refused, fixed bootstrap health preserved", flush=True)


def verify_guest(distribution: str, phase: str) -> None:
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert run("/usr/bin/systemd-detect-virt", "--vm").returncode == 0
    if distribution == "almalinux":
        assert run("/usr/sbin/getenforce").stdout.strip() == "Enforcing"
    sys.path[:0] = [str(SOURCE / "src"), str(SOURCE)]
    from scripts import install_native_root_worker as native
    from scripts import stage_native_root_worker as stage
    from repocache.server_stock_nginx_package_owner_v1 import (
        inspect_stock_nginx_package_file_integrity,
    )

    pins = json.loads((ROOT / "pins.json").read_bytes())
    assert set(pins) == {"commit", "archive_sha256"}
    assets = ROOT / "assets"
    assert stage.verify_installed_worker(assets, **pins)[
        "status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    completion = STATE / ".native-nginx-v1.completed"
    receipt = hashlib.sha256(completion.read_bytes()).hexdigest()
    vendor_conf = hashlib.sha256(VENDOR_CONFIG.read_bytes()).hexdigest()
    assert not (STATE / ".native-nginx-v1.pending").exists()
    assert not (STATE / ".state-v2-native.pending").exists()
    assert inspect_stock_nginx_package_file_integrity()[
        "native_package_file_integrity_verified"] is True

    if phase == "activate":
        require_status(VENDOR, False, False)
        require_status(OWN, False, False)
        assert not OWN_CONFIG.exists() and not OWN_CONFIG.is_symlink()

        # An untrusted pre-existing path must never be adopted or overwritten.
        OWN_CONFIG.symlink_to(VENDOR_CONFIG)
        try:
            try:
                native.activate_authenticated_native_nginx(assets, **pins)
            except stage.WorkerStageError as exc:
                assert str(exc) == "WORKER_PLACEMENT_NATIVE_PRIVATE_CONFIG_FOREIGN_COLLISION"
            else:
                raise AssertionError("pre-existing private config symlink adopted")
        finally:
            OWN_CONFIG.unlink()

        # Matching bytes alone are not proof of REPOCACHE ownership.
        OWN_CONFIG.write_bytes(native._BOOTSTRAP_CONFIG)
        try:
            try:
                native.activate_authenticated_native_nginx(assets, **pins)
            except stage.WorkerStageError as exc:
                assert str(exc) == "WORKER_PLACEMENT_NATIVE_PRIVATE_CONFIG_FOREIGN_COLLISION"
            else:
                raise AssertionError("byte-identical pre-existing config adopted")
        finally:
            OWN_CONFIG.unlink()
        require_status(OWN, False, False)
        require_status(VENDOR, False, False)
        print("PASS: foreign NGINX configuration symlink and matching file both refused before activation", flush=True)

        original = native._nginx_activation_command

        def inject_failed_enable(action: str) -> None:
            if action == "enable":
                raise stage.WorkerStageError("WORKER_PLACEMENT_VM_ENABLE_FAULT")
            original(action)

        native._nginx_activation_command = inject_failed_enable
        try:
            try:
                native.activate_authenticated_native_nginx(assets, **pins)
            except stage.WorkerStageError as exc:
                assert str(exc) == "WORKER_PLACEMENT_NATIVE_ACTIVATION_FAILED_ROLLED_BACK"
            else:
                raise AssertionError("injected systemd enable failure passed")
        finally:
            native._nginx_activation_command = original
        require_status(OWN, False, False)
        require_status(VENDOR, False, False)
        assert hashlib.sha256(VENDOR_CONFIG.read_bytes()).hexdigest() == vendor_conf
        assert hashlib.sha256(completion.read_bytes()).hexdigest() == receipt
        print("PASS: real own-service systemd enable failure rolls back start", flush=True)

        activated = native.activate_authenticated_native_nginx(assets, **pins)
        assert activated["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ACTIVE"
        assert native._own_service_observation(active=True)["main_pid_observed"] > 1
        require_status(OWN, True, True)
        require_status(VENDOR, False, False)
        loopback_response()
        signed_pid = native._own_service_observation(active=True)["main_pid_observed"]
        verify_signed_runtime(signed_pid)
        print("PASS: installed signed worker verified exact dedicated unit and bootstrap health", flush=True)
        verify_signed_runtime_mode_refusal(signed_pid)
        assert stage.verify_installed_worker(assets, **pins)[
            "status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
        repeated = native.activate_authenticated_native_nginx(assets, **pins)
        assert repeated["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ALREADY_ACTIVE"

        # The signed, owned NGINX service must retain its last working
        # in-memory configuration when a foreign invalid config is injected.
        # Neither the signer-gated activation nor systemd reload may adopt it.
        known_good = OWN_CONFIG.read_bytes()
        working_pid = native._own_service_observation(active=True)["main_pid_observed"]
        try:
            OWN_CONFIG.write_bytes(b"events { repocache_invalid_directive on; }\n")
            try:
                native.activate_authenticated_native_nginx(assets, **pins)
            except stage.WorkerStageError as exc:
                assert str(exc) == "WORKER_PLACEMENT_FILE_CONTENT_MISMATCH"
            else:
                raise AssertionError("modified config adopted despite signed bytes mismatch")
            reload_failed = run("/usr/bin/systemctl", "reload", OWN)
            assert reload_failed.returncode != 0, "invalid configuration reloaded"
            assert native._own_service_observation(active=True)[
                "main_pid_observed"] == working_pid
            require_status(OWN, True, True)
            require_status(VENDOR, False, False)
            loopback_response()
        finally:
            OWN_CONFIG.write_bytes(known_good)
        assert hashlib.sha256(OWN_CONFIG.read_bytes()).hexdigest() == hashlib.sha256(known_good).hexdigest()
        assert run("/usr/bin/systemctl", "reload", OWN).returncode == 0
        assert native._own_service_observation(active=True)[
            "main_pid_observed"] == working_pid
        loopback_response()
        print("PASS: invalid owned config and failed real systemd reload preserved previous working service", flush=True)

        assert hashlib.sha256(completion.read_bytes()).hexdigest() == receipt
        assert hashlib.sha256(VENDOR_CONFIG.read_bytes()).hexdigest() == vendor_conf
        assert inspect_stock_nginx_package_file_integrity()[
            "native_package_file_integrity_verified"] is True
        (ROOT / "native-activation-integrity.json").write_text(json.dumps({
            "receipt_sha256": receipt, "vendor_config_sha256": vendor_conf,
            "owned_config_sha256": hashlib.sha256(OWN_CONFIG.read_bytes()).hexdigest(),
        }, sort_keys=True))
        print("PASS: own signed systemd unit enabled and active, vendor unchanged, real PID and loopback HTTP 204", flush=True)
    elif phase == "after":
        original = json.loads((ROOT / "native-activation-integrity.json").read_text())
        assert hashlib.sha256(completion.read_bytes()).hexdigest() == original["receipt_sha256"]
        assert hashlib.sha256(VENDOR_CONFIG.read_bytes()).hexdigest() == original["vendor_config_sha256"]
        assert hashlib.sha256(OWN_CONFIG.read_bytes()).hexdigest() == original["owned_config_sha256"]
        require_status(OWN, True, True)
        require_status(VENDOR, False, False)
        assert native._own_service_observation(active=True)["main_pid_observed"] > 1
        loopback_response()
        verify_signed_runtime(native._own_service_observation(active=True)["main_pid_observed"])
        print("PASS: installed signed worker reverified exact unit and bootstrap health after reboot", flush=True)
        again = native.activate_authenticated_native_nginx(assets, **pins)
        assert again["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ALREADY_ACTIVE"
        assert inspect_stock_nginx_package_file_integrity()[
            "native_package_file_integrity_verified"] is True
        print("PASS: separate REPOCACHE service survives real reboot with vendor service disabled and package integrity intact", flush=True)
        print("NOT VERIFIED: managed HTTPS/v2, full deployment, final publisher-signed release", flush=True)
    else:
        raise AssertionError("invalid test phase")


if __name__ == "__main__":
    if (len(sys.argv) != 3 or sys.argv[1] not in ("debian", "almalinux")
            or sys.argv[2] not in ("activate", "after")):
        raise SystemExit("Usage: ci_native_nginx_activate_guest.py debian|almalinux activate|after")
    verify_guest(sys.argv[1], sys.argv[2])
