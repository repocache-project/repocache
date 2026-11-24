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
OWN_CONFIG = Path("/etc/nginx/repocache.d/repocache.conf")
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



def run_live_wal(distribution: str, operation: str) -> None:
    """Actual installed signed-test archive in a disposable initial-root VM.

    Deliberately not a socket dispatch test. This gives independent native
    evidence of the WAL/reload/TLS sequence before changing broker authority.
    Only the injected failure point is synthetic; reload and health are real.
    """
    code = """
import os
import sys
sys.path.insert(0, "/usr/libexec/repocache/server-control-worker")
from repocache import server_native_v2_transaction_v1 as tx
from repocache.server_protected_state_store_v1 import _locked
from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS
from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions
assert require_native_host_preconditions()["initial_root_credentials_observed"] is True
distribution, operation = sys.argv[1:]
root = os.open("/", _DIRECTORY_FLAGS)
try:
    with _locked(root, 0) as state:
        tx._require_audited_native_package_for_activation(state, distribution=distribution)
        with tx._owned_layout_locked(root, state, recovering=operation == "recover") as layout:
            if operation == "fail-reload":
                actual = tx._owned_live_reload
                calls = []
                def fail_once(*args):
                    calls.append(1)
                    if len(calls) == 1:
                        raise tx.NativeV2TransactionError("NATIVE_V2_DISPOSABLE_RELOAD_FAULT")
                    return actual(*args)
                tx._owned_live_reload = fail_once
                try:
                    tx._apply_prepared_owned_live_locked(root, *layout, distribution)
                except tx.NativeV2TransactionError as error:
                    assert str(error) == "NATIVE_V2_OWNED_LIVE_APPLY_ROLLED_BACK", str(error)
                    assert len(calls) == 2
                else:
                    raise AssertionError("Injected reload fault committed")
            elif operation == "interrupt":
                actual = tx._owned_live_wait_generation
                def interrupt(*args):
                    actual(*args)
                    os._exit(77)
                tx._owned_live_wait_generation = interrupt
                tx._apply_prepared_owned_live_locked(root, *layout, distribution)
                raise AssertionError("Did not interrupt at confirmed new generation")
            elif operation in ("apply", "repeat"):
                result = tx._apply_prepared_owned_live_locked(root, *layout, distribution)
                assert result["status"] == ("OWNED_LIVE_COMMIT_OBSERVED" if operation == "apply"
                                            else "OWNED_LIVE_NO_CHANGE"), result["status"]
                assert result["state_generation"] == 1
            elif operation == "reload":
                result = tx._reload_owned_live_committed_locked(root, *layout)
                assert result == {"status": "OWNED_LIVE_RELOADED", "state_generation": 1}
            elif operation == "recover":
                result = tx._recover_owned_live_locked(root, *layout)
                assert result["status"] == "OWNED_LIVE_ROLLBACK_OBSERVED"
            else:
                raise AssertionError("Unknown test operation")
finally:
    os.close(root)
"""
    outcome = subprocess.run(
        ["/usr/bin/python3", "-IS", "-B", "-c", code, distribution, operation],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
        cwd="/", timeout=180, check=False,
    )
    if outcome.returncode != (77 if operation == "interrupt" else 0):
        import re
        for code in re.findall(
                r"(?:NATIVE_V2|NATIVE_NGINX|NATIVE_HOST|PINNED_TLS_PAIR|FIXED_ADMIN_CANDIDATE|PROTECTED)_[A-Z0-9_]+",
                outcome.stderr):
            print("LIVE_WAL_DIAGNOSTIC: " + code, flush=True)
        raise AssertionError("Actual signed-test live WAL operation failed: " + operation)


def live_wal_resource_hashes() -> dict[str, str]:
    paths = (
        STATE / "state-v2.json", STATE / ".state-v2-owned-nginx.manifest",
        OWN_CONFIG, Path("/etc/nginx/repocache.d/repocache-managed.conf"),
        Path("/var/lib/repocache/public/catalog.json"),
    )
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}



def verify_dedicated_socket(*, bootstrap: bool = False, pending: bool = False) -> None:
    """Exercise the actual installed broker through its kernel-authenticated socket.

    The shared NGINX parent remains read-only in the service. Test
    scoped apply/recover/reload and credential/receipt refusal.
    """
    import grp
    import pwd
    import time
    from scripts.ci_pr237_native_socket_guest import accounts, command
    from repocache.server_native_root_control_client_v1 import (
        NativeRootControlClientError, request_native_fixed_v2,
    )

    accounts()
    command("/usr/bin/systemctl", "start", "repocache-control.socket")
    def call(operation, expected):
        time.sleep(3)
        if expected == "DENIED":
            try:
                request_native_fixed_v2(operation)
            except NativeRootControlClientError as exc:
                assert str(exc) == "NATIVE_ROOT_CLIENT_OPERATION_REFUSED", str(exc)
            else:
                raise AssertionError("Unapproved mutating operation succeeded")
        else:
            try:
                result = request_native_fixed_v2(operation)
            except NativeRootControlClientError:
                status = run("/usr/bin/systemctl", "show", "repocache-control.service",
                             "-p", "ActiveState", "-p", "SubState", "-p", "Result",
                             "-p", "ExecMainStatus")
                print("DEDICATED_SOCKET_DIAGNOSTIC: " + status.stdout, flush=True)
                raise
            assert result["status"] == expected, result["status"]
            assert result["transaction_completed"] is True
            if expected in ("APPLIED", "RELOADED", "UNCHANGED"):
                assert result["state_generation"] == 1

    try:
        if pending:
            wal = STATE / ".state-v2-owned-nginx.pending"
            before = wal.read_bytes()
            assert before
            call("RECOVER_V2", "RECOVERED")
            assert not wal.exists()
            print("PASS: confined socket recovered pending WAL after reboot", flush=True)
            return
        if bootstrap:
            before = OWN_CONFIG.read_bytes()
            call("RECOVER_V2", "CLEAN")
            assert OWN_CONFIG.read_bytes() == before
            loopback_response()
            call("APPLY_V2", "APPLIED")
            assert (STATE / "state-v2.json").is_file()
            assert not (STATE / ".state-v2-owned-nginx.pending").exists()
            print("PASS: authenticated dedicated socket applied first generation through live WAL", flush=True)
            return

        before = live_wal_resource_hashes()
        call("RECOVER_V2", "CLEAN")
        call("APPLY_V2", "UNCHANGED")
        call("RELOAD_V2", "RELOADED")
        assert live_wal_resource_hashes() == before

        # A real non-root operator may request only the fixed managed reload.
        # Do not grant the service identity administrative authority.
        operator = "repocache-vm-operator"
        command("/usr/sbin/useradd", "--system", "--no-create-home",
                "--groups", "repocache-admin", "--shell", "/usr/sbin/nologin", operator)
        try:
            entry = pwd.getpwnam(operator)
            time.sleep(3)
            child = os.fork()
            if child == 0:
                try:
                    os.initgroups(operator, entry.pw_gid)
                    os.setgid(entry.pw_gid)
                    os.setuid(entry.pw_uid)
                    response = request_native_fixed_v2("RELOAD_V2")
                    os._exit(0 if response["status"] == "RELOADED"
                             and response["state_generation"] == 1 else 4)
                except Exception:
                    os._exit(3)
            assert os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]) == 0
        finally:
            command("/usr/sbin/userdel", operator)
        service = pwd.getpwnam("repocache")
        admin = grp.getgrnam("repocache-admin").gr_gid
        time.sleep(3)
        child = os.fork()
        if child == 0:
            try:
                os.setgroups([admin])
                os.setgid(service.pw_gid)
                os.setuid(service.pw_uid)
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
                    conn.settimeout(8)
                    conn.connect("/run/repocache/server-control.sock")
                    conn.sendall(b"reload-v2\n")
                    try:
                        reply = conn.recv(1025)
                    except ConnectionResetError:
                        reply = b""
                    os._exit(0 if reply == b"" else 4)
            except Exception:
                os._exit(3)
        assert os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]) == 0

        # Modify only the local receipt in the disposable guest. The actual
        # broker must not trust a receipt whose marker/hash no longer matches.
        receipt = STATE / ".native-worker-receipt-v1.json"
        raw = receipt.read_bytes()
        try:
            receipt.write_bytes(raw.replace(b'"source_sha":"', b'"source_sha":"0', 1))
            assert receipt.read_bytes() != raw
            call("RELOAD_V2", "DENIED")
        finally:
            receipt.write_bytes(raw)
        call("RELOAD_V2", "RELOADED")
        assert live_wal_resource_hashes() == before
        print("PASS: actual confined dedicated socket clean/replay/reload, non-root operator, service UID and placement receipt refusal", flush=True)
    finally:
        command("/usr/bin/systemctl", "stop", "repocache-control.socket")


def prepare_and_interrupt_live_wal(distribution: str, native, assets, pins) -> None:
    import base64
    from scripts.ci_pr237_native_socket_guest import synthetic_local_tls, https_response

    synthetic_local_tls(distribution)
    document = json.loads((ROOT / "reviewed-install.json").read_bytes())
    assert all(row["desired_state"] == "disabled" for row in document["repositories"])
    document["deployment"]["paths"]["generated_include"] = "/etc/nginx/repocache.d/repocache-managed.conf"
    reviewed = ROOT / "reviewed-owned-live.json"
    proposal = ROOT / "reviewed-owned-proposal.json"
    reviewed.write_text(json.dumps(document), encoding="ascii")
    reviewed.chmod(0o600)
    prepared = native.prepare_authenticated_proposal(
        assets, reviewed, proposal, decision_sha256="a" * 64, **pins,
    )
    assert prepared["state_generation"] == 1
    staged = native.stage_authenticated_proposal(
        assets, proposal, proposal_sha256=prepared["proposed_state_sha256"], **pins,
    )
    assert staged["expected_generation"] == 0
    bootstrap = OWN_CONFIG.read_bytes()
    run_live_wal(distribution, "fail-reload")
    assert OWN_CONFIG.read_bytes() == bootstrap
    assert not (STATE / "state-v2.json").exists()
    assert not (STATE / ".state-v2-owned-nginx.pending").exists()
    loopback_response()
    print("PASS: actual dedicated WAL failure compensation restores private bootstrap", flush=True)

    verify_dedicated_socket(bootstrap=True)
    old = live_wal_resource_hashes()
    run_live_wal(distribution, "repeat")
    run_live_wal(distribution, "reload")
    assert live_wal_resource_hashes() == old
    assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    catalog = Path("/var/lib/repocache/public/catalog.json").read_bytes()
    assert https_response("/.well-known/repocache/catalog.json").endswith(catalog)
    assert not (STATE / ".state-v2-owned-nginx.pending").exists()
    print("PASS: actual installed signed-test dedicated WAL commits TLS generation and exact catalog, repeat and reload preserve resources", flush=True)
    verify_dedicated_socket()
    assert live_wal_resource_hashes() == old
    prior = STATE / "state-v2.json"
    prior_raw = prior.read_bytes()
    repair = json.loads(base64.b64decode(json.loads(prior_raw)["configuration_base64"], validate=True))
    repair["deployment"]["logging"]["retention_days"] += 1
    repair_file = ROOT / "reviewed-owned-repair.json"
    repair_file.write_text(json.dumps(repair), encoding="ascii")
    repair_file.chmod(0o600)
    proposal2 = ROOT / "reviewed-owned-proposal2.json"
    prepared = native.prepare_authenticated_proposal(
        assets, repair_file, proposal2, previous=prior,
        previous_sha256=hashlib.sha256(prior_raw).hexdigest(),
        decision_sha256="b" * 64, **pins,
    )
    assert prepared["state_generation"] == 2
    staged = native.stage_authenticated_proposal(
        assets, proposal2, proposal_sha256=prepared["proposed_state_sha256"],
        expected_state_sha256=hashlib.sha256(prior_raw).hexdigest(), **pins,
    )
    assert staged["expected_generation"] == 1
    assert live_wal_resource_hashes() == old
    run_live_wal(distribution, "interrupt")
    assert (STATE / ".state-v2-owned-nginx.pending").is_file()
    assert not Path("/var/lib/repocache/public/catalog.json").exists()
    assert b"x-repocache-generation: 2" in https_response("/__repocache/healthz").lower()
    (ROOT / "owned-live-prior-hashes.json").write_text(json.dumps(old, sort_keys=True))
    print("PASS: actual dedicated generation-two reload interrupted with durable WAL and catalog withdrawn", flush=True)


def recover_live_wal_after_reboot(distribution: str) -> None:
    from scripts.ci_pr237_native_socket_guest import https_response

    assert (STATE / ".state-v2-owned-nginx.pending").is_file()
    assert not Path("/var/lib/repocache/public/catalog.json").exists()
    old = json.loads((ROOT / "owned-live-prior-hashes.json").read_text())
    verify_dedicated_socket(pending=True)
    assert live_wal_resource_hashes() == old
    assert not (STATE / ".state-v2-owned-nginx.pending").exists()
    assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    catalog = Path("/var/lib/repocache/public/catalog.json").read_bytes()
    assert https_response("/.well-known/repocache/catalog.json").endswith(catalog)
    print("PASS: actual dedicated WAL recovery after kernel reboot restores prior TLS generation and catalog", flush=True)


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
        assert not OWN_CONFIG.parent.exists() and not OWN_CONFIG.parent.is_symlink()
        legacy = OWN_CONFIG.parent.parent / OWN_CONFIG.name
        legacy.symlink_to(VENDOR_CONFIG)
        try:
            try:
                native.activate_authenticated_native_nginx(assets, **pins)
            except stage.WorkerStageError as exc:
                assert str(exc) == "WORKER_PLACEMENT_NATIVE_PRIVATE_CONFIG_LEGACY_LAYOUT_REFUSED"
            else:
                raise AssertionError("legacy layout silently adopted")
            assert legacy.is_symlink()
            assert not OWN_CONFIG.parent.exists()
        finally:
            legacy.unlink()

        # An untrusted pre-existing path must never be adopted or overwritten.
        OWN_CONFIG.parent.mkdir(mode=0o755)
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
            OWN_CONFIG.parent.rmdir()
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
        prepare_and_interrupt_live_wal(distribution, native, assets, pins)
    elif phase == "after":
        original = json.loads((ROOT / "native-activation-integrity.json").read_text())
        assert hashlib.sha256(completion.read_bytes()).hexdigest() == original["receipt_sha256"]
        assert hashlib.sha256(VENDOR_CONFIG.read_bytes()).hexdigest() == original["vendor_config_sha256"]
        require_status(OWN, True, True)
        require_status(VENDOR, False, False)
        assert native._own_service_observation(active=True)["main_pid_observed"] > 1
        recover_live_wal_after_reboot(distribution)
        require_status(OWN, True, True)
        require_status(VENDOR, False, False)
        assert hashlib.sha256(VENDOR_CONFIG.read_bytes()).hexdigest() == original["vendor_config_sha256"]
        assert hashlib.sha256(completion.read_bytes()).hexdigest() == original["receipt_sha256"]
        assert inspect_stock_nginx_package_file_integrity()[
            "native_package_file_integrity_verified"] is True
        print("PASS: separate REPOCACHE service survives real reboot with vendor service disabled and package integrity intact", flush=True)
        print("NOT VERIFIED: active repository routes/storage, managed installer repair, final publisher-signed release", flush=True)
    else:
        raise AssertionError("invalid test phase")


if __name__ == "__main__":
    if (len(sys.argv) != 3 or sys.argv[1] not in ("debian", "almalinux")
            or sys.argv[2] not in ("activate", "after")):
        raise SystemExit("Usage: ci_native_nginx_activate_guest.py debian|almalinux activate|after")
    verify_guest(sys.argv[1], sys.argv[2])
