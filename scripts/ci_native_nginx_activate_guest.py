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
        # Actual installed confined broker must reject storage drift before
        # any mutation or reload, not just the root installer.
        import stat
        marker = Path("/var/cache/nginx/.repocache-managed.owner-v1")
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            original = os.fstat(fd)
            assert stat.S_IMODE(original.st_mode) == 0o600
            marker_bytes = os.read(fd, 1025)
            try:
                os.fchmod(fd, 0o644)
                for operation in ("APPLY_V2", "RELOAD_V2", "RECOVER_V2"):
                    call(operation, "DENIED")
                    assert live_wal_resource_hashes() == before
                    assert not (STATE / ".state-v2-owned-nginx.pending").exists()
                    assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o644
                    assert os.pread(fd, 1025, 0) == marker_bytes
                from scripts.ci_pr237_native_socket_guest import https_response
                assert b"x-repocache-generation: 1" in https_response(
                    "/__repocache/healthz").lower()
            finally:
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        print("PASS: confined broker refused all fixed operations on unsafe storage marker without mutation", flush=True)
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


def verify_managed_installer_repeat(distribution, native, assets, pins):
    """Reauthenticate the same signed test release without bootstrap rewrite."""
    before = live_wal_resource_hashes()
    pid = native._own_service_observation(active=True)["main_pid_observed"]
    result = native.activate_authenticated_native_nginx(assets, **pins)
    assert result["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ALREADY_ACTIVE"
    assert result["state_generation"] == 1
    verify_storage_report(result, distribution)
    assert live_wal_resource_hashes() == before
    assert native._own_service_observation(active=True)["main_pid_observed"] == pid
    # The installer must refuse an unsafe managed include without replacing
    # it or restarting the prior working service. This is a disposable VM.
    include = Path("/etc/nginx/repocache.d/repocache-managed.conf")
    fd = os.open(include, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        import stat
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o644
        try:
            os.fchmod(fd, 0o666)
            from scripts.stage_native_root_worker import WorkerStageError
            try:
                native.activate_authenticated_native_nginx(assets, **pins)
            except WorkerStageError as exc:
                assert str(exc) == "WORKER_PLACEMENT_NATIVE_ACTIVATION_MANAGED_STATE_REFUSED"
            else:
                raise AssertionError("Unsafe managed include accepted")
            assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o666
            assert live_wal_resource_hashes() == before
            assert native._own_service_observation(active=True)["main_pid_observed"] == pid
        finally:
            os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    from scripts.ci_pr237_native_socket_guest import https_response
    assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    assert live_wal_resource_hashes() == before
    print("PASS: signed managed installer repeat and unsafe include refusal preserve exact prior service and generation", flush=True)


def verify_inactive_managed_repair(distribution, native, assets, pins) -> None:
    """Same signed installed generation, enabled but stopped, no resource rewrite."""
    from scripts.stage_native_root_worker import WorkerStageError
    from repocache.server_native_installed_storage_v1 import InstalledStorageError
    from scripts.ci_pr237_native_socket_guest import https_response

    before = live_wal_resource_hashes()
    stopped = run("/usr/bin/systemctl", "stop", OWN)
    assert stopped.returncode == 0
    require_status(OWN, False, True)
    require_status(VENDOR, False, False)
    # Inject only the post-start acceptance failure. The service start and
    # compensating stop are real, on the actual signed installed unit.
    original = native.verify_service_storage_mounts
    def fail(_pid):
        raise InstalledStorageError("INSTALLED_NGINX_STORAGE_DISPOSABLE_MOUNT_FAULT")
    native.verify_service_storage_mounts = fail
    try:
        try:
            native.activate_authenticated_native_nginx(assets, **pins)
        except WorkerStageError as exc:
            assert str(exc) == "WORKER_PLACEMENT_NATIVE_ACTIVATION_FAILED_ROLLED_BACK", str(exc)
        else:
            raise AssertionError("Injected post-start failure accepted")
    finally:
        native.verify_service_storage_mounts = original
    require_status(OWN, False, True)
    assert live_wal_resource_hashes() == before
    result = native.activate_authenticated_native_nginx(assets, **pins)
    assert result["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ACTIVE"
    assert result["state_generation"] == 1
    verify_storage_report(result, distribution)
    require_status(OWN, True, True)
    require_status(VENDOR, False, False)
    assert live_wal_resource_hashes() == before
    assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    catalog = Path("/var/lib/repocache/public/catalog.json").read_bytes()
    assert https_response("/.well-known/repocache/catalog.json").endswith(catalog)
    print("PASS: authenticated inactive managed repair and real start/stop compensation preserve generation and enablement", flush=True)


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
    verify_managed_installer_repeat(distribution, native, assets, pins)
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


def verify_storage_report(report: dict, distribution: str) -> None:
    assert report["storage"] == {
        "cache_root_verified": True,
        "log_root_verified": True,
        "selinux_enforcing_labels_verified": distribution == "almalinux",
        "actual_service_write_verified": False,
    }
    assert report["service_storage_mounts_verified"] is True


def verify_storage_marker_refusal(native, assets, pins, expected_pid: int) -> None:
    """Only on this disposable booted guest: refuse drift without restarting."""
    import stat
    from repocache.server_native_installed_storage_v1 import InstalledStorageError

    marker = Path("/var/cache/nginx/.repocache-managed.owner-v1")
    leaf = marker.parent / "repocache-managed"
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode)
        assert (before.st_uid, before.st_gid, before.st_nlink,
                stat.S_IMODE(before.st_mode)) == (0, 0, 1, 0o600)
        data = os.read(fd, 1025)
        assert 1 <= len(data) <= 1024
        root_before = leaf.lstat()
        try:
            os.fchmod(fd, 0o644)
            try:
                native.activate_authenticated_native_nginx(assets, **pins)
            except InstalledStorageError as exc:
                assert str(exc) == "INSTALLED_NGINX_STORAGE_MARKER_UNSAFE"
            else:
                raise AssertionError("Unsafe storage ownership marker accepted")
            assert native._own_service_observation(active=True)["main_pid_observed"] == expected_pid
            require_status(OWN, True, True)
            require_status(VENDOR, False, False)
            loopback_response()
            assert leaf.lstat() == root_before
            assert os.pread(fd, 1025, 0) == data
            assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o644
        finally:
            os.fchmod(fd, 0o600)
        assert marker.lstat().st_ino == before.st_ino
        assert os.pread(fd, 1025, 0) == data
    finally:
        os.close(fd)
    print("PASS: actual owned storage marker drift refused without service restart or root adoption", flush=True)


def verify_storage_after_recovery(distribution: str, native) -> None:
    """Read-only installed-storage and actual service namespace recheck."""
    from repocache.server_native_installed_storage_v1 import (
        prepare_installed_storage, verify_service_storage_mounts,
    )
    from repocache.server_protected_state_store_v1 import _locked
    from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS

    root = os.open("/", _DIRECTORY_FLAGS)
    try:
        with _locked(root, 0) as state:
            native._require_audited_native_package_for_activation(
                state, distribution=distribution,
            )
            observed = native._own_service_observation(active=True)
            storage = prepare_installed_storage(distribution, allow_create=False)
            verify_service_storage_mounts(observed["main_pid_observed"])
            assert native._own_service_observation(active=True) == observed
            verify_storage_report({"storage": storage,
                                   "service_storage_mounts_verified": True},
                                  distribution)
    finally:
        os.close(root)
    print("PASS: owned storage metadata and actual NGINX mount boundaries verified after WAL recovery and reboot", flush=True)


def verify_owned_service_data_fixture(distribution, native, assets, pins) -> None:
    """Real installed systemd unit, private test-only routes and fixed storage.

    The production socket still refuses active candidates. This disposable
    guest isolates runtime storage/SELinux capability from authoritative
    route exposure, and restores the exact prior committed include.
    """
    import base64
    import collections
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import pwd
    import ssl
    import stat
    import threading
    from scripts.ci_pr237_native_socket_guest import https_response
    from repocache.server_nginx_metrics_bundle_join_v1 import render_repository_nginx_metrics_join
    from repocache.server_nginx_tls_listener_candidate_v1 import render_native_tls_listener_candidate

    platform = {"debian": "debian13", "almalinux": "almalinux10"}[distribution]
    assert os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
    assert socket.gethostname() == "pr237-" + platform
    assert not Path("/.dockerenv").exists()
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert run("/usr/bin/systemd-detect-virt", "--vm").stdout.strip() in ("qemu", "kvm")
    require_status(OWN, True, True)
    require_status(VENDOR, False, False)
    assert run("/usr/bin/systemctl", "is-active", "repocache-control.socket").stdout.strip() == "inactive"
    assert run("/usr/bin/systemctl", "is-active", "repocache-control.service").stdout.strip() == "inactive"
    if distribution == "almalinux":
        assert run("/usr/sbin/getenforce").stdout.strip() == "Enforcing"
    verified = native.stage.verify_installed_worker(assets, **pins)
    assert verified["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    before = live_wal_resource_hashes()
    prior = json.loads((STATE / "state-v2.json").read_bytes())
    doc = json.loads(base64.b64decode(prior["configuration_base64"], validate=True))
    assert all(row["desired_state"] == "disabled" for row in doc["repositories"])
    assert doc["deployment"]["paths"]["cache_root"] == "/var/cache/nginx/repocache-managed"
    assert doc["deployment"]["paths"]["log_root"] == "/var/log/nginx/repocache-managed"
    doc["deployment"]["logging"]["metrics_opt_in"] = True
    payloads = {}
    for repo in doc["repositories"]:
        name = repo["id"]
        repo["desired_state"] = "active"
        repo["upstream"] = {
            "base_url": "https://cache.example.invalid/" + name + "/",
            "allowed_hosts": ["cache.example.invalid"],
        }
        suffix = "fixture.deb" if repo["kind"] == "apt" else "fixture.rpm"
        path = "/" + name + "/" + suffix
        payloads[path] = ("REPOCACHE disposable " + name + "\n").encode("ascii") * 64
    names = sorted(repo["id"] for repo in doc["repositories"])

    # Execute the newly signed module from the actual installed zipapp,
    # after the fixture authenticated the same archive. The existing
    # native lock and closed committed generation remain authoritative.
    code = """
import json, os, sys, zipimport
sys.path.insert(0, "/usr/libexec/repocache/server-control-worker")
from repocache import server_native_installed_storage_v1 as storage
from repocache import server_native_v2_transaction_v1 as tx
from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS
from repocache.server_protected_state_store_v1 import _locked
from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions
assert isinstance(storage.__loader__, zipimport.zipimporter)
assert storage.__loader__.archive == "/usr/libexec/repocache/server-control-worker"
assert require_native_host_preconditions()["initial_root_credentials_observed"] is True
distribution, create = sys.argv[1:]
root = os.open("/", _DIRECTORY_FLAGS)
try:
    with _locked(root, 0) as state:
        tx._require_audited_native_package_for_activation(state, distribution=distribution)
        with tx._owned_layout_locked(root, state, recovering=False) as layout:
            old = tx._read_owned_resources(state, layout[1], layout[2])
            snapshot = tx._validate_owned_resources(old)
            tx._owned_socket_require_inactive_routes(snapshot)
            identity = tx._owned_live_observe(root)
            storage.verify_service_storage_mounts(identity[0])
            report = storage.prepare_installed_repository_storage(
                distribution, json.load(sys.stdin), allow_create=create == "create")
            layout[3]()
            assert tx._read_owned_resources(state, layout[1], layout[2]) == old
            assert tx._owned_live_observe(root) == identity
            print(json.dumps(report))
finally:
    os.close(root)
"""
    def prepare(create):
        outcome = subprocess.run(
            ["/usr/bin/python3", "-IS", "-B", "-c", code, distribution,
             "create" if create else "verify"], input=json.dumps(doc), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False,
            cwd="/", env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
        )
        if outcome.returncode != 0:
            import re
            codes = re.findall(r"(?:INSTALLED_NGINX_STORAGE|NATIVE_V2|NATIVE_HOST)_[A-Z0-9_]+",
                               outcome.stderr)
            raise AssertionError("Signed storage fixture refused: " + ",".join(codes))
        assert json.loads(outcome.stdout) == {
            "repository_cache_roots_verified": names, "metrics_file_verified": True,
            "selinux_enforcing_labels_verified": distribution == "almalinux",
            "actual_service_write_verified": False,
        }

    prepare(True)
    assert live_wal_resource_hashes() == before
    cache = Path(doc["deployment"]["paths"]["cache_root"])
    log = Path(doc["deployment"]["paths"]["log_root"]) / "metrics.jsonl"
    assert log.read_bytes() == b""
    worker = pwd.getpwnam("www-data" if distribution == "debian" else "nginx")
    for name in names:
        info = (cache / name).lstat()
        assert stat.S_ISDIR(info.st_mode)
        assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
            worker.pw_uid, worker.pw_gid, 0o700)
    info = log.lstat()
    assert (info.st_uid, info.st_gid, info.st_nlink, stat.S_IMODE(info.st_mode)) == (0, 0, 1, 0o600)
    log_identity = (info.st_dev, info.st_ino)
    ca = {"debian": "/etc/ssl/certs/ca-certificates.crt",
          "almalinux": "/etc/pki/tls/certs/ca-bundle.crt"}[distribution]
    bundle = render_repository_nginx_metrics_join(
        doc, expected_state_generation=doc["expected_state_generation"],
        candidate_pins_by_repository={name: {"cache.example.invalid": ["8.8.8.8"]}
                                      for name in names},
        ca_bundle_path=ca,
    )
    assert not bundle["authorizes_nginx_activation"]
    assert bundle["http_fragment"].count("server 8.8.8.8:443;") == len(names)
    # Only the disposable VM harness substitutes a fixed loopback origin.
    # Production resolver and renderer continue to reject private pins.
    http = bundle["http_fragment"].replace("server 8.8.8.8:443;", "server 127.0.0.1:8008;")
    server = bundle["server_fragment"].replace(
        "    proxy_cache_valid 200 60s;",
        "    proxy_cache_valid 200 60s;\n    add_header X-RepoCache-Smoke $upstream_cache_status always;",
    )
    tls = render_native_tls_listener_candidate(doc)["server_context_fragment"]
    fixture = (http + "\nserver {\n" + tls + server
               + "location / { return 404; }\n}\n").encode("ascii")
    hits = collections.Counter()
    class Origin(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            if self.path not in payloads:
                self.send_error(404)
                return
            hits[self.path] += 1
            payload = payloads[self.path]
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "public, max-age=60")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    backend = ThreadingHTTPServer(("127.0.0.1", 8008), Origin)
    backend.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(doc["deployment"]["tls"]["certificate_file"],
                            doc["deployment"]["tls"]["private_key_file"])
    backend.socket = context.wrap_socket(backend.socket, server_side=True)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    include = OWN_CONFIG.parent / "repocache-managed.conf"
    fd = os.open(include, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    old = os.fstat(fd)
    assert (old.st_uid, old.st_gid, old.st_nlink, stat.S_IMODE(old.st_mode)) == (0, 0, 1, 0o644)
    raw = os.pread(fd, old.st_size + 1, 0)
    assert hashlib.sha256(raw).hexdigest() == before[str(include)]

    def replace_include(data):
        assert (include.lstat().st_dev, include.lstat().st_ino) == (old.st_dev, old.st_ino)
        os.ftruncate(fd, 0)
        assert os.pwrite(fd, data, 0) == len(data)
        os.fsync(fd)

    try:
        assert run("/usr/bin/systemctl", "stop", OWN).returncode == 0
        require_status(OWN, False, True)
        replace_include(fixture)
        started = run("/usr/bin/systemctl", "start", OWN)
        if started.returncode != 0:
            diagnostic = run("/usr/bin/journalctl", "-u", OWN, "-n", "20", "--no-pager")
            print("STORAGE_FIXTURE_START_DIAGNOSTIC: " + diagnostic.stdout[-2400:], flush=True)
            raise AssertionError("Actual dedicated service refused fixture configuration")
        master = native._own_service_observation(active=True)["main_pid_observed"]
        from repocache.server_native_installed_storage_v1 import verify_service_storage_mounts
        verify_service_storage_mounts(master)
        children = Path(f"/proc/{master}/task/{master}/children").read_text().split()
        observed_worker = False
        for pid in children:
            if not Path(f"/proc/{pid}/cmdline").read_bytes().startswith(b"nginx: worker process"):
                continue
            fields = dict(line.split(":", 1) for line in
                          Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
            assert set(fields["Uid"].split()) == {str(worker.pw_uid)}
            assert set(fields["Gid"].split()) == {str(worker.pw_gid)}
            if distribution == "almalinux":
                assert b":httpd_t:" in Path(f"/proc/{pid}/attr/current").read_bytes()
            observed_worker = True
        assert observed_worker
        for path, payload in payloads.items():
            for expected in (b"miss", b"hit"):
                response = https_response("/__repocache/repos" + path)
                header, body = response.split(b"\r\n\r\n", 1)
                assert header.startswith(b"HTTP/1.1 200 "), header[:160]
                assert b"x-repocache-smoke: " + expected in header.lower()
                assert body == payload
            assert hits[path] == 1
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        assert len(rows) == 2 * len(names)
        assert {row["upstream_cache_status"] for row in rows} == {"MISS", "HIT"}
        assert {row["repocache_repository"] for row in rows} == {
            "/__repocache/repos/" + name + "/" for name in names}
        for name in names:
            files = [p for p in (cache / name).rglob("*") if p.is_file()]
            assert files and all(p.lstat().st_uid == worker.pw_uid for p in files)
        assert (log.lstat().st_dev, log.lstat().st_ino) == log_identity
        print("PASS: actual dedicated systemd NGINX worker writes fixed owned cache and metrics; MISS/HIT and exact fixture bytes", flush=True)
    finally:
        try:
            assert run("/usr/bin/systemctl", "stop", OWN).returncode == 0
            # A refused test configuration can leave systemd in failed
            # state even after stop. Restore the authenticated bytes before
            # clearing that state; never let a status assertion strand the
            # temporary include or mask the original fixture failure.
            replace_include(raw)
            status = run("/usr/bin/systemctl", "is-failed", OWN)
            if status.returncode == 0:
                assert run("/usr/bin/systemctl", "reset-failed", OWN).returncode == 0
            require_status(OWN, False, True)
            assert run("/usr/bin/systemctl", "start", OWN).returncode == 0
            require_status(OWN, True, True)
        finally:
            os.close(fd)
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=5)
    assert live_wal_resource_hashes() == before
    assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    history = log.read_bytes()
    cache_before = {str(p.relative_to(cache)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in cache.rglob("*") if p.is_file()}
    prepare(False)
    prepare(True)
    assert log.read_bytes() == history
    assert cache_before == {str(p.relative_to(cache)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in cache.rglob("*") if p.is_file()}
    assert live_wal_resource_hashes() == before
    print("PASS: restored exact committed generation; repeat signed storage preparation retains cache/history", flush=True)


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
        verify_storage_report(activated, distribution)
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
        verify_storage_marker_refusal(native, assets, pins, signed_pid)
        repeated = native.activate_authenticated_native_nginx(assets, **pins)
        assert repeated["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ALREADY_ACTIVE"
        verify_storage_report(repeated, distribution)

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
        verify_storage_after_recovery(distribution, native)
        verify_managed_installer_repeat(distribution, native, assets, pins)
        verify_inactive_managed_repair(distribution, native, assets, pins)
        verify_owned_service_data_fixture(distribution, native, assets, pins)
        require_status(OWN, True, True)
        require_status(VENDOR, False, False)
        assert hashlib.sha256(VENDOR_CONFIG.read_bytes()).hexdigest() == original["vendor_config_sha256"]
        assert hashlib.sha256(completion.read_bytes()).hexdigest() == original["receipt_sha256"]
        assert inspect_stock_nginx_package_file_integrity()[
            "native_package_file_integrity_verified"] is True
        print("PASS: separate REPOCACHE service survives real reboot with vendor service disabled and package integrity intact", flush=True)
        print("NOT VERIFIED: authoritative active repository transaction/catalog, pending-WAL inactive recovery, final publisher-signed release", flush=True)
    else:
        raise AssertionError("invalid test phase")


if __name__ == "__main__":
    if (len(sys.argv) != 3 or sys.argv[1] not in ("debian", "almalinux")
            or sys.argv[2] not in ("activate", "after")):
        raise SystemExit("Usage: ci_native_nginx_activate_guest.py debian|almalinux activate|after")
    verify_guest(sys.argv[1], sys.argv[2])
