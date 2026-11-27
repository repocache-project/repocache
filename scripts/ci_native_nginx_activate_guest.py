#!/usr/bin/env python3
"""Disposable VM evidence for the independently owned REPOCACHE NGINX unit.

This exercises real PID1, native APT/DNF, NGINX and SELinux enforcing with
test-only signed archive assets, not an authorized production deployment.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import time

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


def fixture_selinux_connect_denied(raw: str, worker_pids: set[int]) -> bool:
    """Match only an enforcing AVC for this disposable upstream fixture."""
    if len(raw) > 1024 * 1024 or not worker_pids:
        return False
    for line in raw.splitlines():
        if not re.search(r"\btype=(?:AVC|1400)\b", line):
            continue
        if not re.search(r"\bavc:\s+denied\s+\{\s*name_connect\s*\}", line):
            continue
        pid = re.search(r"(?:^|\s)pid=([0-9]{1,10})(?:\s|$)", line)
        if pid is None or int(pid.group(1)) not in worker_pids:
            continue
        if all(re.search(pattern, line) for pattern in (
            r'(?:^|\s)comm="nginx"(?:\s|$)',
            r"(?:^|\s)dest=8008(?:\s|$)",
            r"(?:^|\s)scontext=[^\s:]+:[^\s:]+:httpd_t:[^\s]+",
            r"(?:^|\s)tclass=tcp_socket(?:\s|$)",
            r"(?:^|\s)permissive=0(?:\s|$)",
        )):
            return True
    return False


def fixture_port_context(rules, port: int) -> str | None:
    """First matching TCP portcon in the loaded binary policy's order.

    Linux security_port_sid walks OCON_PORT from its head and stops at
    the first match. SETools SELinuxPolicy.portcons() uses the same
    linked-list order; do not sort, deduplicate or prefer the narrowest
    interval (generic reserved/unreserved ranges can overlap).
    """
    if port not in (443, 8008):
        return None
    for rule in rules:
        if str(rule.protocol) != "tcp" or not rule.ports.low <= port <= rule.ports.high:
            continue
        context = str(rule.context)
        if (not 1 <= len(context) <= 1024
                or re.fullmatch(r"[A-Za-z0-9_:.\-,]+", context) is None
                or len(context.split(":", 3)) != 4):
            return None
        return context
    return None


def fixture_upstream_connect_eacces(raw: str, worker_pids: set[int]) -> bool:
    """Require the specific NGINX worker, fixed fixture endpoint and errno."""
    if len(raw) > 1024 * 1024 or not worker_pids:
        return False
    pattern = re.compile(
        r"\[(?:crit|error)\] ([0-9]{1,10})#[0-9]{1,10}: \*[0-9]+ "
        r"connect\(\) to 127\.0\.0\.1:8008 failed "
        r"\(13: Permission denied\) while connecting to upstream(?:,|$)"
    )
    for line in raw.splitlines():
        match = pattern.search(line)
        if match and int(match[1]) in worker_pids:
            return True
    return False


def fixture_selinux_policy_connect(worker_pids: set[int]) -> dict[int, str]:
    """Observe loaded kernel access decisions; never change policy or booleans.

    The fixture connects to 8008; 443 is the actual HTTPS upstream port.
    This observation is distinct from an AVC for the failed connection.
    Only static decision categories leave this disposable guest.
    """
    result = {443: "NOT_VERIFIED", 8008: "NOT_VERIFIED"}
    stage = "IMPORT"
    def unavailable(reason):
        print("STORAGE_FIXTURE_SELINUX_POLICY_UNAVAILABLE: " + reason, flush=True)
        return result
    try:
        import ctypes
        import setools
        stage = "WORKER_CONTEXT"

        if not worker_pids or len(worker_pids) > 32:
            return unavailable(stage)

        def contexts():
            return {Path(f"/proc/{pid}/attr/current").read_bytes().rstrip(b"\0\n")
                    for pid in worker_pids}

        sources = contexts()
        if len(sources) != 1:
            return unavailable(stage)
        source = next(iter(sources))
        if len(source) > 1024 or source.split(b":", 3)[2:3] != [b"httpd_t"]:
            return unavailable(stage)
        stage = "LIBSELINUX"

        class Decision(ctypes.Structure):
            # libselinux public av_decision ABI; unsigned int access vectors.
            _fields_ = [(key, ctypes.c_uint) for key in
                        ("allowed", "decided", "auditallow", "auditdeny", "seqno", "flags")]

        library = ctypes.CDLL("libselinux.so.1")
        library.security_getenforce.argtypes = ()
        library.security_getenforce.restype = ctypes.c_int
        library.string_to_security_class.argtypes = (ctypes.c_char_p,)
        library.string_to_security_class.restype = ctypes.c_ushort
        library.string_to_av_perm.argtypes = (ctypes.c_ushort, ctypes.c_char_p)
        library.string_to_av_perm.restype = ctypes.c_uint
        library.security_compute_av_flags_raw.argtypes = (
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ushort, ctypes.c_uint,
            ctypes.POINTER(Decision),
        )
        library.security_compute_av_flags_raw.restype = ctypes.c_int
        stage = "ENFORCEMENT"
        if library.security_getenforce() != 1:
            return unavailable(stage)
        stage = "PERMISSION_MAPPING"
        klass = library.string_to_security_class(b"tcp_socket")
        perm = library.string_to_av_perm(klass, b"name_connect") if klass else 0
        if not perm:
            return unavailable(stage)

        stage = "POLICY_LOAD"
        policy = setools.SELinuxPolicy("/sys/fs/selinux/policy")
        targets = {}
        seqnos = set()
        observed = dict(result)
        for port in result:
            stage = "PORT_CONTEXT"
            target = fixture_port_context(policy.portcons(), port)
            if target is None:
                unavailable(stage)
                continue
            targets[port] = target
            stage = "ACCESS_DECISION"
            decision = Decision()
            if library.security_compute_av_flags_raw(
                    source, target.encode("ascii"), klass, perm,
                    ctypes.byref(decision)) != 0:
                unavailable(stage)
                continue
            if decision.flags & 1:  # SELINUX_AVD_FLAGS_PERMISSIVE
                unavailable("DOMAIN_PERMISSIVE")
                continue
            seqnos.add(decision.seqno)
            observed[port] = "ALLOW" if decision.allowed & perm else "DENY"
        stage = "POLICY_RECHECK"
        current = setools.SELinuxPolicy("/sys/fs/selinux/policy")
        if (library.security_getenforce() != 1 or contexts() != sources
                or len(seqnos) != 1
                or any(fixture_port_context(current.portcons(), port) != label
                       for port, label in targets.items())):
            return unavailable(stage)
        return observed
    except Exception:
        # Optional diagnosis cannot conceal the original failed fixture or
        # expose policy, process labels, package details or library errors.
        return unavailable(stage)


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



def require_control_worker_idle(timeout: float = 20.0) -> None:
    """Observe clean oneshot exit; never reset or stop a failing worker."""
    fields = ("LoadState", "ActiveState", "SubState", "Result",
              "MainPID", "ControlPID", "ExecMainStatus")
    deadline = time.monotonic() + timeout
    while True:
        status = run("/usr/bin/systemctl", "show", "repocache-control.service",
                     *("-p" + field for field in fields))
        observed = {}
        for line in status.stdout.splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in fields or key in observed:
                raise AssertionError("Control worker state malformed")
            observed[key] = value
        if (status.returncode != 0 or set(observed) != set(fields)
                or observed["LoadState"] != "loaded"):
            raise AssertionError("Control worker state unavailable")
        if observed["Result"] != "success":
            raise AssertionError("Control worker result not successful")
        if observed["ActiveState"] == "inactive":
            if observed["SubState"] == "dead" and all(
                    observed[field] == "0" for field in
                    ("MainPID", "ControlPID", "ExecMainStatus")):
                return
            raise AssertionError("Control worker inactive state not clean")
        if observed["ActiveState"] not in ("activating", "deactivating"):
            raise AssertionError("Control worker unexpected active state")
        if time.monotonic() >= deadline:
            raise AssertionError("Control worker did not finish within deadline")
        time.sleep(0.1)


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
                print("DEDICATED_SOCKET_STATE_PRESENT: "
                      + str((STATE / "state-v2.json").is_file()), flush=True)
                print("DEDICATED_SOCKET_WAL_PRESENT: "
                      + str((STATE / ".state-v2-owned-nginx.pending").is_file()),
                      flush=True)
                journal = run("/usr/bin/journalctl", "-u", "repocache-control.service",
                              "-n", "50", "--no-pager", "-o", "cat")
                from repocache.server_native_v2_transaction_v1 import _AUDIT_FAILURE_CODES
                prefix = "REPOCACHE_FIXED_TRANSACTION_REFUSAL: "
                known = _AUDIT_FAILURE_CODES | {"NATIVE_V2_OTHER_REFUSAL"}
                if journal.returncode == 0:
                    for line in journal.stdout.splitlines():
                        if line.startswith(prefix) and line[len(prefix):] in known:
                            print("DEDICATED_SOCKET_REFUSAL: " + line[len(prefix):],
                                  flush=True)
                raise
            assert result["status"] == expected, result["status"]
            assert result["transaction_completed"] is True
            if expected in ("APPLIED", "RELOADED", "UNCHANGED"):
                assert result["state_generation"] == 1

    completed = False
    try:
        if pending:
            wal = STATE / ".state-v2-owned-nginx.pending"
            before = wal.read_bytes()
            assert before
            call("RECOVER_V2", "RECOVERED")
            assert not wal.exists()
            print("PASS: confined socket recovered pending WAL after reboot", flush=True)
            completed = True
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
            completed = True
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
        completed = True
    finally:
        try:
            if completed:
                require_control_worker_idle()
        finally:
            command("/usr/bin/systemctl", "stop", "repocache-control.socket")
        if completed:
            require_control_worker_idle()
            print("PASS: control worker completed before socket teardown and remained idle", flush=True)


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
    def vendor_temp_identity():
        if distribution != "debian":
            return {}
        result = {}
        for name in ("body", "proxy", "fastcgi", "scgi", "uwsgi"):
            info = Path("/var/lib/nginx", name).lstat()
            result[name] = (info.st_dev, info.st_ino, info.st_mode,
                            info.st_uid, info.st_gid)
        return result
    vendor_temps = vendor_temp_identity()
    run_live_wal(distribution, "fail-reload")
    assert OWN_CONFIG.read_bytes() == bootstrap
    assert not (STATE / "state-v2.json").exists()
    assert not (STATE / ".state-v2-owned-nginx.pending").exists()
    loopback_response()
    print("PASS: actual dedicated WAL failure compensation restores private bootstrap", flush=True)

    assert vendor_temp_identity() == vendor_temps
    verify_dedicated_socket(bootstrap=True)
    assert vendor_temp_identity() == vendor_temps
    if distribution == "debian":
        from repocache.server_native_v2_transaction_v1 import _owned_debian_runtime_temps
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            _, scratch = _owned_debian_runtime_temps(root, require_all=True)
            assert len(scratch) == 5
        finally:
            os.close(root)
        print("PASS: Debian managed syntax and confined APPLY preserve vendor temp metadata and use five private runtime paths", flush=True)
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
    code = """
import os,pwd,sys,zipimport
sys.path.insert(0,"/usr/libexec/repocache/server-control-worker")
from repocache import server_native_v2_transaction_v1 as tx
assert isinstance(tx.__loader__,zipimport.zipimporter)
assert tx.__loader__.archive == "/usr/libexec/repocache/server-control-worker"
distribution=sys.argv[1]
uid=pwd.getpwnam("www-data" if distribution == "debian" else "nginx").pw_uid
root=os.open("/",tx._DIRECTORY_FLAGS)
try:
    with tx._locked(root,0) as state:
        with tx._owned_layout_locked(root,state,recovering=True) as layout:
            state,nginx,public,check=layout
            raw=tx._read_file(state,tx._OWNED_WAL,0,tx._MAX_WAL)
            current=tx._read_owned_resources(state,nginx,public)
            assert current[tx._CATALOG] is None
            report=tx._owned_live_egress_recovery_candidates(
                raw,current,distribution=distribution,worker_uid=uid)
            assert report["prior"]["generation"] == 1
            assert report["proposed"]["generation"] == 2
            assert report["prior"]["destinations"] == report["proposed"]["destinations"] == ()
            assert report["authorizes_firewall_change"] is False
            assert report["authorizes_catalog_publication"] is False
            assert tx._read_owned_resources(state,nginx,public) == current
            assert tx._read_file(state,tx._OWNED_WAL,0,tx._MAX_WAL) == raw
            check()
finally:
    os.close(root)
"""
    subprocess.run(["/usr/bin/python3","-IS","-B","-c",code,distribution],
                   stdin=subprocess.DEVNULL,check=True,timeout=45)
    print("PASS: signed installed worker reconstructs exact prior and proposed egress from durable v3 WAL after reboot, without DNS, mutation or authority", flush=True)
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
    import time
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
    require_control_worker_idle()
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
            snapshot = tx._validate_owned_resources(old, distribution=distribution)
            tx._owned_socket_require_inactive_routes(snapshot)
            identity = tx._owned_live_observe(root)
            storage.verify_service_storage_mounts(identity[0])
            document = json.load(sys.stdin)
            report = storage.prepare_installed_repository_storage(
                distribution, document, allow_create=create == "create")
            observed = storage.verify_control_repository_storage(
                distribution, document, identity[0])
            assert observed == dict(report, service_data_mounts_verified=True)
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
        # Prove the fixture origin's exact native CA/hostname handshake
        # independently, without weakening the production proxy checks.
        upstream_tls = ssl.create_default_context(cafile=ca)
        with socket.create_connection(("127.0.0.1", 8008), timeout=5) as channel:
            with upstream_tls.wrap_socket(channel, server_hostname="cache.example.invalid"):
                pass
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
        worker_pids: set[int] = set()
        for pid in children:
            if not Path(f"/proc/{pid}/cmdline").read_bytes().startswith(b"nginx: worker process"):
                continue
            fields = dict(line.split(":", 1) for line in
                          Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
            assert set(fields["Uid"].split()) == {str(worker.pw_uid)}, "Unexpected worker UID"
            assert set(fields["Gid"].split()) == {str(worker.pw_gid)}, "Unexpected worker GID"
            if distribution == "almalinux":
                assert b":httpd_t:" in Path(f"/proc/{pid}/attr/current").read_bytes()
            observed_worker = True
            worker_pids.add(int(pid))
        assert observed_worker
        for path, payload in payloads.items():
            for expected in (b"miss", b"hit"):
                request_started = int(time.time())
                response = https_response("/__repocache/repos" + path)
                header, body = response.split(b"\r\n\r\n", 1)
                if not header.startswith(b"HTTP/1.1 200 "):
                    # Capture bounded diagnostic categories, not URLs, keys
                    # or raw log lines. No SELinux workaround is permitted.
                    journal = run("/usr/bin/journalctl", "-u", OWN, "-n", "50", "--no-pager")
                    for category in ("Permission denied", "certificate verify failed",
                                     "certificate does not match", "Connection refused",
                                     "upstream timed out", "SSL_do_handshake() failed"):
                        if category in journal.stdout:
                            print("STORAGE_FIXTURE_UPSTREAM_ERROR: " + category, flush=True)
                    if distribution == "almalinux":
                        recent = run("/usr/bin/journalctl", "-u", OWN, "-b",
                                     "--since", "@" + str(request_started),
                                     "-n", "50", "--no-pager", "-o", "cat")
                        matched = (recent.returncode == 0 and
                                   fixture_upstream_connect_eacces(recent.stdout, worker_pids))
                        print("STORAGE_FIXTURE_UPSTREAM_CONNECT_EACCES: "
                              + ("OBSERVED" if matched else "NOT_VERIFIED"), flush=True)
                        # Read-only evidence, no policy change or raw audit output.
                        try:
                            audit = run("/usr/sbin/ausearch", "-m", "AVC",
                                        "-ts", "recent", "--raw")
                            confirmed = (audit.returncode == 0 and
                                         fixture_selinux_connect_denied(
                                             audit.stdout, worker_pids))
                        except (OSError, subprocess.TimeoutExpired):
                            confirmed = False
                        if not confirmed:
                            # The kernel audit record may be in journald rather
                            # than auditd's log. Observe only the current guest
                            # boot and this request's bounded time interval.
                            try:
                                kernel = run("/usr/bin/journalctl", "-k", "-b",
                                             "--since", "@" + str(request_started),
                                             "-n", "1000", "--no-pager", "-o", "cat")
                                confirmed = (kernel.returncode == 0 and
                                             fixture_selinux_connect_denied(
                                                 kernel.stdout, worker_pids))
                            except (OSError, subprocess.TimeoutExpired):
                                confirmed = False
                        print("STORAGE_FIXTURE_SELINUX_CONNECT_DENIAL: "
                              + ("OBSERVED" if confirmed else "NOT_VERIFIED"),
                              flush=True)
                        for port, decision in fixture_selinux_policy_connect(worker_pids).items():
                            print(f"STORAGE_FIXTURE_SELINUX_POLICY_TCP_{port}: {decision}", flush=True)
                        for boolean in ("httpd_can_network_connect", "httpd_can_network_relay"):
                            observed = run("/usr/sbin/getsebool", boolean)
                            if observed.returncode == 0 and observed.stdout.strip() in (
                                    boolean + " --> on", boolean + " --> off"):
                                print("STORAGE_FIXTURE_POLICY: " + observed.stdout.strip(), flush=True)
                    raise AssertionError("Dedicated NGINX upstream fixture failed: "
                                         + header.split(b"\r\n", 1)[0].decode("ascii"))
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



def verify_owned_service_namespace_data_fixture(native, assets, pins):
    """Guarded Alma VM: actual owned unit, paths and signed dedicated candidate.

    Preserve the original disabled-route generation and vendor service. The
    temporary runtime drop-in and fresh labelled storage are not a durable
    installed migration. A failed compensation must fail this campaign.
    """
    import base64
    import contextlib
    import pwd
    import stat
    import tempfile
    from scripts import ci_selinux_nginx_egress_guest as isolated
    from scripts.ci_pr237_native_socket_guest import https_response
    from repocache.server_native_installed_storage_v1 import verify_service_storage_mounts

    isolated.guard()
    require_status(OWN, True, True)
    require_status(VENDOR, False, False)
    require_control_worker_idle()
    assert run("/usr/bin/systemctl", "is-active", "repocache-control.socket").stdout.strip() == "inactive"
    release = native.stage.verify_installed_worker(assets, **pins)
    assert release["publisher_key_id"] == "pr237-synthetic"
    verify_fixed_executable_after_reboot(pins)
    before = live_wal_resource_hashes()
    vendor_before = isolated.VENDOR.lstat()
    booleans = isolated.command("/usr/sbin/getsebool", "-a").stdout
    host_rules = isolated.command("/usr/sbin/nft", "--stateless", "--numeric-priority",
                                  "list", "ruleset").stdout
    worker = pwd.getpwnam("nginx")
    prior = json.loads((STATE / "state-v2.json").read_bytes())
    doc = json.loads(base64.b64decode(prior["configuration_base64"], validate=True))
    assert all(row["desired_state"] == "disabled" for row in doc["repositories"])
    dep = doc["deployment"]
    assert dep["listen"]["bind_address"] == "127.0.0.1" and dep["listen"]["https_port"] == 443
    assert dep["paths"]["cache_root"] == "/var/cache/nginx/repocache-managed"
    assert dep["paths"]["log_root"] == "/var/log/nginx/repocache-managed"
    assert dep["tls"] == {"mode": "operator-provided",
                          "certificate_file": "/etc/repocache/tls/example-chain.pem",
                          "private_key_file": "/etc/repocache/tls/example-key.pem"}
    dep["logging"]["metrics_opt_in"] = True
    payloads = {}
    for repo in doc["repositories"]:
        ident = repo["id"]
        repo["desired_state"] = "active"
        repo["upstream"] = {"base_url": "https://cache.example.invalid:8008/" + ident + "/",
                            "allowed_hosts": ["cache.example.invalid"]}
        suffix = "fixture.deb" if repo["kind"] == "apt" else "fixture.rpm"
        payloads["/" + ident + "/" + suffix] = ("REPOCACHE dedicated " + ident + "\n") * 64
    names = sorted(repo["id"] for repo in doc["repositories"])
    code = r"""
import hashlib,json,os,signal,sys,zipimport
sys.path.insert(0,"/usr/libexec/repocache/server-control-worker")
from repocache import server_native_installed_storage_v1 as storage
from repocache import server_native_nginx_effective_unit_v1 as unit
from repocache import server_native_egress_candidate_v1 as egress
from repocache import server_native_v2_transaction_v1 as tx
from repocache import server_nginx_metrics_bundle_join_v1 as joined
from repocache import server_nginx_metrics_candidate_v1 as metrics
from repocache.server_nginx_metrics_bundle_join_v1 import render_repository_nginx_metrics_join
from repocache.server_nginx_tls_listener_candidate_v1 import render_native_tls_listener_candidate
from repocache.server_protected_state_store_v1 import _locked
from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS
from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions
for module in (storage,unit,egress,tx,joined,metrics):
    assert isinstance(module.__loader__,zipimport.zipimporter)
    assert module.__loader__.archive=="/usr/libexec/repocache/server-control-worker"
require_native_host_preconditions()
doc,uid,action=json.load(sys.stdin)
root=os.open("/",_DIRECTORY_FLAGS)
try:
    with _locked(root,0) as state:
        tx._require_audited_native_package_for_activation(state,distribution="almalinux")
        if action=="legacy":
            result=storage.prepare_installed_repository_storage("almalinux",doc,allow_create=False)
        elif action in ("create","verify"):
            result=storage.prepare_dedicated_candidate_storage(
                "almalinux",doc,allow_create=action=="create")
        elif action in ("unit-inactive","unit-active"):
            result=unit.inspect_signed_owned_namespace_unit(
                https_port=443,active=action=="unit-active")
        elif action in ("unit-place","unit-verify-placement"):
            raw=unit._signed_owned_unit_bytes()
            def prepare(allow):
                return unit._stage_namespace_dropin_under_lock(
                    root,state,raw,https_port=443,owner_uid=0,owner_gid=0,
                    allow_create=allow)
            if action=="unit-place":
                unit.inspect_effective_owned_nginx_unit(active=False)
                # Test-only child dies exactly after the durable receipt,
                # before publication. Retain the caller's state lock.
                pid=os.fork()
                if pid==0:
                    def crash(*args):
                        os.kill(os.getpid(),signal.SIGKILL)
                    storage._rename_directory_noreplace=crash
                    prepare(True)
                    os._exit(77)
                _,status=os.waitpid(pid,0)
                assert os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL
                from repocache.server_protected_state_store_v1 import _read_file
                receipt=_read_file(state,unit._NAMESPACE_PROFILE_RECEIPT,0,
                                   unit._NAMESPACE_PROFILE_RECEIPT_MAX)
                assert receipt
                before=unit._read_namespace_profile_at(
                    root,unit._render_owned_nginx_namespace_dropin_candidate(
                        raw,https_port=443)["dropin_bytes"],
                    owner_uid=0,owner_gid=0,staged=True)
                try:
                    prepare(False)
                except unit.EffectiveNginxUnitError as exc:
                    assert "NAMESPACE_PROFILE_STAGE_PENDING" in str(exc)
                else:
                    raise AssertionError("Verify-only completed pending profile")
                unit.inspect_effective_owned_nginx_unit(active=False)
                result=prepare(True)
                assert result["receipt_sha256"]==hashlib.sha256(receipt).hexdigest()
                assert result["directory_identity"]==before[0]
                assert result["private_dropin_identity"]==before[1]
                assert prepare(False)==result==prepare(True)
            else:
                result=prepare(False)
        else:
            assert action=="render"
            pins={r["id"]:{"cache.example.invalid":["8.8.8.8"]} for r in doc["repositories"]}
            bundle=render_repository_nginx_metrics_join(
                doc,expected_state_generation=doc["expected_state_generation"],
                candidate_pins_by_repository=pins,ca_bundle_path="/etc/pki/tls/certs/ca-bundle.crt")
            # The exact upstream/cache fragment is the authenticated renderer's
            # output; metrics add their own separate HTTP directives.
            from repocache.server_nginx_repository_bundle_v1 import render_repository_nginx_bundle_candidate
            upstream=render_repository_nginx_bundle_candidate(
                doc,expected_state_generation=doc["expected_state_generation"],
                candidate_pins_by_repository=pins,ca_bundle_path="/etc/pki/tls/certs/ca-bundle.crt")
            rules=egress.render_namespace_egress_candidate(
                doc,generation=doc["expected_state_generation"],
                http_fragment=upstream["http_upstream_fragment"].encode("ascii"),worker_uid=uid)
            dropin=unit.render_owned_nginx_namespace_dropin_candidate(https_port=443)
            assert not dropin["authorizes_systemctl"] and not rules["authorizes_firewall_change"]
            result={"http":bundle["http_fragment"],"locations":bundle["server_fragment"],
                    "tls":render_native_tls_listener_candidate(doc)["server_context_fragment"],
                    "rules":rules["nft_candidate"],"dropin":dropin["dropin_bytes"].decode("ascii"),
                    "source_unit_sha256":dropin["source_unit_sha256"]}
        print(json.dumps(result))
finally:
    os.close(root)
"""
    def signed(action, document=doc):
        return json.loads(isolated.command(
            "/usr/bin/python3", "-IS", "-B", "-c", code,
            input_text=json.dumps([document, worker.pw_uid, action]), timeout=90).stdout)

    rendered = signed("render")
    unit_path = Path("/etc/systemd/system", OWN)
    assert hashlib.sha256(unit_path.read_bytes()).hexdigest() == rendered["source_unit_sha256"] == release["files"][OWN]
    assert rendered["http"].count("server 8.8.8.8:8008;") == len(names)
    http = rendered["http"].replace("server 8.8.8.8:8008;", "server 127.0.0.1:8008;")
    # All temporary paths remain within the newly created owned cache root.
    scratch = "".join(f"{directive}_temp_path /var/cache/nginx/repocache-managed/.ci-{directive};\n"
                      for directive in ("client_body", "proxy", "fastcgi", "scgi", "uwsgi"))
    locations = rendered["locations"].replace(
        "    proxy_cache_valid 200 60s;",
        "    proxy_cache_valid 200 60s;\n    add_header X-RepoCache-Smoke $upstream_cache_status always;")
    fixture = (scratch + http + "\nserver {\n" + rendered["tls"] + locations
               + "location / { return 404; }\n}\n").encode("ascii")
    assert rendered["rules"].count("ip daddr 8.8.8.8 tcp dport 8008") == 1
    rules = rendered["rules"].replace("ip daddr 8.8.8.8 tcp dport 8008",
                                     "ip daddr 127.0.0.1 tcp dport 8008")
    cache = Path(dep["paths"]["cache_root"])
    log = Path(dep["paths"]["log_root"])
    metrics = log / "metrics.jsonl"
    include = OWN_CONFIG.parent / "repocache-managed.conf"
    saved_include = include.read_bytes()
    assert hashlib.sha256(saved_include).hexdigest() == before[str(include)]
    # Legacy roots are fully verified, empty, owned and never relabelled.
    # Preserve their exact inodes/markers in their existing native parents.
    legacy_doc = json.loads(base64.b64decode(prior["configuration_base64"], validate=True))
    signed("legacy", legacy_doc)
    assert not any(cache.iterdir()) and not any(log.iterdir())
    fixed = (cache, cache.parent / ".repocache-managed.owner-v1",
             log, log.parent / ".repocache-managed.owner-v1")
    backups = tuple(path.with_name(".ci-legacy-" + path.name) for path in fixed)
    assert not any(os.path.lexists(path) for path in backups)
    for parent in (cache.parent, log.parent):
        assert not any(p.name.startswith((".repocache-repository-", ".repocache-metrics-"))
                       for p in parent.iterdir())
    dropdir = Path("/etc/systemd/system", OWN + ".d")
    dropin = dropdir / "90-repocache-dedicated.conf"
    assert not os.path.lexists(dropdir)
    assert not os.path.lexists(Path("/run/systemd/system", OWN + ".d"))
    profile_receipt = STATE / ".native-nginx-profile-v1.json"
    profile_stage = dropdir.parent / ".repocache-dedicated-unit.stage"
    assert not os.path.lexists(profile_receipt) and not os.path.lexists(profile_stage)
    assert run("/usr/bin/systemctl", "show", "-p", "DropInPaths", "--value", OWN).stdout.strip() == ""
    ns = Path("/run/netns/repocache-nginx")
    runtime = Path("/run/repocache-nginx")
    assert not os.path.lexists(ns)
    target = Path("/usr/libexec/repocache/nginx")
    saved_target = target.stat()
    label_paths = (OWN_CONFIG.parent, OWN_CONFIG, include, Path("/etc/repocache/tls"),
                   Path(dep["tls"]["certificate_file"]), Path(dep["tls"]["private_key_file"]))
    labels = []
    moved = []
    created_storage = False
    legacy_stopped = False
    include_changed = False
    namespace = False
    placement_attempted = False
    unit_placed = False
    started = False
    origin = None
    def require(*argv):
        return isolated.command(*argv, timeout=90)
    def sync_dir(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    def rename_absent(source, dest):
        assert not os.path.lexists(dest)
        # Same filesystem, exact leaves, no overwrite.
        from repocache.server_native_installed_storage_v1 import _rename_directory_noreplace
        parent = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            assert source.parent == dest.parent
            _rename_directory_noreplace(parent, source.name, parent, dest.name)
            os.fsync(parent)
        finally:
            os.close(parent)
    with contextlib.ExitStack() as stack:
        for path in label_paths:
            assert path.resolve(strict=True) == path
            info = path.lstat()
            assert info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022
            assert stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            stack.callback(os.close, fd)
            assert (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (info.st_dev, info.st_ino)
            assert set(os.listxattr(fd)) == {"security.selinux"}
            labels.append((path, fd, (info.st_dev, info.st_ino), os.getxattr(fd, "security.selinux")))
        include_fd = os.open(include, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, include_fd)
        assert os.pread(include_fd, len(saved_include)+1, 0) == saved_include
        def replace_include(raw):
            assert include.stat().st_ino == os.fstat(include_fd).st_ino
            os.ftruncate(include_fd, 0)
            assert os.pwrite(include_fd, raw, 0) == len(raw)
            os.fsync(include_fd)
        try:
            require("/usr/bin/systemctl", "stop", OWN)
            legacy_stopped = True
            require_status(OWN, False, True)
            assert not os.path.lexists(runtime)
            for path, backup in zip(fixed, backups):
                info = path.lstat()
                rename_absent(path, backup)
                moved.append((path, backup, (info.st_dev, info.st_ino)))
            # A failed preparation retains evidence; no partial object is
            # deleted or mistaken for a legacy root.
            created_storage = True
            report = signed("create")
            assert report == {"repository_cache_roots_verified": names, "metrics_file_verified": True,
                              "selinux_enforcing_labels_verified": True, "actual_service_write_verified": False}
            assert signed("verify") == report
            assert cache.stat().st_uid == cache.stat().st_gid == 0
            assert stat.S_IMODE(cache.stat().st_mode) == 0o711
            for ident in names:
                leaf = cache / ident
                assert (leaf.stat().st_uid, leaf.stat().st_gid,
                        stat.S_IMODE(leaf.stat().st_mode)) == (worker.pw_uid, worker.pw_gid, 0o700)
            for path, fd, identity, _ in labels:
                assert (path.lstat().st_dev, path.lstat().st_ino) == identity
                os.setxattr(fd, "security.selinux", b"system_u:object_r:repocache_nginx_ro_t:s0\0")
                assert os.getxattr(fd, "security.selinux").rstrip(b"\0") == b"system_u:object_r:repocache_nginx_ro_t:s0"
            include_changed = True
            replace_include(fixture)
            runtime.mkdir(mode=0o755)
            require("/usr/bin/chcon", "-t", "repocache_nginx_pid_t", str(runtime))
            require("/usr/sbin/ip", "netns", "add", "repocache-nginx")
            namespace = True
            ns_identity = (ns.stat().st_dev, ns.stat().st_ino)
            require("/usr/sbin/ip", "-n", "repocache-nginx", "link", "set", "lo", "up")
            assert {x["ifname"] for x in json.loads(require(
                "/usr/sbin/ip", "-n", "repocache-nginx", "-j", "link", "show").stdout)} == {"lo"}
            isolated.command("/usr/sbin/ip", "netns", "exec", "repocache-nginx",
                             "/usr/sbin/nft", "-c", "-f", "-", input_text=rules)
            isolated.command("/usr/sbin/ip", "netns", "exec", "repocache-nginx",
                             "/usr/sbin/nft", "-f", "-", input_text=rules)
            placement_attempted = True
            placement = signed("unit-place")
            unit_placed = True
            assert placement["receipt_matches_owned_dropin"]
            assert not placement["authorizes_systemctl"] and not placement["authorizes_nginx_activation"]
            assert dropin.read_text() == rendered["dropin"]
            assert not os.path.lexists(profile_stage)
            assert hashlib.sha256(profile_receipt.read_bytes()).hexdigest() == placement["receipt_sha256"]
            print("PASS: signed drop-in receipt survived SIGKILL before no-replace publication; exact inode resumed", flush=True)
            require("/usr/bin/systemctl", "daemon-reload")
            assert run("/usr/bin/systemctl", "show", "-p", "DropInPaths", "--value", OWN).stdout.strip() == str(dropin)
            inactive_profile = signed("unit-inactive")
            assert inactive_profile["main_pid_observed"] == 0
            assert inactive_profile["signed_worker_unit_bytes_match"]
            assert inactive_profile["dropin_sha256"] == hashlib.sha256(dropin.read_bytes()).hexdigest()
            assert not inactive_profile["authorizes_systemctl"]
            origin_code = r"""
import json,ssl,sys
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
root=Path(sys.argv[1])
payloads=json.loads((root/"payloads").read_text())
class Origin(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        if self.path not in payloads:
            self.send_error(404); return
        data=payloads[self.path].encode("ascii")
        with (root/"hits").open("a") as stream: stream.write(self.path+"\n")
        self.send_response(200)
        self.send_header("Content-Length",str(len(data)))
        self.send_header("Cache-Control","public, max-age=60")
        self.end_headers()
        self.wfile.write(data)
server=ThreadingHTTPServer(("127.0.0.1",8008),Origin)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/etc/repocache/tls/example-chain.pem","/etc/repocache/tls/example-key.pem")
server.socket=context.wrap_socket(server.socket,server_side=True)
(root/"ready").write_text("ready")
server.serve_forever()
"""
            with tempfile.TemporaryDirectory(prefix="repocache-owned-namespace-", dir="/root") as place:
                work = Path(place)
                (work / "payloads").write_text(json.dumps(payloads))
                origin = subprocess.Popen(["/usr/sbin/ip", "netns", "exec", "repocache-nginx",
                                           "/usr/bin/python3", "-IS", "-B", "-c", origin_code, str(work)],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for _ in range(100):
                    assert origin.poll() is None
                    if (work / "ready").exists():
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("Private origin not ready")
                started = True
                result = run("/usr/bin/systemctl", "start", OWN)
                if result.returncode:
                    print("DEDICATED_FIXED_SERVICE_START_REFUSED:", result.stderr[-1000:], flush=True)
                    print(run("/usr/bin/journalctl", "-u", OWN, "-n", "20", "--no-pager").stdout[-2000:], flush=True)
                    raise AssertionError("Actual owned service dedicated transition refused")
                require_status(OWN, True, True)
                pid = int(require("/usr/bin/systemctl", "show", "-p", "MainPID", "--value", OWN).stdout)
                profile = signed("unit-active")
                assert profile["main_pid_observed"] == pid
                assert profile["private_unit_identity"] == inactive_profile["private_unit_identity"]
                assert profile["private_dropin_identity"] == inactive_profile["private_dropin_identity"]
                assert not profile["authorizes_nginx_activation"]
                proc = Path("/proc") / str(pid)
                assert (proc / "exe").stat().st_ino == saved_target.st_ino
                assert (proc / "ns/net").stat().st_ino == ns_identity[1]
                assert ":repocache_nginx_t:" in (proc / "attr/current").read_text()
                fields = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
                bound = isolated.MASTER_CAPS | (1 << 10)
                assert int(fields["CapEff"].strip(), 16) == int(fields["CapBnd"].strip(), 16) == bound
                assert fields["NoNewPrivs"].strip() == "1"
                assert int(fields["CapAmb"].strip(), 16) == 0
                verify_service_storage_mounts(pid)
                children = (proc / "task" / str(pid) / "children").read_text().split()
                observed_workers = 0
                for child in children:
                    entry = Path("/proc") / child
                    if not (entry / "cmdline").read_bytes().startswith(b"nginx: worker process"):
                        continue
                    fields = dict(line.split(":", 1) for line in
                                  (entry / "status").read_text().splitlines() if ":" in line)
                    assert set(fields["Uid"].split()) == {str(worker.pw_uid)}
                    assert set(fields["Gid"].split()) == {str(worker.pw_gid)}
                    assert int(fields["CapEff"].strip(), 16) == int(fields["CapPrm"].strip(), 16) == 0
                    assert fields["NoNewPrivs"].strip() == "1"
                    assert ":repocache_nginx_t:" in (entry / "attr/current").read_text()
                    assert (entry / "exe").stat().st_ino == saved_target.st_ino
                    assert (entry / "ns/net").stat().st_ino == ns_identity[1]
                    observed_workers += 1
                assert observed_workers
                readback = r"""
import json,sys,zipimport
sys.path.insert(0,"/usr/libexec/repocache/server-control-worker")
from repocache import server_native_egress_candidate_v1 as egress
assert isinstance(egress.__loader__,zipimport.zipimporter)
assert egress.__loader__.archive=="/usr/libexec/repocache/server-control-worker"
print(json.dumps(egress.inspect_fixed_namespace_egress(json.load(sys.stdin))))
"""
                observed = json.loads(isolated.command(
                    "/usr/bin/python3", "-IS", "-B", "-c", readback,
                    input_text=json.dumps(rules)).stdout)
                assert observed["ruleset_shape_matches"]
                assert (observed["namespace_device"], observed["namespace_inode"]) == ns_identity
                # Actual native client request inside the service-only namespace.
                # The isolated peer campaign already proves veth ingress.
                request_code = r"""
import sys
sys.path.insert(0,"/home/pr237ci/combined")
from scripts.ci_pr237_native_socket_guest import https_response
sys.stdout.buffer.write(https_response(sys.argv[1]))
"""
                for path, expected in payloads.items():
                    for status in (b"miss", b"hit"):
                        response = subprocess.run(
                            ["/usr/sbin/ip", "netns", "exec", "repocache-nginx", "/usr/bin/python3",
                             "-IS", "-B", "-c", request_code, "/__repocache/repos" + path],
                            capture_output=True, check=True, timeout=15).stdout
                        header, body = response.split(b"\r\n\r\n", 1)
                        assert header.startswith(b"HTTP/1.1 200 "), header.split(b"\r\n")[0]
                        assert b"x-repocache-smoke: " + status in header.lower()
                        assert body == expected.encode("ascii")
                assert sorted((work / "hits").read_text().splitlines()) == sorted(payloads)
                rows = [json.loads(line) for line in metrics.read_text().splitlines()]
                assert len(rows) == 2 * len(names)
                assert {row["upstream_cache_status"] for row in rows} == {"MISS", "HIT"}
                assert {row["repocache_repository"] for row in rows} == {
                    "/__repocache/repos/" + name + "/" for name in names}
                for name in names:
                    entries = [p for p in (cache / name).rglob("*") if p.is_file()]
                    assert entries and all(p.stat().st_uid == worker.pw_uid for p in entries)
                    assert all(b":repocache_nginx_rw_t:" in os.getxattr(p, "security.selinux") for p in entries)
                assert signed("verify") == report == signed("create")
                assert signed("unit-active") == profile
                assert signed("unit-verify-placement") == placement
                print("PASS: authenticated exact persistent drop-in and fixed PID1/master identity, inactive/active/repeat observation", flush=True)
                assert isolated.command("/usr/sbin/nft", "--stateless", "--numeric-priority",
                                        "list", "ruleset").stdout == host_rules
                print("PASS: actual owned systemd unit using signed dedicated executable, private netns, "
                      "fixed labelled cache and metrics; exact TLS MISS/HIT, preserved vendor resources", flush=True)
        finally:
            # Never restore legacy labels/bytes under a running candidate.
            if started:
                require("/usr/bin/systemctl", "stop", OWN)
            if origin is not None:
                origin.terminate()
                origin.wait(timeout=15)
            if placement_attempted and not unit_placed:
                # Unknown or partial test placement must never be removed
                # or followed by a legacy restart. Preserve VM evidence.
                raise AssertionError("Incomplete owned profile placement retained")
            if unit_placed:
                assert signed("unit-verify-placement") == placement
                assert dropin.read_text() == rendered["dropin"]
                assert hashlib.sha256(profile_receipt.read_bytes()).hexdigest() == placement["receipt_sha256"]
                # Only the exact fixture-owned profile and private receipt
                # are removed, with the test service stopped. No installed
                # cleanup or arbitrary removal operation is introduced.
                dropin.unlink()
                dropdir.rmdir()
                sync_dir(dropdir.parent)
                profile_receipt.unlink()
                sync_dir(STATE)
                require("/usr/bin/systemctl", "daemon-reload")
            if namespace:
                assert (ns.stat().st_dev, ns.stat().st_ino) == ns_identity
                require("/usr/sbin/ip", "netns", "delete", "repocache-nginx")
            if include_changed:
                replace_include(saved_include)
            for path, fd, identity, label in reversed(labels):
                assert (path.lstat().st_dev, path.lstat().st_ino) == identity
                if os.getxattr(fd, "security.selinux") != label:
                    os.setxattr(fd, "security.selinux", label)
                assert os.getxattr(fd, "security.selinux") == label
            if created_storage:
                # Preserve all dedicated data and ownership evidence rather
                # than deleting it or adopting it into the legacy profile.
                generated = set(fixed)
                for name in names:
                    marker = cache.parent / (".repocache-repository-" + name + ".owner-v1")
                    generated.update((marker, marker.with_name(marker.name + ".stage")))
                generated.add(log.parent / ".repocache-metrics-log.owner-v1")
                for path in sorted(generated):
                    if os.path.lexists(path):
                        rename_absent(path, path.with_name(".ci-dedicated-" + path.name))
            for path, backup, identity in reversed(moved):
                assert (backup.lstat().st_dev, backup.lstat().st_ino) == identity
                rename_absent(backup, path)
            if legacy_stopped and runtime.exists():
                # No foreign object is removed; an unclean runtime fails.
                assert not list(runtime.iterdir())
                runtime.rmdir()
            if legacy_stopped:
                status = run("/usr/bin/systemctl", "is-failed", OWN)
                if status.returncode == 0:
                    require("/usr/bin/systemctl", "reset-failed", OWN)
                require("/usr/bin/systemctl", "start", OWN)
    require_status(OWN, True, True)
    require_status(VENDOR, False, False)
    assert live_wal_resource_hashes() == before
    assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    assert isolated.command("/usr/sbin/getsebool", "-a").stdout == booleans
    assert isolated.command("/usr/sbin/nft", "--stateless", "--numeric-priority", "list", "ruleset").stdout == host_rules
    assert isolated.VENDOR.stat().st_ino == vendor_before.st_ino
    assert native.stage.verify_installed_worker(assets, **pins) == release
    print("PASS: exact previous installed service, owned generation and storage roots restored", flush=True)
    print("NOT VERIFIED: durable installed dedicated transition, boot activation of that profile, "
          "WAL-driven active publication and authoritative upstream routes; legacy httpd_t upstream remains unsupported", flush=True)


def signed_namespace_unit_candidate():
    """Render from the actual installed authenticated worker, without writing."""
    code = r"""
import json,sys,zipimport
sys.path.insert(0, "/usr/libexec/repocache/server-control-worker")
from repocache import server_native_nginx_effective_unit_v1 as unit
assert isinstance(unit.__loader__, zipimport.zipimporter)
assert unit.__loader__.archive == "/usr/libexec/repocache/server-control-worker"
report=unit.render_owned_nginx_namespace_unit_candidate(https_port=8008)
raw=report.pop("unit_bytes")
assert raw.count(b"/usr/libexec/repocache/nginx ") == 4
assert b"NetworkNamespacePath=/run/netns/repocache-nginx\n" in raw
assert b"CapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETGID CAP_SETUID\n" in raw
assert not report["authorizes_nginx_activation"] and not report["authorizes_systemctl"]
assert not report["runtime_namespace_verified"] and not report["runtime_selinux_verified"]
print(json.dumps(report))
"""
    return json.loads(subprocess.run(
        ["/usr/bin/python3", "-IS", "-B", "-c", code], check=True,
        capture_output=True, text=True, timeout=30).stdout)


def verify_fixed_executable_candidate(native, assets, pins, distribution):
    """Exercise the actual fixed installer candidate in the guarded VM."""
    import stat
    assert __debug__ and os.getresuid() == os.getresgid() == (0, 0, 0)
    assert socket.gethostname() == "pr237-" + {"debian": "debian13", "almalinux": "almalinux10"}[distribution]
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert run("/usr/bin/systemd-detect-virt", "--vm").returncode == 0
    assert run("/usr/bin/systemd-detect-virt", "--container").returncode != 0
    assert native._native_distro() == distribution
    assert ROOT.is_dir() and not ROOT.is_symlink() and ROOT.stat().st_uid == 0
    if distribution == "almalinux":
        assert run("/usr/sbin/getenforce").stdout.strip() == "Enforcing"
    release = native.stage.verify_installed_worker(assets, **pins)
    assert release["publisher_key_id"] == "pr237-synthetic"
    target = Path("/usr/libexec/repocache/nginx")
    marker = target.with_name(".native-nginx-executable-v1.json")
    vendor = Path("/usr/sbin/nginx")
    assert not os.path.lexists(target) and not os.path.lexists(marker)
    before = vendor.lstat()
    label = (os.getxattr(vendor, "security.selinux") if distribution == "almalinux" else None)
    policy = None
    if distribution == "almalinux":
        from scripts import ci_selinux_nginx_egress_guest as isolated
        policy = isolated.load_fixed_candidate_policy()
    result = native._stage_authenticated_native_executable_candidate(
        assets, **pins, dedicated_selinux=policy is not None)
    if policy is not None:
        assert result["dedicated_executable_label_observed"]
        assert result["dedicated_policy_sha256"] == policy["policy_sha256"]
        assert os.getxattr(target, "security.selinux").rstrip(b"\0") == policy["executable_context"].encode("ascii")
    else:
        assert not result["dedicated_executable_label_observed"]
        assert result["dedicated_policy_sha256"] is None
    assert not result["runtime_selinux_policy_verified"]
    assert result["status"] == "NGINX_EXECUTABLE_CANDIDATE_STAGED"
    assert result["native_payload_authenticated_by_installer"]
    assert not result["authorizes_nginx_activation"]
    assert not result["service_enabled"] and not result["service_active"]
    info = target.lstat()
    assert stat.S_IMODE(info.st_mode) == 0o755 and info.st_uid == info.st_gid == 0
    assert (info.st_dev, info.st_ino) == (result["device"], result["inode"])
    assert (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == result["sha256"]
    assert hashlib.sha256(marker.read_bytes()).hexdigest() == result["receipt_sha256"]
    fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    assert all(getattr(before, k) == getattr(vendor.lstat(), k) for k in fields)
    if label is not None:
        assert os.getxattr(vendor, "security.selinux") == label
    unit_candidate = signed_namespace_unit_candidate()
    assert unit_candidate["source_unit_sha256"] == release["files"][OWN]
    assert hashlib.sha256(Path("/etc/systemd/system", OWN).read_bytes()).hexdigest() == unit_candidate["source_unit_sha256"]
    result["namespace_unit_candidate"] = unit_candidate
    print("PASS: authenticated installed worker derives fixed namespace unit candidate; signed unit unchanged", flush=True)
    # Preserve separate fixture-only evidence across the real reboot.
    record = ROOT / "native-executable-candidate-proof.json"
    with record.open("x") as out:
        os.fchmod(out.fileno(), 0o600)
        json.dump(result, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())
    print("PASS: authenticated fixed native executable installed but not activated; "
          "exact package and release receipt, repeated staging, vendor preserved", flush=True)
    if policy is not None:
        # Replace the prior private-copy root-master experiment with its
        # exact installed-executable counterpart. Only private fixture
        # config/storage and a runtime-only service are used; the installed
        # signed unit remains inactive and untouched.
        subprocess.run(
            ["/usr/bin/python3", "-B", str(SOURCE / "scripts/ci_selinux_nginx_egress_guest.py"),
             "--fixed-candidate"], check=True, timeout=600)
        assert hashlib.sha256(marker.read_bytes()).hexdigest() == result["receipt_sha256"]
        require_status(OWN, False, False)
        require_status(VENDOR, False, False)
        assert native.stage.verify_installed_worker(assets, **pins) == release


def verify_fixed_executable_after_reboot(pins):
    """Read the exact unchanged receipt and candidate from the installed archive."""
    expected = json.loads((ROOT / "native-executable-candidate-proof.json").read_text("ascii"))
    code = """
import hashlib,json,os,sys,zipimport
sys.path.insert(0, "/usr/libexec/repocache/server-control-worker")
from repocache import server_native_nginx_executable_v1 as candidate
assert isinstance(candidate.__loader__, zipimport.zipimporter)
assert candidate.__loader__.archive == "/usr/libexec/repocache/server-control-worker"
report,pins=json.load(sys.stdin)
directory=os.open("/usr/libexec/repocache",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    raw=candidate._read_executable_receipt(directory)
    assert hashlib.sha256(raw).hexdigest() == report["receipt_sha256"]
    record=json.loads(raw)
    assert record["release_source_sha"] == pins["commit"]
    assert record["release_archive_sha256"] == pins["archive_sha256"]
    dedicated=report["dedicated_policy_sha256"] is not None
    if dedicated:
        policy=candidate.signed_owned_nginx_policy_candidate()
        assert record["dedicated_policy_sha256"] == policy["policy_sha256"] == report["dedicated_policy_sha256"]
        assert record["executable_context"] == policy["executable_context"]
    else:
        assert "dedicated_policy_sha256" not in record and "executable_context" not in record
    observed=candidate._verify_leaf(directory,record["executable_sha256"],dedicated_selinux=dedicated)
    assert observed[:2] == (record["device"],record["inode"])
    assert observed[6:] == (record["size"],record["mtime_ns"],record["ctime_ns"])
    assert candidate._named(directory,candidate._PENDING) is None
    assert record["authorizes_nginx_activation"] is False
finally:
    os.close(directory)
"""
    subprocess.run(["/usr/bin/python3", "-IS", "-B", "-c", code],
                   input=json.dumps([expected,pins]),text=True,check=True,timeout=30)
    if expected["dedicated_policy_sha256"] is not None:
        assert run("/usr/sbin/getenforce").stdout.strip() == "Enforcing"
        modules = run("/usr/sbin/semodule", "-l").stdout.splitlines()
        assert "repocache_nginx" in {line.split()[0] for line in modules if line}
        print("PASS: dedicated executable label and signed policy identity retained across reboot", flush=True)
    assert signed_namespace_unit_candidate() == expected["namespace_unit_candidate"]
    print("PASS: exact fixed executable and authenticated release receipt survive real reboot; no activation authority", flush=True)
    print("PASS: authenticated namespace unit candidate digest is unchanged after reboot", flush=True)


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
        verify_fixed_executable_candidate(native, assets, pins, distribution)
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
        verify_fixed_executable_after_reboot(pins)
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
        if distribution == "almalinux":
            verify_owned_service_namespace_data_fixture(native, assets, pins)
        else:
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
