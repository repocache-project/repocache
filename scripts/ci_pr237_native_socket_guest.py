#!/usr/bin/env python3
"""PR237-only native systemd socket + TLS v2 lifecycle in disposable QEMU guests.

All source signatures, local TLS and trust anchors are synthetic. There is no
publisher acceptance, production credential, or deployed-server assertion.
Use the real installed zipapp worker via kernel-credentialed systemd socket.
"""
from __future__ import annotations

import base64
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import ssl
import stat
import subprocess
import sys
import time

FIXTURE = Path("/root/pr237-synthetic-fixture")
STATE = Path("/var/lib/repocache/server")
SOCKET = Path("/run/repocache/server-control.sock")
SOURCE = Path("/home/pr237ci/combined")


def command(*argv: str, timeout: int = 30) -> str:
    result = subprocess.run(
        argv, check=False, capture_output=True, text=True,
        stdin=subprocess.DEVNULL, timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode:
        raise AssertionError(
            "Guest command failed: " + argv[0] + " " + " ".join(argv[1:3])
            + " (exit " + str(result.returncode) + ")"
        )
    return result.stdout.strip()


def assert_disabled(unit: str) -> None:
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-enabled", unit], capture_output=True,
        text=True, check=False, timeout=15,
    )
    assert result.returncode == 1 and result.stdout.strip() == "disabled", (
        "Unexpected enabled state for " + unit
    )


def assert_static_socket() -> None:
    # The signed socket reference has deliberately no [Install] section.
    # systemd reports "static", NOT "disabled", for a valid non-enableable
    # socket. Preserve the precise state rather than loosening this check.
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-enabled", "repocache-control.socket"],
        capture_output=True, text=True, check=False, timeout=15,
    )
    assert result.returncode == 0 and result.stdout.strip() == "static", (
        "Unexpected boot activation state for fixed root socket"
    )


def accounts() -> None:
    if "repocache-admin" not in [g.gr_name for g in grp.getgrall()]:
        command("/usr/sbin/groupadd", "--system", "repocache-admin")
    if "repocache" not in [g.gr_name for g in grp.getgrall()]:
        command("/usr/sbin/groupadd", "--system", "repocache")
    try:
        pwd.getpwnam("repocache")
    except KeyError:
        command(
            "/usr/sbin/useradd", "--system", "--no-create-home",
            "--gid", "repocache", "--shell", "/usr/sbin/nologin", "repocache",
        )
    assert grp.getgrnam("repocache-admin").gr_gid != 0
    assert pwd.getpwnam("repocache").pw_uid != 0


def synthetic_local_tls(distribution: str) -> tuple[Path, Path]:
    """Make a short-lived private CA, trusted by this discarded guest only."""
    directory = Path("/etc/repocache/tls")
    directory.mkdir(mode=0o755, exist_ok=False)
    cert = directory / "example-chain.pem"
    key = directory / "example-key.pem"
    ca_key = FIXTURE / "pr237-tls-ca-key.pem"
    ca = FIXTURE / "pr237-tls-ca.crt"
    csr = FIXTURE / "pr237-tls-leaf.csr"
    ext = FIXTURE / "pr237-tls-leaf.ext"
    command("/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(ca_key))
    command(
        "/usr/bin/openssl", "req", "-x509", "-new", "-sha256",
        "-key", str(ca_key), "-out", str(ca), "-days", "2",
        "-subj", "/CN=PR237 disposable test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    command("/usr/bin/openssl", "genpkey", "-algorithm", "EC",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", str(key))
    command("/usr/bin/openssl", "req", "-new", "-sha256", "-key", str(key),
            "-out", str(csr), "-subj", "/CN=cache.example.invalid")
    ext.write_text(
        "subjectAltName=DNS:cache.example.invalid\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n", encoding="ascii",
    )
    command(
        "/usr/bin/openssl", "x509", "-req", "-sha256", "-in", str(csr),
        "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(cert), "-days", "2", "-extfile", str(ext),
    )
    key.chmod(0o600)
    cert.chmod(0o644)
    ca_key.unlink()
    csr.unlink()
    ext.unlink()
    if distribution == "debian":
        dest = Path("/usr/local/share/ca-certificates/pr237-disposable.crt")
        dest.write_bytes(ca.read_bytes())
        dest.chmod(0o644)
        command("/usr/sbin/update-ca-certificates", timeout=60)
    else:
        dest = Path("/etc/pki/ca-trust/source/anchors/pr237-disposable.crt")
        dest.write_bytes(ca.read_bytes())
        dest.chmod(0o644)
        command("/usr/bin/update-ca-trust", "extract", timeout=60)
        command("/usr/sbin/restorecon", "-R", str(directory))
    assert (stat.S_IMODE(key.stat().st_mode), key.stat().st_uid) == (0o600, 0)
    assert (stat.S_IMODE(cert.stat().st_mode), cert.stat().st_uid) == (0o644, 0)
    return cert, key


def https_response(path: str) -> bytes:
    context = ssl.create_default_context()
    with socket.create_connection(("127.0.0.1", 443), timeout=5) as channel:
        with context.wrap_socket(channel, server_hostname="cache.example.invalid") as tls:
            tls.settimeout(5)
            tls.sendall(
                ("GET " + path + " HTTP/1.1\r\nHost: cache.example.invalid\r\n"
                 "Connection: close\r\n\r\n").encode("ascii")
            )
            parts = []
            size = 0
            while True:
                data = tls.recv(8192)
                if not data:
                    break
                size += len(data)
                assert size <= 1024 * 1024
                parts.append(data)
    return b"".join(parts)


def snapshot() -> dict[str, tuple[str, int, int]]:
    paths = [
        STATE / "state-v2.json",
        STATE / ".state-v2-native.manifest",
        Path("/etc/nginx/conf.d/repocache-managed.conf"),
        Path("/var/lib/repocache/public/catalog.json"),
    ]
    result = {}
    for path in paths:
        info = path.stat()
        result[str(path)] = (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            info.st_ino,
            info.st_mtime_ns,
        )
    return result



def assert_native_socket_refuses_arbitrary_unit() -> None:
    """Exercise actual installed root dispatch, bypassing the safe client allowlist.

    A valid fixed-command prefix plus a caller-selected unit must be rejected
    as one whole SOCK_SEQPACKET message, without performing a reload.
    """
    packet = b"reload-v2\nunit=sshd.service\n"
    assert len(packet) <= 32
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
        conn.settimeout(8)
        conn.connect(str(SOCKET))
        assert conn.send(packet) == len(packet)
        try:
            reply = conn.recv(1025)
        except ConnectionResetError:
            reply = b""
        assert reply == b"", "Installed root broker accepted a caller-selected unit"


def main(distribution: str) -> None:
    assert distribution in ("debian", "almalinux")
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert command("/usr/bin/systemd-detect-virt", "--vm") in ("qemu", "kvm")
    if distribution == "almalinux":
        assert command("/usr/sbin/getenforce") == "Enforcing"
    assert not SOCKET.exists()
    assert (STATE / ".admin-candidate-v2.json").is_file()
    assert not (STATE / "state-v2.json").exists()
    assert not (STATE / ".state-v2-native.pending").exists()
    sys.path[:0] = [str(SOURCE / "src"), str(SOURCE)]
    from repocache.server_native_root_control_client_v1 import (
        NativeRootControlClientError, request_native_fixed_v2,
    )

    def authenticated_native_operation(operation: str) -> dict:
        # Each request starts the one-shot installed worker. Preserve its
        # vendor systemd StartLimitBurst rather than weakening rate limits.
        time.sleep(3)
        try:
            return request_native_fixed_v2(operation)
        except NativeRootControlClientError:
            # The client intentionally reports UNKNOWN after send. Inspect
            # only bounded, fixed systemd properties and redacted error
            # classes from this disposed guest. Never dump key material,
            # NGINX -T, arbitrary journal text, or private state.
            status = subprocess.run(
                [
                    "/usr/bin/systemctl", "show", "repocache-control.service",
                    "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
                    "-p", "Result", "-p", "ExecMainStatus",
                    "-p", "ExecMainCode", "-p", "UnitFileState",
                ],
                capture_output=True, text=True, timeout=12, check=False,
            )
            if status.returncode == 0:
                for line in status.stdout.splitlines():
                    if re.fullmatch(
                        r"(?:LoadState|ActiveState|SubState|Result|ExecMainStatus|ExecMainCode|UnitFileState)=[A-Za-z0-9_.-]{1,50}",
                        line,
                    ):
                        print("NATIVE_SOCKET_DIAGNOSTIC: " + line, flush=True)
            # The installed signed reference lists precisely these five
            # ReadWritePaths. A missing target yields systemd 226/NAMESPACE;
            # observe by fixed labels without creating, remounting or
            # broadening any protected directory.
            for label, fixed in (
                ("NGINX_CONF", "/etc/nginx/conf.d"),
                ("PROTECTED_STATE", "/var/lib/repocache/server"),
                ("PUBLIC_CATALOG", "/var/lib/repocache/public"),
                ("NGINX_LOG", "/var/log/nginx"),
                ("NGINX_CACHE", "/var/cache/nginx"),
            ):
                try:
                    observed = os.lstat(fixed)
                except FileNotFoundError:
                    print("NATIVE_SOCKET_DIAGNOSTIC: MISSING_" + label, flush=True)
                except OSError:
                    print("NATIVE_SOCKET_DIAGNOSTIC: UNREADABLE_" + label, flush=True)
                else:
                    if not stat.S_ISDIR(observed.st_mode):
                        print("NATIVE_SOCKET_DIAGNOSTIC: NOT_DIRECTORY_" + label, flush=True)
                    elif observed.st_uid != 0 or observed.st_mode & 0o022:
                        print("NATIVE_SOCKET_DIAGNOSTIC: UNSAFE_OWNER_MODE_" + label, flush=True)
                    else:
                        print("NATIVE_SOCKET_DIAGNOSTIC: PRESENT_" + label, flush=True)
            logs = subprocess.run(
                [
                    "/usr/bin/journalctl", "-u", "repocache-control.service",
                    "--no-pager", "--quiet", "-n", "50", "-o", "cat",
                ],
                capture_output=True, text=True, timeout=12, check=False,
            )
            for line in logs.stdout.splitlines()[-50:]:
                for code in re.findall(
                    r"(?:NATIVE_ROOT_CONTROL|ROOT_CONTROL|NATIVE_HOST|FIXED_REQUEST)_[A-Z0-9_]{2,100}",
                    line,
                ):
                    print("NATIVE_SOCKET_DIAGNOSTIC: " + code, flush=True)
                for error_class in (
                    "ModuleNotFoundError", "ImportError", "PermissionError",
                    "FileNotFoundError", "OSError", "AttributeError",
                    "SyntaxError", "ValueError", "TypeError",
                ):
                    if error_class + ":" in line:
                        print(
                            "NATIVE_SOCKET_DIAGNOSTIC: exception="
                            + error_class, flush=True,
                        )
                if "Failed at step EXEC" in line:
                    print("NATIVE_SOCKET_DIAGNOSTIC: SYSTEMD_EXEC_FAILED", flush=True)
                if ("Failed to set up mount namespacing" in line
                        or "Failed at step NAMESPACE" in line):
                    print("NATIVE_SOCKET_DIAGNOSTIC: SYSTEMD_NAMESPACE_FAILED", flush=True)
                if "No such file or directory" in line:
                    print("NATIVE_SOCKET_DIAGNOSTIC: SYSTEMD_MISSING_PATH", flush=True)
                if "Permission denied" in line:
                    print("NATIVE_SOCKET_DIAGNOSTIC: SYSTEMD_PERMISSION_REFUSED", flush=True)
            raise

    accounts()
    certificate, private_key = synthetic_local_tls(distribution)
    saved_tls = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (certificate, private_key)
    }
    command("/usr/bin/systemctl", "daemon-reload")
    command("/usr/bin/systemctl", "start", "nginx.service", timeout=35)
    assert command("/usr/bin/systemctl", "is-active", "nginx.service") == "active"
    command("/usr/bin/systemctl", "start", "repocache-control.socket")
    info = SOCKET.lstat()
    assert stat.S_ISSOCK(info.st_mode)
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
        0, grp.getgrnam("repocache-admin").gr_gid, 0o660,
    )
    assert command("/usr/bin/systemctl", "is-active", "repocache-control.socket") == "active"
    assert_static_socket()
    print("PASS: native installed systemd AF_UNIX seqpacket socket with root/admin ownership and static non-enableable boot state", flush=True)

    # The same protected socket must refuse its own unprivileged service UID
    # at the kernel permission boundary (not through a mocked peer id).
    service = pwd.getpwnam("repocache")
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(service.pw_gid)
            os.setuid(service.pw_uid)
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as untrusted:
                untrusted.settimeout(3)
                untrusted.connect(str(SOCKET))
        except PermissionError:
            os._exit(0)
        except OSError:
            os._exit(2)
        os._exit(3)
    _, denial_status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(denial_status) == 0
    print("PASS: kernel denied unprivileged REPOCACHE service identity at fixed admin socket", flush=True)

    # Refuse ordinary service-UID reads of the actual root-owned native TLS
    # private key. Real kernel permission check, not stat-only or mock ACL.
    key_reader = os.fork()
    if key_reader == 0:
        try:
            os.setgroups([])
            os.setgid(service.pw_gid)
            os.setuid(service.pw_uid)
            fd = os.open(private_key, os.O_RDONLY | os.O_NOFOLLOW)
        except PermissionError:
            os._exit(0)
        except OSError:
            os._exit(2)
        else:
            os.close(fd)
            os._exit(3)
    _, key_status = os.waitpid(key_reader, 0)
    assert os.waitstatus_to_exitcode(key_status) == 0
    assert (stat.S_IMODE(private_key.stat().st_mode), private_key.stat().st_uid) == (0o600, 0)
    print("PASS: native kernel denied unprivileged REPOCACHE service UID access to root-owned TLS private key", flush=True)

    clean = authenticated_native_operation("RECOVER_V2")
    assert clean["status"] == "CLEAN" and clean["transaction_completed"] is True
    assert not (STATE / "state-v2.json").exists()
    print("PASS: installed root zipapp served actual kernel-credentialed RECOVER_V2/CLEAN", flush=True)

    applied = authenticated_native_operation("APPLY_V2")
    assert applied["status"] == "APPLIED", applied
    assert applied["state_generation"] == 1
    assert applied["active_catalog_published"] is True
    assert applied["nginx_reload_and_exposure_observed"] is True
    assert not (STATE / ".state-v2-native.pending").exists()
    assert not (STATE / ".state-v2-native.pending-tmp").exists()
    before = snapshot()
    assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    catalog_raw = Path("/var/lib/repocache/public/catalog.json").read_bytes()
    assert https_response("/.well-known/repocache/catalog.json").endswith(catalog_raw)
    print("PASS: native installed worker APPLY_V2 committed durable generation 1, reloaded nginx and exposed TLS/catalog", flush=True)

    reloaded = authenticated_native_operation("RELOAD_V2")
    assert (reloaded["status"], reloaded["state_generation"]) == ("RELOADED", 1)
    assert snapshot() == before
    unchanged = authenticated_native_operation("APPLY_V2")
    assert (unchanged["status"], unchanged["state_generation"]) == ("UNCHANGED", 1)
    assert snapshot() == before
    clean_again = authenticated_native_operation("RECOVER_V2")
    assert clean_again["status"] == "CLEAN"
    assert snapshot() == before
    # Send a malicious raw packet to the ACTUAL installed systemd service.
    # The public client already rejects unknown operations locally; this
    # independently proves the privileged server's exact-message boundary.
    assert_native_socket_refuses_arbitrary_unit()
    assert snapshot() == before
    assert not (STATE / ".state-v2-native.pending").exists()
    assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    assert (authenticated_native_operation("RELOAD_V2")["status"] == "RELOADED")
    assert snapshot() == before
    print("PASS: installed root socket rejected injected unit selection, kept live generation and recovered normal reload", flush=True)
    for path in (certificate, private_key):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == saved_tls[str(path)]
    if distribution == "almalinux":
        assert command("/usr/sbin/getenforce") == "Enforcing"
    print("PASS: real native RELOAD_V2, idempotent APPLY_V2 and RECOVER_V2/CLEAN preserve managed bytes and TLS", flush=True)

    # Prepare a genuine generation-two partial repair on the already live
    # v0.6 deployment. The operator proposal is synthetic but staged via
    # the signed-fixture authenticated installer, not a direct state writer.
    from scripts import install_native_root_worker
    pins = json.loads((FIXTURE / "pins.json").read_bytes())
    assert set(pins) == {"commit", "archive_sha256"}
    assets = FIXTURE / "assets"
    prior_state = (STATE / "state-v2.json").read_bytes()
    prior_digest = hashlib.sha256(prior_state).hexdigest()
    prior = json.loads(prior_state)
    assert prior["state_generation"] == 1
    repair_document = json.loads(
        base64.b64decode(prior["configuration_base64"], validate=True)
    )
    assert repair_document["expected_state_generation"] == 1
    assert repair_document["deployment"]["logging"]["retention_days"] == 7
    repair_document["deployment"]["logging"]["retention_days"] = 8
    previous_file = FIXTURE / "pr237-previous-state-v2.json"
    repair_file = FIXTURE / "pr237-reviewed-repair.json"
    proposal_file = FIXTURE / "pr237-repair-proposal-v2.json"
    assert not any(x.exists() for x in (previous_file, repair_file, proposal_file))
    for path, raw in (
        (previous_file, prior_state),
        (repair_file, (json.dumps(repair_document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")),
    ):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())

    # Nonempty synthetic test assets in real cache/log/metrics directories:
    # a directory existing alone is not preservation evidence.
    preserved = {}
    for name, path in (
        ("cache", Path("/var/cache/nginx/repocache-managed/pr237-cache-record")),
        ("logs", Path("/var/log/nginx/repocache-managed/pr237-log-record")),
        ("metrics", Path("/var/lib/repocache/metrics/pr237-metrics-record")),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = ("PR237 private synthetic preservation marker: " + name + "\n").encode("ascii")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        st = path.stat()
        preserved[name] = (path, hashlib.sha256(raw).hexdigest(), st.st_ino, st.st_mtime_ns)
    prepared = install_native_root_worker.prepare_authenticated_proposal(
        assets, repair_file, proposal_file,
        previous=previous_file, previous_sha256=prior_digest,
        decision_sha256="e" * 64, **pins,
    )
    assert prepared["status"] == "AUTHENTICATED_V2_PROPOSAL_PREPARED"
    assert prepared["state_generation"] == 2
    assert prepared["requires_operator_review"] is True
    assert prepared["authorizes_service_activation"] is False
    repair_proposal_digest = hashlib.sha256(proposal_file.read_bytes()).hexdigest()
    staged = install_native_root_worker.stage_authenticated_proposal(
        assets, proposal_file, proposal_sha256=repair_proposal_digest,
        expected_state_sha256=prior_digest, **pins,
    )
    assert staged["status"] == "AUTHENTICATED_V2_PROPOSAL_STAGED"
    assert staged["expected_generation"] == 1
    assert snapshot() == before
    print("PASS: authenticated generation-two repair staged without premature service changes", flush=True)

    repaired = authenticated_native_operation("APPLY_V2")
    assert (repaired["status"], repaired["state_generation"]) == ("APPLIED", 2)
    after_repair = snapshot()
    assert after_repair != before
    assert json.loads((STATE / "state-v2.json").read_bytes())["state_generation"] == 2
    assert b"x-repocache-generation: 2" in https_response("/__repocache/healthz").lower()
    assert https_response("/.well-known/repocache/catalog.json").endswith(
        Path("/var/lib/repocache/public/catalog.json").read_bytes()
    )
    for name, (path, digest, inode, mtime) in preserved.items():
        info = path.stat()
        assert (hashlib.sha256(path.read_bytes()).hexdigest(), info.st_ino, info.st_mtime_ns) == (
            digest, inode, mtime
        ), name
    for path in (certificate, private_key):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == saved_tls[str(path)]
    unchanged_repair = authenticated_native_operation("APPLY_V2")
    assert (unchanged_repair["status"], unchanged_repair["state_generation"]) == ("UNCHANGED", 2)
    reloaded_repair = authenticated_native_operation("RELOAD_V2")
    assert (reloaded_repair["status"], reloaded_repair["state_generation"]) == ("RELOADED", 2)
    assert snapshot() == after_repair
    assert authenticated_native_operation("RECOVER_V2")["status"] == "CLEAN"
    assert snapshot() == after_repair
    print("PASS: native worker applied partial same-version v0.6 generation-two repair, preserving nonempty TLS/cache/log/metrics data", flush=True)

    # Stage a second partial repair and force an ACTUAL post-WAL nginx -t
    # failure on the installed worker. The invalid include is foreign and
    # deliberately remains until the first compensation attempt. This must
    # retain the durable WAL for a separate real RECOVER_V2, never certify
    # the partial candidate as a completed generation.
    prior_repair_state = (STATE / "state-v2.json").read_bytes()
    prior_repair_sha = hashlib.sha256(prior_repair_state).hexdigest()
    repair3_document = json.loads(
        base64.b64decode(
            json.loads(prior_repair_state)["configuration_base64"], validate=True
        )
    )
    assert repair3_document["expected_state_generation"] == 2
    assert repair3_document["deployment"]["logging"]["retention_days"] == 8
    repair3_document["deployment"]["logging"]["retention_days"] = 9
    previous3 = FIXTURE / "pr237-previous-state-gen2.json"
    repair3 = FIXTURE / "pr237-reviewed-repair-gen3.json"
    proposal3 = FIXTURE / "pr237-repair-proposal-gen3.json"
    assert not any(path.exists() for path in (previous3, repair3, proposal3))
    for path, raw in (
        (previous3, prior_repair_state),
        (repair3, (json.dumps(repair3_document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")),
    ):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    prep3 = install_native_root_worker.prepare_authenticated_proposal(
        assets, repair3, proposal3,
        previous=previous3, previous_sha256=prior_repair_sha,
        decision_sha256="f" * 64, **pins,
    )
    assert prep3["status"] == "AUTHENTICATED_V2_PROPOSAL_PREPARED"
    assert prep3["state_generation"] == 3
    stage3 = install_native_root_worker.stage_authenticated_proposal(
        assets, proposal3, proposal_sha256=hashlib.sha256(proposal3.read_bytes()).hexdigest(),
        expected_state_sha256=prior_repair_sha, **pins,
    )
    assert stage3["expected_generation"] == 2
    assert snapshot() == after_repair

    from repocache.server_native_root_control_client_v1 import NativeRootControlClientError
    invalid = Path("/etc/nginx/conf.d/pr237-disposable-invalid.conf")
    assert not invalid.exists()
    fd = os.open(invalid, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    failed_wal = STATE / ".state-v2-native.pending"
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(b"unknown_pr237_nginx_directive on;\n")
            output.flush()
            os.fsync(output.fileno())
        try:
            authenticated_native_operation("APPLY_V2")
        except NativeRootControlClientError as error:
            assert str(error) == "NATIVE_ROOT_CLIENT_OPERATION_REFUSED"
        else:
            raise AssertionError("Broken NGINX syntax unexpectedly activated generation three")
        assert failed_wal.is_file(), "Post-WAL syntax failure must retain recoverable journal"
        assert stat.S_IMODE(failed_wal.stat().st_mode) == 0o600
        assert b"x-repocache-generation: 2" in https_response("/__repocache/healthz").lower()
        assert hashlib.sha256(
            Path("/var/lib/repocache/public/catalog.json").read_bytes()
        ).hexdigest() == after_repair["/var/lib/repocache/public/catalog.json"][0]
    finally:
        invalid.unlink()
    print("PASS: real post-WAL nginx syntax failure refused installed APPLY_V2 and retained durable recovery journal", flush=True)

    restored = authenticated_native_operation("RECOVER_V2")
    assert restored["status"] == "RECOVERED" and restored["transaction_completed"] is True
    assert not failed_wal.exists()
    assert not (STATE / ".state-v2-native.pending-tmp").exists()
    assert json.loads((STATE / "state-v2.json").read_bytes())["state_generation"] == 2
    assert b"x-repocache-generation: 2" in https_response("/__repocache/healthz").lower()
    assert https_response("/.well-known/repocache/catalog.json").endswith(
        Path("/var/lib/repocache/public/catalog.json").read_bytes()
    )
    after_recovery = snapshot()
    for path, (digest, _inode, _mtime) in after_repair.items():
        assert after_recovery[path][0] == digest
    for name, (path, digest, inode, mtime) in preserved.items():
        st = path.stat()
        assert (hashlib.sha256(path.read_bytes()).hexdigest(), st.st_ino, st.st_mtime_ns) == (
            digest, inode, mtime
        ), name
    assert authenticated_native_operation("RECOVER_V2")["status"] == "CLEAN"
    assert snapshot() == after_recovery
    assert authenticated_native_operation("RELOAD_V2")["status"] == "RELOADED"
    assert snapshot() == after_recovery
    for path in (certificate, private_key):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == saved_tls[str(path)]
    if distribution == "almalinux":
        assert command("/usr/sbin/getenforce") == "Enforcing"
    print("PASS: real installed RECOVER_V2 restored prior live generation and preserved TLS/cache/log/metrics; repeat recovery clean", flush=True)
    command("/usr/bin/systemctl", "stop", "repocache-control.socket")
    command("/usr/bin/systemctl", "stop", "nginx.service")
    assert_static_socket()
    assert_disabled("nginx.service")
    print("PASS: guest native services stopped; no socket/nginx autostart enabled; synthetic trust only", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("debian", "almalinux"):
        raise SystemExit("Usage: ci_pr237_native_socket_guest.py debian|almalinux")
    main(sys.argv[1])
