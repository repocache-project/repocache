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



def unmanaged_nginx_snapshot() -> dict[str, tuple[str, int, int, int, int, int]]:
    """Bounded read-only proof that the vendor's global NGINX files stay intact."""
    records = {}
    for path in (Path("/etc/nginx/nginx.conf"), Path("/etc/nginx/mime.types")):
        # A vendor may omit mime.types, but nginx.conf is mandatory on both
        # supported packaged NGINX installations. Never follow a foreign link.
        if not path.exists() and not path.is_symlink():
            continue
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
        records[str(path)] = (
            hashlib.sha256(path.read_bytes()).hexdigest(), info.st_dev,
            info.st_ino, info.st_mtime_ns, info.st_uid, stat.S_IMODE(info.st_mode),
        )
    assert "/etc/nginx/nginx.conf" in records
    return records


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
    unmanaged_before = unmanaged_nginx_snapshot()
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
    # A foreign actor may replace the managed include with a symlink after
    # generation one was committed. The installed broker must refuse to follow
    # it or reload anything. Restore the exact original inode afterwards.
    owned_include = Path("/etc/nginx/conf.d/repocache-managed.conf")
    displaced = owned_include.with_name(".pr237-owned-include-displaced")
    assert owned_include.is_file() and not owned_include.is_symlink()
    assert not displaced.exists() and not displaced.is_symlink()
    previous_include = owned_include.lstat()
    previous_include_digest = hashlib.sha256(owned_include.read_bytes()).hexdigest()
    os.rename(owned_include, displaced)
    try:
        os.symlink(displaced.name, owned_include)
        assert owned_include.is_symlink()
        try:
            authenticated_native_operation("RELOAD_V2")
        except NativeRootControlClientError as error:
            assert str(error) == "NATIVE_ROOT_CLIENT_OPERATION_REFUSED"
        else:
            raise AssertionError("Installed root worker accepted foreign managed include link")
        assert owned_include.is_symlink()
        assert os.readlink(owned_include) == displaced.name
        assert not (STATE / ".state-v2-native.pending").exists()
        assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    finally:
        # Restore only the link introduced here. Never overwrite an unexpected
        # substituted inode in a failed negative-path test.
        if owned_include.is_symlink() and os.readlink(owned_include) == displaced.name:
            owned_include.unlink()
        assert not owned_include.exists() and not owned_include.is_symlink()
        assert displaced.is_file() and not displaced.is_symlink()
        os.rename(displaced, owned_include)
    restored_include = owned_include.lstat()
    assert (restored_include.st_dev, restored_include.st_ino,
            restored_include.st_mtime_ns) == (
        previous_include.st_dev, previous_include.st_ino,
        previous_include.st_mtime_ns,
    )
    assert hashlib.sha256(owned_include.read_bytes()).hexdigest() == previous_include_digest
    assert snapshot() == before
    assert unmanaged_nginx_snapshot() == unmanaged_before
    assert authenticated_native_operation("RELOAD_V2")["status"] == "RELOADED"
    assert snapshot() == before
    print("PASS: installed root worker refused foreign managed include symlink without changing vendor NGINX, TLS, catalog or active generation", flush=True)

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
    assert unmanaged_nginx_snapshot() == unmanaged_before
    print("PASS: native worker applied partial same-version v0.6 generation-two repair, preserving nonempty TLS/cache/log/metrics data", flush=True)

    # Reinstall the *identical authenticated worker and systemd units* while
    # generation two is actually live. A completed signed candidate must be
    # a byte/inode/mtime no-op, never replace live root-executable bytes.
    # The first-install-only APT/DNF entry is intentionally different: it
    # must reject reentry on the managed host, before package effects.
    worker_paths = (
        Path("/usr/libexec/repocache/server-control-worker"),
        Path("/etc/systemd/system/repocache-control.service"),
        Path("/etc/systemd/system/repocache-control.socket"),
    )
    worker_before = {}
    for path in worker_paths:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0
        worker_before[str(path)] = (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            info.st_dev, info.st_ino, info.st_mtime_ns,
            info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
        )
    receipt_path = STATE / ".native-nginx-v1.completed"
    # The installed package completion marker is durable across host reboots.
    assert receipt_path.is_file() and not receipt_path.is_symlink()
    receipt_before = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    worker_retry = install_native_root_worker.install_authenticated_worker(
        assets, **pins,
    )
    assert worker_retry["status"] == "AUTHENTICATED_WORKER_FILES_PLACED"
    assert worker_retry["authorizes_service_activation"] is False
    for path in worker_paths:
        info = path.lstat()
        assert (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            info.st_dev, info.st_ino, info.st_mtime_ns,
            info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
        ) == worker_before[str(path)]
    assert hashlib.sha256(receipt_path.read_bytes()).hexdigest() == receipt_before

    original_document = FIXTURE / "reviewed-install.json"
    document_digest = hashlib.sha256(original_document.read_bytes()).hexdigest()
    try:
        install_native_root_worker.install_authenticated_native_nginx(
            assets, original_document, document_digest, **pins,
        )
    except ValueError as error:
        assert str(error) == (
            "WORKER_PLACEMENT_NATIVE_PREPACKAGE_BOUNDARY_UNVERIFIED"
        ), str(error)
    else:
        raise AssertionError("Fresh-only package installer re-entered active v2 host")
    assert hashlib.sha256(receipt_path.read_bytes()).hexdigest() == receipt_before
    assert not (STATE / ".native-nginx-v1.pending").exists()
    assert not (STATE / ".native-nginx-v1.pending-tmp").exists()
    assert snapshot() == after_repair
    assert unmanaged_nginx_snapshot() == unmanaged_before
    for name, (path, digest, inode, mtime) in preserved.items():
        info = path.stat()
        assert (hashlib.sha256(path.read_bytes()).hexdigest(),
                info.st_ino, info.st_mtime_ns) == (digest, inode, mtime), name
    for path in (certificate, private_key):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == saved_tls[str(path)]
    assert b"x-repocache-generation: 2" in https_response("/__repocache/healthz").lower()
    print(
        "PASS: same-version worker+unit installation no-op on active native v2; "
        "fresh-only APT/DNF reentry refused with no journal or live changes",
        flush=True,
    )

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

    # The genuine interrupted v2 WAL must survive a FULL GUEST REBOOT, not
    # merely another Python call. Persist only fixed test-harness hashes and
    # inode observations outside the managed state before shutting down.
    wal_info = failed_wal.lstat()
    assert stat.S_ISREG(wal_info.st_mode) and wal_info.st_uid == 0
    proof = {
        "schema_version": 1,
        "distribution": distribution,
        "synthetic_source_sha": pins["commit"],
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "wal_sha256": hashlib.sha256(failed_wal.read_bytes()).hexdigest(),
        "wal_inode": wal_info.st_ino,
        "wal_mtime_ns": wal_info.st_mtime_ns,
        "managed_sha256": {
            path: data[0] for path, data in after_repair.items()
        },
        "unmanaged": {
            path: list(data) for path, data in unmanaged_before.items()
        },
        "preserved": {
            name: {
                "path": str(path), "sha256": digest,
                "inode": inode, "mtime_ns": mtime,
            }
            for name, (path, digest, inode, mtime) in preserved.items()
        },
        "tls_sha256": saved_tls,
    }
    proof_path = FIXTURE / "pr237-v2-recovery-reboot.json"
    assert not proof_path.exists() and not proof_path.is_symlink()
    raw_proof = (
        json.dumps(proof, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("ascii")
    fd = os.open(
        proof_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    with os.fdopen(fd, "wb") as output:
        output.write(raw_proof)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(FIXTURE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(
        "PASS: real installed v2 apply failed after durable WAL; old HTTPS "
        "generation still serves, WAL and exact recovery proof fsynced for reboot",
        flush=True,
    )


def recover_after_reboot(distribution: str) -> None:
    """Verify and recover exact prior generation after actual QEMU kernel reboot."""
    assert distribution in ("debian", "almalinux")
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert command("/usr/bin/systemd-detect-virt", "--vm") in ("qemu", "kvm")
    if distribution == "almalinux":
        assert command("/usr/sbin/getenforce") == "Enforcing"
    proof_path = FIXTURE / "pr237-v2-recovery-reboot.json"
    proof_info = proof_path.lstat()
    assert stat.S_ISREG(proof_info.st_mode) and proof_info.st_uid == 0
    assert stat.S_IMODE(proof_info.st_mode) == 0o600
    assert proof_info.st_size < 8192
    proof = json.loads(proof_path.read_bytes())
    assert set(proof) == {
        "schema_version", "distribution", "synthetic_source_sha", "boot_id",
        "wal_sha256", "wal_inode", "wal_mtime_ns", "managed_sha256",
        "unmanaged", "preserved", "tls_sha256",
    }
    assert proof["schema_version"] == 1 and proof["distribution"] == distribution
    pins = json.loads((FIXTURE / "pins.json").read_bytes())
    assert pins["commit"] == proof["synthetic_source_sha"]
    assert Path("/proc/sys/kernel/random/boot_id").read_text().strip() != proof["boot_id"]
    wal = STATE / ".state-v2-native.pending"
    info = wal.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert (hashlib.sha256(wal.read_bytes()).hexdigest(),
            info.st_ino, info.st_mtime_ns) == (
        proof["wal_sha256"], proof["wal_inode"], proof["wal_mtime_ns"],
    )
    assert not (STATE / ".state-v2-native.pending-tmp").exists()
    assert set(proof["preserved"]) == {"cache", "logs", "metrics"}
    for name, expected in proof["preserved"].items():
        fixed = {
            "cache": "/var/cache/nginx/repocache-managed/pr237-cache-record",
            "logs": "/var/log/nginx/repocache-managed/pr237-log-record",
            "metrics": "/var/lib/repocache/metrics/pr237-metrics-record",
        }[name]
        assert expected["path"] == fixed
        path = Path(fixed)
        current = path.stat()
        assert (hashlib.sha256(path.read_bytes()).hexdigest(),
                current.st_ino, current.st_mtime_ns) == (
            expected["sha256"], expected["inode"], expected["mtime_ns"],
        ), name
    assert_static_socket()
    assert_disabled("nginx.service")
    # Units are disabled on boot intentionally for these disposable guests.
    # Start the same installed vendor NGINX and root-owned control socket,
    # NEVER enable or alter their sandbox for the recovery.
    command("/usr/bin/systemctl", "start", "nginx.service", timeout=35)
    command("/usr/bin/systemctl", "start", "repocache-control.socket")
    assert b"x-repocache-generation: 2" in https_response("/__repocache/healthz").lower()
    sys.path[:0] = [str(SOURCE / "src"), str(SOURCE)]
    from repocache.server_native_root_control_client_v1 import request_native_fixed_v2

    def fixed(operation: str) -> dict:
        time.sleep(3)
        return request_native_fixed_v2(operation)

    restored = fixed("RECOVER_V2")
    assert restored["status"] == "RECOVERED"
    assert restored["transaction_completed"] is True
    assert not wal.exists() and not (STATE / ".state-v2-native.pending-tmp").exists()
    assert json.loads((STATE / "state-v2.json").read_bytes())["state_generation"] == 2
    assert b"x-repocache-generation: 2" in https_response("/__repocache/healthz").lower()
    assert https_response("/.well-known/repocache/catalog.json").endswith(
        Path("/var/lib/repocache/public/catalog.json").read_bytes()
    )
    after = snapshot()
    assert set(after) == set(proof["managed_sha256"])
    for path, (digest, _inode, _mtime) in after.items():
        assert digest == proof["managed_sha256"][path], path
    assert set(proof["unmanaged"]) == set(unmanaged_nginx_snapshot())
    for path, metadata in unmanaged_nginx_snapshot().items():
        assert list(metadata) == proof["unmanaged"][path]
    for path, digest in proof["tls_sha256"].items():
        assert path in (
            "/etc/repocache/tls/server.crt", "/etc/repocache/tls/server.key",
        ) or path.startswith("/etc/repocache/tls/")
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
    assert fixed("RECOVER_V2")["status"] == "CLEAN"
    assert snapshot() == after
    assert fixed("RELOAD_V2")["status"] == "RELOADED"
    assert snapshot() == after

    # Repeat the same-version deployment sequence AFTER a real kernel reboot.
    # Re-place only authenticated fixed worker/unit bytes; the native NGINX
    # package installer must still refuse on managed v2 before any APT/DNF.
    from scripts import install_native_root_worker, stage_native_root_worker
    assets = FIXTURE / "assets"
    worker_files = (
        Path("/usr/libexec/repocache/server-control-worker"),
        Path("/etc/systemd/system/repocache-control.service"),
        Path("/etc/systemd/system/repocache-control.socket"),
    )

    def owned_identity(path: Path) -> tuple:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0
        return (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            info.st_dev, info.st_ino, info.st_mtime_ns,
            info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
        )

    previous_workers = {str(path): owned_identity(path) for path in worker_files}
    completed_receipt = STATE / ".native-nginx-v1.completed"
    receipt_before = owned_identity(completed_receipt)
    assert stage_native_root_worker.verify_installed_worker(
        assets, **pins,
    )["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    placed = install_native_root_worker.install_authenticated_worker(
        assets, **pins,
    )
    assert placed["status"] == "AUTHENTICATED_WORKER_FILES_PLACED"
    assert all(owned_identity(path) == previous_workers[str(path)]
               for path in worker_files)
    assert owned_identity(completed_receipt) == receipt_before
    # A reviewed generation-three proposal intentionally remains staged
    # after compensating WAL recovery. Do NOT submit a fresh APPLY_V2 here:
    # that would be a new administrator instruction to apply that proposal,
    # not an idempotent reinstall. Prove that worker replacement itself does
    # not reactivate a recovered transaction.
    assert fixed("RECOVER_V2")["status"] == "CLEAN"
    assert snapshot() == after

    reviewed = FIXTURE / "reviewed-install.json"
    try:
        install_native_root_worker.install_authenticated_native_nginx(
            assets, reviewed,
            hashlib.sha256(reviewed.read_bytes()).hexdigest(), **pins,
        )
    except ValueError as error:
        assert str(error) == "WORKER_PLACEMENT_NATIVE_PREPACKAGE_BOUNDARY_UNVERIFIED"
    else:
        raise AssertionError("Native APT/DNF installer re-entered managed v2")
    assert owned_identity(completed_receipt) == receipt_before
    assert not (STATE / ".native-nginx-v1.pending").exists()
    assert not (STATE / ".native-nginx-v1.pending-tmp").exists()
    assert all(owned_identity(path) == previous_workers[str(path)]
               for path in worker_files)
    assert snapshot() == after
    assert b"x-repocache-generation: 2" in https_response("/__repocache/healthz").lower()
    for path, digest in proof["tls_sha256"].items():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
    for entry in proof["preserved"].values():
        assert hashlib.sha256(Path(entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    print(
        "PASS: post-reboot identical worker/units preserved byte/inode/mtime; "
        "v2 recovery clean without proposal replay; APT/DNF re-entry refused without "
        "native journal or TLS/cache/log/metrics mutation", flush=True,
    )
    command("/usr/bin/systemctl", "stop", "repocache-control.socket")
    command("/usr/bin/systemctl", "stop", "nginx.service")
    assert_static_socket()
    assert_disabled("nginx.service")
    print(
        "PASS: real kernel reboot preserved native v2 WAL; installed worker "
        "RECOVER_V2 restored prior live generation and TLS/cache/log/metrics; "
        "repeated recovery clean, reload valid, no service autostart",
        flush=True,
    )


if __name__ == "__main__":
    if (len(sys.argv) not in (2, 3)
            or sys.argv[1] not in ("debian", "almalinux")
            or (len(sys.argv) == 3 and sys.argv[2] != "recover-after-reboot")):
        raise SystemExit(
            "Usage: ci_pr237_native_socket_guest.py debian|almalinux [recover-after-reboot]"
        )
    if len(sys.argv) == 3:
        recover_after_reboot(sys.argv[1])
    else:
        main(sys.argv[1])
