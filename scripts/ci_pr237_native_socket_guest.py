#!/usr/bin/env python3
"""PR237-only native systemd socket + TLS v2 lifecycle in disposable QEMU guests.

All source signatures, local TLS and trust anchors are synthetic. There is no
publisher acceptance, production credential, or deployed-server assertion.
Use the real installed zipapp worker via kernel-credentialed systemd socket.
"""
from __future__ import annotations

import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import ssl
import stat
import subprocess
import sys

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
    from repocache.server_native_root_control_client_v1 import request_native_fixed_v2

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
    assert_disabled("repocache-control.socket")
    print("PASS: native installed systemd AF_UNIX seqpacket socket with root/admin ownership and disabled boot", flush=True)

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

    clean = request_native_fixed_v2("RECOVER_V2")
    assert clean["status"] == "CLEAN" and clean["transaction_completed"] is True
    assert not (STATE / "state-v2.json").exists()
    print("PASS: installed root zipapp served actual kernel-credentialed RECOVER_V2/CLEAN", flush=True)

    applied = request_native_fixed_v2("APPLY_V2")
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

    reloaded = request_native_fixed_v2("RELOAD_V2")
    assert (reloaded["status"], reloaded["state_generation"]) == ("RELOADED", 1)
    assert snapshot() == before
    unchanged = request_native_fixed_v2("APPLY_V2")
    assert (unchanged["status"], unchanged["state_generation"]) == ("UNCHANGED", 1)
    assert snapshot() == before
    clean_again = request_native_fixed_v2("RECOVER_V2")
    assert clean_again["status"] == "CLEAN"
    assert snapshot() == before
    for path in (certificate, private_key):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == saved_tls[str(path)]
    if distribution == "almalinux":
        assert command("/usr/sbin/getenforce") == "Enforcing"
    print("PASS: real native RELOAD_V2, idempotent APPLY_V2 and RECOVER_V2/CLEAN preserve managed bytes and TLS", flush=True)

    # Real syntax refusal on the running, installed worker: NGINX must keep
    # serving the prior accepted generation, without changing durable v2.
    from repocache.server_native_root_control_client_v1 import NativeRootControlClientError
    invalid = Path("/etc/nginx/conf.d/pr237-disposable-invalid.conf")
    assert not invalid.exists()
    fd = os.open(invalid, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(b"unknown_pr237_nginx_directive on;\n")
            output.flush()
            os.fsync(output.fileno())
        try:
            request_native_fixed_v2("RELOAD_V2")
        except NativeRootControlClientError as error:
            assert str(error) == "NATIVE_ROOT_CLIENT_OPERATION_REFUSED"
        else:
            raise AssertionError("Invalid live NGINX syntax was reloaded by installed worker")
        assert snapshot() == before
        assert b"x-repocache-generation: 1" in https_response("/__repocache/healthz").lower()
    finally:
        invalid.unlink()
    print("PASS: native installed worker refused live invalid nginx syntax without changing known-good v2 and HTTPS exposure", flush=True)
    command("/usr/bin/systemctl", "stop", "repocache-control.socket")
    command("/usr/bin/systemctl", "stop", "nginx.service")
    assert_disabled("repocache-control.socket")
    assert_disabled("nginx.service")
    print("PASS: guest native services stopped; no autostart enabled; synthetic trust only", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("debian", "almalinux"):
        raise SystemExit("Usage: ci_pr237_native_socket_guest.py debian|almalinux")
    main(sys.argv[1])
