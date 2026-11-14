#!/usr/bin/env python3
"""Real rootless stock-NGINX TLS credential rotation and rollback (#30).

Disposable distro containers only. No systemd, root, public sockets or
production certificate/key paths. TLS state is observed on actual handshakes,
never inferred from nginx -t or a successful reload signal.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

HOST = "cache.example.invalid"
PORT = 18643
BODY = b"repocache-tls-rotation"
TIMEOUT = 15.0


def run(*command: str, timeout: float = 12.0) -> subprocess.CompletedProcess:
    return subprocess.run(command, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=timeout, check=False)


def pair(openssl: str, root: Path, label: str) -> tuple[Path, Path]:
    cert, key = root / (label + ".crt"), root / (label + ".key")
    assert run(openssl, "req", "-x509", "-newkey", "rsa:2048",
               "-nodes", "-days", "1", "-keyout", str(key),
               "-out", str(cert), "-subj", "/CN=" + HOST,
               "-addext", "subjectAltName=DNS:" + HOST,
               timeout=30).returncode == 0
    key.chmod(0o600)
    cert.chmod(0o644)
    return cert, key


def config(root: Path, cert: Path, key: Path) -> bytes:
    return (
        f"pid {root / 'nginx.pid'};\n"
        f"error_log {root / 'error.log'} error;\n"
        "worker_processes 1;\n"
        "events { worker_connections 64; }\n"
        "http {\n"
        "access_log off;\n"
        f"client_body_temp_path {root / 'client_body'};\n"
        f"proxy_temp_path {root / 'proxy'};\n"
        f"fastcgi_temp_path {root / 'fastcgi'};\n"
        f"uwsgi_temp_path {root / 'uwsgi'};\n"
        f"scgi_temp_path {root / 'scgi'};\n"
        "server {\n"
        f"listen 127.0.0.1:{PORT} ssl;\n"
        f"server_name {HOST};\n"
        f"ssl_certificate {cert};\n"
        f"ssl_certificate_key {key};\n"
        "ssl_protocols TLSv1.2 TLSv1.3;\n"
        f'location = /health {{ return 200 "{BODY.decode("ascii")}"; }}\n'
        "}\n}\n"
    ).encode("ascii")


def sample(ca: Path) -> str:
    client = ssl.create_default_context(cafile=str(ca))
    client.check_hostname = True
    with socket.create_connection(("127.0.0.1", PORT), timeout=2) as raw:
        with client.wrap_socket(raw, server_hostname=HOST) as tls:
            assert tls.version() in ("TLSv1.2", "TLSv1.3")
            received = tls.getpeercert(binary_form=True)
            tls.sendall(b"GET /health HTTP/1.1\r\n"
                        b"Host: cache.example.invalid\r\nConnection: close\r\n\r\n")
            response = tls.recv(4096)
            assert b"200 OK" in response and BODY in response
            return hashlib.sha256(received).hexdigest()


def expect_fingerprint(ca: Path, expected: str) -> None:
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        try:
            if sample(ca) == expected:
                return
        except (OSError, ssl.SSLError, AssertionError):
            pass
        time.sleep(0.1)
    raise AssertionError("TLS_ROTATION_NOT_OBSERVED_ON_WIRE")


def main() -> None:
    assert os.geteuid() != 0, "ROOT_DISALLOWED"
    assert Path("/.dockerenv").is_file(), "NATIVE_HOST_DISALLOWED"
    assert os.environ.get("REPOCACHE_DISPOSABLE_TLS_ROTATION") == "1"
    nginx = shutil.which("nginx")
    openssl = shutil.which("openssl")
    assert nginx and openssl, "NATIVE_BINARY_MISSING"
    with tempfile.TemporaryDirectory(prefix="repocache-tls-rotation-",
                                     dir="/tmp") as dirname:
        root = Path(dirname)
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (root / name).mkdir(mode=0o700)
        original_cert, original_key = pair(openssl, root, "old")
        next_cert, next_key = pair(openssl, root, "new")
        before = [(p, p.read_bytes()) for p in (
            original_cert, original_key, next_cert, next_key
        )]
        original = config(root, original_cert, original_key)
        rotated = config(root, next_cert, next_key)
        conf = root / "nginx.conf"
        conf.write_bytes(original)
        argv = [nginx, "-p", str(root), "-c", str(conf)]
        assert run(*argv[:1], "-t", *argv[1:]).returncode == 0
        service = subprocess.Popen(
            [*argv, "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            # Derive exact certificate identities via TLS itself, not config.
            expected_old = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(original_cert.read_text())
            ).hexdigest()
            expected_new = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(next_cert.read_text())
            ).hexdigest()
            expect_fingerprint(original_cert, expected_old)
            print("PASS old trusted TLS listener observed", flush=True)
            # A mismatched pair cannot be activated even if a distro's nginx
            # syntax check incorrectly reports zero.
            bad_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                bad_context.load_cert_chain(str(original_cert), str(next_key),
                                            password=b"")
            except (ssl.SSLError, OSError, ValueError):
                pass
            else:
                raise AssertionError("MISMATCHED_TLS_PAIR_ACCEPTED")
            assert conf.read_bytes() == original
            expect_fingerprint(original_cert, expected_old)
            print("PASS invalid TLS pair refused before rotation", flush=True)
            conf.write_bytes(rotated)
            assert run(*argv[:1], "-t", *argv[1:]).returncode == 0
            assert run(*argv[:1], "-s", "reload", *argv[1:]).returncode == 0
            expect_fingerprint(next_cert, expected_new)
            print("PASS new TLS certificate observed after NGINX reload", flush=True)
            # Exact original config restored and actual TLS old generation
            # observed, not a successful reload return code alone.
            conf.write_bytes(original)
            assert run(*argv[:1], "-t", *argv[1:]).returncode == 0
            assert run(*argv[:1], "-s", "reload", *argv[1:]).returncode == 0
            expect_fingerprint(original_cert, expected_old)
            assert service.poll() is None and conf.read_bytes() == original
            assert all(p.read_bytes() == data for p, data in before)
            assert original_key.stat().st_mode & 0o777 == 0o600
            assert next_key.stat().st_mode & 0o777 == 0o600
            print("PASS TLS rollback restores original live certificate and bytes",
                  flush=True)
        finally:
            service.terminate()
            try:
                service.wait(timeout=6)
            except subprocess.TimeoutExpired:
                service.kill()
                service.wait(timeout=6)


if __name__ == "__main__":
    main()
