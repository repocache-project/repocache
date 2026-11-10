"""Issue #30: real isolated, trusted-client HTTPS for disposable NGINX.

This is NOT a host installer, operator-key validator, privileged reload
or booted systemd/SELinux acceptance. Only synthetic TLS keys in pytest
temporary storage, with a Unix-domain SSL listener and zero public ports.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import time

import pytest

_NGINX = shutil.which("nginx")
_OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(
    not _NGINX or not _OPENSSL,
    reason="distro-packaged nginx and openssl required for native TLS smoke",
)
_HOST = "cache.example.invalid"
_REPLY = b"repocache-disposable-https"


def _certificate(root: Path, prefix: str, *, hostname: str = _HOST):
    """Generate synthetic test-only X.509 leaf and matching key."""
    cert = root / (prefix + "-cert.pem")
    key = root / (prefix + "-key.pem")
    result = subprocess.run(
        [_OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-keyout", str(key), "-out", str(cert),
         "-subj", "/CN=" + hostname,
         "-addext", "subjectAltName=DNS:" + hostname],
        shell=False, check=False, capture_output=True, timeout=15,
        stdin=subprocess.DEVNULL, cwd=str(root),
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    assert result.returncode == 0, "synthetic fixture certificate creation failed"
    key.chmod(0o600)
    cert.chmod(0o644)
    return cert, key


def _config(root: Path, cert: Path, key: Path) -> bytes:
    sock = root / "tls.sock"
    assert len(os.fsencode(sock)) < 100
    return (
        f"pid {root / 'nginx.pid'};\n"
        f"error_log {root / 'nginx-error.log'} notice;\n"
        "worker_processes 1;\n"
        "events { worker_connections 32; }\n"
        "http { access_log off;\n"
        "server {\n"
        f"listen unix:{sock} ssl;\n"
        f"ssl_certificate {cert};\n"
        f"ssl_certificate_key {key};\n"
        "ssl_protocols TLSv1.2 TLSv1.3;\n"
        "location = /__test_health {\n"
        f'return 200 "{_REPLY.decode("ascii")}";\n'
        "}\n"
        "}\n"
        "}\n"
    ).encode("ascii")


def _write_config(path: Path, data: bytes) -> None:
    assert not path.exists()
    with path.open("xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _nginx(root: Path, conf: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_NGINX, *args, "-c", str(conf), "-p", str(root)],
        shell=False, check=False, capture_output=True, timeout=10,
        stdin=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )


def _query_ssl(sock: Path, cafile: Path, *, hostname: str) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(cafile))
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as plain:
        plain.settimeout(1)
        plain.connect(str(sock))
        with context.wrap_socket(plain, server_hostname=hostname) as tls:
            tls.sendall(
                b"GET /__test_health HTTP/1.1\r\n"
                b"Host: cache.example.invalid\r\nConnection: close\r\n\r\n"
            )
            response = bytearray()
            while len(response) < 16 * 1024:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
            return bytes(response)


def test_disposable_real_tls_server_validates_client_trust_and_hostname(
    tmp_path: Path,
):
    """Real HTTPS handshake, no public port, no client/source mutation."""
    cert, key = _certificate(tmp_path, "approved")
    original = cert.read_bytes(), key.read_bytes()
    conf = tmp_path / "nginx.conf"
    _write_config(conf, _config(tmp_path, cert, key))
    assert _nginx(tmp_path, conf, "-t").returncode == 0

    process = subprocess.Popen(
        [_NGINX, "-c", str(conf), "-p", str(tmp_path),
         "-g", "daemon off;"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    try:
        success = None
        for _ in range(100):
            assert process.poll() is None, "isolated NGINX master exited"
            try:
                success = _query_ssl(
                    tmp_path / "tls.sock", cert, hostname=_HOST,
                )
                break
            except (OSError, TimeoutError):
                time.sleep(0.05)
        assert success is not None
        assert b" 200 " in success.split(b"\r\n", 1)[0]
        assert success.endswith(_REPLY)
        with pytest.raises(ssl.SSLCertVerificationError):
            _query_ssl(
                tmp_path / "tls.sock", cert,
                hostname="different.example.invalid",
            )
        # An untrusted client CA must not accept the self-signed server.
        other_cert, _ = _certificate(tmp_path, "unrelated")
        with pytest.raises(ssl.SSLCertVerificationError):
            _query_ssl(
                tmp_path / "tls.sock", other_cert, hostname=_HOST,
            )
        assert (cert.read_bytes(), key.read_bytes()) == original
        assert key.stat().st_mode & 0o777 == 0o600
        assert conf.is_file()
    finally:
        if process.poll() is None:
            _nginx(tmp_path, conf, "-s", "quit")
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


@pytest.mark.parametrize("case", ["missing-cert", "missing-key", "key-mismatch",
                                   "invalid-cert", "invalid-key"])
def test_independent_tls_pair_preflight_refuses_bad_material_before_any_reload(
    tmp_path: Path, case: str,
):
    cert, key = _certificate(tmp_path, "approved")
    raw_cert, raw_key = cert.read_bytes(), key.read_bytes()
    selected_cert, selected_key = cert, key
    if case == "missing-cert":
        selected_cert = tmp_path / "absent-cert.pem"
    elif case == "missing-key":
        selected_key = tmp_path / "absent-key.pem"
    elif case == "key-mismatch":
        _, selected_key = _certificate(tmp_path, "foreign")
    elif case == "invalid-cert":
        selected_cert = tmp_path / "broken-cert.pem"
        selected_cert.write_bytes(b"not a PEM certificate\n")
    else:
        selected_key = tmp_path / "broken-key.pem"
        selected_key.write_bytes(b"not a PEM private key\n")
        selected_key.chmod(0o600)
    conf = tmp_path / "nginx.conf"
    _write_config(conf, _config(tmp_path, selected_cert, selected_key))
    # IMPORTANT distro result: stock AlmaLinux 10 NGINX 1.26.3 can report
    # nginx -t SUCCESS for a missing, invalid or mismatched key. An actual
    # independent TLS pair-load check is therefore mandatory and MUST run
    # before attempting to activate the candidate. Only synthetic keys
    # in the disposable fixture are read by this test-only SSL context.
    result = _nginx(tmp_path, conf, "-t")
    assert result.returncode in (0, 1)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with pytest.raises((ssl.SSLError, OSError, ValueError)):
        context.load_cert_chain(
            certfile=str(selected_cert), keyfile=str(selected_key),
        )
    if case in ("missing-cert", "invalid-cert"):
        assert result.returncode != 0
    assert (cert.read_bytes(), key.read_bytes()) == (raw_cert, raw_key)
    assert not (tmp_path / "tls.sock").exists()
    assert not (tmp_path / "nginx.pid").exists()
