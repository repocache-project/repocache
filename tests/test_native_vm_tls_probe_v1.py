"""Disposable TLS listener acceptance tests for the read-only #30 VM receipt."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "inspect_native_vm_tls_v1.py"
HOST = "cache.example.invalid"


@pytest.fixture
def tls_server(tmp_path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL executable unavailable; no synthetic TLS evidence")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run([
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-keyout", str(key), "-out", str(cert),
        "-subj", "/CN=decoy.example.invalid", "-addext", f"subjectAltName=DNS:{HOST}",
    ], check=True, capture_output=True, timeout=25)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                accepted, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with context.wrap_socket(accepted, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield cert, listener.getsockname()[1]
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)


def run_probe(*argv):
    proc = subprocess.run([sys.executable, "-B", str(SCRIPT), *map(str, argv)],
                          text=True, capture_output=True, timeout=15)
    assert not proc.stderr, proc.stderr
    assert len(proc.stdout.splitlines()) == 1
    line = proc.stdout.strip()
    assert line.startswith("REPOCACHE_TLS_VM_V1=")
    result = json.loads(line.split("=", 1)[1])
    assert result["issue_30_accepted"] is False
    assert result["authorizes_nginx_activation"] is False
    assert result["authorizes_firewall_change"] is False
    assert result["private_key_ownership_verified"] is False
    return proc.returncode, result, line


def test_valid_tls_only_proves_partial_identity(tls_server):
    cert, port = tls_server
    code, result, line = run_probe("--hostname", HOST, "--connect-ip", "127.0.0.1",
                                   "--port", port, "--ca-file", cert)
    assert code == 0
    assert result["status"] == "PARTIAL_EVIDENCE"
    assert result["trusted_tls_handshake_observed"]
    assert result["exact_dns_san_observed"]
    assert result["tls_version"] in ("TLSv1.2", "TLSv1.3")
    assert HOST not in line and str(cert) not in line


@pytest.mark.parametrize("override,expected", [
    ({"hostname": "foreign.example.invalid"}, "TLS_IDENTITY_REFUSED"),
    ({"connect_ip": "1.1.1.1"}, "NON_LOOPBACK_REFUSED"),
    ({"connect_ip": "::ffff:127.0.0.1"}, "NON_LOOPBACK_REFUSED"),
    ({"connect_ip": "localhost"}, "INPUT_REFUSED"),
    ({"hostname": "*.example.invalid"}, "INPUT_REFUSED"),
    ({"hostname": "UPPER.example.invalid"}, "INPUT_REFUSED"),
    ({"hostname": "127.0.0.1"}, "INPUT_REFUSED"),
    ({"ca_file": "/absent/ca.pem"}, "TRUST_STORE_UNAVAILABLE"),
])
def test_negative_fail_closed_no_leak(tls_server, override, expected):
    cert, port = tls_server
    values = {"hostname": HOST, "connect_ip": "127.0.0.1", "port": port,
              "ca_file": str(cert)}
    values.update(override)
    argv = []
    for key, value in values.items():
        argv.extend(["--" + key.replace("_", "-"), str(value)])
    code, result, line = run_probe(*argv)
    assert code == 2
    assert result["check_code"] == expected
    assert not result["trusted_tls_handshake_observed"]
    assert values["hostname"] not in line
    assert values["connect_ip"] not in line
    assert values["ca_file"] not in line


def test_untrusted_ca_rejected(tls_server, tmp_path):
    _, port = tls_server
    ca = tmp_path / "empty-ca.pem"
    ca.write_text("invalid certificate")
    code, result, _ = run_probe("--hostname", HOST, "--connect-ip", "127.0.0.1",
                                "--port", port, "--ca-file", ca)
    assert code == 2
    assert result["check_code"] == "TRUST_STORE_UNAVAILABLE"
