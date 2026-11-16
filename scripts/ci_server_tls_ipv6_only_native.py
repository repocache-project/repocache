#!/usr/bin/env python3
"""Rootless stock-NGINX IPv6-only TLS socket smoke, not host activation (#30)."""
from __future__ import annotations
import errno
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from repocache.server_nginx_tls_listener_candidate_v1 import render_native_tls_listener_candidate

HOST = "cache.example.invalid"
PORT = 18445
MARKER = b"repocache-ipv6-only"


def request(context, sni, http_host=HOST):
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as raw:
        raw.settimeout(3)
        raw.connect(("::1", PORT, 0, 0))
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            tls.sendall(("GET /__ipv6_test HTTP/1.1\r\n"
                         f"Host: {http_host}\r\n"
                         "Connection: close\r\n\r\n").encode("ascii"))
            response = b""
            while True:
                piece = tls.recv(4096)
                if not piece:
                    return response
                response += piece
                assert len(response) <= 65536, "RESPONSE_BOUND_EXCEEDED"


def main():
    assert os.geteuid() != 0, "ROOTLESS_ONLY"
    assert Path("/.dockerenv").exists(), "DISPOSABLE_CONTAINER_ONLY"
    assert os.environ.get("REPOCACHE_DISPOSABLE_NGINX_IPV6") == "1"
    nginx = shutil.which("nginx")
    openssl = shutil.which("openssl")
    assert nginx and openssl, "STOCK_DISTRO_TOOLS_REQUIRED"
    # A skipped IPv6 capability check must never be reported as PASS.
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
        probe.bind(("::1", 0, 0, 0))
    with tempfile.TemporaryDirectory(prefix="repocache-ipv6-tls-") as tmp:
        root = Path(tmp)
        cert, key = root / "synthetic.pem", root / "synthetic.key"
        made = subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-keyout", str(key), "-out", str(cert),
             "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30, check=False,
        )
        assert made.returncode == 0, "SYNTHETIC_TLS_FIXTURE_INVALID"
        key.chmod(0o600)
        document = json.loads(Path("/repo/docs/examples/server-install-v1.json").read_text())
        document["deployment"]["listen"]["bind_address"] = "::"
        document["deployment"]["listen"]["https_port"] = PORT
        document["deployment"]["tls"]["certificate_file"] = str(cert)
        document["deployment"]["tls"]["private_key_file"] = str(key)
        candidate = render_native_tls_listener_candidate(document)
        assert candidate["status"] == "NATIVE_TLS_LISTENER_CANDIDATE_ONLY"
        assert candidate["authorizes_nginx_activation"] is False
        assert candidate["authorizes_firewall_change"] is False
        fragment = candidate["server_context_fragment"]
        assert f"listen [::]:{PORT} ssl ipv6only=on;\n" in fragment
        assert "$ssl_server_name" in fragment and "$http_host" in fragment
        assert "$host" in fragment
        scratch = ""
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            folder = root / name
            folder.mkdir(mode=0o700)
            scratch += f"{name}_temp_path {folder};\n"
        config = (
            f"pid {root / 'nginx.pid'};\n"
            f"error_log {root / 'nginx-error.log'} notice;\n"
            "worker_processes 1;\n"
            "events { worker_connections 32; }\n"
            "http {\naccess_log off;\n" + scratch
            + "server {\n" + fragment
            + 'location = /__ipv6_test { return 200 "repocache-ipv6-only"; }\n'
            + "}\n}\n"
        )
        conf = root / "nginx.conf"
        conf.write_text(config)
        syntax = subprocess.run(
            [nginx, "-t", "-p", str(root), "-c", str(conf)],
            capture_output=True, timeout=15, check=False,
        )
        assert syntax.returncode == 0, "STOCK_NGINX_IPV6_SYNTAX_INVALID"
        print("PASS: stock NGINX accepts generated IPv6-only TLS", flush=True)
        proc = subprocess.Popen(
            [nginx, "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            trusted = ssl.create_default_context()
            trusted.load_verify_locations(cafile=str(cert))
            payload = None
            for _ in range(60):
                assert proc.poll() is None, "STOCK_NGINX_IPV6_START_FAILED"
                try:
                    payload = request(trusted, HOST)
                    break
                except (ConnectionRefusedError, ConnectionResetError):
                    time.sleep(0.05)
            assert payload and b"200 OK" in payload and MARKER in payload
            print("PASS: trusted IPv6 TLS handshake + approved HTTP Host", flush=True)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ipv4:
                ipv4.settimeout(3)
                result = ipv4.connect_ex(("127.0.0.1", PORT))
            assert result == errno.ECONNREFUSED, "IPV4_SOCKET_ADMITTED"
            print("PASS: IPv4 connection refused on same listener port", flush=True)
            negative = ssl.create_default_context()
            negative.load_verify_locations(cafile=str(cert))
            negative.check_hostname = False  # negative SNI only
            for sni in (None, "other.example.invalid"):
                denied = request(negative, sni)
                assert b"421 Misdirected Request" in denied and MARKER not in denied
            denied = request(trusted, HOST, "other.example.invalid")
            assert b"421 Misdirected Request" in denied and MARKER not in denied
            print("PASS: no/foreign SNI and foreign Host blocked on IPv6", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=6)


if __name__ == "__main__":
    main()
