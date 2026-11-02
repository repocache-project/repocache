"""Isolated stock-NGINX runtime tests of TLS, SNI and upstream redirects.

Tests substitute a disposable loopback origin for otherwise valid public
numeric pins only *after* pure validation. No production service, firewall,
global configuration, package manager or trusted persistence is touched.
"""
from __future__ import annotations

import http.server
import json
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from repocache.server_nginx_pin_render_v1 import render_pinned_upstream_fragments


EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
NGINX = shutil.which("nginx")
OPENSSL = shutil.which("openssl")
APPROVED_HOST = "mirror.example.invalid"
CANARY_PATH = "/__repocache_unrelated_internal_canary"


def render(*, ca):
    document = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    document["repositories"][0]["desired_state"] = "active"
    return render_pinned_upstream_fragments(
        document,
        repository_id="debian-trixie-main",
        candidate_pins_by_host={
            APPROVED_HOST: ["8.8.8.8", "2001:4860:4860::8888"],
        },
        ca_bundle_path=ca,
    )


class _Origin(http.server.BaseHTTPRequestHandler):
    """HTTPS origin owned by this test process, never a real network host."""

    def do_GET(self):
        # The proxy_pass base path must be preserved (path prefix replaced).
        if not self.path.startswith("/debian/"):
            self.send_error(404)
            return
        if self.path.rsplit("/", 1)[-1].startswith("redirect-"):
            redirect_code = int(self.path.rsplit("-", 1)[-1])
            if redirect_code not in (301, 302, 303, 307, 308):
                raise AssertionError("unknown test-only redirect")
            self.send_response(redirect_code)
            self.send_header("Location", "http://127.0.0.1/internal-metadata")
            self.end_headers()
        elif self.path.endswith("/accel"):
            self.send_response(200)
            self.send_header("X-Accel-Redirect", CANARY_PATH)
            self.end_headers()
            self.wfile.write(b"UPSTREAM-BODY-NOT-INTERNAL-CANARY")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"REPOCACHE-PINNED-TLS-OK")

    def log_message(self, *_args):
        pass


def _ephemeral_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _status_body_headers(opener, url):
    try:
        with opener.open(url, timeout=2) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as response:
        try:
            return response.code, response.read(), response.headers
        finally:
            response.close()


@pytest.mark.skipif(NGINX is None or OPENSSL is None,
                    reason="real stock nginx and openssl required")
@pytest.mark.parametrize("origin_address", ["127.0.0.1", "::1"], ids=["ipv4", "ipv6"])
@pytest.mark.parametrize(
    "certificate_case", ["valid", "wrong-host", "untrusted-ca"],
    ids=["valid-cert", "wrong-hostname", "untrusted-ca"],
)
def test_real_nginx_pinned_tls_sni_and_redirects(
    tmp_path, origin_address, certificate_case,
):
    """Real proxy data-plane test; a public-IP policy bypass is never exposed."""
    cert_hostname = (
        "wrong.example.invalid" if certificate_case == "wrong-host"
        else APPROVED_HOST
    )
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    subprocess.run([
        OPENSSL, "req", "-x509", "-newkey", "rsa:2048",
        "-nodes", "-days", "1", "-keyout", str(key),
        "-out", str(cert), "-subj", f"/CN={cert_hostname}",
        "-addext", f"subjectAltName=DNS:{cert_hostname}",
    ], check=True, capture_output=True, timeout=15)

    if origin_address == "::1":
        class _V6Server(http.server.HTTPServer):
            address_family = socket.AF_INET6
        server_type = _V6Server
    else:
        server_type = http.server.HTTPServer
    try:
        origin = server_type((origin_address, 0), _Origin)
    except OSError:
        if origin_address == "::1":
            pytest.skip("runner does not provide IPv6 loopback")
        raise

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    seen_sni = []

    def record_sni(_tls_socket, hostname, _context):
        seen_sni.append(hostname)

    context.set_servername_callback(record_sni)
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    listener_port = _ephemeral_port()
    trusted_bundle = cert
    if certificate_case == "untrusted-ca":
        trusted_bundle = tmp_path / "unrelated-ca.pem"
        subprocess.run([
            OPENSSL, "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-days", "1",
            "-keyout", str(tmp_path / "unrelated-ca-key.pem"),
            "-out", str(trusted_bundle),
            "-subj", "/CN=unrelated-ca.example.invalid",
            "-addext", "subjectAltName=DNS:unrelated-ca.example.invalid",
        ], check=True, capture_output=True, timeout=15)
    candidate = render(ca=str(trusted_bundle))
    upstream = candidate["http_upstream_fragment"]
    assert "server 8.8.8.8:443;" in upstream
    assert "server [2001:4860:4860::8888]:443;" in upstream

    # Test-only mapping: the real renderer still rejects all loopback pins.
    numeric = (
        f"[::1]:{origin.server_address[1]}"
        if origin_address == "::1"
        else f"127.0.0.1:{origin.server_address[1]}"
    )
    upstream = upstream.replace("server 8.8.8.8:443;", f"server {numeric};")
    upstream = upstream.replace("    server [2001:4860:4860::8888]:443;\n", "")
    assert "8.8.8.8" not in upstream
    assert "2001:4860" not in upstream

    config = tmp_path / "nginx.conf"
    config.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'error.log'} notice;\n"
        "events {}\nhttp { access_log off;\n"
        + upstream
        + f"server {{ listen 127.0.0.1:{listener_port};\n"
        + candidate["server_location_fragment"]
        + f'location = {CANARY_PATH} {{ internal; return 200 "SECRET-INTERNAL-LOCATION"; }}\n'
        + "}\n}\n",
        encoding="utf-8",
    )
    nginx = None
    try:
        syntax = subprocess.run(
            [NGINX, "-t", "-c", str(config), "-p", str(tmp_path)],
            capture_output=True, text=True, timeout=10,
        )
        assert syntax.returncode == 0, syntax.stderr

        nginx = subprocess.Popen(
            [NGINX, "-c", str(config), "-p", str(tmp_path),
             "-g", "daemon off; master_process off;"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = (
            f"http://127.0.0.1:{listener_port}"
            "/__repocache/repos/debian-trixie-main/"
        )
        observed = None
        for _ in range(40):
            try:
                observed = _status_body_headers(opener, base + "ok")
                break
            except (OSError, urllib.error.URLError):
                if nginx.poll() is not None:
                    pytest.fail("isolated nginx process exited before serving")
                time.sleep(0.1)
        assert observed is not None, "isolated NGINX proxy never became ready"

        if certificate_case != "valid":
            assert observed[0] == 502, "invalid TLS trust/hostname was accepted"
            assert b"REPOCACHE-PINNED-TLS-OK" not in observed[1]
        else:
            assert observed[0] == 200
            assert observed[1] == b"REPOCACHE-PINNED-TLS-OK"

            for code in (301, 302, 303, 307, 308):
                status, body, headers = _status_body_headers(
                    opener, base + f"redirect-{code}",
                )
                assert status == 502, f"upstream HTTP {code} escaped proxy"
                assert headers.get("Location") is None

            status, body, headers = _status_body_headers(
                opener, base + "accel",
            )
            assert status == 200
            assert body == b"UPSTREAM-BODY-NOT-INTERNAL-CANARY"
            assert b"SECRET-INTERNAL-LOCATION" not in body
            assert headers.get("X-Accel-Redirect") is None

        assert seen_sni, "NGINX made no TLS connection with SNI"
        assert set(seen_sni) == {APPROVED_HOST}
    finally:
        if nginx is not None:
            nginx.terminate()
            nginx.wait(timeout=5)
            if nginx.stderr is not None:
                nginx.stderr.close()
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=3)
