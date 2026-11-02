"""Isolated real-NGINX TLS/redirect check for pinned upstream fragment semantics.

The generated production candidate is validated with real public IPv4/IPv6.
ONLY THIS TEST replaces the numeric servers with loopback to exercise the
HTTP/TLS semantics entirely inside a disposable runner. No real endpoints,
system nginx includes, firewall, systemd services or packages are altered.
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


def render(*, ca):
    document = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    document["repositories"][0]["desired_state"] = "active"
    return render_pinned_upstream_fragments(
        document,
        repository_id="debian-trixie-main",
        candidate_pins_by_host={
            "mirror.example.invalid": ["8.8.8.8", "2001:4860:4860::8888"],
        },
        ca_bundle_path=ca,
    )

NGINX = shutil.which("nginx")
OPENSSL = shutil.which("openssl")


class _Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1/internal-metadata")
            self.end_headers()
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


@pytest.mark.skipif(NGINX is None or OPENSSL is None,
                    reason="real nginx and openssl are required for runtime test")
def test_real_nginx_pinned_tls_and_redirect_refusal(tmp_path):
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    subprocess.run([
        OPENSSL, "req", "-x509", "-newkey", "rsa:2048",
        "-nodes", "-days", "1", "-keyout", str(key),
        "-out", str(cert), "-subj", "/CN=mirror.example.invalid",
        "-addext", "subjectAltName=DNS:mirror.example.invalid",
    ], check=True, capture_output=True, timeout=15)

    origin = http.server.HTTPServer(("127.0.0.1", 0), _Origin)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()

    server_port = _ephemeral_port()
    candidate = render(ca=str(cert))
    upstream = candidate["http_upstream_fragment"]
    assert "server 8.8.8.8:443;" in upstream
    assert "server [2001:4860:4860::8888]:443;" in upstream
    # Fixture-only loopback substitution: production pin validation still
    # rejects loopback and the renderer itself has no test-mode bypass.
    upstream = upstream.replace(
        "server 8.8.8.8:443;",
        f"server 127.0.0.1:{origin.server_address[1]};",
    ).replace("    server [2001:4860:4860::8888]:443;\n", "")
    assert "8.8.8.8" not in upstream
    assert "2001:4860" not in upstream

    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'error.log'} notice;\n"
        "events {}\nhttp { access_log off;\n"
        + upstream
        + f"server {{ listen 127.0.0.1:{server_port};\n"
        + candidate["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    nginx = None
    try:
        syntax = subprocess.run(
            [NGINX, "-t", "-c", str(conf), "-p", str(tmp_path)],
            capture_output=True, text=True, timeout=10,
        )
        assert syntax.returncode == 0, syntax.stderr

        nginx = subprocess.Popen(
            [NGINX, "-c", str(conf), "-p", str(tmp_path),
             "-g", "daemon off; master_process off;"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = (
            f"http://127.0.0.1:{server_port}"
            "/__repocache/repos/debian-trixie-main/"
        )
        for _ in range(40):
            try:
                with opener.open(base + "ok", timeout=1) as response:
                    assert response.status == 200
                    assert response.read() == b"REPOCACHE-PINNED-TLS-OK"
                break
            except (OSError, urllib.error.URLError):
                if nginx.poll() is not None:
                    pytest.fail("isolated nginx process exited before serving")
                time.sleep(0.1)
        else:
            pytest.fail("isolated nginx proxy did not become ready")

        with pytest.raises(urllib.error.HTTPError) as failure:
            opener.open(base + "redirect", timeout=3)
        assert failure.value.code == 502
        assert failure.value.headers.get("Location") is None
    finally:
        if nginx is not None:
            nginx.terminate()
            nginx.wait(timeout=5)
            if nginx.stderr is not None:
                nginx.stderr.close()
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=3)
