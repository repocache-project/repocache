#!/usr/bin/env python3
"""Real packaged NGINX syntax, TLS and APT/DNF HTTP cache smoke (#28/#27).

Run only in the two disposable distro CI containers as a non-root UID with
network=none and a read-only container root. All requests use the loopback
namespace. This is NOT an installer or proof of production NGINX activation,
repository authorization, systemd, host root provenance or SELinux enforcing.
"""
from __future__ import annotations

import collections
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)

ROOT = Path(__file__).resolve().parents[1]
HOST = "mirror.example.invalid"
FIXTURES = {
    "/apt/dists/trixie/InRelease": (
        "application/octet-stream", b"APT-INRELEASE-DISPOSABLE-PAYLOAD\n"
    ),
    "/apt/pool/main/r/repocache-fixture.deb": (
        "application/vnd.debian.binary-package", b"DEB\x00immutable-disposable-test"
    ),
    "/dnf/repodata/repomd.xml": (
        "application/xml", b"<repomd>signed-metadata-fixture</repomd>\n"
    ),
    "/dnf/Packages/r/repocache-fixture.rpm": (
        "application/x-rpm", b"RPM\x00immutable-disposable-test"
    ),
    "/apt/accel": ("application/octet-stream", b"UPSTREAM-ACCEL-HEADER-IGNORED"),
    "/apt/dists/trixie/Release.gpg": (
        "application/octet-stream", b"PUBLIC-DISPOSABLE-RELEASE-SIGNATURE",
    ),
}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise AssertionError(message)
    print("PASS: " + message, flush=True)


def run(*argv: str, timeout: float = 20) -> subprocess.CompletedProcess:
    result = subprocess.run(
        argv, text=True, capture_output=True, timeout=timeout, check=False,
    )
    if result.returncode:
        raise AssertionError(
            "FAILED command " + Path(argv[0]).name + ": " +
            result.stderr[-900:]
        )
    return result


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def make_backend(counts: collections.Counter[str], lock: threading.Lock):
    class Backend(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with lock:
                counts[self.path] += 1
            if self.path == "/apt/redirect":
                self.send_response(302)
                self.send_header("Location", "http://redirect.example.invalid/unsafe")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            item = FIXTURES.get(self.path)
            if item is None:
                self.send_error(404)
                return
            mimetype, body = item
            # Deliberately return personalized bytes with a PUBLIC cache
            # directive: the proxy must never store credentialed responses.
            if self.path == "/apt/dists/trixie/Release.gpg":
                auth, cookie = self.headers.get("Authorization"), self.headers.get("Cookie")
                if auth:
                    body = b"PRIVATE-AUTH:" + auth.encode("ascii")
                elif cookie:
                    body = b"PRIVATE-COOKIE:" + cookie.encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", mimetype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=600")
            if self.path == "/apt/accel":
                self.send_header("X-Accel-Redirect", "/internal")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            # No client-supplied paths or headers go to CI output.
            return

    return Backend


def config(root: Path, port: int, upstream: int, cert: Path, key: Path) -> Path:
    for name in ("cache", "client_temp", "proxy_temp", "fastcgi_temp",
                 "uwsgi_temp", "scgi_temp"):
        (root / name).mkdir(mode=0o700, exist_ok=True)
    conf = root / "nginx.conf"
    # The test-only loopback origin is intentionally NOT accepted by the
    # production pin renderer, which must continue refusing private/loopback.
    # This exercises stock NGINX's real cache semantics and TLS separately
    # from production candidate rendering, without bypassing pin validation.
    locations = []
    for repo_id, upstream_prefix in (
        ("debian-trixie-main", "apt"),
        ("almalinux-baseos", "dnf"),
    ):
        locations.append(
            f"location ^~ /__repocache/repos/{repo_id}/ {{\n"
            "    limit_except GET HEAD { deny all; }\n"
            f"    proxy_pass http://127.0.0.1:{upstream}/{upstream_prefix}/;\n"
            "    proxy_cache repocache_disposable;\n"
            "    proxy_cache_valid 200 10m;\n"
            "    proxy_cache_methods GET HEAD;\n"
            "    proxy_cache_lock on;\n"
            "    proxy_cache_bypass $http_authorization $http_cookie;\n"
            "    proxy_no_cache $http_authorization $http_cookie;\n"
            "    proxy_ignore_headers X-Accel-Redirect;\n"
            "    proxy_hide_header X-Accel-Redirect;\n"
            "    proxy_redirect off;\n"
            "    proxy_intercept_errors on;\n"
            "    error_page 301 302 303 307 308 =502 @deny_redirect;\n"
            "    add_header X-RepoCache-Smoke $upstream_cache_status always;\n"
            "}\n"
        )
    content = (
        f"pid {root / 'nginx.pid'};\n"
        f"error_log {root / 'nginx-error.log'} notice;\n"
        "worker_processes 1;\nevents { worker_connections 64; }\n"
        "http {\n"
        "    access_log off;\n"
        f"    client_body_temp_path {root / 'client_temp'};\n"
        f"    proxy_temp_path {root / 'proxy_temp'};\n"
        f"    fastcgi_temp_path {root / 'fastcgi_temp'};\n"
        f"    uwsgi_temp_path {root / 'uwsgi_temp'};\n"
        f"    scgi_temp_path {root / 'scgi_temp'};\n"
        f"    proxy_cache_path {root / 'cache'} levels=1:2 "
        "keys_zone=repocache_disposable:2m max_size=32m "
        "inactive=10m use_temp_path=off;\n"
        "    server {\n"
        f"        listen 127.0.0.1:{port} ssl;\n"
        "        server_name localhost;\n"
        f"        ssl_certificate {cert};\n"
        f"        ssl_certificate_key {key};\n"
        "        ssl_protocols TLSv1.2 TLSv1.3;\n"
        "        location @deny_redirect { internal; return 502; }\n"
        "        location / { return 404; }\n"
        + "".join(locations)
        + "    }\n}\n"
    )
    conf.write_text(content, encoding="utf-8")
    return conf


def check_candidate_syntax(root: Path, nginx: str) -> None:
    document = json.loads(
        (ROOT / "docs/examples/server-install-v1.json").read_text("utf-8")
    )
    for item in document["repositories"]:
        item["desired_state"] = "active"
        if item["kind"] == "dnf":
            item["id"] = "almalinux-baseos"
    document["deployment"]["paths"]["cache_root"] = str(root / "candidate_cache")
    for item in document["repositories"]:
        (root / "candidate_cache" / item["id"]).mkdir(parents=True, mode=0o700)
    pins = {
        item["id"]: {HOST: ["8.8.8.8"]}
        for item in document["repositories"]
    }
    ca = next((
        p for p in (
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ) if Path(p).is_file()
    ), None)
    require(ca is not None, "distribution provides a genuine CA bundle")
    result = render_repository_nginx_bundle_candidate(
        document, expected_state_generation=0,
        candidate_pins_by_repository=pins, ca_bundle_path=ca,
    )
    require(
        result["proposed_repository_ids"] ==
        ["almalinux-baseos", "debian-trixie-main"]
        and result["authorizes_nginx_activation"] is False
        and result["authorizes_catalog_publication"] is False,
        "both real APT/DNF route candidates remain non-authorizing",
    )
    for name in ("client_temp", "proxy_temp", "fastcgi_temp",
                 "uwsgi_temp", "scgi_temp"):
        (root / name).mkdir(mode=0o700, exist_ok=True)
    conf = root / "candidate.conf"
    conf.write_text(
        f"pid {root / 'candidate.pid'};\n"
        f"error_log {root / 'candidate-error.log'};\n"
        "events {}\nhttp {\n"
        "access_log off;\n"
        f"client_body_temp_path {root / 'client_temp'};\n"
        f"proxy_temp_path {root / 'proxy_temp'};\n"
        f"fastcgi_temp_path {root / 'fastcgi_temp'};\n"
        f"uwsgi_temp_path {root / 'uwsgi_temp'};\n"
        f"scgi_temp_path {root / 'scgi_temp'};\n"
        + result["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19991;\n"
        + result["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    run(nginx, "-t", "-e", str(root / "candidate-bootstrap.log"),
        "-p", str(root), "-c", str(conf))
    require(True, "actual stock NGINX -t parses both generated pinned routes")


def request(url: str, context: ssl.SSLContext, *,
            method: str = "GET", headers: dict[str, str] | None = None,
            ) -> tuple[int, bytes, str, dict[str, str]]:
    r = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, context=context, timeout=3) as response:
            return (response.status, response.read(),
                    response.headers.get("X-RepoCache-Smoke", ""),
                    dict(response.headers))
    except urllib.error.HTTPError as error:
        return (error.code, error.read(), error.headers.get(
            "X-RepoCache-Smoke", ""), dict(error.headers))


def main() -> None:
    nginx = shutil.which("nginx")
    openssl = shutil.which("openssl")
    require(bool(nginx and openssl), "stock NGINX and OpenSSL are installed")
    require(
        os.geteuid() != 0 and Path("/.dockerenv").exists(),
        "NGINX smoke runs only as an unprivileged disposable container UID",
    )
    require(
        os.environ.get("REPOCACHE_DISPOSABLE_NGINX_SMOKE") == "1",
        "explicit disposable-container execution intent",
    )
    with tempfile.TemporaryDirectory(prefix="repocache-native-nginx-") as temp:
        root = Path(temp)
        check_candidate_syntax(root, nginx)
        cert, key = root / "cert.pem", root / "key.pem"
        run(
            openssl, "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-days", "1", "-keyout", str(key),
            "-out", str(cert), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        )
        key.chmod(0o600)
        origin = free_port()
        front = free_port()
        require(origin != front, "fixture upstream/frontend are distinct")
        counts: collections.Counter[str] = collections.Counter()
        lock = threading.Lock()
        server = ThreadingHTTPServer(
            ("127.0.0.1", origin), make_backend(counts, lock),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        conf = config(root, front, origin, cert, key)
        run(nginx, "-t", "-e", str(root / "runtime-bootstrap.log"),
            "-p", str(root), "-c", str(conf))
        ctx = ssl.create_default_context(cafile=str(cert))
        proc = subprocess.Popen(
            [nginx, "-e", str(root / "runtime-bootstrap.log"),
             "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        try:
            base = f"https://127.0.0.1:{front}/__repocache/repos/"
            ready = False
            for _ in range(100):
                if proc.poll() is not None:
                    raise AssertionError("packaged NGINX died on startup")
                try:
                    status, _, _, _ = request(
                        f"https://127.0.0.1:{front}/", ctx
                    )
                    ready = status == 404
                    if ready:
                        break
                except (OSError, TimeoutError):
                    time.sleep(0.03)
            require(ready, "real stock NGINX serves HTTPS with verified certificate")
            for repo_id, prefix, paths in (
                ("debian-trixie-main", "apt", (
                    "dists/trixie/InRelease",
                    "pool/main/r/repocache-fixture.deb",
                )),
                ("almalinux-baseos", "dnf", (
                    "repodata/repomd.xml", "Packages/r/repocache-fixture.rpm",
                )),
            ):
                for path in paths:
                    route = base + repo_id + "/" + path
                    expected = FIXTURES["/" + prefix + "/" + path][1]
                    initial = request(route, ctx)
                    repeated = request(route, ctx)
                    require(
                        initial[:3] == (200, expected, "MISS"),
                        "real " + prefix + " metadata/package first request is MISS",
                    )
                    require(
                        repeated[:3] == (200, expected, "HIT"),
                        "real " + prefix + " metadata/package repeat is HIT",
                    )
                    with lock:
                        touches = counts["/" + prefix + "/" + path]
                    require(
                        touches == 1,
                        "stock NGINX cache prevents repeat upstream " + prefix +
                        " metadata/package fetch",
                    )
            auth_url = base + "debian-trixie-main/dists/trixie/Release.gpg"
            a = request(auth_url, ctx, headers={"Authorization": "Bearer first"})
            b = request(auth_url, ctx, headers={"Authorization": "Bearer second"})
            require(
                a[1] == b"PRIVATE-AUTH:Bearer first" and
                b[1] == b"PRIVATE-AUTH:Bearer second" and
                a[2] == b[2] == "BYPASS",
                "two different bearer tokens are never stored or cross-served",
            )
            public = request(auth_url, ctx)
            repeat_public = request(auth_url, ctx)
            require(
                public[:3] == (
                    200, FIXTURES["/apt/dists/trixie/Release.gpg"][1], "MISS"
                ) and repeat_public[2] == "HIT" and
                repeat_public[1] == public[1],
                "credentialed response never poisons anonymous signed metadata",
            )
            cookie = request(auth_url, ctx, headers={"Cookie": "session=test"})
            require(
                cookie[1] == b"PRIVATE-COOKIE:session=test" and
                cookie[2] == "BYPASS" and
                request(auth_url, ctx)[2] == "HIT",
                "cookie-specific response bypasses and cannot poison public HIT",
            )
            with lock:
                calls = counts["/apt/dists/trixie/Release.gpg"]
            require(
                calls == 4, "native cache makes no upstream repeat for public object",
            )
            require(
                request(base + "unapproved/foo", ctx)[0] == 404,
                "unapproved route does not access backend",
            )
            require(
                request(base + "debian-trixie-main/dists/trixie/InRelease",
                        ctx, method="POST")[0] == 403,
                "non-read HTTP method is refused",
            )
            accel = request(base + "debian-trixie-main/accel", ctx)
            require(
                accel[0] == 200
                and accel[1] == FIXTURES["/apt/accel"][1]
                and "X-Accel-Redirect" not in accel[3],
                "upstream X-Accel-Redirect cannot switch NGINX location",
            )
            redirect = request(base + "debian-trixie-main/redirect", ctx)
            require(
                redirect[0] == 502,
                "unapproved upstream HTTP redirect is not followed",
            )
            require(True, "native cache/HTTPS smoke uses only disposable loopback")
        finally:
            proc.terminate()
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=5)
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print("PASS: verified HTTPS, native APT/DNF metadata+package MISS/HIT, 4 objects")
    print("NOT VERIFIED: actual supported host systemd/SELinux, privileged deployment, "
          "authentic signed package/repository metadata or staged rollback")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as e:
        print("FAIL: disposable stock NGINX smoke: " + str(e), file=sys.stderr)
        raise SystemExit(1)
