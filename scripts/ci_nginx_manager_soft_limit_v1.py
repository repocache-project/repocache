#!/usr/bin/env python3
"""Real packaged NGINX capacity reclamation, disposable nonroot only (#97)."""
from __future__ import annotations

from collections import Counter
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        with self.server.lock:
            self.server.count[self.path] += 1
        content = hashlib.sha256(self.path.encode("ascii")).digest() * 2048
        self.send_response(200)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *_):
        pass


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def render(root, upstream, proxy, limit):
    if limit not in ("16m", "128k"):
        raise ValueError("PRIVATE_NGINX_CAPACITY_UNSUPPORTED")
    return (
        f"worker_processes 1; pid {root}/nginx.pid;\n"
        f"error_log {root}/nginx-error.log notice;\n"
        "events { worker_connections 128; }\n"
        "http { access_log off;\n"
        + "".join(f"{name}_temp_path {root}/{name};\n"
                  for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        + f"proxy_cache_path {root}/cache levels=1:2 "
        "keys_zone=repocache_pressure:1m inactive=120s "
        f"max_size={limit} min_free=1m "
        "manager_files=100 manager_sleep=50ms "
        "manager_threshold=200ms use_temp_path=off;\n"
        f"server {{ listen 127.0.0.1:{proxy};\n"
        "location / {\n"
        f"proxy_pass http://127.0.0.1:{upstream};\n"
        "proxy_cache repocache_pressure;\n"
        "proxy_cache_valid 200 60m;\n"
        "add_header X-RepoCache-Test $upstream_cache_status always;\n"
        "}\n}\n}\n"
    )


def usage(cache):
    sizes = [p.stat().st_size for p in cache.rglob("*") if p.is_file()]
    return len(sizes), sum(sizes)


def main():
    if (os.geteuid() == 0 or not Path("/.dockerenv").is_file()
            or os.environ.get("REPOCACHE_DISPOSABLE_NGINX_PRESSURE") != "1"):
        raise RuntimeError("DISPOSABLE_NONROOT_REQUIRED")
    nginx = "/usr/sbin/nginx"
    if not Path(nginx).is_file():
        raise RuntimeError("STOCK_NGINX_UNAVAILABLE")
    with tempfile.TemporaryDirectory(prefix="repocache-native-manager-pressure-") as tmp:
        root = Path(tmp)
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi", "cache"):
            (root / name).mkdir(mode=0o700)
        upstream_port, proxy_port = port(), port()
        if upstream_port == proxy_port:
            raise AssertionError("PORT_COLLISION")
        backend = ThreadingHTTPServer(("127.0.0.1", upstream_port), Origin)
        backend.lock = threading.Lock()
        backend.count = Counter()
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        conf = root / "nginx.conf"
        conf.write_text(render(root, upstream_port, proxy_port, "16m"), encoding="ascii")
        def check():
            result = subprocess.run(
                [nginx, "-t", "-p", str(root), "-c", str(conf)],
                stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=12,
            )
            if result.returncode:
                raise AssertionError("PRIVATE_NGINX_SYNTAX_REFUSED")
        check()
        process = subprocess.Popen(
            [nginx, "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = f"http://127.0.0.1:{proxy_port}"
        def request(path):
            with opener.open(base + path, timeout=3) as response:
                return (response.status,
                        response.headers.get("X-RepoCache-Test", ""),
                        response.read())
        try:
            for _ in range(100):
                try:
                    first = request("/first")
                    break
                except (OSError, TimeoutError):
                    if process.poll() is not None:
                        raise AssertionError("NGINX_EXITED_ON_START")
                    time.sleep(0.05)
            else:
                raise AssertionError("NGINX_LOOPBACK_NOT_READY")
            if first[0] != 200 or request("/first")[1] != "HIT":
                raise AssertionError("BASELINE_CACHE_HIT_MISSING")
            for i in range(20):
                response = request(f"/object-{i}")
                if response[0] != 200 or len(response[2]) != 65536:
                    raise AssertionError("SYNTHETIC_PAYLOAD_INTEGRITY_FAILURE")
            before = usage(root / "cache")
            if before[0] < 18 or before[1] < 900000:
                raise AssertionError("BASELINE_CACHE_SIZE_NOT_MEASURED")
            conf.write_text(render(root, upstream_port, proxy_port, "128k"),
                            encoding="ascii")
            check()
            process.send_signal(signal.SIGHUP)  # Test-only private subprocess.
            samples = []
            for _ in range(12):
                time.sleep(1)
                samples.append(usage(root / "cache"))
                if process.poll() is not None:
                    raise AssertionError("NGINX_EXITED_DURING_RECLAIM")
            # A native manager is asynchronous; do NOT assert an exact,
            # instantaneous quota or a particular LRU/object priority.
            if (min(n for n, _ in samples) >= before[0] // 2
                    or min(n for _, n in samples) >= before[1] // 2):
                raise AssertionError("REAL_NATIVE_RECLAMATION_NOT_OBSERVED")
            if request("/post-reclaim")[0] != 200:
                raise AssertionError("PROXY_UNAVAILABLE_AFTER_RECLAIM")
            print("PASS: real NGINX native cache manager reclaimed over half "
                  "the synthetic bytes and files after soft max_size reduction")
            print("NOT VERIFIED: installed NGINX, SELinux/systemd, real ENOSPC "
                  "and signed client fallback; max_size is NOT a hard quota")
        finally:
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=4)
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=4)


if __name__ == "__main__":
    main()
