#!/usr/bin/env python3
"""Measure real NGINX min_free cache manager when available space is scarce.

This deliberately does NOT fill disks, use root, install services or rewrite
any host NGINX configuration. Only a disposable non-root Linux container.
"""
from __future__ import annotations

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
        body = hashlib.sha256(self.path.encode("ascii")).digest() * 2048
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def config(root, upstream, proxy, free_megabytes):
    if (type(free_megabytes) is not int or not 1 <= free_megabytes < 2**40):
        raise ValueError("PRIVATE_MIN_FREE_INVALID")
    return (
        f"worker_processes 1; pid {root}/nginx.pid;\n"
        f"error_log {root}/error.log notice;\n"
        "events { worker_connections 128; }\n"
        "http { access_log off;\n"
        + "".join(
            f"{name}_temp_path {root}/{name};\n"
            for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
        )
        + f"proxy_cache_path {root}/cache levels=1:2 "
        "keys_zone=repocache_minfree:1m inactive=120s max_size=16m "
        f"min_free={free_megabytes}m manager_files=100 "
        "manager_sleep=50ms manager_threshold=200ms use_temp_path=off;\n"
        f"server {{ listen 127.0.0.1:{proxy};\n"
        "location / {\n"
        f"proxy_pass http://127.0.0.1:{upstream};\n"
        "proxy_cache repocache_minfree;\n"
        "proxy_cache_valid 200 60m;\n"
        "add_header X-RepoCache-State $upstream_cache_status always;\n"
        "}\n}\n}\n"
    )


def usage(cache):
    files = [p.stat().st_size for p in cache.rglob("*") if p.is_file()]
    return len(files), sum(files)


def main():
    if (os.geteuid() == 0 or not Path("/.dockerenv").is_file()
            or os.getenv("REPOCACHE_DISPOSABLE_MIN_FREE_PRESSURE") != "1"):
        raise RuntimeError("NONROOT_DISPOSABLE_CONTAINER_REQUIRED")
    nginx = "/usr/sbin/nginx"
    if not Path(nginx).is_file():
        raise RuntimeError("STOCK_NGINX_NOT_INSTALLED")
    with tempfile.TemporaryDirectory(prefix="repocache-minfree-pressure-") as tmp:
        root = Path(tmp)
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi", "cache"):
            (root / name).mkdir(mode=0o700)
        upstream_port, proxy_port = port(), port()
        if upstream_port == proxy_port:
            raise AssertionError("PORT_COLLISION")
        backend = ThreadingHTTPServer(("127.0.0.1", upstream_port), Origin)
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        conf = root / "nginx.conf"
        conf.write_text(config(root, upstream_port, proxy_port, 1))
        def checked():
            result = subprocess.run(
                [nginx, "-t", "-p", str(root), "-c", str(conf)],
                stdin=subprocess.DEVNULL, capture_output=True,
                check=False, timeout=12,
            )
            if result.returncode:
                raise AssertionError("NATIVE_MIN_FREE_SYNTAX_REFUSED")
        checked()
        proc = subprocess.Popen(
            [nginx, "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        address = f"http://127.0.0.1:{proxy_port}"
        def fetch(path):
            with opener.open(address + path, timeout=3) as response:
                return response.status, response.headers.get("X-RepoCache-State")
        try:
            for _ in range(100):
                try:
                    if fetch("/first")[0] == 200:
                        break
                except (OSError, TimeoutError):
                    if proc.poll() is not None:
                        raise AssertionError("NGINX_EXITED")
                    time.sleep(0.05)
            else:
                raise AssertionError("NGINX_NOT_READY")
            if fetch("/first")[1] != "HIT":
                raise AssertionError("CACHE_HIT_UNVERIFIED")
            for index in range(20):
                if fetch(f"/package-{index}")[0] != 200:
                    raise AssertionError("SYNTHETIC_PACKAGE_FAILED")
            before = usage(root / "cache")
            if before[0] < 18 or before[1] < 900000:
                raise AssertionError("BASELINE_CACHE_UNVERIFIED")
            fs = os.statvfs(root / "cache")
            actual_free = fs.f_frsize * fs.f_bavail
            watermark_mb = actual_free // (1024 * 1024) + 16
            # This is a test-only threshold above the observed free bytes,
            # NOT a disk-filling operation or a production policy proposal.
            conf.write_text(config(root, upstream_port, proxy_port, watermark_mb))
            checked()
            proc.send_signal(signal.SIGHUP)  # Our own private NGINX master.
            samples = []
            for _ in range(12):
                time.sleep(1)
                samples.append(usage(root / "cache"))
                if proc.poll() is not None:
                    raise AssertionError("NGINX_DIED_DURING_MIN_FREE")
            if (min(v[0] for v in samples) >= before[0] // 2
                    or min(v[1] for v in samples) >= before[1] // 2):
                raise AssertionError("MIN_FREE_NATIVE_RECLAIM_NOT_OBSERVED")
            if fetch("/after-watermark")[0] != 200:
                raise AssertionError("PROXY_UNAVAILABLE_UNDER_MIN_FREE")
            # Restore the unpressured manager config. Never claim the
            # waterline itself measured real host ENOSPC or service safety.
            conf.write_text(config(root, upstream_port, proxy_port, 1))
            checked()
            proc.send_signal(signal.SIGHUP)
            time.sleep(0.4)
            if fetch("/after-recovery")[0] != 200:
                raise AssertionError("PROXY_UNAVAILABLE_AFTER_RECOVERY")
            print("PASS: real packaged NGINX min_free manager reclaimed "
                  "synthetic cache while keeping HTTP service available")
            print("NOT VERIFIED: actual host ENOSPC, native installed NGINX, "
                  "SELinux/systemd, client signed fallback or exact LRU")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=4)
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=4)


if __name__ == "__main__":
    main()
