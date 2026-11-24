"""Bounded stock NGINX capacity experiment for the existing #97 VM guest.

The caller must pass its native guest guard before invoking this probe.
No installed service, cache path, policy state or client source is changed.
"""
from __future__ import annotations

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from urllib.request import ProxyHandler, build_opener

LIMIT = 512 * 1024
BODY_SIZE = 128 * 1024
OBJECTS = 12


def observe_native_capacity(nginx: str) -> None:
    if os.geteuid() == 0 or nginx != "/usr/sbin/nginx":
        raise RuntimeError("NONROOT_PACKAGED_NGINX_REQUIRED")
    payloads = {f"/pressure/{i}": bytes([i]) * BODY_SIZE for i in range(OBJECTS)}
    payloads["/control/object"] = b"C" * BODY_SIZE
    counts: Counter[str] = Counter()
    lock = threading.Lock()

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = payloads.get(self.path)
            if body is None:
                self.send_error(404)
                return
            with lock:
                counts[self.path] += 1
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=600")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    with tempfile.TemporaryDirectory(prefix="repocache-vm-capacity-") as tmp:
        root = Path(tmp)
        for name in ("pressure", "control", "client", "proxy", "fastcgi", "uwsgi", "scgi"):
            (root / name).mkdir(mode=0o700)
        with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin:
            thread = threading.Thread(target=origin.serve_forever, daemon=True)
            thread.start()
            process = None
            try:
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = sock.getsockname()[1]
                conf = root / "nginx.conf"
                conf.write_text(
                    f"pid {root}/nginx.pid;\nerror_log {root}/error.log notice;\n"
                    "worker_processes 1;\nevents { worker_connections 64; }\nhttp {\n"
                    "access_log off;\n"
                    + "".join(f"{directive}_temp_path {root}/{name};\n" for directive, name in (
                        ("client_body", "client"), ("proxy", "proxy"), ("fastcgi", "fastcgi"),
                        ("uwsgi", "uwsgi"), ("scgi", "scgi")))
                    + f"proxy_cache_path {root}/pressure levels=1:2 keys_zone=pressure:1m "
                    "inactive=600s max_size=512k use_temp_path=off;\n"
                    + f"proxy_cache_path {root}/control levels=1:2 keys_zone=control:1m "
                    "inactive=600s max_size=8m use_temp_path=off;\n"
                    + f"server {{ listen 127.0.0.1:{port};\n"
                    + "".join(
                        f"location /{zone}/ {{ proxy_pass http://127.0.0.1:{origin.server_port}; "
                        f"proxy_cache {zone}; proxy_cache_key $uri; proxy_cache_valid 200 600s; "
                        "add_header X-Cache $upstream_cache_status always; }\n"
                        for zone in ("pressure", "control"))
                    + "location / { return 204; }\n}\n}\n", encoding="ascii")
                args = [nginx, "-e", str(root / "bootstrap.log"), "-p", str(root), "-c", str(conf)]
                subprocess.run(args + ["-t"], check=True, timeout=15, capture_output=True)
                process = subprocess.Popen(args + ["-g", "daemon off;"],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                opener = build_opener(ProxyHandler({}))
                base = f"http://127.0.0.1:{port}"

                def request(path: str) -> str:
                    with opener.open(base + path, timeout=5) as response:
                        assert response.status == 200 and response.read() == payloads[path]
                        return response.headers.get("X-Cache", "")

                def occupancy() -> int:
                    total = 0
                    for entry in (root / "pressure").rglob("*"):
                        try:
                            if entry.is_file():
                                total += entry.stat().st_blocks * 512
                        except FileNotFoundError:
                            pass  # Native manager may unlink during observation.
                    return total

                deadline = time.monotonic() + 15
                while True:
                    assert process.poll() is None, "PRIVATE_NGINX_EXITED"
                    try:
                        with opener.open(base + "/", timeout=2) as response:
                            assert response.status == 204
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
                started = time.monotonic()
                control = "/control/object"
                assert request(control) == "MISS" and request(control) == "HIT"
                warmed = []
                peak = 0
                for i in range(OBJECTS):
                    path = f"/pressure/{i}"
                    assert request(path) == "MISS"
                    if request(path) == "HIT":
                        warmed.append(path)
                    peak = max(peak, occupancy())
                assert warmed, "NO_WARMED_PRESSURE_OBJECT"
                # No more requests to the pressured zone during manager settlement.
                deadline = time.monotonic() + 90
                while occupancy() > LIMIT:
                    assert process.poll() is None, "PRIVATE_NGINX_EXITED"
                    assert time.monotonic() < deadline, "NATIVE_CAPACITY_DID_NOT_SETTLE"
                    time.sleep(0.25)
                settled = occupancy()
                evicted = None
                for path in warmed:
                    with lock:
                        before = counts[path]
                    status = request(path)
                    if status == "MISS":
                        with lock:
                            assert counts[path] == before + 1
                        evicted = path
                        break
                    assert status == "HIT", "UNEXPECTED_CACHE_STATUS"
                assert evicted is not None, "NO_PREVIOUSLY_WARMED_OBJECT_EVICTED"
                assert request(control) == "HIT"
                with lock:
                    assert counts[control] == 1
                elapsed = time.monotonic() - started
                assert elapsed < 600, "INACTIVITY_COULD_EXPLAIN_EVICTION"
                print(f"PASS: native capacity eviction before inactivity; "
                      f"peak_allocated_bytes={peak} settled_allocated_bytes={settled} "
                      f"limit_bytes={LIMIT} elapsed_seconds={elapsed:.2f}; "
                      "previous HIT became MISS with intact bytes; independent zone stayed HIT", flush=True)
            finally:
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                origin.shutdown()
                thread.join(timeout=5)
