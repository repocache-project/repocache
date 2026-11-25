"""Bounded native NGINX inactivity expiry, independent of capacity (#97).

The standalone entrypoint is restricted to a disposable nonroot container.
A future VM caller must enforce its own native guest guard.
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


def observe_native_inactivity(nginx: str) -> None:
    if os.geteuid() == 0 or nginx != '/usr/sbin/nginx':
        raise RuntimeError('NONROOT_PACKAGED_NGINX_REQUIRED')
    body = b'repocache-inactivity-fixture\n' * 1024
    counts: Counter[str] = Counter()
    lock = threading.Lock()

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ('/idle/object', '/control/object'):
                self.send_error(404)
                return
            with lock:
                counts[self.path] += 1
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'public, max-age=600')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    with tempfile.TemporaryDirectory(prefix='repocache-vm-inactivity-', dir='/tmp') as temp:
        root = Path(temp)
        for name in ('idle', 'control', 'client', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
            (root / name).mkdir(mode=0o700)
        with ThreadingHTTPServer(('127.0.0.1', 0), Origin) as origin:
            thread = threading.Thread(target=origin.serve_forever, daemon=True)
            thread.start()
            proc = None
            try:
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                conf = root / 'nginx.conf'
                conf.write_text(
                    f'pid {root}/nginx.pid;\nerror_log {root}/error.log notice;\n'
                    'worker_processes 1;\nevents { worker_connections 64; }\nhttp {\n'
                    'access_log off;\n'
                    + ''.join(f'{directive}_temp_path {root}/{name};\n' for directive, name in (
                        ('client_body', 'client'), ('proxy', 'proxy'), ('fastcgi', 'fastcgi'),
                        ('uwsgi', 'uwsgi'), ('scgi', 'scgi')))
                    + ''.join(f'proxy_cache_path {root}/{zone} levels=1:2 keys_zone={zone}:1m '
                              f'inactive={idle}s max_size=8m use_temp_path=off;\n'
                              for zone, idle in (('idle', 3), ('control', 600)))
                    + f'server {{ listen 127.0.0.1:{port};\n'
                    + ''.join(f'location /{zone}/ {{ proxy_pass http://127.0.0.1:{origin.server_port}; '
                              f'proxy_cache {zone}; proxy_cache_key $uri; proxy_cache_valid 200 600s; '
                              'add_header X-Cache $upstream_cache_status always; }\n'
                              for zone in ('idle', 'control'))
                    + 'location / { return 204; }\n}\n}\n', encoding='ascii')
                args = [nginx, '-e', str(root / 'bootstrap.log'), '-p', str(root), '-c', str(conf)]
                subprocess.run(args + ['-t'], check=True, timeout=15, capture_output=True)
                proc = subprocess.Popen(args + ['-g', 'daemon off;'],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                opener = build_opener(ProxyHandler({}))
                base = f'http://127.0.0.1:{port}'

                def request(path):
                    with opener.open(base + path, timeout=5) as response:
                        assert response.status == 200 and response.read() == body
                        return response.headers.get('X-Cache', '')

                def cache_files(zone):
                    return [p for p in (root / zone).rglob('*') if p.is_file()]

                deadline = time.monotonic() + 15
                while True:
                    assert proc.poll() is None
                    try:
                        with opener.open(base + '/', timeout=2) as response:
                            assert response.status == 204
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
                for zone in ('control', 'idle'):
                    assert request(f'/{zone}/object') == 'MISS'
                    assert request(f'/{zone}/object') == 'HIT'
                    files = cache_files(zone)
                    assert len(files) == 1
                    assert 0 < files[0].stat().st_blocks * 512 < 8 * 1024 * 1024
                started = time.monotonic()
                deadline = started + 45
                while cache_files('idle'):
                    assert proc.poll() is None
                    assert time.monotonic() < deadline, 'IDLE_OBJECT_NOT_EVICTED'
                    time.sleep(0.2)
                elapsed = time.monotonic() - started
                # NGINX timestamps are whole seconds; allow quantization.
                assert 2 <= elapsed < 600, 'UNEXPECTED_EXPIRY_TIMING'
                assert len(cache_files('control')) == 1
                with lock:
                    assert counts == {'/idle/object': 1, '/control/object': 1}
                assert request('/idle/object') == 'MISS'
                assert request('/idle/object') == 'HIT'
                assert request('/control/object') == 'HIT'
                with lock:
                    assert counts == {'/idle/object': 2, '/control/object': 1}
                print(f'PASS: native inactivity eviction with fresh payload and no capacity pressure; elapsed_seconds={elapsed:.2f}; inactive_seconds=3; freshness_seconds=600; independent zone retained HIT; exact bytes verified', flush=True)
            finally:
                if proc is not None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                origin.shutdown()
                thread.join(timeout=5)


def main() -> None:
    if (os.geteuid() == 0 or not Path('/.dockerenv').is_file()
            or os.environ.get('REPOCACHE_DISPOSABLE_MIN_FREE_PRESSURE') != '1'):
        raise RuntimeError('NONROOT_DISPOSABLE_CONTAINER_REQUIRED')
    observe_native_inactivity('/usr/sbin/nginx')


if __name__ == '__main__':
    main()
