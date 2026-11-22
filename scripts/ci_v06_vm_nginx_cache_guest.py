#!/usr/bin/env python3
"""P0-2: native-VM NGINX APT/DNF cache smoke using disposable loopback only.

Reuse the CI fixture components without weakening their Docker-only
entrypoint guard. No client source rewrite, installed service reload,
CA import, firewall change, or publisher-signed metadata claim.
"""
from __future__ import annotations

import collections
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

from ci_native_nginx_cache_smoke import (
    FIXTURES, check_candidate_syntax, config, free_port, make_backend,
    request, require, run,
)


def native_guard(platform: str) -> None:
    require(platform in ("debian13", "almalinux10"), "only fixed native targets")
    require(os.geteuid() != 0 and os.geteuid() == os.getuid(), "non-root runner")
    require(not Path("/.dockerenv").exists(), "not inside a Docker container")
    require(Path("/proc/1/comm").read_text(encoding="ascii").strip() == "systemd",
            "PID 1 is native systemd")
    require(Path("/home/pr237ci/source/scripts/ci_pr237_guest.sh").is_file(),
            "expected disposable VM checkout")
    require(socket.gethostname().startswith("pr237-"),
            "expected disposable VM hostname")
    vm = subprocess.run(
        ["/usr/bin/systemd-detect-virt", "--vm"], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6,
    )
    require(vm.stdout.strip() in ("qemu", "kvm"), "booted QEMU/KVM kernel")
    osr = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text(encoding="ascii").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    )
    distro, version = ("debian", "13") if platform == "debian13" else ("almalinux", "10")
    require(
        osr.get("ID", "").strip('"') == distro
        and osr.get("VERSION_ID", "").strip('"').split(".")[0] == version,
        "exact supported native distro",
    )
    if platform == "almalinux10":
        se = subprocess.run(
            ["/usr/sbin/getenforce"], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        require(se.stdout.strip() == "Enforcing", "SELinux stays enforcing")
    state = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "nginx.service"],
        capture_output=True, text=True, timeout=5, check=False,
    )
    require(
        state.returncode != 0 and state.stdout.strip() == "inactive",
        "original packaged NGINX service remains stopped",
    )


def main(platform: str) -> None:
    native_guard(platform)
    # On Debian 13 the stock nginx binary lives in /usr/sbin, which is not
    # necessarily included in the non-root SSH guest PATH. Use the distro's
    # fixed packaged executable paths, never a caller-controlled PATH.
    nginx, openssl = "/usr/sbin/nginx", "/usr/bin/openssl"
    require(
        all(Path(binary).is_file() and os.access(binary, os.X_OK)
            for binary in (nginx, openssl)),
        "fixed stock NGINX and OpenSSL executables available",
    )
    with tempfile.TemporaryDirectory(prefix="repocache-p02-vm-cache-") as temp:
        root = Path(temp)
        check_candidate_syntax(root, nginx)
        cert, key = root / "cert.pem", root / "key.pem"
        run(
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        )
        key.chmod(0o600)
        origin, frontend = free_port(), free_port()
        require(origin != frontend, "disjoint private loopback ports")
        counts: collections.Counter[str] = collections.Counter()
        lock = threading.Lock()
        backend = ThreadingHTTPServer(
            ("127.0.0.1", origin), make_backend(counts, lock),
        )
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        process = None
        try:
            conf = config(root, frontend, origin, cert, key)
            run(nginx, "-t", "-e", str(root / "bootstrap.log"),
                "-p", str(root), "-c", str(conf))
            process = subprocess.Popen(
                [nginx, "-e", str(root / "bootstrap.log"), "-p", str(root),
                 "-c", str(conf), "-g", "daemon off;"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, text=True,
            )
            ctx = ssl.create_default_context(cafile=str(cert))
            base = f"https://127.0.0.1:{frontend}/__repocache/repos/"
            for _ in range(200):
                if process.poll() is not None:
                    raise AssertionError("private NGINX process exited unexpectedly")
                try:
                    if request(f"https://127.0.0.1:{frontend}/", ctx)[0] == 404:
                        break
                except (OSError, TimeoutError):
                    pass
                time.sleep(0.1)
            else:
                raise AssertionError("private HTTPS listener not ready")
            for rid, prefix, targets in (
                ("debian-trixie-main", "apt",
                 ("dists/trixie/InRelease", "pool/main/r/repocache-fixture.deb")),
                ("almalinux-baseos", "dnf",
                 ("repodata/repomd.xml", "Packages/r/repocache-fixture.rpm")),
            ):
                for target in targets:
                    url = base + rid + "/" + target
                    expected = FIXTURES[f"/{prefix}/{target}"][1]
                    first, second = request(url, ctx), request(url, ctx)
                    require(
                        first[:3] == (200, expected, "MISS")
                        and second[:3] == (200, expected, "HIT"),
                        "native " + prefix.upper()
                        + " metadata/package exact bytes and MISS/HIT",
                    )
                    with lock:
                        calls = counts[f"/{prefix}/{target}"]
                    require(calls == 1, "no repeat upstream fetch")
            require(request(base + "unapproved/repo", ctx)[0] == 404,
                    "unapproved repository is not exposed")
            require(
                request(base + "debian-trixie-main/dists/trixie/InRelease",
                        ctx, method="POST")[0] == 403,
                "non-read method refused",
            )
            require(request(base + "debian-trixie-main/redirect", ctx)[0] == 502,
                    "untrusted redirect not followed")
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=5)
    assert subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", "nginx.service"],
        check=False, timeout=5,
    ).returncode != 0
    print("PASS: booted native VM stock NGINX disposable HTTPS APT/DNF MISS/HIT")
    print("NOT VERIFIED: authentic APT/DNF signatures, native package manager, "
          "managed route/SELinux context, persistent cache, client fallback")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("debian13", "almalinux10"):
        raise SystemExit("Only the two fixed native VM platforms are supported")
    main(sys.argv[1])
