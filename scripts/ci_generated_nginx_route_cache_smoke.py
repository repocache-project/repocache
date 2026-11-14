#!/usr/bin/env python3
"""Real stock NGINX proxy/cache smoke using REPOCACHE-generated fragments.

Test-only pin remapping after strict validation allows a localhost TLS fixture.
This does NOT permit loopback pins in production or grant host activation.
"""
from __future__ import annotations

import collections
import copy
import hashlib
from contextlib import contextmanager
import json
import os
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ci_native_nginx_cache_smoke import (
    FIXTURES, HOST, ROOT, free_port, request, require, run,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)
from repocache.server_derived_catalog_candidate_v1 import (
    preview_derived_catalog_from_nginx_dump,
)


# A previously unrequested, disposable metadata-shaped object, not signed
# APT metadata or native package-manager acceptance evidence.
READ_ONLY_APT_PATH = "/apt/dists/trixie/Packages.gz"
READ_ONLY_APT_BYTES = b"DISPOSABLE-APT-INDEX-CACHE-WRITE-DENIAL\n"
BYPASS_READY_APT_PATH = "/apt/dists/trixie/BypassReadiness"
RECOVERY_READY_APT_PATH = "/apt/dists/trixie/RecoveryReadiness"
READY_APT_BYTES = b"DISPOSABLE-APT-ROUTE-READINESS\n"


@contextmanager
def deny_cache_directory_writes(cache_root: Path):
    """Inject test-only cache EACCES; restore original modes on every exit."""
    directories = [cache_root, *sorted(
        (p for p in cache_root.rglob("*") if p.is_dir()),
        key=lambda path: (len(path.parts), str(path)),
    )]
    previous_modes = [
        (path, stat.S_IMODE(path.stat().st_mode)) for path in directories
    ]
    try:
        for path, mode in previous_modes:
            path.chmod(mode & ~0o222)
        yield
    finally:
        for path, mode in reversed(previous_modes):
            path.chmod(mode)


def nginx_master_children(pid: int) -> frozenset[int]:
    """CI-only Linux procfs snapshot; never log host process identifiers."""
    if type(pid) is not int or pid <= 0:
        raise AssertionError("invalid disposable NGINX process identity")
    try:
        raw = Path(f"/proc/{pid}/task/{pid}/children").read_text(
            encoding="ascii"
        ).split()
        if (len(raw) > 64
                or any(len(item) > 12 or not item.isdecimal() for item in raw)):
            raise ValueError("invalid procfs children")
        return frozenset(int(item) for item in raw)
    except (OSError, UnicodeError, ValueError) as exc:
        raise AssertionError("NGINX procfs worker observation unavailable") from None


def await_worker_generation_drained(
    process: subprocess.Popen, former: frozenset[int]
) -> None:
    """Do not test post-reload behavior on an old, still-serving worker."""
    if not former:
        raise AssertionError("NGINX old worker generation not observed")
    for _ in range(200):
        if process.poll() is not None:
            raise AssertionError("NGINX master exited while draining workers")
        current = nginx_master_children(process.pid)
        if current and current.isdisjoint(former):
            return
        time.sleep(0.05)
    raise AssertionError("NGINX old worker generation did not drain")


def trusted_fixture_origin(counts, lock):
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            names = (
                ("/debian/", "/apt/"),
                ("/almalinux/10/BaseOS/x86_64/os/", "/dnf/"),
            )
            path = next(
                (mapped + self.path[len(prefix):]
                 for prefix, mapped in names if self.path.startswith(prefix)),
                None,
            )
            if path is None:
                self.send_error(404)
                return
            with lock:
                counts[path] += 1
            # Exercise every redirect class the actual renderer prohibits,
            # on both APT and DNF routes; never contact the foreign host.
            redirect_status = None
            for kind in ("apt", "dnf"):
                if path == "/" + kind + "/redirect":
                    redirect_status = 302
                for code in (301, 302, 303, 307, 308):
                    if path == f"/{kind}/redirect-{code}":
                        redirect_status = code
            if redirect_status is not None:
                self.send_response(redirect_status)
                self.send_header("Location", "http://unapproved.example.invalid/secret")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            probes = {
                READ_ONLY_APT_PATH: READ_ONLY_APT_BYTES,
                BYPASS_READY_APT_PATH: READY_APT_BYTES,
                RECOVERY_READY_APT_PATH: READY_APT_BYTES,
            }
            item = (("application/octet-stream", probes[path])
                    if path in probes else FIXTURES.get(path))
            if item is None:
                self.send_error(404)
                return
            mimetype, body = item
            if path == "/apt/dists/trixie/Release.gpg":
                credential = self.headers.get("Authorization")
                cookie = self.headers.get("Cookie")
                if credential:
                    body = b"PRIVATE-AUTH:" + credential.encode("ascii")
                elif cookie:
                    body = b"PRIVATE-COOKIE:" + cookie.encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", mimetype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=600")
            if path == "/apt/accel":
                self.send_header("X-Accel-Redirect", "/__repocache_canary")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            return

    return Origin


def self_signed(openssl: str, cert: Path, key: Path, name: str) -> None:
    run(
        openssl, "req", "-x509", "-newkey", "rsa:2048",
        "-nodes", "-days", "1", "-keyout", str(key),
        "-out", str(cert), "-subj", "/CN=" + name,
        "-addext", "subjectAltName=DNS:" + name +
        (",IP:127.0.0.1" if name == "localhost" else ""),
    )
    key.chmod(0o600)


def main() -> None:
    require(
        os.geteuid() != 0 and Path("/.dockerenv").exists()
        and os.environ.get("REPOCACHE_DISPOSABLE_NGINX_SMOKE") == "1",
        "strict generated-route runtime test only in unprivileged container",
    )
    nginx, openssl = shutil.which("nginx"), shutil.which("openssl")
    require(bool(nginx and openssl), "distribution-packaged NGINX/OpenSSL")
    with tempfile.TemporaryDirectory(prefix="repocache-generated-data-plane-") as temp:
        root = Path(temp)
        origin_cert, origin_key = root / "origin.pem", root / "origin-key.pem"
        front_cert, front_key = root / "front.pem", root / "front-key.pem"
        self_signed(openssl, origin_cert, origin_key, HOST)
        self_signed(openssl, front_cert, front_key, "localhost")
        document = json.loads(
            (ROOT / "docs/examples/server-install-v1.json").read_text("utf-8")
        )
        document["deployment"]["paths"]["cache_root"] = str(root / "cache")
        for repository in document["repositories"]:
            repository["desired_state"] = "active"
            if repository["kind"] == "dnf":
                repository["id"] = "almalinux-baseos"
            (root / "cache" / repository["id"]).mkdir(parents=True, mode=0o700)
        fragment = render_repository_nginx_bundle_candidate(
            document,
            expected_state_generation=0,
            candidate_pins_by_repository={
                repo["id"]: {HOST: ["8.8.8.8"]}
                for repo in document["repositories"]
            },
            ca_bundle_path=str(origin_cert),
        )
        require(
            fragment["authorizes_nginx_activation"] is False
            and fragment["authorizes_catalog_publication"] is False
            and fragment["http_upstream_fragment"].count(
                "server 8.8.8.8:443;"
            ) == 2,
            "production renderer first validates public numeric pins",
        )
        origin_port, frontend_port = free_port(), free_port()
        require(origin_port != frontend_port, "two distinct isolated ports")
        # TEST-ONLY numeric address remap AFTER renderer validation. This
        # substitution MUST NEVER enter deployment code or production config.
        upstream = fragment["http_upstream_fragment"].replace(
            "server 8.8.8.8:443;",
            f"server 127.0.0.1:{origin_port};",
        )
        require(
            "8.8.8.8" not in upstream and
            upstream.count(f"server 127.0.0.1:{origin_port};") == 2,
            "local fixture remaps exact two approved-renderer server lines",
        )
        locations = fragment["server_location_fragment"].replace(
            "    proxy_cache_valid 200 60s;",
            "    proxy_cache_valid 200 60s;\n"
            "    add_header X-RepoCache-Smoke $upstream_cache_status always;",
        )
        for name in (
            "client_temp", "proxy_temp", "fastcgi_temp",
            "uwsgi_temp", "scgi_temp",
        ):
            (root / name).mkdir(mode=0o700)
        config = root / "nginx.conf"
        config.write_text(
            f"pid {root / 'nginx.pid'};\n"
            f"error_log {root / 'error.log'} notice;\n"
            "worker_processes 1;\nevents { worker_connections 64; }\n"
            "http { access_log off;\n"
            f"client_body_temp_path {root / 'client_temp'};\n"
            f"proxy_temp_path {root / 'proxy_temp'};\n"
            f"fastcgi_temp_path {root / 'fastcgi_temp'};\n"
            f"uwsgi_temp_path {root / 'uwsgi_temp'};\n"
            f"scgi_temp_path {root / 'scgi_temp'};\n"
            + upstream
            + "server {\n"
            + f"listen 127.0.0.1:{frontend_port} ssl;\n"
            + "server_name localhost;\n"
            + f"ssl_certificate {front_cert};\n"
            + f"ssl_certificate_key {front_key};\n"
            + "location / { return 404; }\n"
            + "location = /__repocache_canary { internal; return 200; }\n"
            + locations
            + "}\n}\n",
            encoding="utf-8",
        )
        run(nginx, "-t", "-e", str(root / "bootstrap.log"),
            "-c", str(config), "-p", str(root))
        require(True, "stock nginx -t accepts actual project cache/HTTPS fragment")

        # Derive a client-schema-1 CANDIDATE from an actual stock nginx -T
        # parse of the *exact* generated public-pin fragments. This is a
        # separate throwaway file: the live smoke NGINX still requires its
        # deliberately mapped localhost origin and its extra HIT header.
        expected_pins = {
            repo["id"]: {HOST: ["8.8.8.8"]}
            for repo in document["repositories"]
        }
        preview_config = root / "nginx-catalog-candidate.conf"
        native_candidate_bytes = config.read_text(encoding="utf-8")
        native_candidate_bytes = native_candidate_bytes.replace(
            f"server 127.0.0.1:{origin_port};", "server 8.8.8.8:443;",
        ).replace(
            "    add_header X-RepoCache-Smoke $upstream_cache_status always;\n",
            "",
        )
        require(
            fragment["http_upstream_fragment"] in native_candidate_bytes
            and fragment["server_location_fragment"] in native_candidate_bytes,
            "exact generated reference fragments restored in temporary -T file",
        )
        preview_config.write_text(native_candidate_bytes, encoding="utf-8")
        real_dump = subprocess.run(
            [nginx, "-T", "-e", str(root / "catalog-preview.log"),
             "-c", str(preview_config), "-p", str(root)],
            capture_output=True, text=True, timeout=10, check=False,
        )
        require(real_dump.returncode == 0,
                "stock nginx -T validates exact generated candidate")
        observed_candidate = preview_derived_catalog_from_nginx_dump(
            document, candidate_pins_by_repository=expected_pins,
            ca_bundle_path=str(origin_cert),
            nginx_dump_text=real_dump.stdout,
            nginx_t_exit_code=real_dump.returncode,
        )
        require(
            observed_candidate["candidate_catalog"]["schema"] == 1
            and len(observed_candidate["candidate_catalog"]["repositories"]) == 2
            and observed_candidate["authorizes_catalog_publication"] is False
            and observed_candidate["actual_active_exposure_verified"] is False,
            "nginx -T dump only produces a non-publishable active-only candidate",
        )

        counts: collections.Counter[str] = collections.Counter()
        lock = threading.Lock()
        origin = ThreadingHTTPServer(
            ("127.0.0.1", origin_port), trusted_fixture_origin(counts, lock)
        )
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(origin_cert), str(origin_key))
        observed_sni: list[str | None] = []
        tls.set_servername_callback(
            lambda sock, name, context: observed_sni.append(name)
        )
        origin.socket = tls.wrap_socket(origin.socket, server_side=True)
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        process = subprocess.Popen(
            [nginx, "-e", str(root / "bootstrap.log"),
             "-p", str(root), "-c", str(config), "-g", "daemon off;"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            client_tls = ssl.create_default_context(cafile=str(front_cert))
            base = (
                f"https://127.0.0.1:{frontend_port}/__repocache/repos/"
            )
            for _ in range(100):
                require(process.poll() is None, "generated-route NGINX did not exit")
                try:
                    if request(
                        f"https://127.0.0.1:{frontend_port}/", client_tls
                    )[0] == 404:
                        break
                except (OSError, TimeoutError):
                    time.sleep(0.03)
            else:
                raise AssertionError("generated-route TLS endpoint never ready")
            for repository, prefix, filenames in (
                ("debian-trixie-main", "apt", (
                    "dists/trixie/InRelease",
                    "pool/main/r/repocache-fixture.deb",
                )),
                ("almalinux-baseos", "dnf", (
                    "repodata/repomd.xml",
                    "Packages/r/repocache-fixture.rpm",
                )),
            ):
                for name in filenames:
                    url = base + repository + "/" + name
                    first, second = request(url, client_tls), request(url, client_tls)
                    payload = FIXTURES["/" + prefix + "/" + name][1]
                    with lock:
                        calls = counts["/" + prefix + "/" + name]
                    require(
                        first[:3] == (200, payload, "MISS")
                        and second[:3] == (200, payload, "HIT")
                        and calls == 1,
                        "generated TLS-pinned " + prefix +
                        " route caches exact signed-shape object with one fetch",
                    )

                    # APT/DNF metadata discovery may issue HEAD before GET.
                    # On a warm GET cache, a native NGINX HEAD must not
                    # transfer a body, request another upstream object, or
                    # corrupt the subsequent verified GET representation.
                    head = request(url, client_tls, method="HEAD")
                    after_head = request(url, client_tls)
                    with lock:
                        calls_after_head = counts["/" + prefix + "/" + name]
                    require(
                        head[:3] == (200, b"", "HIT")
                        and head[3].get("Content-Length") == str(len(payload))
                        and after_head[:3] == (200, payload, "HIT")
                        and calls_after_head == 1,
                        "stock NGINX " + prefix + " HEAD/GET cache parity "
                        "retains exact body, length and one upstream GET",
                    )

            # The baseline cache-active route may close connections under
            # EACCES (observed on the first CI attempt). Do not claim that
            # read-only storage is safe with proxy_cache still enabled.
            # Instead, verify the real renderer's isolated recovery candidate
            # with a genuine nginx -t and an explicit test-only master reload.
            bypass = render_repository_nginx_bundle_candidate(
                document,
                expected_state_generation=0,
                candidate_pins_by_repository={
                    repo["id"]: {HOST: ["8.8.8.8"]}
                    for repo in document["repositories"]
                },
                ca_bundle_path=str(origin_cert),
                cache_bypass_repository_ids=("debian-trixie-main",),
            )
            require(
                bypass["cache_bypass_recovery_candidate_repository_ids"]
                == ["debian-trixie-main"]
                and bypass["cache_bypass_activation_verified"] is False
                and bypass["authorizes_nginx_activation"] is False
                and bypass["http_upstream_fragment"]
                == fragment["http_upstream_fragment"]
                and "    proxy_cache off;" in bypass["server_location_fragment"]
                and "    proxy_cache repocache_cache_almalinux_baseos;"
                in bypass["server_location_fragment"],
                "actual non-authorizing renderer bypasses only selected APT "
                "cache while preserving DNF cache and all pinned upstreams",
            )
            bypass_locations = bypass["server_location_fragment"].replace(
                "    proxy_cache_valid 200 60s;",
                "    proxy_cache_valid 200 60s;\n"
                "    add_header X-RepoCache-Smoke $upstream_cache_status always;",
            )
            normal_config = config.read_text(encoding="utf-8")
            require(
                normal_config.count(locations) == 1
                and bypass_locations != locations,
                "test-only reload changes exactly the generated location bundle",
            )
            config.write_text(
                normal_config.replace(locations, bypass_locations),
                encoding="utf-8",
            )
            run(nginx, "-t", "-e", str(root / "bypass-syntax.log"),
                "-p", str(root), "-c", str(config))
            original_workers = nginx_master_children(process.pid)
            run(nginx, "-s", "reload", "-e", str(root / "bypass-reload.log"),
                "-p", str(root), "-c", str(config))
            bypass_ready_url = (
                base + "debian-trixie-main/dists/trixie/BypassReadiness"
            )
            bypass_live = False
            for _ in range(100):
                require(process.poll() is None, "NGINX survives bypass reload")
                probe = request(bypass_ready_url, client_tls)
                if probe[:3] == (200, READY_APT_BYTES, ""):
                    bypass_live = True
                    break
                time.sleep(0.05)
            require(
                bypass_live,
                "real NGINX master switched APT to isolated cache-off recovery",
            )
            await_worker_generation_drained(process, original_workers)
            require(True, "old cache-enabled NGINX worker generation has drained")

            apt_cache = root / "cache" / "debian-trixie-main"
            probe_url = base + "debian-trixie-main/dists/trixie/Packages.gz"
            with lock:
                before_denial = counts[READ_ONLY_APT_PATH]
            with deny_cache_directory_writes(apt_cache):
                require(
                    not os.access(apt_cache, os.W_OK),
                    "rootless APT cache directory actually denies writes",
                )
                bypass_first = request(probe_url, client_tls)
                bypass_second = request(probe_url, client_tls)
                dnf_still_cached = request(
                    base + "almalinux-baseos/repodata/repomd.xml",
                    client_tls,
                )
                with lock:
                    bypass_calls = counts[READ_ONLY_APT_PATH]
                require(
                    bypass_first[:3] == (200, READ_ONLY_APT_BYTES, "")
                    and bypass_second[:3] == (200, READ_ONLY_APT_BYTES, "")
                    and bypass_calls == before_denial + 2
                    and dnf_still_cached[:3] == (
                        200, FIXTURES["/dnf/repodata/repomd.xml"][1], "HIT"
                    )
                    and process.poll() is None,
                    "validated cache-off candidate serves uncached APT upstream "
                    "during EACCES and preserves independent DNF cache HIT",
                )

            # Restore the unchanged normal route via real syntax check and
            # reload. Readiness uses a separate uncached fixture so it cannot
            # accidentally warm the EACCES recovery object under test.
            config.write_text(normal_config, encoding="utf-8")
            run(nginx, "-t", "-e", str(root / "normal-restore-syntax.log"),
                "-p", str(root), "-c", str(config))
            bypass_workers = nginx_master_children(process.pid)
            run(nginx, "-s", "reload", "-e", str(root / "normal-restore.log"),
                "-p", str(root), "-c", str(config))
            restored_ready_url = (
                base + "debian-trixie-main/dists/trixie/RecoveryReadiness"
            )
            normal_live = False
            for _ in range(100):
                require(process.poll() is None, "NGINX survives normal-mode reload")
                probe = request(restored_ready_url, client_tls)
                if probe[:2] == (200, READY_APT_BYTES) and probe[2] in (
                    "MISS", "HIT"
                ):
                    normal_live = True
                    break
                time.sleep(0.05)
            require(normal_live, "real NGINX master restored normal cache route")
            await_worker_generation_drained(process, bypass_workers)
            require(True, "old bypass NGINX worker generation has drained")
            recovered_first = request(probe_url, client_tls)
            recovered_second = request(probe_url, client_tls)
            with lock:
                recovered_origin_calls = counts[READ_ONLY_APT_PATH]
            recovery_valid = (
                recovered_first[:3] == (200, READ_ONLY_APT_BYTES, "MISS")
                and recovered_second[:3] == (200, READ_ONLY_APT_BYTES, "HIT")
                and recovered_origin_calls == before_denial + 3
                and os.access(apt_cache, os.W_OK)
                and config.read_text(encoding="utf-8") == normal_config
                and process.poll() is None
            )
            if not recovery_valid:
                # Only static HTTP status, cache state and a bounded fixture
                # request count are logged. Never print payload, key, headers,
                # request URL or arbitrary NGINX logs.
                raise AssertionError(
                    "cache recovery: "
                    f"first_status={recovered_first[0]} "
                    f"first_cache={recovered_first[2]!r} "
                    f"first_fixture={recovered_first[1] == READ_ONLY_APT_BYTES} "
                    f"second_status={recovered_second[0]} "
                    f"second_cache={recovered_second[2]!r} "
                    f"second_fixture={recovered_second[1] == READ_ONLY_APT_BYTES} "
                    f"origin_delta={recovered_origin_calls - before_denial} "
                    f"permissions_restored={os.access(apt_cache, os.W_OK)} "
                    f"config_restored={config.read_text(encoding='utf-8') == normal_config} "
                    f"nginx_alive={process.poll() is None}"
                )
            require(
                True, "reversible cache-off EACCES recovery restores APT MISS/HIT "
                "without process restart, while preserving original config",
            )
            require(
                bool(observed_sni)
                and all(sni == HOST for sni in observed_sni),
                "production renderer sends approved HTTPS upstream SNI",
            )
            private = base + "debian-trixie-main/dists/trixie/Release.gpg"
            one = request(private, client_tls,
                          headers={"Authorization": "Bearer first"})
            two = request(private, client_tls,
                          headers={"Authorization": "Bearer second"})
            public = request(private, client_tls)
            hit = request(private, client_tls)
            cookie = request(private, client_tls,
                             headers={"Cookie": "session=private"})
            require(
                one[:3] == (200, b"PRIVATE-AUTH:Bearer first", "BYPASS")
                and two[:3] == (200, b"PRIVATE-AUTH:Bearer second", "BYPASS")
                and public[:3] == (
                    200, FIXTURES["/apt/dists/trixie/Release.gpg"][1], "MISS"
                ) and hit[2] == "HIT"
                and cookie[:3] == (
                    200, b"PRIVATE-COOKIE:session=private", "BYPASS"
                ),
                "actual rendered cache excludes credential/cookie responses",
            )
            require(
                request(base + "debian-trixie-main/redirect", client_tls)[0] == 502
                and request(base + "missing/other", client_tls)[0] == 404
                and request(base + "debian-trixie-main/accel",
                            client_tls)[1] == FIXTURES["/apt/accel"][1],
                "generated pin route denies 3xx/unmanaged paths/internal redirects",
            )
            # Actual HTTPS NGINX client behavior, not a string-only render
            # assertion. None of 301/302/303/307/308 may reach a package
            # client as a followable Location, be cached, or contact a
            # foreign host; exercise independently for APT and DNF routes.
            for repository, kind in (
                ("debian-trixie-main", "apt"),
                ("almalinux-baseos", "dnf"),
            ):
                for status in (301, 302, 303, 307, 308):
                    route = base + repository + f"/redirect-{status}"
                    for attempt in range(2):
                        result = request(route, client_tls)
                        require(
                            result[0] == 502
                            and not any(k.lower() == "location" for k in result[3])
                            and b"unapproved.example.invalid" not in result[1]
                            and result[2] != "HIT",
                            f"actual {kind} upstream {status} fails closed "
                            f"without redirect, Location leak or cache HIT",
                        )
                    with lock:
                        requests = counts[f"/{kind}/redirect-{status}"]
                    require(
                        requests == 2,
                        f"actual {kind} {status} denial not cached as a success",
                    )
            # A candidate with invalid NGINX syntax must not replace the
            # running test-only generation or destroy cache availability.
            original_conf = config.read_bytes()
            damaged = original_conf.replace(
                b"proxy_ssl_verify on;",
                b"proxy_ssl_verify unsupported-value;", 1,
            )
            require(damaged != original_conf, "negative mutation is effective")
            config.write_bytes(damaged)
            rejected = subprocess.run(
                [nginx, "-t", "-e", str(root / "invalid-candidate.log"),
                 "-p", str(root), "-c", str(config)],
                text=True, capture_output=True, timeout=10, check=False,
            )
            require(
                rejected.returncode != 0,
                "stock nginx -t refuses malformed staged TLS/cache candidate",
            )
            # Explicitly recheck the already-cached object while the
            # malformed candidate is on disk. No reload was attempted.
            stable = request(
                base + "debian-trixie-main/dists/trixie/InRelease",
                client_tls,
            )
            require(
                stable[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT",
                ) and process.poll() is None,
                "rejected candidate leaves actual running service/cache usable",
            )
            config.write_bytes(original_conf)
            run(nginx, "-t", "-e", str(root / "restored-candidate.log"),
                "-p", str(root), "-c", str(config))
            require(True, "verified good config restored in disposable fixture")

            # Exercise actual NGINX master reloads and a reversible routing
            # change while keeping the SAME real TLS listener and cache zone.
            # This is never an operator/root reload helper or production API.
            probe = f"https://127.0.0.1:{frontend_port}/__repocache_reload_probe"
            require(
                request(probe, client_tls)[0] == 404,
                "previous running generation does not expose proposed route",
            )
            staged = original_conf.replace(
                b"location = /__repocache_canary { internal; return 200; }",
                b"location = /__repocache_canary { internal; return 200; }\n"
                b"location = /__repocache_reload_probe { return 204; }",
            )
            require(
                staged != original_conf,
                "test-only managed NGINX reload candidate changes one fixed route",
            )
            config.write_bytes(staged)
            run(nginx, "-t", "-e", str(root / "staged-reload.log"),
                "-p", str(root), "-c", str(config))
            run(nginx, "-s", "reload", "-e", str(root / "staged-reload.log"),
                "-p", str(root), "-c", str(config))
            changed_live = False
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError("running NGINX exited during valid reload")
                if request(probe, client_tls)[0] == 204:
                    changed_live = True
                    break
                time.sleep(0.05)
            require(
                changed_live,
                "real NGINX master accepted staged route after validated reload",
            )
            cached_during_reload = request(
                base + "debian-trixie-main/dists/trixie/InRelease", client_tls,
            )
            require(
                cached_during_reload[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT",
                ),
                "TLS/cache remained usable after actual successful reload",
            )

            # Revert the temporary route with another genuine NGINX reload
            # and verify the old route set is once again what is exposed.
            config.write_bytes(original_conf)
            run(nginx, "-t", "-e", str(root / "rollback-reload.log"),
                "-p", str(root), "-c", str(config))
            run(nginx, "-s", "reload", "-e", str(root / "rollback-reload.log"),
                "-p", str(root), "-c", str(config))
            rolled_back = False
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError("running NGINX exited during rollback")
                if request(probe, client_tls)[0] == 404:
                    rolled_back = True
                    break
                time.sleep(0.05)
            require(
                rolled_back,
                "real rollback reload restores original route exposure",
            )
            stable_after_rollback = request(
                base + "debian-trixie-main/dists/trixie/InRelease", client_tls,
            )
            with lock:
                origin_requests = counts["/apt/dists/trixie/InRelease"]
            require(
                stable_after_rollback[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT",
                ) and origin_requests == 1
                and config.read_bytes() == original_conf
                and process.poll() is None,
                "rollback restores exact config and existing TLS/cache HIT without refetch",
            )

            # Normal repository removal MUST withdraw its *live* NGINX
            # route without deleting retained cache objects or interrupting
            # independent APT access. This is a disposable, nonroot fixture:
            # a production state/catalog transaction is NOT implemented here.
            dnf_url = base + "almalinux-baseos/repodata/repomd.xml"
            apt_url = base + "debian-trixie-main/dists/trixie/InRelease"
            retained_root = root / "cache" / "almalinux-baseos"
            def retained_snapshot():
                return {
                    str(item.relative_to(retained_root)): (
                        hashlib.sha256(item.read_bytes()).hexdigest(),
                        item.stat().st_ino,
                    )
                    for item in retained_root.rglob("*") if item.is_file()
                }
            retained_before = retained_snapshot()
            require(
                bool(retained_before)
                and request(dnf_url, client_tls)[:3] ==
                    (200, FIXTURES["/dnf/repodata/repomd.xml"][1], "HIT"),
                "native DNF cache holds real on-disk objects before removal",
            )
            removed = copy.deepcopy(document)
            removed["repositories"] = [
                repo for repo in removed["repositories"]
                if repo["id"] != "almalinux-baseos"
            ]
            surviving_pins = {"debian-trixie-main": {HOST: ["8.8.8.8"]}}
            withdrawal = render_repository_nginx_bundle_candidate(
                removed, expected_state_generation=0,
                candidate_pins_by_repository=surviving_pins,
                ca_bundle_path=str(origin_cert),
            )
            require(
                withdrawal["proposed_repository_ids"] == ["debian-trixie-main"]
                and not withdrawal["authorizes_nginx_activation"]
                and not withdrawal["authorizes_catalog_publication"]
                and withdrawal["http_upstream_fragment"].count(
                    "proxy_cache_path "
                ) == 1,
                "normal removal candidate omits exactly the DNF cache zone",
            )
            withdrawn_upstream = withdrawal["http_upstream_fragment"].replace(
                "server 8.8.8.8:443;",
                f"server 127.0.0.1:{origin_port};",
            )
            withdrawn_locations = withdrawal["server_location_fragment"].replace(
                "    proxy_cache_valid 200 60s;",
                "    proxy_cache_valid 200 60s;\n"
                "    add_header X-RepoCache-Smoke $upstream_cache_status always;",
            )
            normal_text = original_conf.decode("utf-8")
            require(
                normal_text.count(upstream) == 1
                and normal_text.count(locations) == 1,
                "removal fixture identifies exact original generated fragments",
            )
            withdrawn_text = normal_text.replace(
                upstream, withdrawn_upstream, 1,
            ).replace(locations, withdrawn_locations, 1)
            require(
                withdrawn_text != normal_text
                and "repocache_cache_almalinux_baseos" not in withdrawn_text
                and "location ^~ /__repocache/repos/almalinux-baseos/" not
                    in withdrawn_text,
                "removed DNF repository has no remaining generated exposure",
            )
            config.write_text(withdrawn_text, encoding="utf-8")
            run(nginx, "-t", "-e", str(root / "remove-syntax.log"),
                "-p", str(root), "-c", str(config))

            # The separately generated public-pin -T file verifies the
            # read-only active-only discovery projection. Neither this
            # temporary -T text nor the live fixture publishes a catalog.
            removed_catalog_conf = root / "removed-catalog-candidate.conf"
            removed_catalog_conf.write_text(
                withdrawn_text.replace(
                    f"server 127.0.0.1:{origin_port};",
                    "server 8.8.8.8:443;",
                ).replace(
                    "    add_header X-RepoCache-Smoke $upstream_cache_status always;\n",
                    "",
                ), encoding="utf-8",
            )
            removed_dump = subprocess.run(
                [nginx, "-T", "-e", str(root / "removed-catalog-syntax.log"),
                 "-p", str(root), "-c", str(removed_catalog_conf)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            require(
                removed_dump.returncode == 0,
                "stock nginx -T validates reduced candidate before live reload",
            )
            projected = preview_derived_catalog_from_nginx_dump(
                removed, candidate_pins_by_repository=surviving_pins,
                ca_bundle_path=str(origin_cert),
                nginx_dump_text=removed_dump.stdout,
                nginx_t_exit_code=removed_dump.returncode,
            )
            require(
                len(projected["candidate_catalog"]["repositories"]) == 1
                and projected["desired_active_repository_ids"]
                    == ["debian-trixie-main"]
                and projected["authorizes_catalog_publication"] is False
                and projected["actual_active_exposure_verified"] is False,
                "derived catalog candidate withdraws removed DNF entry",
            )
            removal_workers = nginx_master_children(process.pid)
            run(nginx, "-s", "reload", "-e", str(root / "remove-reload.log"),
                "-p", str(root), "-c", str(config))
            await_worker_generation_drained(process, removal_workers)
            refused = request(dnf_url, client_tls)
            continued = request(apt_url, client_tls)
            require(
                refused[0] == 404
                and continued[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT",
                ) and retained_snapshot() == retained_before
                and process.poll() is None,
                "real NGINX route removal returns 404; APT stays HIT and "
                "all DNF cache bytes/inodes survive",
            )

            # Restore the exact original configuration through another
            # tested reload. Retained on-disk cache bytes are not proof
            # that NGINX will immediately reload its former in-memory keys.
            config.write_bytes(original_conf)
            run(nginx, "-t", "-e", str(root / "remove-restore-syntax.log"),
                "-p", str(root), "-c", str(config))
            removed_workers = nginx_master_children(process.pid)
            run(nginx, "-s", "reload", "-e", str(root / "remove-restore.log"),
                "-p", str(root), "-c", str(config))
            await_worker_generation_drained(process, removed_workers)
            readded_first = request(dnf_url, client_tls)
            readded_second = request(dnf_url, client_tls)
            require(
                readded_first[:2] == (
                    200, FIXTURES["/dnf/repodata/repomd.xml"][1],
                ) and readded_second[:3] == (
                    200, FIXTURES["/dnf/repodata/repomd.xml"][1], "HIT",
                ) and request(apt_url, client_tls)[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT",
                ) and config.read_bytes() == original_conf
                and process.poll() is None,
                "re-add restores verified DNF bytes/HIT and unchanged APT "
                "availability under the exact prior configuration",
            )
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
            origin.shutdown()
            origin.server_close()
            thread.join(timeout=5)
    print("PASS: actual generated pinned TLS/cache fragments carried 4 MISS/HIT objects")
    print("NOT VERIFIED: real authenticated DNS, signed package origin, host activation/systemd/SELinux")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, OSError, subprocess.TimeoutExpired) as e:
        print("FAIL: generated pinned NGINX cache test: " + str(e),
              file=sys.stderr)
        raise SystemExit(1)
