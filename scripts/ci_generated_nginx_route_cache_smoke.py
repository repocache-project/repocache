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
from repocache.server_repository_plan_v1 import (
    plan_batch_repository_removals,
    plan_repository_change,
    propose_automatic_repository_id,
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
HELD_DNF_PATH = "/dnf/repodata/held-transfer"
HELD_DNF_BYTES = b"NONROOT-NGINX-INFLIGHT-TRANSFER-SURVIVES-WITHDRAWAL\n"


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


def trusted_fixture_origin(counts, lock, held_entered, held_release):
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            names = (
                ("/debian/", "/apt/"),
                ("/debian-auto/", "/apt/"),
                ("/almalinux/10/AppStream/x86_64/os/", "/dnf/"),
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
            if path == HELD_DNF_PATH:
                # Explicit barrier: test a genuine request accepted by the
                # OLD worker before the generated DNF route is withdrawn.
                # A bounded wait prevents CI hangs on an unexpected reload.
                held_entered.set()
                if not held_release.wait(timeout=12):
                    self.send_error(504)
                    return
                item = ("application/octet-stream", HELD_DNF_BYTES)
            else:
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
            self.send_header(
                "Cache-Control",
                "private, no-store" if path == HELD_DNF_PATH
                else "public, max-age=600",
            )
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
        held_entered, held_release = threading.Event(), threading.Event()
        origin = ThreadingHTTPServer(
            ("127.0.0.1", origin_port),
            trusted_fixture_origin(counts, lock, held_entered, held_release),
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
            removal_plan = plan_batch_repository_removals(
                document, current_generation=0,
                repository_ids=("almalinux-baseos",),
            )
            require(
                removal_plan["status"] == "BATCH_REMOVE_PLAN_ONLY"
                and removal_plan["retired_ids_proposed"] == ["almalinux-baseos"]
                and removal_plan["cache_retained"] is True
                and removal_plan["authorizes_state_write"] is False
                and removal_plan["authorizes_cache_purge"] is False,
                "reviewed batch removal planner retains cache and grants no write",
            )
            removed = removal_plan["candidate_document"]
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
            # A normal removal must not tear down an already accepted
            # transfer. Hold the DNF origin response behind an Event while
            # the OLD NGINX worker serves a fresh path; then SIGHUP to the
            # newly validated config and release the response before waiting
            # for the old worker to exit. Cache-Control: no-store keeps the
            # in-flight test from changing the retained-cache snapshot.
            held_url = base + "almalinux-baseos/repodata/held-transfer"
            held_result: dict[str, object] = {}

            def fetch_inflight() -> None:
                try:
                    held_result["response"] = request(held_url, client_tls)
                except Exception as exc:
                    held_result["error_type"] = type(exc).__name__

            in_flight = threading.Thread(target=fetch_inflight, daemon=True)
            in_flight.start()
            if not held_entered.wait(timeout=5):
                held_release.set()
                raise AssertionError("INFLIGHT_DNF_ORIGIN_NOT_REACHED")
            removal_workers = nginx_master_children(process.pid)
            try:
                require(in_flight.is_alive(), "DNF transfer must still be in flight")
                run(nginx, "-s", "reload", "-e", str(root / "remove-reload.log"),
                    "-p", str(root), "-c", str(config))
                require(in_flight.is_alive(),
                        "NGINX reload must preserve accepted old-worker transfer")
            finally:
                held_release.set()
            in_flight.join(timeout=8)
            require(
                not in_flight.is_alive()
                and held_result.get("response", (None, None))[:2]
                    == (200, HELD_DNF_BYTES)
                and "error_type" not in held_result,
                "accepted pre-withdrawal DNF transfer survived NGINX reload",
            )
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
                "all DNF cache bytes/inodes and the accepted transfer survive",
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

            # Real CI data-plane acceptance for a NEW administrator-added
            # supported APT repository selected only by install-v1 metadata.
            # No repository-specific production source code or CLI extension
            # is allowed. Inert ID allocation and plan remain untrusted:
            # neither authenticates the owner nor commits protected state.
            auto_candidate = copy.deepcopy(document["repositories"][0])
            del auto_candidate["id"]
            auto_candidate["upstream"]["base_url"] = (
                "https://mirror.example.invalid/debian-auto/"
            )
            all_time_ids = {repo["id"] for repo in document["repositories"]}
            auto = propose_automatic_repository_id(
                document, auto_candidate, current_generation=0,
                reserved_ids=all_time_ids,
            )
            again = propose_automatic_repository_id(
                document, copy.deepcopy(auto_candidate),
                current_generation=0, reserved_ids=frozenset(all_time_ids),
            )
            auto_id = auto["repository_id"]
            require(
                auto == again and auto["existing"] is False
                and auto["status"] == "PLAN_ONLY"
                and auto_id not in all_time_ids
                and auto_id.startswith("repo-"),
                "deterministic, distinct, untrusted automatic ID for a new APT repo",
            )
            addition = plan_repository_change(
                document, current_generation=0, operation="add",
                proposed_repository={**auto_candidate, "id": auto_id},
                reserved_ids=all_time_ids,
            )
            candidate_document = addition["candidate_document"]
            require(
                addition["changed"] is True
                and addition["id_eligibility"] == "CALLER_SNAPSHOT_ONLY"
                and len(candidate_document["repositories"]) == 3
                and len(document["repositories"]) == 2,
                "validated metadata-only add creates a candidate, not state",
            )
            repeated = plan_repository_change(
                candidate_document, current_generation=0, operation="add",
                proposed_repository={**auto_candidate, "id": auto_id},
                reserved_ids=all_time_ids | {auto_id},
            )
            require(
                repeated["changed"] is False,
                "repeated complete add is an idempotent non-authorizing plan",
            )

            # Only a disposable test-owned directory is created; the future
            # protected #31 writer must separately prove/lock real ownership.
            new_cache_root = root / "cache" / auto_id
            new_cache_root.mkdir(mode=0o700)
            added_pins = {
                item["id"]: {HOST: ["8.8.8.8"]}
                for item in candidate_document["repositories"]
            }
            added_fragment = render_repository_nginx_bundle_candidate(
                candidate_document, expected_state_generation=0,
                candidate_pins_by_repository=added_pins,
                ca_bundle_path=str(origin_cert),
            )
            require(
                added_fragment["proposed_repository_ids"]
                    == sorted((*all_time_ids, auto_id))
                and added_fragment["http_upstream_fragment"].count(
                    "proxy_cache_path "
                ) == 3
                and added_fragment["http_upstream_fragment"].count(
                    "server 8.8.8.8:443;"
                ) == 3
                and not added_fragment["authorizes_nginx_activation"]
                and not added_fragment["authorizes_catalog_publication"],
                "production renderer generated a new isolated cache zone and route",
            )
            added_upstream = added_fragment["http_upstream_fragment"].replace(
                "server 8.8.8.8:443;",
                f"server 127.0.0.1:{origin_port};",
            )
            added_locations = added_fragment["server_location_fragment"].replace(
                "    proxy_cache_valid 200 60s;",
                "    proxy_cache_valid 200 60s;\n"
                "    add_header X-RepoCache-Smoke $upstream_cache_status always;",
            )
            require(
                normal_text.count(upstream) == 1
                and normal_text.count(locations) == 1,
                "exact original nginx fragments are uniquely identified",
            )
            added_text = normal_text.replace(
                upstream, added_upstream, 1,
            ).replace(locations, added_locations, 1)
            require(
                added_text != normal_text
                and f"location ^~ /__repocache/repos/{auto_id}/" in added_text
                and added_text.count("proxy_cache_path ") == 3,
                "generated route add modifies only the disposable fixture",
            )

            # An actual packaged nginx -T proves the catalogue projection
            # refers to the new route and only the validated public-pin
            # candidate. No real catalog is written or published.
            added_public = added_text.replace(
                f"server 127.0.0.1:{origin_port};",
                "server 8.8.8.8:443;",
            ).replace(
                "    add_header X-RepoCache-Smoke $upstream_cache_status always;\n",
                "",
            )
            added_catalog_config = root / "added-catalog-candidate.conf"
            added_catalog_config.write_text(added_public, encoding="utf-8")
            added_dump = subprocess.run(
                [nginx, "-T", "-e", str(root / "added-catalog.log"),
                 "-p", str(root), "-c", str(added_catalog_config)],
                capture_output=True, text=True, check=False, timeout=10,
            )
            require(
                added_dump.returncode == 0,
                "stock nginx -T accepts newly generated three-repository candidate",
            )
            added_catalog = preview_derived_catalog_from_nginx_dump(
                candidate_document, candidate_pins_by_repository=added_pins,
                ca_bundle_path=str(origin_cert),
                nginx_dump_text=added_dump.stdout,
                nginx_t_exit_code=added_dump.returncode,
            )
            expected_cache = (
                "https://cache.example.invalid/__repocache/repos/"
                + auto_id + "/"
            )
            require(
                len(added_catalog["candidate_catalog"]["repositories"]) == 3
                and expected_cache in {
                    entry["cache"]
                    for entry in added_catalog["candidate_catalog"]["repositories"]
                }
                and added_catalog["desired_active_repository_ids"]
                    == sorted((*all_time_ids, auto_id))
                and not added_catalog["authorizes_catalog_publication"],
                "candidate discovery includes only the new validated active route",
            )

            config.write_text(added_text, encoding="utf-8")
            run(nginx, "-t", "-e", str(root / "added-syntax.log"),
                "-p", str(root), "-c", str(config))
            old_add_workers = nginx_master_children(process.pid)
            run(nginx, "-s", "reload", "-e", str(root / "added-reload.log"),
                "-p", str(root), "-c", str(config))
            await_worker_generation_drained(process, old_add_workers)
            dynamic_url = base + auto_id + "/dists/trixie/InRelease"
            with lock:
                before_dynamic_origin = counts["/apt/dists/trixie/InRelease"]
            dynamic_first = request(dynamic_url, client_tls)
            dynamic_second = request(dynamic_url, client_tls)
            with lock:
                after_dynamic_origin = counts["/apt/dists/trixie/InRelease"]
            require(
                dynamic_first[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "MISS"
                ) and dynamic_second[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT"
                ) and after_dynamic_origin == before_dynamic_origin + 1
                and request(apt_url, client_tls)[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT"
                ) and request(dnf_url, client_tls)[:3] == (
                    200, FIXTURES["/dnf/repodata/repomd.xml"][1], "HIT"
                ) and process.poll() is None,
                "real NGINX adds an unknown APT route with isolated MISS/HIT "
                "while existing APT and DNF remain cached",
            )

            def dynamic_cache_snapshot():
                return {
                    str(f.relative_to(new_cache_root)): (
                        hashlib.sha256(f.read_bytes()).hexdigest(), f.stat().st_ino
                    )
                    for f in new_cache_root.rglob("*") if f.is_file()
                }
            dynamic_bytes = dynamic_cache_snapshot()
            require(bool(dynamic_bytes),
                    "new route created genuine isolated cache bytes")
            removal = plan_repository_change(
                candidate_document, current_generation=0,
                operation="remove", repository_id=auto_id,
            )
            require(
                removal["changed"] and removal["candidate_document"] == document,
                "normal remove withdraws the new ID without cache cleanup",
            )
            config.write_bytes(original_conf)
            run(nginx, "-t", "-e", str(root / "dynamic-restore-syntax.log"),
                "-p", str(root), "-c", str(config))
            dynamic_workers = nginx_master_children(process.pid)
            run(nginx, "-s", "reload", "-e", str(root / "dynamic-restore.log"),
                "-p", str(root), "-c", str(config))
            await_worker_generation_drained(process, dynamic_workers)
            require(
                request(dynamic_url, client_tls)[0] == 404
                and dynamic_cache_snapshot() == dynamic_bytes
                and request(apt_url, client_tls)[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT"
                ) and request(dnf_url, client_tls)[:3] == (
                    200, FIXTURES["/dnf/repodata/repomd.xml"][1], "HIT"
                ) and process.poll() is None
                and config.read_bytes() == original_conf,
                "dynamic remove withdraws real TLS route, retains all cache "
                "bytes/inodes and preserves independent APT/DNF service",
            )
            future = propose_automatic_repository_id(
                document, copy.deepcopy(auto_candidate), current_generation=0,
                reserved_ids=all_time_ids | {auto_id},
            )
            require(
                future["repository_id"] != auto_id
                and future["id_eligibility"] == "CALLER_SNAPSHOT_ONLY",
                "retired ID is not reused in a supplied all-time snapshot",
            )

            # Repeat the same *real* data-driven lifecycle for a previously
            # unknown DNF repository. The third-party origin is a disposable
            # signed-shape fixture; the actual production generic renderer,
            # not code for a named package, creates the DNF route/cache.
            dnf_candidate = copy.deepcopy(document["repositories"][1])
            del dnf_candidate["id"]
            dnf_candidate["upstream"]["base_url"] = (
                "https://mirror.example.invalid/almalinux/10/AppStream/x86_64/os/"
            )
            recorded_ids = all_time_ids | {auto_id}
            dnf_auto = propose_automatic_repository_id(
                document, dnf_candidate, current_generation=0,
                reserved_ids=recorded_ids,
            )
            dnf_id = dnf_auto["repository_id"]
            require(
                dnf_auto["existing"] is False and dnf_id not in recorded_ids
                and dnf_auto["id_eligibility"] == "CALLER_SNAPSHOT_ONLY",
                "new DNF metadata obtains a new candidate ID without source edits",
            )
            dnf_add = plan_repository_change(
                document, current_generation=0, operation="add",
                proposed_repository={**dnf_candidate, "id": dnf_id},
                reserved_ids=recorded_ids,
            )
            dnf_document = dnf_add["candidate_document"]
            require(
                dnf_add["changed"]
                and len(dnf_document["repositories"]) == 3
                and len(document["repositories"]) == 2,
                "DNF metadata-only plan adds exactly one inert repository",
            )
            dnf_cache_root = root / "cache" / dnf_id
            dnf_cache_root.mkdir(mode=0o700)
            dnf_pins = {
                item["id"]: {HOST: ["8.8.8.8"]}
                for item in dnf_document["repositories"]
            }
            dnf_render = render_repository_nginx_bundle_candidate(
                dnf_document, expected_state_generation=0,
                candidate_pins_by_repository=dnf_pins,
                ca_bundle_path=str(origin_cert),
            )
            require(
                dnf_render["proposed_repository_ids"]
                    == sorted((*all_time_ids, dnf_id))
                and dnf_render["http_upstream_fragment"].count(
                    "proxy_cache_path "
                ) == 3
                and not dnf_render["authorizes_nginx_activation"]
                and not dnf_render["authorizes_catalog_publication"],
                "new DNF cache zone and route are generated without grants",
            )
            dnf_upstream = dnf_render["http_upstream_fragment"].replace(
                "server 8.8.8.8:443;",
                f"server 127.0.0.1:{origin_port};",
            )
            dnf_locations = dnf_render["server_location_fragment"].replace(
                "    proxy_cache_valid 200 60s;",
                "    proxy_cache_valid 200 60s;\n"
                "    add_header X-RepoCache-Smoke $upstream_cache_status always;",
            )
            dnf_live_text = normal_text.replace(
                upstream, dnf_upstream, 1,
            ).replace(locations, dnf_locations, 1)
            require(
                dnf_live_text != normal_text
                and f"location ^~ /__repocache/repos/{dnf_id}/"
                    in dnf_live_text,
                "generated DNF route is present only in disposable candidate",
            )
            dnf_public = dnf_live_text.replace(
                f"server 127.0.0.1:{origin_port};",
                "server 8.8.8.8:443;",
            ).replace(
                "    add_header X-RepoCache-Smoke $upstream_cache_status always;\n",
                "",
            )
            dnf_catalog_conf = root / "dnf-added-catalog-candidate.conf"
            dnf_catalog_conf.write_text(dnf_public, encoding="utf-8")
            dnf_dump = subprocess.run(
                [nginx, "-T", "-e", str(root / "dnf-added-catalog.log"),
                 "-p", str(root), "-c", str(dnf_catalog_conf)],
                capture_output=True, text=True, check=False, timeout=10,
            )
            require(dnf_dump.returncode == 0,
                    "stock nginx -T accepts new DNF repository config")
            dnf_catalog = preview_derived_catalog_from_nginx_dump(
                dnf_document, candidate_pins_by_repository=dnf_pins,
                ca_bundle_path=str(origin_cert),
                nginx_dump_text=dnf_dump.stdout,
                nginx_t_exit_code=dnf_dump.returncode,
            )
            require(
                len(dnf_catalog["candidate_catalog"]["repositories"]) == 3
                and dnf_id in dnf_catalog["desired_active_repository_ids"]
                and not dnf_catalog["authorizes_catalog_publication"],
                "real nginx -T includes new DNF route only in inert catalog",
            )

            config.write_text(dnf_live_text, encoding="utf-8")
            run(nginx, "-t", "-e", str(root / "dnf-added-syntax.log"),
                "-p", str(root), "-c", str(config))
            old_dnf_workers = nginx_master_children(process.pid)
            run(nginx, "-s", "reload", "-e", str(root / "dnf-added-reload.log"),
                "-p", str(root), "-c", str(config))
            await_worker_generation_drained(process, old_dnf_workers)
            dynamic_dnf_url = base + dnf_id + "/repodata/repomd.xml"
            with lock:
                before_new_dnf = counts["/dnf/repodata/repomd.xml"]
            dnf_first = request(dynamic_dnf_url, client_tls)
            dnf_second = request(dynamic_dnf_url, client_tls)
            with lock:
                after_new_dnf = counts["/dnf/repodata/repomd.xml"]
            require(
                dnf_first[:3] == (
                    200, FIXTURES["/dnf/repodata/repomd.xml"][1], "MISS"
                ) and dnf_second[:3] == (
                    200, FIXTURES["/dnf/repodata/repomd.xml"][1], "HIT"
                ) and after_new_dnf == before_new_dnf + 1
                and request(apt_url, client_tls)[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT"
                ) and request(dnf_url, client_tls)[:3] == (
                    200, FIXTURES["/dnf/repodata/repomd.xml"][1], "HIT"
                ) and process.poll() is None,
                "new DNF repository has isolated real MISS/HIT with no "
                "interruption to existing APT/DNF cache",
            )
            def dynamic_dnf_bytes():
                return {
                    str(f.relative_to(dnf_cache_root)): (
                        hashlib.sha256(f.read_bytes()).hexdigest(), f.stat().st_ino
                    )
                    for f in dnf_cache_root.rglob("*") if f.is_file()
                }
            dnf_retained = dynamic_dnf_bytes()
            require(bool(dnf_retained), "new DNF cache has retained bytes")
            dnf_removal = plan_repository_change(
                dnf_document, current_generation=0,
                operation="remove", repository_id=dnf_id,
            )
            require(
                dnf_removal["changed"]
                and dnf_removal["candidate_document"] == document,
                "normal DNF removal proposes route withdrawal without purge",
            )
            config.write_bytes(original_conf)
            run(nginx, "-t", "-e", str(root / "dnf-remove-syntax.log"),
                "-p", str(root), "-c", str(config))
            active_dnf_workers = nginx_master_children(process.pid)
            run(nginx, "-s", "reload", "-e", str(root / "dnf-remove-reload.log"),
                "-p", str(root), "-c", str(config))
            await_worker_generation_drained(process, active_dnf_workers)
            require(
                request(dynamic_dnf_url, client_tls)[0] == 404
                and dynamic_dnf_bytes() == dnf_retained
                and request(apt_url, client_tls)[:3] == (
                    200, FIXTURES["/apt/dists/trixie/InRelease"][1], "HIT"
                ) and request(dnf_url, client_tls)[:3] == (
                    200, FIXTURES["/dnf/repodata/repomd.xml"][1], "HIT"
                ) and process.poll() is None
                and config.read_bytes() == original_conf,
                "DNF dynamic withdrawal preserves bytes/inodes, original "
                "APT/DNF cache and running NGINX",
            )
            future_dnf = propose_automatic_repository_id(
                document, copy.deepcopy(dnf_candidate), current_generation=0,
                reserved_ids=recorded_ids | {dnf_id},
            )
            require(
                future_dnf["repository_id"] != dnf_id,
                "new DNF tombstone also blocks candidate ID reuse",
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
