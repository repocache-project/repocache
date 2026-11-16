#!/usr/bin/env python3
"""Exercise real ENOSPC and read-only mounts with cache-off candidates (#97).

This is a rootless throwaway Linux container integration test. It never mounts
or fills an actual host filesystem, mutates installed NGINX, invokes systemd,
or authorizes a deployed cache/NGINX transaction. TLS and metadata payloads
are generated disposable fixtures, not publisher-signed client data.
"""
from __future__ import annotations

import collections
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

from ci_generated_nginx_route_cache_smoke import (
    HOST, await_worker_generation_drained, nginx_master_children,
    self_signed, trusted_fixture_origin,
)
from ci_native_nginx_cache_smoke import FIXTURES, ROOT, free_port, request, run
from repocache.server_cache_bypass_decision_v1 import (
    preview_cache_pressure_nginx_recovery_candidate,
)
from repocache.server_cache_pressure_observe_v1 import _capacity
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)

MOUNT = Path("/repocache-ci-enospc")
READ_ONLY_MOUNT = Path("/repocache-ci-readonly")
MAX_TEST_VOLUME_BYTES = 8 * 1024 * 1024
MIN_TEST_VOLUME_BYTES = 3 * 1024 * 1024
WRITE_CHUNK = b"X" * (64 * 1024)
MAX_FILL_ATTEMPTS = 128
APT_ID = "debian-trixie-main"
DNF_ID = "almalinux-baseos"
WARM = (
    (APT_ID, "/apt/dists/trixie/InRelease", "dists/trixie/InRelease"),
    (DNF_ID, "/dnf/repodata/repomd.xml", "repodata/repomd.xml"),
)
COLD = (
    (APT_ID, "/apt/pool/main/r/repocache-fixture.deb",
     "pool/main/r/repocache-fixture.deb"),
    (DNF_ID, "/dnf/Packages/r/repocache-fixture.rpm",
     "Packages/r/repocache-fixture.rpm"),
)


def verify_disposable_scope() -> None:
    """Never permit a host disk fill or silently broaden the test volume."""
    if (os.geteuid() == 0
            or os.environ.get("REPOCACHE_DISPOSABLE_ENOSPC_TEST") != "1"
            or not Path("/.dockerenv").is_file()
            or not MOUNT.is_dir()
            or not os.path.ismount(MOUNT)):
        raise RuntimeError("DISPOSABLE_ROOTLESS_TMPFS_REQUIRED")
    fs = os.statvfs(MOUNT)
    total = fs.f_blocks * fs.f_frsize
    available = fs.f_bavail * fs.f_frsize
    if (not MIN_TEST_VOLUME_BYTES <= total <= MAX_TEST_VOLUME_BYTES
            or available < 2 * 1024 * 1024):
        raise RuntimeError("DEDICATED_BOUNDED_TMPFS_NOT_VERIFIED")
    # Docker's dedicated ephemeral tmpfs is the only accepted target.
    with open("/proc/self/mountinfo", encoding="utf-8") as handle:
        mounts = [line.split(" - ", 1) for line in handle if " - " in line]
    if not any(
        len(parts) == 2 and len(parts[0].split()) > 4
        and parts[0].split()[4] == str(MOUNT)
        and parts[1].split()[0] == "tmpfs"
        for parts in mounts
    ):
        raise RuntimeError("DEDICATED_TMPFS_MOUNT_IDENTITY_UNVERIFIED")


def available_bytes(cache: Path) -> int:
    fs = os.statvfs(cache)
    return fs.f_bavail * fs.f_frsize


def fill_until_real_enospc(cache: Path) -> Path:
    """Write only into the prechecked 3–8 MiB container-private filesystem."""
    if not cache.is_dir() or cache.is_symlink():
        raise AssertionError("UNSAFE_DISPOSABLE_CACHE_DIRECTORY")
    path = cache / ".ci-test-fill"
    hit_enospc = False
    with path.open("xb", buffering=0) as handle:
        for _ in range(MAX_FILL_ATTEMPTS):
            try:
                handle.write(WRITE_CHUNK)
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                hit_enospc = True
                break
    if not hit_enospc or available_bytes(cache) >= 1024 * 1024:
        raise AssertionError("ACTUAL_BOUNDED_ENOSPC_NOT_OBSERVED")
    return path


def cached_hashes(cache: Path) -> dict[str, str]:
    """Record byte identity of preexisting files; exclude our fill fixture."""
    return {
        str(entry.relative_to(cache)): hashlib.sha256(entry.read_bytes()).hexdigest()
        for entry in cache.rglob("*")
        if entry.is_file() and entry.name != ".ci-test-fill"
    }


def validated_document(cache: Path) -> tuple[dict, dict]:
    doc = json.loads(
        (ROOT / "docs/examples/server-install-v1.json").read_text("utf-8")
    )
    doc["deployment"]["paths"]["cache_root"] = str(cache)
    pressure = doc["deployment"]["cache_policy"]["disk_pressure"]
    # Bounded disposable-only thresholds, no production policy adjustment.
    pressure["warning_free_bytes"] = 2 * 1024 * 1024
    pressure["critical_free_bytes"] = 1 * 1024 * 1024
    for row in doc["repositories"]:
        row["desired_state"] = "active"
        if row["kind"] == "dnf":
            row["id"] = DNF_ID
        (cache / row["id"]).mkdir(mode=0o700)
    return doc, {row["id"]: {HOST: ["8.8.8.8"]} for row in doc["repositories"]}


def render_test_config(
    root: Path, candidate: dict, *, origin_port: int, frontend_port: int,
    origin_cert: Path, frontend_cert: Path, frontend_key: Path,
) -> str:
    """Substitute a fixed loopback origin ONLY after production pin validation."""
    fragment = candidate["nginx_candidate"] if "nginx_candidate" in candidate else candidate
    upstream = fragment["http_upstream_fragment"].replace(
        "server 8.8.8.8:443;", f"server 127.0.0.1:{origin_port};"
    )
    if (upstream.count(f"server 127.0.0.1:{origin_port};") != 2
            or "8.8.8.8" in upstream
            or fragment["authorizes_nginx_activation"] is not False):
        raise AssertionError("FIXTURE_PIN_REMAP_UNVERIFIED")
    locations = fragment["server_location_fragment"].replace(
        "    proxy_cache_valid 200 60s;",
        "    proxy_cache_valid 200 60s;\n"
        "    add_header X-RepoCache-Smoke $upstream_cache_status always;",
    )
    temp_dirs = ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
    for name in temp_dirs:
        (root / name).mkdir(mode=0o700, exist_ok=True)
    return (
        f"pid {root / 'nginx.pid'};\n"
        f"error_log {root / 'nginx-error.log'} notice;\n"
        "worker_processes 1;\nevents { worker_connections 128; }\n"
        "http { access_log off;\n"
        + "".join(
            f"{'client_body' if name == 'client_body' else name}_temp_path "
            f"{root / name};\n"
            for name in temp_dirs
        )
        + upstream
        + f"server {{ listen 127.0.0.1:{frontend_port} ssl;\n"
        + "server_name localhost;\n"
        + f"ssl_certificate {frontend_cert};\n"
        + f"ssl_certificate_key {frontend_key};\n"
        + "location / { return 404; }\n"
        + locations
        + "}\n}\n"
    )


def assert_nginx_syntax(nginx: str, root: Path, conf: Path) -> None:
    run(nginx, "-t", "-p", str(root), "-c", str(conf))


def start_test_nginx(nginx: str, root: Path, conf: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [nginx, "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_for_test_nginx(
    process: subprocess.Popen, url_root: str, context: ssl.SSLContext,
) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError("DISPOSABLE_NGINX_DIED")
        try:
            if request(url_root + "/", context)[0] == 404:
                return
        except (OSError, TimeoutError):
            time.sleep(0.05)
    raise AssertionError("DISPOSABLE_NGINX_NOT_READY")


def stop_test_nginx(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=6)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=4)


def read_only_capacity() -> tuple[int, int]:
    fd = os.open(READ_ONLY_MOUNT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        free_bytes, free_inodes, read_only = _capacity(fd)
        if not read_only:
            raise AssertionError("READ_ONLY_MOUNT_FLAG_NOT_OBSERVED")
        # Probe only the pinned, confirmed read-only test mount. Successful
        # creation would contradict the mount observation and fail the job.
        try:
            probe_fd = os.open(".write-probe", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                               0o600, dir_fd=fd)
        except OSError as exc:
            if exc.errno != errno.EROFS:
                raise
        else:
            os.close(probe_fd)
            raise AssertionError("KERNEL_READ_ONLY_WRITE_REFUSAL_NOT_OBSERVED")
    finally:
        os.close(fd)
    return free_bytes, free_inodes


def assert_uncached_origin(
    url_root: str, context: ssl.SSLContext, counts: collections.Counter[str],
) -> None:
    for repo_id, fixture, suffix in COLD:
        uri = f"{url_root}/__repocache/repos/{repo_id}/{suffix}"
        expected = FIXTURES[fixture][1]
        before = counts[fixture]
        first, second = request(uri, context), request(uri, context)
        if (first[:2] != (200, expected)
                or second[:2] != (200, expected)
                or first[2] == "HIT" or second[2] == "HIT"
                or counts[fixture] != before + 2):
            raise AssertionError("CACHE_OFF_UPSTREAM_BYTES_UNVERIFIED")


def main() -> None:
    verify_disposable_scope()
    nginx = shutil.which("nginx")
    openssl = shutil.which("openssl")
    if nginx != "/usr/sbin/nginx" or not openssl:
        raise RuntimeError("STOCK_DISTRIBUTION_TOOLS_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="repocache-enospc-") as outer:
        root = Path(outer)
        with tempfile.TemporaryDirectory(prefix="rc-cache-", dir=MOUNT) as inner:
            cache = Path(inner)
            doc, pins = validated_document(cache)
            origin_cert, origin_key = root / "origin.crt", root / "origin.key"
            front_cert, front_key = root / "front.crt", root / "front.key"
            self_signed(openssl, origin_cert, origin_key, HOST)
            self_signed(openssl, front_cert, front_key, "localhost")
            origin_port, frontend_port = free_port(), free_port()
            if origin_port == frontend_port:
                raise AssertionError("PORT_COLLISION")
            counts: collections.Counter[str] = collections.Counter()
            lock = threading.Lock()
            origin = ThreadingHTTPServer(
                ("127.0.0.1", origin_port), trusted_fixture_origin(counts, lock)
            )
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(str(origin_cert), str(origin_key))
            origin.socket = tls.wrap_socket(origin.socket, server_side=True)
            origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
            origin_thread.start()

            base = render_repository_nginx_bundle_candidate(
                doc, expected_state_generation=0,
                candidate_pins_by_repository=pins,
                ca_bundle_path=str(origin_cert),
            )
            conf = root / "nginx.conf"
            conf.write_text(
                render_test_config(
                    root, base, origin_port=origin_port,
                    frontend_port=frontend_port,
                    origin_cert=origin_cert, frontend_cert=front_cert,
                    frontend_key=front_key,
                ), encoding="ascii",
            )
            assert_nginx_syntax(nginx, root, conf)
            process = start_test_nginx(nginx, root, conf)
            try:
                url_root = f"https://127.0.0.1:{frontend_port}"
                context = ssl.create_default_context(cafile=str(front_cert))
                wait_for_test_nginx(process, url_root, context)
                for repo_id, fixture, suffix in WARM:
                    uri = f"{url_root}/__repocache/repos/{repo_id}/{suffix}"
                    expected = FIXTURES[fixture][1]
                    one, two = request(uri, context), request(uri, context)
                    if (one[:3] != (200, expected, "MISS")
                            or two[:3] != (200, expected, "HIT")
                            or counts[fixture] != 1):
                        raise AssertionError("WARM_APT_DNF_CACHE_MISS_HIT_UNVERIFIED")
                original_bytes = cached_hashes(cache)
                if len(original_bytes) < 2:
                    raise AssertionError("WARM_CACHE_FILES_NOT_PERSISTED")

                filler = fill_until_real_enospc(cache)
                # Evidence of kernel ENOSPC is independent of any NGINX
                # HTTP error: unbypassed NGINX may drop an upstream response.
                exhausted = available_bytes(cache)
                if exhausted > doc["deployment"]["cache_policy"]["disk_pressure"]["critical_free_bytes"]:
                    raise AssertionError("CRITICAL_DISK_PRESSURE_NOT_OBSERVED")
                decision = preview_cache_pressure_nginx_recovery_candidate(
                    doc, expected_state_generation=0,
                    candidate_pins_by_repository=pins,
                    ca_bundle_path=str(origin_cert),
                    free_bytes=exhausted, free_inodes=256,
                    disk_writable=False, measurements_complete=True,
                    recovery_margin_bytes=64 * 1024,
                )
                if (decision["decision_code"] != "PROPOSE_BYPASS_ON_OBSERVED_CRITICAL"
                        or decision["bypass_repository_ids"] != [DNF_ID, APT_ID]
                        or decision["authorizes_nginx_reload"] is not False):
                    raise AssertionError("CRITICAL_BYPASS_PROPOSAL_UNVERIFIED")
                normal_config = conf.read_text("ascii")
                bypass_config = render_test_config(
                    root, decision, origin_port=origin_port,
                    frontend_port=frontend_port,
                    origin_cert=origin_cert, frontend_cert=front_cert,
                    frontend_key=front_key,
                )
                if (bypass_config.count("    proxy_cache off;") != 2
                        or normal_config == bypass_config):
                    raise AssertionError("CRITICAL_CACHE_OFF_NOT_RENDERED")
                old_workers = nginx_master_children(process.pid)
                conf.write_text(bypass_config, encoding="ascii")
                assert_nginx_syntax(nginx, root, conf)
                process.send_signal(signal.SIGHUP)  # Only our own test process
                await_worker_generation_drained(process, old_workers)

                assert_uncached_origin(url_root, context, counts)
                for item, digest in original_bytes.items():
                    if hashlib.sha256((cache / item).read_bytes()).hexdigest() != digest:
                        raise AssertionError("PREEXISTING_CACHE_BYTES_MODIFIED")

                filler.unlink()
                recovered_bytes = available_bytes(cache)
                if recovered_bytes <= 2 * 1024 * 1024 + 64 * 1024:
                    raise AssertionError("FREE_SPACE_NOT_RECOVERED")
                restored = preview_cache_pressure_nginx_recovery_candidate(
                    doc, expected_state_generation=0,
                    candidate_pins_by_repository=pins,
                    ca_bundle_path=str(origin_cert),
                    free_bytes=recovered_bytes, free_inodes=256,
                    disk_writable=True, measurements_complete=True,
                    recovery_margin_bytes=64 * 1024,
                    previous_alarm=decision["alarm_candidate"]["next_state"],
                    previously_bypassed_ids=(DNF_ID, APT_ID),
                )
                if (restored["decision_code"] != "PROPOSE_RESTORE_AFTER_VERIFIED_RECOVERY"
                        or restored["bypass_repository_ids"]
                        or restored["nginx_candidate"] != base):
                    raise AssertionError("RECOVERED_NORMAL_CANDIDATE_UNVERIFIED")
                old_workers = nginx_master_children(process.pid)
                conf.write_text(normal_config, encoding="ascii")
                assert_nginx_syntax(nginx, root, conf)
                process.send_signal(signal.SIGHUP)
                await_worker_generation_drained(process, old_workers)

                for repo_id, fixture, suffix in WARM:
                    uri = f"{url_root}/__repocache/repos/{repo_id}/{suffix}"
                    expected = FIXTURES[fixture][1]
                    before = counts[fixture]
                    if request(uri, context)[:3] != (200, expected, "HIT"):
                        raise AssertionError("WARM_CACHE_NOT_RETAINED_AFTER_RECOVERY")
                    if counts[fixture] != before:
                        raise AssertionError("RECOVERY_UNEXPECTED_UPSTREAM_FETCH")
                for repo_id, fixture, suffix in COLD:
                    uri = f"{url_root}/__repocache/repos/{repo_id}/{suffix}"
                    expected = FIXTURES[fixture][1]
                    before = counts[fixture]
                    if (request(uri, context)[:3] != (200, expected, "MISS")
                            or request(uri, context)[:3] != (200, expected, "HIT")
                            or counts[fixture] != before + 1):
                        raise AssertionError("REACTIVATED_CACHE_MISS_HIT_UNVERIFIED")
                if process.poll() is not None:
                    raise AssertionError("NGINX_MASTER_NOT_ALIVE_AFTER_RECOVERY")
                print("PASS: bounded real tmpfs ENOSPC; validated cache-off reload, "
                      "exact uncached APT/DNF upstream fixture bytes, retained warm "
                      "cache hashes, hysteresis restore and MISS/HIT recovery")

                readonly_bytes, readonly_inodes = read_only_capacity()
                pressure = doc["deployment"]["cache_policy"]["disk_pressure"]
                warning = pressure["warning_free_bytes"]
                if readonly_bytes <= warning or readonly_inodes == 0:
                    raise AssertionError("READ_ONLY_FAILURE_NOT_ISOLATED_FROM_CAPACITY")
                readonly_files = cached_hashes(READ_ONLY_MOUNT)
                if set(readonly_files) != {f"{APT_ID}/fixture"}:
                    raise AssertionError("READ_ONLY_CACHE_FIXTURE_MISSING")
                readonly_doc = copy.deepcopy(doc)
                readonly_doc["deployment"]["paths"]["cache_root"] = str(READ_ONLY_MOUNT)
                readonly_candidate = preview_cache_pressure_nginx_recovery_candidate(
                    readonly_doc, expected_state_generation=0,
                    candidate_pins_by_repository=pins, ca_bundle_path=str(origin_cert),
                    free_bytes=readonly_bytes, free_inodes=readonly_inodes,
                    disk_writable=False, measurements_complete=True,
                    recovery_margin_bytes=64 * 1024,
                )
                if (readonly_candidate["decision_code"] != "PROPOSE_BYPASS_ON_OBSERVED_CRITICAL"
                        or readonly_candidate["alarm_candidate"]["reason_code"] != "STORAGE_WRITE_REFUSED"
                        or readonly_candidate["bypass_repository_ids"] != [DNF_ID, APT_ID]
                        or readonly_candidate["authorizes_nginx_reload"] is not False):
                    raise AssertionError("READ_ONLY_BYPASS_PROPOSAL_UNVERIFIED")
                # NGINX cannot reuse a cache shared-memory zone across a
                # live cache path change. Start this separate mount fixture
                # with a fresh master; both reloads above keep their path.
                readonly_config = render_test_config(
                    root, readonly_candidate, origin_port=origin_port,
                    frontend_port=frontend_port, origin_cert=origin_cert,
                    frontend_cert=front_cert, frontend_key=front_key,
                )
                if readonly_config.count("    proxy_cache off;") != 2:
                    raise AssertionError("READ_ONLY_CACHE_OFF_NOT_RENDERED")
                stop_test_nginx(process)
                conf.write_text(readonly_config, encoding="ascii")
                assert_nginx_syntax(nginx, root, conf)
                process = start_test_nginx(nginx, root, conf)
                wait_for_test_nginx(process, url_root, context)
                assert_uncached_origin(url_root, context, counts)
                if cached_hashes(READ_ONLY_MOUNT) != readonly_files:
                    raise AssertionError("READ_ONLY_CACHE_FILES_CHANGED")
                print("PASS: kernel EROFS with healthy capacity; validated NGINX "
                      "cache-off startup, exact APT/DNF fixture bytes and preserved files")
                print("NOT VERIFIED: deployed NGINX, root authorization, real signed "
                      "APT/DNF payloads, native systemd/SELinux or client fallback")
            finally:
                stop_test_nginx(process)
                origin.shutdown()
                origin.server_close()
                origin_thread.join(timeout=4)


if __name__ == "__main__":
    main()
