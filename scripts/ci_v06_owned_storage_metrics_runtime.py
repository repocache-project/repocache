#!/usr/bin/env python3
"""Actual native NGINX master/worker on detached owner-marked storage (#29).

The command-line entrypoint is Docker-only. The separately guarded booted
VM probe reuses the detached exercise on Debian 13. No installed service,
real host log, package trust or SELinux acceptance is implied.
"""
from __future__ import annotations

import collections
import base64
from datetime import datetime, timezone
import grp
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

from ci_generated_nginx_route_cache_smoke import (
    await_worker_generation_drained, nginx_master_children, self_signed,
    trusted_fixture_origin,
)
from ci_native_nginx_cache_smoke import FIXTURES, HOST, ROOT, free_port, request, run
from repocache.core import Settings, metrics
from repocache.server_install_v1 import validate_os_identity, validate_server_architecture
from repocache.server_native_storage_bootstrap_v1 import bootstrap_native_nginx_storage_under_root
from repocache.server_native_repository_cache_v1 import bootstrap_repository_cache_under_root
from repocache.server_native_metrics_file_bootstrap_v1 import (
    bootstrap_private_metrics_file_under_root,
    reconcile_private_metrics_rotation_under_root,
)
from repocache.server_native_metrics_logrotate_candidate_v1 import render_native_metrics_rotation_candidate
from repocache.server_protected_namespace_bootstrap_v1 import bootstrap_protected_namespace_under_root
from repocache.server_nginx_metrics_bundle_join_v1 import render_repository_nginx_metrics_join

_MARKER = ".repocache-metrics-log.owner-v1"
_FIXED_LOG = "/var/log/nginx/repocache-managed/metrics.jsonl"
_REOPEN = "/usr/bin/systemctl kill --kill-who=main --signal=USR1 nginx.service"


def _identity(path: Path) -> tuple[int, int, int, int, int]:
    info = path.lstat()
    return info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink


def _cache_snapshot(cache: Path) -> dict[str, tuple[tuple[int, ...], str]]:
    return {str(path.relative_to(cache)): (_identity(path), hashlib.sha256(path.read_bytes()).hexdigest())
            for path in cache.rglob("*") if path.is_file()}


def _wait_for_rows(log: Path, expected: int) -> list[dict]:
    for _ in range(100):
        rows = log.read_text(encoding="utf-8").splitlines()
        if len(rows) == expected:
            return [json.loads(row) for row in rows]
        time.sleep(0.05)
    raise AssertionError("NATIVE_OWNED_METRICS_COUNT_MISMATCH")


def _rotate_and_reload(root: Path, fd: int, log: Path, process: subprocess.Popen,
                       conf: Path, profile: Path) -> None:
    """Only the known disposable child; no systemd or installed hook.

    A validated master reload starts workers with a new inherited log FD;
    do not assume a direct USR1 reopen works with a root-only log parent.
    Requests are quiescent in this fixture until the old generation drains.
    """
    nginx = "/usr/sbin/nginx"
    previous = _identity(log)
    old_bytes = log.read_bytes()
    run(nginx, "-t", "-e", str(root / "bootstrap.log"), "-p", str(root), "-c", str(conf))
    if process.poll() is not None:
        raise AssertionError("NATIVE_OWNED_NGINX_EXITED")
    former = nginx_master_children(process.pid)
    assert former and old_bytes
    run("/usr/sbin/logrotate", "--force", "--state", str(root / "rotation.state"), str(profile))
    archive = log.with_name(log.name + ".1")
    assert _identity(archive) == previous and archive.read_bytes() == old_bytes
    assert log.stat().st_size == 0 and _identity(log)[1:] == (0, 0, 0o600, 1)
    assert _identity(log)[0] != previous[0]
    result = reconcile_private_metrics_rotation_under_root(fd, owner_uid=0, owner_gid=0)
    assert result["owner_marker_rebound"] and not result["authorizes_host_installation"]
    run(nginx, "-t", "-e", str(root / "bootstrap.log"), "-p", str(root), "-c", str(conf))
    process.send_signal(signal.SIGHUP)
    await_worker_generation_drained(process, former)
    assert _identity(log)[1:] == (0, 0, 0o600, 1)
    assert archive.read_bytes() == old_bytes and log.stat().st_size == 0
    assert not bootstrap_private_metrics_file_under_root(fd, owner_uid=0, owner_gid=0)["file_created"]


def main() -> None:
    if (os.geteuid() != 0 or not Path("/.dockerenv").is_file()
            or os.environ.get("REPOCACHE_NATIVE_OWNED_RUNTIME_CI") != "CONFIRMED_DISPOSABLE_DOCKER_ONLY"
            or Path("/proc/1/comm").read_text(encoding="ascii").strip() == "systemd"):
        raise AssertionError("DISPOSABLE_NATIVE_RUNTIME_REQUIRED")
    exercise_owned_runtime()


def exercise_owned_runtime() -> None:
    """Detached fixture only; callers must enforce their environment guard."""
    if os.geteuid() != 0 or os.getuid() != 0:
        raise AssertionError("DISPOSABLE_ROOT_RUNTIME_REQUIRED")
    distro = validate_os_identity(Path("/etc/os-release").read_text("ascii"), sys.version_info[:2])
    import platform
    validate_server_architecture(platform.machine())
    worker = pwd.getpwnam({"debian": "www-data", "almalinux": "nginx"}[distro])
    assert worker.pw_uid != 0 and worker.pw_gid != 0
    group = grp.getgrgid(worker.pw_gid).gr_name
    nginx, openssl = "/usr/sbin/nginx", "/usr/bin/openssl"
    with tempfile.TemporaryDirectory(prefix="repocache-owned-runtime-") as scratch:
        root = Path(scratch)
        root.chmod(0o755)
        for relative in ("var", "var/cache", "var/cache/nginx", "var/log", "var/log/nginx", "var/lib"):
            (root / relative).mkdir(mode=0o755)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            owners = dict(root_uid=0, cache_uid=worker.pw_uid, cache_gid=worker.pw_gid)
            cache = root / "var/cache/nginx/repocache-managed"
            log = root / "var/log/nginx/repocache-managed/metrics.jsonl"
            document = json.loads((ROOT / "docs/examples/server-install-v1.json").read_text())
            document["deployment"]["paths"]["cache_root"] = str(cache)
            document["deployment"]["logging"]["metrics_opt_in"] = True
            document["deployment"]["logging"]["retention_days"] = 3
            for repo in document["repositories"]:
                repo["desired_state"] = "active"
                if repo["kind"] == "dnf":
                    repo["id"] = "almalinux-baseos"
            ids = [repo["id"] for repo in document["repositories"]]

            def prepare(expect_fresh: bool) -> None:
                storage = bootstrap_native_nginx_storage_under_root(fd, **owners)
                assert storage["cache_directory_created"] is expect_fresh
                assert storage["log_directory_created"] is expect_fresh
                assert storage["authorizes_host_installation"] is False
                for name in ids:
                    result = bootstrap_repository_cache_under_root(fd, repository_id=name, **owners)
                    assert not result["authorizes_host_installation"]
                result = bootstrap_private_metrics_file_under_root(fd, owner_uid=0, owner_gid=0)
                assert result["file_created"] is expect_fresh
                assert result["authorizes_host_installation"] is False

            prepare(True)
            bootstrap_protected_namespace_under_root(fd, owner_uid=0)
            original_log = _identity(log)
            assert original_log[1:] == (0, 0, 0o600, 1)
            marker = log.parent.parent / _MARKER
            marker_before = marker.read_bytes()
            rotation = render_native_metrics_rotation_candidate(document)
            assert not rotation["authorizes_logrotate_installation"]
            profile = root / "rotation.conf"
            source = rotation["rotation_candidate"]
            assert source.count(_FIXED_LOG) == source.count(_REOPEN) == 1
            profile.write_text(source.replace(_FIXED_LOG, str(log)).replace(_REOPEN, "/bin/true"))
            origin_cert, origin_key = root / "origin.pem", root / "origin-key.pem"
            front_cert, front_key = root / "front.pem", root / "front-key.pem"
            self_signed(openssl, origin_cert, origin_key, HOST)
            self_signed(openssl, front_cert, front_key, "localhost")
            candidate = render_repository_nginx_metrics_join(
                document, expected_state_generation=0,
                candidate_pins_by_repository={name: {HOST: ["8.8.8.8"]} for name in ids},
                ca_bundle_path=str(origin_cert),
            )
            assert candidate["authorizes_nginx_activation"] is False
            assert candidate["http_fragment"].count("server 8.8.8.8:443;") == 2
            origin, front = free_port(), free_port()
            assert origin != front
            # The validated production pins remain unchanged in the renderer.
            # These exact substitutions exist ONLY in the isolated CI harness.
            upstream = candidate["http_fragment"].replace("server 8.8.8.8:443;", f"server 127.0.0.1:{origin};")
            assert candidate["server_fragment"].count(_FIXED_LOG) == 2
            locations = candidate["server_fragment"].replace(_FIXED_LOG, str(log))
            locations = locations.replace("    proxy_cache_valid 200 60s;",
                                          "    proxy_cache_valid 200 60s;\n    add_header X-RepoCache-Smoke $upstream_cache_status always;")
            for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
                (root / name).mkdir(mode=0o700)
                os.chown(root / name, worker.pw_uid, worker.pw_gid)
            conf = root / "nginx.conf"
            conf.write_text(
                f"user {worker.pw_name} {group};\npid {root / 'nginx.pid'};\n"
                f"error_log {root / 'nginx-error.log'} notice;\n"
                "worker_processes 1;\nevents { worker_connections 64; }\nhttp {\naccess_log off;\n"
                + "".join(f"{name}_temp_path {root / name};\n" for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
                + upstream + f"server {{ listen 127.0.0.1:{front} ssl;\nserver_name localhost;\n"
                + f"ssl_certificate {front_cert};\nssl_certificate_key {front_key};\n"
                + "location / { return 404; }\n" + locations + "}\n}\n", encoding="utf-8",
            )
            counts: collections.Counter[str] = collections.Counter()
            lock = threading.Lock()
            backend = ThreadingHTTPServer(("127.0.0.1", origin), trusted_fixture_origin(counts, lock))
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(origin_cert, origin_key)
            backend.socket = tls.wrap_socket(backend.socket, server_side=True)
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            process = None
            try:
                run(nginx, "-t", "-e", str(root / "bootstrap.log"), "-p", str(root), "-c", str(conf))
                process = subprocess.Popen([nginx, "-e", str(root / "bootstrap.log"), "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                context = ssl.create_default_context(cafile=str(front_cert))
                base = f"https://127.0.0.1:{front}/"
                for _ in range(100):
                    if process.poll() is not None:
                        raise AssertionError("NATIVE_OWNED_NGINX_EXITED")
                    try:
                        if request(base, context)[0] == 404:
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise AssertionError("NATIVE_OWNED_NGINX_NOT_READY")
                pairs = [(ids[0], "/apt/dists/trixie/InRelease", "dists/trixie/InRelease"),
                         (ids[0], "/apt/pool/main/r/repocache-fixture.deb", "pool/main/r/repocache-fixture.deb"),
                         (ids[1], "/dnf/repodata/repomd.xml", "repodata/repomd.xml"),
                         (ids[1], "/dnf/Packages/r/repocache-fixture.rpm", "Packages/r/repocache-fixture.rpm")]
                for repo, fixture, path in pairs:
                    for expected in ("MISS", "HIT"):
                        status, body, observed, _headers = request(base + f"__repocache/repos/{repo}/{path}", context)
                        assert (status, body, observed) == (200, FIXTURES[fixture][1], expected)
                    assert counts[fixture] == 1
                rows = _wait_for_rows(log, 8)
                assert {row["upstream_cache_status"] for row in rows} == {"MISS", "HIT"}
                assert _identity(log) == original_log
                observed_cache = _cache_snapshot(cache)
                assert observed_cache and all(row[0][1] == worker.pw_uid for row in observed_cache.values())
                assert all(any(key.startswith(name + "/") for key in observed_cache) for name in ids)
                report = metrics(Settings(metrics_log=log), hours=1, now=datetime.now(timezone.utc))
                assert report["available"] and report["requests"] == 8
                assert report["hit"] == 4 and report["miss"] == 4
                assert report["cache_observed"] == 8
                first_history = log.read_bytes()
                invalid = root / "invalid-rotation.conf"
                invalid.write_text(conf.read_text() + "\nINVALID_ROTATION_DIRECTIVE;\n")
                try:
                    _rotate_and_reload(root, fd, log, process, invalid, profile)
                except AssertionError:
                    pass
                else:
                    raise AssertionError("INVALID_ROTATION_CONFIGURATION_ACCEPTED")
                assert log.read_bytes() == first_history and _identity(log) == original_log
                assert marker.read_bytes() == marker_before and _cache_snapshot(cache) == observed_cache
                assert not log.with_name(log.name + ".1").exists() and process.poll() is None
                for turn in range(2):
                    _rotate_and_reload(root, fd, log, process, conf, profile)
                    for repo, fixture, path in pairs:
                        status, body, observed, _headers = request(base + f"__repocache/repos/{repo}/{path}", context)
                        assert (status, body, observed) == (200, FIXTURES[fixture][1], "HIT")
                        assert counts[fixture] == 1
                    _wait_for_rows(log, 4)
                    assert _identity(log)[1:] == (0, 0, 0o600, 1)
                    assert _cache_snapshot(cache) == observed_cache
                    assert json.loads(marker.read_bytes())["ino"] == _identity(log)[0]
                    if turn == 0:
                        assert log.with_name(log.name + ".1").read_bytes() == first_history
                with gzip.open(log.with_name(log.name + ".2.gz"), "rb") as history:
                    assert history.read() == first_history
                assert all(_identity(log.with_name(log.name + suffix))[1:] == (0, 0, 0o600, 1)
                           for suffix in (".1", ".2.gz"))
                report = metrics(Settings(metrics_log=log), hours=1, now=datetime.now(timezone.utc))
                assert report["available"] and report["requests"] == 16
                assert report["hit"] == 12 and report["miss"] == 4
                assert report["cache_observed"] == 16 and report["history_files_read"] == 3
                assert report["rotation_incomplete"] is False
                original_log, marker_before = _identity(log), marker.read_bytes()
                print("PASS: two real stock rotations and validated master reloads retain root-only log ownership, exact history and cache HITs", flush=True)
            finally:
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                backend.shutdown()
                backend.server_close()
                thread.join(timeout=3)
            saved_cache = _cache_snapshot(cache)
            saved_log = log.read_bytes()
            archives = {name: log.with_name(name).read_bytes() for name in (log.name + ".1", log.name + ".2.gz")}
            assert saved_cache and saved_log
            prepare(False)
            assert _cache_snapshot(cache) == saved_cache
            assert log.read_bytes() == saved_log and _identity(log) == original_log
            assert marker.read_bytes() == marker_before
            assert all(log.with_name(name).read_bytes() == raw for name, raw in archives.items())
            # Only the deliberately generated, privacy-limited fixture rows
            # may leave the disposable job for the separate actual CLI test.
            samples = {log.name: saved_log, **archives}
            plain = saved_log + archives[log.name + ".1"] + gzip.decompress(archives[log.name + ".2.gz"])
            assert len(plain) <= 16384 and len(plain.splitlines()) == 16
            assert all(set(json.loads(line)) == {"time_iso8601", "repocache_repository", "status",
                       "upstream_cache_status", "body_bytes_sent", "request_time"}
                       for line in plain.splitlines())
            print("METRICS_ROTATED_FIXTURE_JSON:" + json.dumps({name: base64.b64encode(raw).decode("ascii")
                  for name, raw in samples.items()}), flush=True)
            print("PASS: actual native NGINX worker cache MISS/HIT and private root-owned metrics; repeat provisioning preserves cache/history", flush=True)
        finally:
            os.close(fd)


if __name__ == "__main__":
    main()
