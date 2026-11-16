#!/usr/bin/env python3
"""Real signed APT/DNF metadata + package download through a dynamic NGINX route.

Stage-A issue #95: use a CONFIG-ONLY new repository ID in the existing
validated renderer, then run the real OS package manager against the isolated
stock NGINX HTTPS cache with ephemeral (CI-only) signature fixtures.

The test never installs fixture packages, publishes a catalog, mutates real
APT/DNF sources, authenticates a live host root or authorizes nginx reload.
Only an explicitly disposable Docker container is accepted.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

import ci_client_native_fallback as native
import ci_dnf_signed_rpm_fallback as signed_rpm
from ci_generated_nginx_route_cache_smoke import (
    HOST, await_worker_generation_drained, nginx_master_children, self_signed,
)
from ci_native_nginx_cache_smoke import ROOT, free_port, request
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)

ID_APT = "ci-dynamic-signed-apt"
ID_DNF = "ci-dynamic-signed-dnf"
MAX_COMMAND_OUTPUT = 12 * 1024


def disposable_only(kind: str) -> None:
    if (kind not in ("apt", "dnf")
            or os.geteuid() != 0
            or not Path("/.dockerenv").is_file()
            or os.environ.get("REPOCACHE_DISPOSABLE_SIGNED_ROUTE_CI") != "1"
            or not Path("/workspace/scripts/ci_client_native_fallback.py").is_file()):
        raise RuntimeError("DISPOSABLE_SIGNED_NATIVE_ROUTE_ONLY")
    os_release = Path("/etc/os-release").read_text(encoding="ascii")
    if kind == "apt" and not ("ID=debian" in os_release and "VERSION_ID=\"13" in os_release):
        raise RuntimeError("DEBIAN_13_IMAGE_REQUIRED")
    if kind == "dnf" and not ("ID=\"almalinux\"" in os_release
                              and "VERSION_ID=\"10" in os_release):
        raise RuntimeError("ALMALINUX_10_IMAGE_REQUIRED")


def subprocess_status(argv: list[str], *, cwd: Path | None = None,
                      timeout: int = 120) -> bool:
    """Run fixed fixture tools; never echo untrusted subprocess output."""
    completed = subprocess.run(
        argv, cwd=cwd, text=True, capture_output=True, shell=False,
        check=False, timeout=timeout, stdin=subprocess.DEVNULL,
        env={**os.environ, "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"},
    )
    if (type(completed.stdout) is not str or type(completed.stderr) is not str
            or len(completed.stdout) > MAX_COMMAND_OUTPUT
            or len(completed.stderr) > MAX_COMMAND_OUTPUT):
        raise RuntimeError("NATIVE_PACKAGE_MANAGER_OUTPUT_UNBOUNDED")
    return completed.returncode == 0


def fixture_document(kind: str, cache: Path) -> tuple[dict, str, dict]:
    doc = json.loads((ROOT / "docs/examples/server-install-v1.json").read_text("utf-8"))
    row = next(r for r in doc["repositories"]
               if r["kind"] == ("apt" if kind == "apt" else "dnf"))
    rid = ID_APT if kind == "apt" else ID_DNF
    row["id"] = rid
    row["desired_state"] = "active"
    row["upstream"]["base_url"] = "https://" + HOST + "/repo/"
    row["upstream"]["allowed_hosts"] = [HOST]
    if kind == "apt":
        row["layout"]["suites"] = ["stable"]
        row["layout"]["components"] = ["main"]
        row["layout"]["architectures"] = ["amd64"]
    doc["repositories"] = [row]
    doc["deployment"]["paths"]["cache_root"] = str(cache)
    return doc, rid, {rid: {HOST: ["8.8.8.8"]}}


def chown_worker_paths(base: Path, rid: str, kind: str) -> str:
    """Make cache and temp paths writable to the distro's actual worker UID."""
    worker = "www-data" if kind == "apt" else "nginx"
    user = pwd.getpwnam(worker)
    base.chmod(0o755)  # NGINX master can traverse TLS fixture parents.
    cache = base / "cache"
    cache.mkdir(mode=0o700)
    cache.mkdir(exist_ok=True)
    repo = cache / rid
    repo.mkdir(mode=0o700)
    for folder in (cache, repo, *(base / n for n in
                                   ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))):
        if not folder.exists():
            folder.mkdir(mode=0o700)
        os.chown(folder, user.pw_uid, user.pw_gid)
        folder.chmod(0o700)
    return worker


def nginx_config(base: Path, rid: str, pins: dict, doc: dict, *,
                 nginx_port: int, origin_port: int,
                 origin_cert: Path, front_cert: Path, front_key: Path,
                 worker: str, bypass: bool = False) -> Path:
    rendered = render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=0,
        candidate_pins_by_repository=pins, ca_bundle_path=str(origin_cert),
        cache_bypass_repository_ids=(rid,) if bypass else (),
    )
    if bypass and (
        rendered["cache_bypass_recovery_candidate_repository_ids"] != [rid]
        or rendered["cache_bypass_activation_verified"] is not False
        or "    proxy_cache off;" not in rendered["server_location_fragment"]
    ):
        raise RuntimeError("TEST_ONLY_CACHE_BYPASS_UNVERIFIED")
    if (rendered["proposed_repository_ids"] != [rid]
            or rendered["authorizes_nginx_activation"] is not False
            or rendered["authorizes_catalog_publication"] is not False):
        raise RuntimeError("DYNAMIC_ROUTE_RENDERING_UNVERIFIED")
    raw = rendered["http_upstream_fragment"]
    marker = "server 8.8.8.8:443;"
    if raw.count(marker) != 1:
        raise RuntimeError("PUBLIC_PIN_RENDERING_UNVERIFIED")
    test_upstream = raw.replace(marker, f"server 127.0.0.1:{origin_port};")
    if marker in test_upstream:
        raise RuntimeError("UNSAFE_FIXTURE_REMAP")
    locations = rendered["server_location_fragment"].replace(
        "    proxy_cache_valid 200 60s;",
        "    proxy_cache_valid 200 60s;\n"
        "    add_header X-RepoCache-Smoke $upstream_cache_status always;",
    )
    if (locations.count(f"location ^~ /__repocache/repos/{rid}/") != 1
            or "    add_header X-RepoCache-Smoke " not in locations):
        raise RuntimeError("DYNAMIC_LOCATION_RENDERING_UNVERIFIED")
    conf = base / "nginx.conf"
    conf.write_text(
        f"user {worker};\n"
        f"pid {base / 'nginx.pid'};\n"
        f"error_log {base / 'nginx-error.log'} notice;\n"
        "worker_processes 1;\nevents { worker_connections 128; }\n"
        "http { access_log off;\n"
        + "".join(f"{name}_temp_path {base / name};\n"
                  for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        + test_upstream
        + f"server {{ listen 127.0.0.1:{nginx_port} ssl;\n"
        + "server_name localhost;\n"
        + f"ssl_certificate {front_cert};\n"
        + f"ssl_certificate_key {front_key};\n"
        + "location / { return 404; }\n"
        + locations
        + "}\n}\n",
        encoding="ascii",
    )
    return conf


def wait_for_nginx(process: subprocess.Popen, root_url: str, cert: Path) -> None:
    context = ssl.create_default_context(cafile=str(cert))
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError("PRIVATE_NGINX_MASTER_EXITED")
        try:
            if request(root_url + "/", context)[0] == 404:
                return
        except (OSError, TimeoutError):
            time.sleep(0.05)
    raise AssertionError("PRIVATE_NGINX_HTTPS_NOT_READY")


def apt_native_signed_download(
    base: Path, base_url: str, frontend_cert: Path,
    signed_keyring: Path, expected: Path,
) -> list[str]:
    source = base / "native-dynamic.sources"
    source.write_text(
        "Types: deb\n"
        f"URIs: {base_url}\n"
        "Suites: stable\nComponents: main\n"
        f"Signed-By: {signed_keyring}\n",
        encoding="ascii",
    )
    lists = base / "apt-lists"
    (lists / "partial").mkdir(parents=True)
    cache = base / "apt-cache"
    cache.mkdir()
    status = base / "absent-dpkg-status"
    status.write_bytes(b"")
    args = [
        "/usr/bin/apt-get",
        "-o", f"Dir::Etc::sourcelist={source}",
        "-o", "Dir::Etc::sourceparts=-",
        "-o", f"Dir::State::lists={lists}",
        "-o", f"Dir::State::status={status}",
        "-o", f"Dir::Cache={cache}",
        "-o", "Acquire::Retries=0",
        "-o", "APT::Update::Error-Mode=any",
        "-o", "APT::Get::AllowUnauthenticated=false",
        "-o", "Acquire::AllowInsecureRepositories=false",
        "-o", "APT::Sandbox::User=root",
        "-o", f"Acquire::https::CaInfo={frontend_cert}",
        "-o", "Acquire::https::Verify-Peer=true",
        "-o", "Acquire::https::Verify-Host=true",
    ]
    if not subprocess_status([*args, "update"]):
        raise AssertionError("NATIVE_APT_SIGNED_METADATA_REFUSED")
    dest = base / "apt-download"
    dest.mkdir()
    if not subprocess_status([*args, "download", "repocache-ci-probe"], cwd=dest):
        raise AssertionError("NATIVE_APT_SIGNED_DOWNLOAD_REFUSED")
    downloaded = dest / "repocache-ci-probe_0.0.1_all.deb"
    if (not downloaded.is_file()
            or hashlib.sha256(downloaded.read_bytes()).digest()
               != hashlib.sha256(expected.read_bytes()).digest()):
        raise AssertionError("NATIVE_APT_SIGNED_ARTIFACT_HASH_INVALID")
    # Explicitly reject an unrelated CA before package-manager metadata reads.
    foreign_cert, _ = native.temporary_tls_identity(base, "wrong-ca")
    other_lists = base / "apt-foreign-lists"
    (other_lists / "partial").mkdir(parents=True)
    wrong = [
        (f"Dir::State::lists={other_lists}"
         if token.startswith("Dir::State::lists=") else
         f"Acquire::https::CaInfo={foreign_cert}"
         if token.startswith("Acquire::https::CaInfo=") else token)
        for token in args
    ]
    if subprocess_status([*wrong, "update"]):
        raise AssertionError("UNTRUSTED_APT_FRONTEND_CA_ACCEPTED")
    return args


def dnf_native_signed_download(
    base: Path, base_url: str, frontend_cert: Path, key: Path,
    expected: Path, private_rpmdb: Path,
) -> list[str]:
    # Reuse the existing tested signed DNF5 fixture harness rather than
    # creating separate unreviewed DNF signature/security options.
    target = SimpleNamespace(origin=base_url)
    args = native.dnf_command(
        base, target, target, "dynamic-native",
        ca_certificate=frontend_cert, metadata_key=key,
    )
    if not subprocess_status(args):
        raise AssertionError("NATIVE_DNF_SIGNED_METADATA_REFUSED")
    destination = base / "dnf-download"
    downloaded = signed_rpm._download_dnf(args, destination)
    artifact = destination / signed_rpm._RPM_NAME
    if (downloaded.returncode != 0 or not artifact.is_file()
            or hashlib.sha256(artifact.read_bytes()).digest()
               != hashlib.sha256(expected.read_bytes()).digest()):
        raise AssertionError("NATIVE_DNF_SIGNED_ARTIFACT_HASH_INVALID")
    verified = signed_rpm._run(
        ["rpm", "--dbpath", str(private_rpmdb), "-Kv", str(artifact)]
    )
    if not signed_rpm._rpm_signature_verified(verified):
        raise AssertionError("NATIVE_DNF_RPM_SIGNATURE_UNVERIFIED")
    # A fully signed repository is still refused if the frontend TLS CA is
    # unrelated: keep a fresh native cache so previous success cannot mask it.
    foreign_cert, _ = native.temporary_tls_identity(base, "dnf-wrong-ca")
    wrong = native.dnf_command(
        base, target, target, "dynamic-wrong-ca",
        ca_certificate=foreign_cert, metadata_key=key,
    )
    if subprocess_status(wrong):
        raise AssertionError("UNTRUSTED_DNF_FRONTEND_CA_ACCEPTED")
    return args


def exercise(kind: str) -> None:
    disposable_only(kind)
    nginx = shutil.which("nginx")
    if nginx != "/usr/sbin/nginx":
        raise RuntimeError("STOCK_NGINX_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="repocache-dynamic-signed-") as tmp:
        base = Path(tmp)
        (base / "www").mkdir()
        signed_key = None
        expected = None
        rpmdb = None
        if kind == "apt":
            signed_key = native.apt_repository(base, package_transfer=True)
            expected = (base / "www/repo/pool/main/r/repocache-ci-probe/"
                        "repocache-ci-probe_0.0.1_all.deb")
        else:
            signed_key, expected, _, rpmdb = signed_rpm._signed_fixture(base)
        origin_cert, origin_key = base / "origin.crt", base / "origin.key"
        front_cert, front_key = base / "front.crt", base / "front.key"
        self_signed(shutil.which("openssl"), origin_cert, origin_key, HOST)
        self_signed(shutil.which("openssl"), front_cert, front_key, "localhost")
        backend = native.HTTPBackend(
            base / "www", certificate=origin_cert, key=origin_key,
        )
        origin_port = backend.server.server_port
        frontend_port = free_port()
        if origin_port == frontend_port:
            raise AssertionError("TLS_FRONTEND_PORT_COLLISION")
        rid = ID_APT if kind == "apt" else ID_DNF
        worker = chown_worker_paths(base, rid, kind)
        doc, rid, pins = fixture_document(kind, base / "cache")
        conf = nginx_config(
            base, rid, pins, doc, nginx_port=frontend_port,
            origin_port=origin_port, origin_cert=origin_cert,
            front_cert=front_cert, front_key=front_key,
            worker=worker,
        )
        if not subprocess_status([nginx, "-t", "-p", str(base), "-c", str(conf)]):
            raise AssertionError("STOCK_NGINX_DYNAMIC_ROUTE_SYNTAX_REFUSED")
        process = subprocess.Popen(
            [nginx, "-p", str(base), "-c", str(conf), "-g", "daemon off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            root_url = f"https://127.0.0.1:{frontend_port}"
            wait_for_nginx(process, root_url, front_cert)
            route_url = root_url + "/__repocache/repos/" + rid + "/"
            assert expected is not None and signed_key is not None
            if kind == "apt":
                original_native_args = apt_native_signed_download(
                    base, route_url, front_cert, signed_key, expected,
                )
                metadata = "dists/stable/InRelease"
                original = base / "www/repo" / metadata
            else:
                assert rpmdb is not None
                original_native_args = dnf_native_signed_download(
                    base, route_url, front_cert, signed_key, expected, rpmdb,
                )
                metadata = "repodata/repomd.xml"
                original = base / "www/repo" / metadata

            context = ssl.create_default_context(cafile=str(front_cert))
            first = request(route_url + metadata, context)
            second = request(route_url + metadata, context)
            signed_metadata_bytes = original.read_bytes()
            if (first[:2] != (200, signed_metadata_bytes)
                    or second[:3] != (200, signed_metadata_bytes, "HIT")
                    or not any(metadata in url for url in backend.hits)):
                raise AssertionError("DYNAMIC_METADATA_CACHE_INTEGRITY_UNVERIFIED")
            package_path = (
                "pool/main/r/repocache-ci-probe/repocache-ci-probe_0.0.1_all.deb"
                if kind == "apt" else signed_rpm._RPM_NAME
            )
            one, two = (
                request(route_url + package_path, context),
                request(route_url + package_path, context),
            )
            artifact_bytes = expected.read_bytes()
            if (one[:2] != (200, artifact_bytes)
                    or two[:3] != (200, artifact_bytes, "HIT")
                    or not any(package_path in hit for hit in backend.hits)):
                raise AssertionError("DYNAMIC_ARTIFACT_CACHE_INTEGRITY_UNVERIFIED")
            # A warm, valid cache is not a signature-negative test.
            # Change ONLY this detached test NGINX generation to a validated
            # cache-off candidate, then force a fresh native manager cache.
            # This tests signature refusal against actual modified upstream
            # bytes rather than incorrectly claiming a valid cached object
            # should become invalid when the origin later changes.
            tampered_path = (
                base / "www/repo/dists/stable/InRelease"
                if kind == "apt" else
                base / "www/repo/repodata/repomd.xml.asc"
            )
            recorded = tampered_path.read_bytes()
            before_hits = len(backend.hits)
            prior_workers = nginx_master_children(process.pid)
            nginx_config(
                base, rid, pins, doc, nginx_port=frontend_port,
                origin_port=origin_port, origin_cert=origin_cert,
                front_cert=front_cert, front_key=front_key,
                worker=worker, bypass=True,
            )
            if not subprocess_status([nginx, "-t", "-p", str(base), "-c", str(conf)]):
                raise AssertionError("TEST_ONLY_BYPASS_NGINX_SYNTAX_REFUSED")
            process.send_signal(signal.SIGHUP)  # Only detached test process
            await_worker_generation_drained(process, prior_workers)
            try:
                tampered_path.write_bytes(b"invalid-ephemeral-metadata-signature\\n")
                if kind == "apt":
                    fresh = base / "apt-tampered-lists"
                    (fresh / "partial").mkdir(parents=True)
                    args = [
                        f"Dir::State::lists={fresh}"
                        if arg.startswith("Dir::State::lists=") else arg
                        for arg in original_native_args
                    ]
                    accepted = subprocess_status([*args, "update"])
                    marker = "dists/stable/InRelease"
                else:
                    target = SimpleNamespace(origin=route_url)
                    args = native.dnf_command(
                        base, target, target, "dynamic-tampered-signature",
                        ca_certificate=front_cert, metadata_key=signed_key,
                    )
                    accepted = subprocess_status(args)
                    marker = "repomd.xml.asc"
                new_hits = backend.hits[before_hits:]
                if accepted or not any(marker in hit for hit in new_hits):
                    raise AssertionError("NATIVE_TAMPERED_METADATA_NOT_REFUSED")
            finally:
                tampered_path.write_bytes(recorded)

            print("PASS: " + kind.upper() +
                  " configuration-only repository + stock NGINX HTTPS cache, "
                  "real native signed metadata, package hash/signature, "
                  "metadata and artifact HIT with identical bytes; signed "
                  "metadata tampering refused on a fresh cache-off path")
            print("NOT VERIFIED: real publisher signatures, installed "
                  "root/systemd/SELinux, protected lifecycle activation, "
                  "catalog publication, state v2 or client source fallback")
        finally:
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=4)
            backend.close()


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("apt", "dnf"):
        raise SystemExit("Only one fixed disposable APT or DNF mode is allowed")
    exercise(sys.argv[1])
