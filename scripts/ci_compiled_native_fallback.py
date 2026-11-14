#!/usr/bin/env python3
"""Execute exact compiler-generated APT/DNF5 proposals in disposable CI images.

Requires a fresh GitHub Actions Docker container, ephemeral loopback TLS,
synthetic OpenPGP keys, and no host/repository source mounts writable.
Never execute on an installed host. No packages are installed from test repos.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
import native_fallback_plan as compiler
import ci_client_native_fallback as fixture


def _checked_container():
    if (os.geteuid() != 0 or not Path("/.dockerenv").exists()
            or os.environ.get("REPOCACHE_DISPOSABLE_NATIVE_CI") != "1"):
        raise RuntimeError("Refuse native configuration smoke outside explicit disposable Docker CI")


def _create_unique(path: Path, payload: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _compile(path: str, original: bytes, upstream: str, cache: str,
             ident: str) -> compiler.FallbackProposal:
    return compiler.compile_fallback(
        source=path, original=original,
        expected_source_sha256=hashlib.sha256(original).hexdigest(),
        selected_entry_sha256=hashlib.sha256(original).hexdigest(),
        managed_id=ident, upstream=upstream, cache=cache)


def _assert_compiled_tls_refusal(
    returncode: int, cache_hits: list[str], upstream_hits: list[str],
) -> None:
    """Refuse any false-positive result from a native wrong-CA fetch.

    A TLS handshake must not succeed at either endpoint, whether the
    primary is healthy or the package manager tries its signed fallback.
    """
    if (type(returncode) is not int or returncode == 0
            or type(cache_hits) is not list or type(upstream_hits) is not list
            or cache_hits or upstream_hits):
        raise RuntimeError("COMPILED_NATIVE_TLS_FOREIGN_CA_NOT_REFUSED")


def smoke(manager: str):
    _checked_container()
    with tempfile.TemporaryDirectory(prefix="repocache-compiled-native-ci-") as work:
        base = Path(work)
        (base / "www").mkdir()
        ident = secrets.token_hex(16)
        if manager == "apt":
            key = fixture.apt_repository(base, package_transfer=True)
            installed_key = Path("/etc/apt/keyrings") / ("repocache-ci-" + ident + ".gpg")
        else:
            key = fixture.dnf_repository(base, signed=True)
            installed_key = Path("/etc/pki/rpm-gpg") / ("repocache-ci-" + ident + ".asc")
        assert key is not None
        _create_unique(installed_key, key.read_bytes())
        cert, tls_key = fixture.temporary_tls_identity(base, "compiled")
        cache = fixture.HTTPBackend(base / "www", certificate=cert, key=tls_key)
        upstream = fixture.HTTPBackend(base / "www", certificate=cert, key=tls_key)
        managed_companion = None
        try:
            if manager == "apt":
                original = (
                    "Types: deb\n"
                    "URIs: " + upstream.origin + "\n"
                    "Suites: stable\nComponents: main\n"
                    "Signed-By: " + str(installed_key) + "\n"
                ).encode()
                native = _compile("etc/apt/sources.list.d/repocache-ci.sources",
                                  original, upstream.origin, cache.origin, ident)
                assert native.companion is not None
                name, payload = native.companion
                managed_companion = Path("/") / name
                _create_unique(managed_companion, payload)
            else:
                original = (
                    "[repocache-ci]\n"
                    "name=REPOCACHE CI only\n"
                    "baseurl=" + upstream.origin + "\n"
                    "enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"
                    "gpgkey=file://" + str(installed_key) + "\n"
                ).encode()
                native = _compile("etc/yum.repos.d/repocache-ci.repo",
                                  original, upstream.origin, cache.origin, ident)
                assert native.companion is None
            assert not native.production_write_eligible
            assert not native.route_approval_verified
            assert not native.native_fallback_verified

            for phase, primary_mode, upstream_mode in (
                ("preferred", "healthy", "healthy"),
                ("fallback", "unavailable", "healthy"),
                ("recovery", "healthy", "healthy"),
                ("both-failed", "unavailable", "unavailable"),
            ):
                cache.mode = primary_mode
                upstream.mode = upstream_mode
                cache.hits.clear()
                upstream.hits.clear()
                if manager == "apt":
                    argv = fixture.apt_command(base, cache, upstream, phase, key,
                                               ca_certificate=cert)
                    source = base / "ci.sources"
                    source.write_bytes(native.proposed)
                else:
                    argv = fixture.dnf_command(base, cache, upstream, phase,
                                               ca_certificate=cert,
                                               metadata_key=key)
                    repo = base / "repos" / "repocache-ci.repo"
                    # Harness-only CA path: the compiler does not change CA
                    # or key policy from the original input.
                    repo.write_bytes(native.proposed +
                                     ("sslverify=1\nsslcacert=" + str(cert) +
                                      "\n").encode("utf-8"))
                run = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, timeout=120)
                if phase == "both-failed":
                    accepted = run.returncode != 0 and cache.hits and upstream.hits
                elif phase == "fallback":
                    accepted = run.returncode == 0 and cache.hits and upstream.hits
                else:
                    accepted = run.returncode == 0 and cache.hits and not upstream.hits
                if not accepted:
                    raise RuntimeError("Compiled %s %s fallback refusal:\n%s" %
                                       (manager, phase, run.stdout[-6500:]))
                if manager == "apt" and phase != "both-failed":
                    # Verify a real signed-metadata-to-package hash chain.
                    download = base / ("download-" + phase)
                    download.mkdir()
                    command = list(argv)
                    command[1] = "download"
                    command.append("repocache-ci-probe")
                    package = subprocess.run(
                        command, cwd=download, text=True, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=120)
                    source_deb = base / "www/repo/pool/main/r/repocache-ci-probe/repocache-ci-probe_0.0.1_all.deb"
                    fetched = download / source_deb.name
                    if (package.returncode != 0 or not fetched.exists()
                            or hashlib.sha256(fetched.read_bytes()).digest() !=
                               hashlib.sha256(source_deb.read_bytes()).digest()):
                        raise RuntimeError("Signed APT package hash or transfer failed:\n" +
                                           package.stdout[-3500:])
                print("compiled-%s %s PASS: primary_hits=%d upstream_hits=%d" %
                      (manager, phase, len(cache.hits), len(upstream.hits)),
                      flush=True)

            # The *actual compiled* source must never accept a cache or
            # upstream certificate signed by an unrelated CI-only CA.
            # APT and DNF use a fresh metadata cache/repository for this
            # negative check; a previously valid update is not evidence.
            foreign_ca, _foreign_key = fixture.temporary_tls_identity(
                base, "compiled-foreign-ca",
            )
            cache.mode = "healthy"
            upstream.mode = "healthy"
            cache.hits.clear()
            upstream.hits.clear()
            if manager == "apt":
                argv = fixture.apt_command(
                    base, cache, upstream, "foreign-ca", key,
                    ca_certificate=foreign_ca,
                )
                (base / "ci.sources").write_bytes(native.proposed)
            else:
                argv = fixture.dnf_command(
                    base, cache, upstream, "foreign-ca",
                    ca_certificate=foreign_ca, metadata_key=key,
                )
                (base / "repos" / "repocache-ci.repo").write_bytes(
                    native.proposed
                    + ("sslverify=1\nsslcacert=" + str(foreign_ca)
                       + "\n").encode("utf-8")
                )
            assert cache.origin.startswith("https://")
            assert upstream.origin.startswith("https://")
            negative = subprocess.run(
                argv, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False, timeout=120,
            )
            _assert_compiled_tls_refusal(
                negative.returncode, cache.hits, upstream.hits,
            )
            print("compiled-%s foreign-ca PASS: native TLS rejects both "
                  "healthy origins before serving metadata" % manager,
                  flush=True)
        finally:
            cache.close()
            upstream.close()
            if managed_companion is not None:
                managed_companion.unlink(missing_ok=True)
            installed_key.unlink(missing_ok=True)


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("manager", choices=("apt", "dnf"))
    args = cli.parse_args()
    smoke(args.manager)
