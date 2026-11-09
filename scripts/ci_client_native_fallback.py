#!/usr/bin/env python3
"""Isolated, executable APT/DNF HTTP metadata failover probe (#24).

This experiment runs ONLY in disposable Debian 13/AlmaLinux 10 containers.
It does not configure a production REPOCACHE host, disable repository signing
or prove package download, installation, real TLS or power-loss behavior.

Exit nonzero if native metadata preference/fallback/recovery fails. Record
manager version and local HTTP request counts for reproducible evidence.
"""
from __future__ import annotations

import argparse
import email.utils
import gzip
import hashlib
import http.server
import lzma
import shutil
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path


class HTTPBackend:
    def __init__(self, files: Path, *, certificate: Path | None = None,
                 key: Path | None = None):
        self.mode = "healthy"
        self.hits: list[str] = []

        class Handler(http.server.SimpleHTTPRequestHandler):
            def _respond(handler, method: str):
                self.hits.append(method + " " + handler.path)
                if self.mode != "healthy":
                    handler.send_error(503, "Synthetic cache unavailable")
                    return
                if method == "GET":
                    super().do_GET()
                else:
                    super().do_HEAD()

            def do_GET(handler):
                handler._respond("GET")

            def do_HEAD(handler):
                handler._respond("HEAD")

            def log_message(handler, _format, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            lambda *args, **kwargs: Handler(*args, directory=str(files), **kwargs),
        )
        if certificate is not None:
            if key is None:
                raise ValueError("TLS test server key is required")
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(str(certificate), str(key))
            self.server.socket = tls_context.wrap_socket(
                self.server.socket, server_side=True)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True,
        )
        self.thread.start()
        scheme = "https" if certificate is not None else "http"
        self.origin = "%s://127.0.0.1:%d/repo/" % (
            scheme, self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)


def checked(argv: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    result = subprocess.run(
        argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, check=False,
    )
    if result.returncode:
        raise RuntimeError("Command failed (%s): %s\n%s" %
                           (result.returncode, argv[0], result.stdout[-4500:]))
    return result



def temporary_tls_identity(base: Path, label: str) -> tuple[Path, Path]:
    """Generate private, short-lived loopback TLS identity for CI only."""
    cert = base / (label + "-tls-cert.pem")
    key = base / (label + "-tls-key.pem")
    checked([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-sha256", "-nodes", "-days", "1",
        "-keyout", str(key), "-out", str(cert),
        "-subj", "/CN=repocache-ci-loopback",
        "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
    ], timeout=60)
    key.chmod(0o600)
    cert.chmod(0o644)
    return cert, key


def apt_repository(base: Path) -> Path:
    repository = base / "www" / "repo"
    index_dir = repository / "dists" / "stable" / "main" / "binary-amd64"
    index_dir.mkdir(parents=True)
    files = {
        "main/binary-amd64/Packages": b"",
        "main/binary-amd64/Packages.gz": gzip.compress(b"", mtime=0),
        "main/binary-amd64/Packages.xz": lzma.compress(b""),
    }
    for name, data in files.items():
        (repository / "dists" / "stable" / name).write_bytes(data)
    release = "\n".join([
        "Origin: REPOCACHE CI",
        "Label: REPOCACHE CI",
        "Suite: stable",
        "Codename: stable",
        "Date: %s" % email.utils.formatdate(usegmt=True),
        "Architectures: amd64",
        "Components: main",
        "SHA256:",
        *[" %s %s %s" % (hashlib.sha256(data).hexdigest(), len(data), name)
          for name, data in sorted(files.items())],
        "",
    ])
    meta = repository / "dists" / "stable"
    (meta / "Release").write_text(release, encoding="utf-8")

    homedir = base / "gnupg"
    homedir.mkdir(mode=0o700)
    gpg = ["gpg", "--homedir", str(homedir), "--batch", "--yes",
           "--pinentry-mode", "loopback", "--passphrase", ""]
    checked(gpg + ["--quick-generate-key",
                   "REPOCACHE Fixture <ci@repocache.invalid>",
                   "ed25519", "sign", "1d"])
    keyring = base / "fixture-keyring.gpg"
    # Binary GPG output must never pass through text decoding.
    with keyring.open("wb") as sink:
        subprocess.run(gpg + ["--export"], stdout=sink, check=True, timeout=20)
    keyring.chmod(0o644)
    checked(gpg + ["--clearsign", "--digest-algo", "SHA256",
                   "--output", str(meta / "InRelease"), str(meta / "Release")])
    return keyring


def dnf_repository(base: Path) -> None:
    repository = base / "www" / "repo"
    repository.mkdir(parents=True)
    checked(["createrepo_c", "--quiet", str(repository)])


def apt_command(base: Path, primary: HTTPBackend,
                upstream: HTTPBackend, cycle: str, keyring: Path,
                *, ca_certificate: Path | None = None) -> list[str]:
    mirrors = base / "mirrors.txt"
    mirrors.write_text(
        primary.origin + "\tpriority:1\n" +
        upstream.origin + "\tpriority:2\n",
        encoding="utf-8",
    )
    source = base / "ci.sources"
    source.write_text(
        "Types: deb\n"
        "URIs: mirror+file:%s\n" % mirrors +
        "Suites: stable\nComponents: main\n"
        "Signed-By: %s\n" % keyring,
        encoding="utf-8",
    )
    lists = base / ("apt-lists-" + cycle)
    (lists / "partial").mkdir(parents=True)
    cache = base / ("apt-cache-" + cycle)
    cache.mkdir()
    return [
        "apt-get", "update",
        "-o", "Dir::Etc::sourcelist=" + str(source),
        "-o", "Dir::Etc::sourceparts=-",
        "-o", "Dir::State::lists=" + str(lists),
        "-o", "Dir::Cache=" + str(cache),
        "-o", "APT::Update::Error-Mode=any",
        "-o", "Acquire::Retries=0",
        "-o", "APT::Sandbox::User=root",
    ] + ([
        "-o", "Acquire::https::CaInfo=" + str(ca_certificate),
        "-o", "Acquire::https::Verify-Peer=true",
        "-o", "Acquire::https::Verify-Host=true",
    ] if ca_certificate is not None else [])


def dnf_command(base: Path, primary: HTTPBackend,
                upstream: HTTPBackend, cycle: str,
                *, ca_certificate: Path | None = None) -> list[str]:
    repo_dir = base / "repos"
    repo_dir.mkdir(exist_ok=True)
    (repo_dir / "repocache-ci.repo").write_text(
        "[repocache-ci]\n"
        "name=REPOCACHE Native Metadata Probe\n"
        "enabled=1\n"
        "gpgcheck=1\n"
        "repo_gpgcheck=0\n"
        "skip_if_unavailable=0\n"
        "fastestmirror=0\n"
        "baseurl=%s\n        %s\n" % (primary.origin, upstream.origin)
        + ("sslverify=1\nsslcacert=%s\n" % ca_certificate
           if ca_certificate is not None else ""),
        encoding="utf-8",
    )
    cache = base / ("dnf-cache-" + cycle)
    cache.mkdir()
    logs = base / ("dnf-logs-" + cycle)
    logs.mkdir()
    config = base / ("dnf-" + cycle + ".conf")
    config.write_text(
        "[main]\n"
        "reposdir=%s\n" % repo_dir +
        "cachedir=%s\n" % cache +
        "system_cachedir=%s\n" % cache +
        "logdir=%s\n" % logs +
        "skip_if_unavailable=0\n"
        "fastestmirror=0\n"
        "metadata_expire=0\n",
        encoding="utf-8",
    )
    executable = shutil.which("dnf5") or shutil.which("dnf")
    if not executable:
        raise RuntimeError("Missing DNF on native AlmaLinux container")
    return [executable, "--config=" + str(config), "--refresh", "makecache"]


def probe(manager: str, *, tls: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix="repocache-native-fallback-") as tmp:
        base = Path(tmp)
        (base / "www").mkdir()
        keyring = apt_repository(base) if manager == "apt" else None
        if manager == "dnf":
            dnf_repository(base)

        certificate, tls_key = temporary_tls_identity(base, "trusted") if tls else (None, None)
        # A different private CA must be rejected. Never disable TLS checking
        # or downgrade to HTTP for a metadata probe.
        bad_ca = temporary_tls_identity(base, "untrusted")[0] if tls else None
        primary = HTTPBackend(base / "www", certificate=certificate, key=tls_key)
        upstream = HTTPBackend(base / "www", certificate=certificate, key=tls_key)
        try:
            command = apt_command if manager == "apt" else dnf_command
            cases = [
                ("preferred", "healthy", "healthy"),
                ("fallback", "unavailable", "healthy"),
                ("recovery", "healthy", "healthy"),
                ("both-failed", "unavailable", "unavailable"),
            ]
            if tls:
                cases.append(("wrong-ca", "healthy", "healthy"))
            for cycle, first, second in cases:
                primary.mode, upstream.mode = first, second
                primary.hits.clear()
                upstream.hits.clear()
                ca = bad_ca if cycle == "wrong-ca" else certificate
                argv = (command(base, primary, upstream, cycle, keyring,
                                ca_certificate=ca)
                        if manager == "apt"
                        else command(base, primary, upstream, cycle,
                                     ca_certificate=ca))
                result = subprocess.run(
                    argv, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=120, check=False,
                )
                print("%s %s %s exit=%d primary_hits=%d upstream_hits=%d" %
                      (manager, "https" if tls else "http", cycle, result.returncode,
                       len(primary.hits), len(upstream.hits)), flush=True)
                if cycle == "wrong-ca":
                    # No HTTP request is permitted after an untrusted TLS
                    # handshake: fallback must not bypass CA verification.
                    ok = result.returncode != 0 and not primary.hits and not upstream.hits
                elif cycle == "both-failed":
                    ok = result.returncode != 0 and primary.hits and upstream.hits
                elif cycle == "fallback":
                    ok = result.returncode == 0 and primary.hits and upstream.hits
                else:
                    ok = result.returncode == 0 and primary.hits and not upstream.hits
                if not ok:
                    raise RuntimeError(
                        "Failover assertion failed for %s / %s:\n%s" %
                        (manager, cycle, result.stdout[-6000:]))
        finally:
            primary.close()
            upstream.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manager", choices=["apt", "dnf"])
    parser.add_argument("--tls", action="store_true",
                        help="Use private loopback TLS and test untrusted-CA refusal")
    args = parser.parse_args()
    probe(args.manager, tls=args.tls)
