#!/usr/bin/env python3
"""Test real synthetic-key stock NGINX TLS via validated v0.6 candidate."""
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_https_server_candidate,
)

HOST="cache.example.invalid"
PORT=18443


def main():
    assert os.geteuid() != 0 and Path("/.dockerenv").is_file()
    assert os.environ.get("REPOCACHE_DISPOSABLE_NGINX_SMOKE") == "1"
    nginx=shutil.which("nginx")
    openssl=shutil.which("openssl")
    assert nginx and openssl
    with tempfile.TemporaryDirectory(prefix="repocache-tls-v06-") as tmp:
        root=Path(tmp)
        cert=root/"test-cert.pem"
        key=root/"test-key.pem"
        made=subprocess.run([openssl,"req","-x509","-newkey","rsa:2048",
                             "-nodes","-days","1","-keyout",str(key),
                             "-out",str(cert),"-subj",f"/CN={HOST}",
                             "-addext",f"subjectAltName=DNS:{HOST}"],
                            timeout=25,stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,check=False)
        assert made.returncode == 0, "SYNTHETIC_TLS_FIXTURE_INVALID"
        key.chmod(0o600)
        d=json.loads(Path("/repo/docs/examples/server-install-v1.json").read_text())
        d["deployment"]["listen"]["https_port"]=PORT
        d["deployment"]["tls"]["certificate_file"]=str(cert)
        d["deployment"]["tls"]["private_key_file"]=str(key)
        d["repositories"][0]["desired_state"]="active"
        d["repositories"][1]["id"]="almalinux-baseos"
        d["repositories"][1]["desired_state"]="active"
        d["deployment"]["paths"]["cache_root"]=str(root/"managed-cache")
        for repo in d["repositories"]:
            (root/"managed-cache"/repo["id"]).mkdir(parents=True,mode=0o700)
        ca=next((candidate for candidate in (
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ) if Path(candidate).is_file()),None)
        assert ca is not None, "STOCK_CA_BUNDLE_UNAVAILABLE"
        result=render_repository_https_server_candidate(
            d,expected_state_generation=d["expected_state_generation"],
            candidate_pins_by_repository={
                repo["id"]:{"mirror.example.invalid":["8.8.8.8"]}
                for repo in d["repositories"]
            },
            ca_bundle_path=ca,
        )
        assert result["proposed_repository_ids"]==[
            "almalinux-baseos","debian-trixie-main",
        ]
        assert result["http_context_fragment"].count("proxy_cache_path ")==2
        assert result["server_block_fragment"].count(
            "location ^~ /__repocache/repos/"
        )==2
        assert not result["authorizes_nginx_activation"]
        # Stock distro NGINX default temp paths are root-owned. Pin all
        # private scratch paths to the disposable rootless namespace.
        for dirname in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (root / dirname).mkdir(mode=0o700)
        temp_paths = "".join(
            f"{dirname}_temp_path {root / dirname};\n"
            for dirname in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
        )
        config=(f"pid {root/'nginx.pid'};\n"
                f"error_log {root/'error.log'} notice;\n"
                "worker_processes 1;\nevents { worker_connections 32; }\n"
                "http {\naccess_log off;\n" + temp_paths
                + result["http_context_fragment"]
                # The diagnostic health route is test-only, inserted inside
                # the already closed validated server block, not generated
                # by the candidate composer.
                + result["server_block_fragment"][:-2]
                + 'location = /__test { return 200 "repocache-https"; }\n'
                + "}\n}\n")
        conf=root/"nginx.conf"
        conf.write_text(config)
        syntax=subprocess.run([nginx,"-t","-p",str(root),"-c",str(conf)],
                              capture_output=True,timeout=15,check=False)
        assert syntax.returncode == 0, "STOCK_NGINX_TLS_SYNTAX_INVALID"
        print("PASS: generated TLS + APT/DNF route/cache candidate accepted by stock NGINX",flush=True)
        proc=subprocess.Popen([nginx,"-p",str(root),"-c",str(conf),
                               "-g","daemon off;"],stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            def handshake(hostname,context):
                with socket.create_connection(("127.0.0.1",PORT),timeout=3) as raw:
                    with context.wrap_socket(raw,server_hostname=hostname) as sock:
                        sock.sendall(b"GET /__test HTTP/1.1\r\nHost: cache.example.invalid\r\nConnection: close\r\n\r\n")
                        return sock.recv(4096)
            context=ssl.create_default_context()
            context.load_verify_locations(cafile=str(cert))
            payload=None
            for _ in range(40):
                try:
                    payload=handshake(HOST,context)
                    break
                except (ConnectionRefusedError,ConnectionResetError):
                    time.sleep(0.05)
            assert payload and b"200 OK" in payload
            print("PASS: trusted synthetic certificate and canonical hostname over real TLS",flush=True)
            # The certificate and SNI can be valid while a client presents a
            # different HTTP Host. Never serve managed routes to that authority.
            with socket.create_connection(("127.0.0.1",PORT),timeout=3) as raw:
                with context.wrap_socket(raw,server_hostname=HOST) as sock:
                    sock.sendall(
                        b"GET /__test HTTP/1.1\r\n"
                        b"Host: unrelated.example.invalid\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    mismatch=sock.recv(4096)
            assert b"421 Misdirected Request" in mismatch, "FOREIGN_HTTP_HOST_ADMITTED"
            assert b"repocache-https" not in mismatch, "HOST_BOUNDARY_BODY_LEAK"
            print("PASS: valid TLS SNI refuses foreign HTTP Host with 421", flush=True)
            # An unapproved source URL must never become a route, even
            # with two explicitly active APT/DNF repository candidates.
            with socket.create_connection(("127.0.0.1",PORT),timeout=3) as raw:
                with context.wrap_socket(raw,server_hostname=HOST) as sock:
                    sock.sendall(
                        b"GET /__repocache/repos/unapproved/ HTTP/1.1\r\n"
                        b"Host: cache.example.invalid\r\nConnection: close\r\n\r\n"
                    )
                    refused=sock.recv(4096)
                    assert b"404 Not Found" in refused
                    assert b"200 OK" not in refused
            print("PASS: unapproved repository route is not exposed",flush=True)
            try:
                handshake("wrong.example.invalid",context)
            except ssl.SSLCertVerificationError:
                pass
            else:
                raise AssertionError("HOSTNAME_MISMATCH_ADMITTED")
            print("PASS: mismatched hostname refused by trusted TLS client",flush=True)
            try:
                handshake(HOST,ssl.create_default_context())
            except ssl.SSLCertVerificationError:
                pass
            else:
                raise AssertionError("UNTRUSTED_CERTIFICATE_ADMITTED")
            print("PASS: untrusted signing authority refused",flush=True)
            # Exercise exact NGINX negotiation, not only default SSL settings.
            for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                pinned=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                pinned.minimum_version=version
                pinned.maximum_version=version
                pinned.check_hostname=True
                pinned.verify_mode=ssl.CERT_REQUIRED
                pinned.load_verify_locations(cafile=str(cert))
                with socket.create_connection(("127.0.0.1",PORT),timeout=3) as raw:
                    with pinned.wrap_socket(raw,server_hostname=HOST) as session:
                        assert session.version()==(
                            "TLSv1.2" if version==ssl.TLSVersion.TLSv1_2
                            else "TLSv1.3"
                        ), "TLS_VERSION_MISMATCH"
                        session.sendall(
                            b"GET /__test HTTP/1.1\r\n"
                            b"Host: cache.example.invalid\r\n"
                            b"Connection: close\r\n\r\n"
                        )
                        assert b"200 OK" in session.recv(4096)
                print("PASS: trusted synthetic TLS exact protocol "
                      + ("1.2" if version==ssl.TLSVersion.TLSv1_2 else "1.3"),
                      flush=True)
            # Plain HTTP must never return the protected endpoint body.
            with socket.create_connection(("127.0.0.1",PORT),timeout=3) as raw:
                raw.sendall(
                    b"GET /__test HTTP/1.1\r\n"
                    b"Host: cache.example.invalid\r\nConnection: close\r\n\r\n"
                )
                raw.settimeout(3)
                plaintext=raw.recv(1024)
                assert b"200 OK" not in plaintext
                assert b"repocache-https" not in plaintext
                assert b"PRIVATE KEY" not in plaintext
            print("PASS: plaintext HTTP denied at HTTPS-only listener",
                  flush=True)
        finally:
            proc.terminate()
            try: proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=6)


if __name__=="__main__":
    main()
