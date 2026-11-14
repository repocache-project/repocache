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

from repocache.server_nginx_tls_listener_candidate_v1 import (
    render_native_tls_listener_candidate,
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
        result=render_native_tls_listener_candidate(d)
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
                "http {\naccess_log off;\n" + temp_paths + "server {\n" + result["server_context_fragment"]
                + 'location = /__test { return 200 "repocache-https"; }\n'
                + "}\n}\n")
        conf=root/"nginx.conf"
        conf.write_text(config)
        syntax=subprocess.run([nginx,"-t","-p",str(root),"-c",str(conf)],
                              capture_output=True,timeout=15,check=False)
        assert syntax.returncode == 0, "STOCK_NGINX_TLS_SYNTAX_INVALID"
        print("PASS: validated v1 candidate accepted by actual native NGINX",flush=True)
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
        finally:
            proc.terminate()
            try: proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=6)


if __name__=="__main__":
    main()
