#!/usr/bin/env python3
"""Actual NGINX, isolated service SELinux domain and exact egress experiment.

Only the marked booted AlmaLinux VM. This never edits the signed service,
vendor labels, global booleans or host firewall. No production installer.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time

MODULE = "repocache_ci_nginx"
DOMAIN = MODULE + "_t"
UNIT = "repocache-ci-nginx-egress.service"
NS = "repocache-ci-nginx-egress"
PREFIX = "/var/lib/repocache-ci-selinux-"
VENDOR = Path("/usr/sbin/nginx")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
PORT = 8443
PAYLOAD = b"REPOCACHE isolated SELinux egress fixture\n" * 32

# Fixed origin process inside the new namespace; three independent listeners.
# The database-port listener and other-address listener are negative canaries.
ORIGIN = r"""
import http.server, ssl, sys, threading
from pathlib import Path
root = Path(sys.argv[1])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(root / 'cert.pem', root / 'key.pem')
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with (root / 'origin-counts').open('a') as f:
            f.write(str(self.server.server_address[0]) + ':' +
                    str(self.server.server_address[1]) + '\n')
        payload = b'REPOCACHE isolated SELinux egress fixture\n' * 32
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'public, max-age=600')
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *args):
        pass
servers = []
for address in (('127.0.0.1', 443), ('127.0.0.2', 443), ('127.0.0.1', 5432)):
    server = http.server.ThreadingHTTPServer(address, Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    servers.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
(root / 'origin-ready').touch(exist_ok=False)
threading.Event().wait()
"""


def command(*argv, timeout=60, input_text=None, check=True):
    result = subprocess.run(argv, input=input_text, capture_output=True,
                            text=True, env=ENV, timeout=timeout, check=False)
    if check and result.returncode:
        raise AssertionError("Isolated command failed: " + Path(argv[0]).name
                             + "\n" + result.stderr[-2500:])
    return result


def guard():
    assert os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
    assert socket.gethostname() == "pr237-almalinux10"
    assert not Path("/.dockerenv").exists()
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert command("/usr/bin/systemd-detect-virt", "--vm").stdout.strip() in ("qemu", "kvm")
    assert command("/usr/sbin/getenforce").stdout.strip() == "Enforcing"
    osr = Path("/etc/os-release").read_text()
    assert re.search(r'^ID="?almalinux"?$', osr, re.M)
    assert re.search(r'^VERSION_ID="?10(?:\.[0-9]+)?"?$', osr, re.M)
    assert Path("/root/pr237-synthetic-fixture").is_dir()


def installed_modules():
    return command("/usr/sbin/semodule", "-l").stdout


def nft_rules(uid):
    """The namespace has no external links; deny new nonapproved UID flows.

    5432 is intentionally allowed by the independent packet filter ONLY
    for the negative SELinux probe. The policy must deny its name_connect.
    All other fresh connections by the fixture UID are rejected.
    """
    assert type(uid) is int and 0 < uid < 2**31
    return f"""table inet repocache_ci {{
        counter denied {{ }}
        chain output {{
            type filter hook output priority 0; policy accept;
            meta skuid {uid} ct state established,related accept
            meta skuid {uid} ip daddr 127.0.0.1 tcp dport {{443,5432}} accept
            meta skuid {uid} counter name denied reject
        }}
    }}
    """


def request(root, path):
    assert path in ("allowed", "other-address", "other-port")
    result = command("/usr/sbin/ip", "netns", "exec", NS, "/usr/bin/curl",
                     "--silent", "--show-error", "--max-time", "8",
                     "--noproxy", "*", "--cacert", str(root / "cert.pem"),
                     "--dump-header", str(root / "headers"),
                     "--output", str(root / "response"),
                     "--write-out", "%{http_code}",
                     f"https://127.0.0.1:{PORT}/{path}")
    return (int(result.stdout), (root / "response").read_bytes(),
            (root / "headers").read_text().lower())


def probe():
    guard()
    modules_before = installed_modules()
    assert MODULE not in {line.split()[0] for line in modules_before.splitlines() if line}
    assert not Path("/run/netns", NS).exists()
    assert command("/usr/bin/systemctl", "show", "-p", "LoadState",
                   "--value", UNIT).stdout.strip() == "not-found"
    booleans = command("/usr/sbin/getsebool", "-a").stdout
    original = (VENDOR.stat(), hashlib.sha256(VENDOR.read_bytes()).hexdigest(),
                os.getxattr(VENDOR, "security.selinux"))
    account = pwd.getpwnam("nginx")
    assert account.pw_uid != 0 and account.pw_gid != 0
    loaded = False
    namespace = False
    started = False
    origin = None
    with tempfile.TemporaryDirectory(prefix=PREFIX) as place:
        root = Path(place)
        # tempfile supports an absolute prefix; verify the actual private path.
        assert root.parent == Path("/var/lib") and root.name.startswith(Path(PREFIX).name)
        assert root.resolve(strict=True) == root and root.stat().st_uid == 0
        root.chmod(0o755)
        writable = root / "runtime"
        writable.mkdir(mode=0o750)
        os.chown(writable, account.pw_uid, account.pw_gid)
        for name in ("body", "proxy", "fastcgi", "scgi", "uwsgi", "cache"):
            path = writable / name
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
        executable = root / "nginx"
        shutil.copyfile(VENDOR, executable)
        executable.chmod(0o755)
        assert hashlib.sha256(executable.read_bytes()).hexdigest() == original[1]
        cert, key = root / "cert.pem", root / "key.pem"
        command("/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-days", "1", "-keyout", str(key), "-out", str(cert),
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
        os.chown(key, 0, account.pw_gid)
        key.chmod(0o640)
        cert.chmod(0o644)
        conf = root / "nginx.conf"
        locations = ""
        for name, target in (("allowed", "127.0.0.1:443"),
                             ("other-address", "127.0.0.2:443"),
                             ("other-port", "127.0.0.1:5432")):
            locations += f"""
location = /{name} {{
    proxy_pass https://{target}/fixture;
    proxy_ssl_verify on;
    proxy_ssl_server_name on;
    proxy_ssl_name localhost;
    proxy_ssl_trusted_certificate {cert};
    proxy_connect_timeout 2s;
    proxy_read_timeout 5s;
    proxy_max_temp_file_size 0;
    proxy_cache {'fixture' if name == 'allowed' else 'off'};
    proxy_cache_valid 200 60s;
    add_header X-Cache $upstream_cache_status always;
}}
"""
        conf.write_text(f"""
daemon off;
master_process off;
worker_processes 1;
pid {writable}/nginx.pid;
error_log {writable}/error.log notice;
events {{ worker_connections 64; }}
http {{
access_log {writable}/access.log;
client_body_temp_path {writable}/body;
proxy_temp_path {writable}/proxy;
fastcgi_temp_path {writable}/fastcgi;
scgi_temp_path {writable}/scgi;
uwsgi_temp_path {writable}/uwsgi;
proxy_cache_path {writable}/cache levels=1:2 keys_zone=fixture:1m use_temp_path=off;
server {{
listen 127.0.0.1:{PORT} ssl;
ssl_certificate {cert};
ssl_certificate_key {key};
location = /health {{ return 204; }}
{locations}
}}
}}
""", encoding="ascii")
        conf.chmod(0o644)
        with tempfile.TemporaryDirectory(prefix="repocache-policy-build-") as build:
            build = Path(build)
            policy = build / (MODULE + ".te")
            shutil.copyfile(Path(__file__).with_name("ci_selinux_nginx_egress_fixture.te"), policy)
            command("/usr/bin/make", "-C", str(build), "-f",
                    "/usr/share/selinux/devel/Makefile", MODULE + ".pp", timeout=120)
            try:
                command("/usr/sbin/semodule", "-i", str(build / (MODULE + ".pp")), timeout=120)
                loaded = True
                command("/usr/bin/chcon", "-t", MODULE + "_ro_t", str(root),
                        str(cert), str(key), str(conf))
                command("/usr/bin/chcon", "-t", MODULE + "_exec_t", str(executable))
                command("/usr/bin/chcon", "-R", "-t", MODULE + "_rw_t", str(writable))
                command("/usr/sbin/ip", "netns", "add", NS)
                namespace = True
                command("/usr/sbin/ip", "-n", NS, "link", "set", "lo", "up")
                command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                        "-f", "-", input_text=nft_rules(account.pw_uid))
                origin = subprocess.Popen(
                    ["/usr/sbin/ip", "netns", "exec", NS, "/usr/bin/python3",
                     "-I", "-c", ORIGIN, str(root)], env=ENV,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)
                for _ in range(100):
                    assert origin.poll() is None
                    if (root / "origin-ready").is_file():
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("Origin not ready")
                # NoNewPrivileges plus native init domain transition, no
                # capabilities, no root service process, dedicated network.
                started = True
                command("/usr/bin/systemd-run", "--unit=" + UNIT, "--property=Type=exec",
                        "--property=User=nginx", "--property=Group=nginx",
                        "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
                        "--property=ProtectSystem=strict",
                        "--property=ReadWritePaths=" + str(writable),
                        "--property=NetworkNamespacePath=/run/netns/" + NS,
                        "--property=RestrictAddressFamilies=AF_UNIX AF_INET",
                        "--property=PrivateTmp=yes",
                        str(executable), "-p", str(root), "-c", str(conf))
                for _ in range(100):
                    ready = command("/usr/sbin/ip", "netns", "exec", NS, "/usr/bin/curl",
                                    "-sS", "--max-time", "1", "--noproxy", "*",
                                    "--cacert", str(cert), "-o", "/dev/null",
                                    "-w", "%{http_code}",
                                    f"https://127.0.0.1:{PORT}/health", check=False)
                    if ready.returncode == 0 and ready.stdout == "204":
                        break
                    time.sleep(0.1)
                else:
                    status = command("/usr/bin/systemctl", "show", UNIT,
                                     "-p", "ActiveState", "-p", "SubState", "-p", "Result",
                                     check=False)
                    raise AssertionError("Confined fixture not ready: " + status.stdout
                                         + "\n" + ((writable / "error.log").read_text()[-2000:]
                                                   if (writable / "error.log").is_file() else ""))
                pid = int(command("/usr/bin/systemctl", "show", "--value",
                                  "-p", "MainPID", UNIT).stdout)
                assert pid > 1
                context = Path(f"/proc/{pid}/attr/current").read_text().strip("\0\n")
                assert context.split(":", 3)[2] == DOMAIN
                status = Path(f"/proc/{pid}/status").read_text()
                assert re.search(r"^NoNewPrivs:\s+1$", status, re.M)
                assert re.search(r"^CapEff:\s+0+$", status, re.M)
                assert re.search(r"^Uid:\s+" + str(account.pw_uid) + r"\s", status, re.M)
                assert os.stat(f"/proc/{pid}/ns/net").st_ino == Path("/run/netns", NS).stat().st_ino
                first, second = request(root, "allowed"), request(root, "allowed")
                assert first[:2] == second[:2] == (200, PAYLOAD)
                assert "x-cache: miss" in first[2] and "x-cache: hit" in second[2]
                assert request(root, "other-address")[0] == 502
                assert request(root, "other-port")[0] == 502
                assert (root / "origin-counts").read_text().splitlines() == ["127.0.0.1:443"]
                log = (writable / "error.log").read_text()
                assert "127.0.0.1:5432 failed (13: Permission denied)" in log
                counters = json.loads(command("/usr/sbin/ip", "netns", "exec", NS,
                                               "/usr/sbin/nft", "-j", "list", "counter",
                                               "inet", "repocache_ci", "denied").stdout)
                assert any(row.get("counter", {}).get("packets", 0) > 0
                           for row in counters["nftables"])
                assert any(p.is_file() for p in (writable / "cache").rglob("*"))
                assert command("/usr/sbin/getenforce").stdout.strip() == "Enforcing"
                print("PASS: dedicated enforcing NGINX domain, verified HTTPS MISS/HIT, "
                      "SELinux non-HTTP-port refusal and independent exact-address refusal", flush=True)
            finally:
                if started:
                    command("/usr/bin/systemctl", "stop", UNIT, check=False)
                    assert command("/usr/bin/systemctl", "is-active", UNIT,
                                   check=False).stdout.strip() in ("inactive", "unknown")
                if origin is not None:
                    if origin.poll() is None:
                        os.killpg(origin.pid, signal.SIGTERM)
                    origin.wait(timeout=10)
                if namespace:
                    command("/usr/sbin/ip", "netns", "delete", NS)
                # Remove only this new VM fixture tree before policy removal.
                # TemporaryDirectory will then observe an already absent tree.
                if loaded:
                    shutil.rmtree(root)
                    command("/usr/sbin/semodule", "-r", MODULE, timeout=120)
        assert not Path("/run/netns", NS).exists()
        assert installed_modules() == modules_before
        assert command("/usr/sbin/getsebool", "-a").stdout == booleans
        assert hashlib.sha256(VENDOR.read_bytes()).hexdigest() == original[1]
        assert os.getxattr(VENDOR, "security.selinux") == original[2]
        guard()
        print("PASS: isolated SELinux module and netns removed; stock booleans and vendor unchanged",
              flush=True)
        print("NOT VERIFIED: signed dedicated service transition, custom HTTPS port lifecycle, "
              "production egress transaction and actual installed cache acceptance", flush=True)


if __name__ == "__main__":
    probe()
