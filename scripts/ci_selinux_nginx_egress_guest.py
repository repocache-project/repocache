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
import stat
import subprocess
import sys
import tempfile
import time

MODULE = "repocache_ci_nginx"
DOMAIN = MODULE + "_t"
UNIT = "repocache-ci-nginx-egress.service"
NS = "repocache-ci-nginx-egress"
PREFIX = "repocache-ci-selinux-"
VENDOR = Path("/usr/sbin/nginx")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
PORT = 8443
PAYLOAD = b"REPOCACHE isolated SELinux egress fixture\n" * 32

# Fixed origins and negative canaries inside the new namespace.
# The custom HTTPS port is tested without changing stock port labels.
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
for address in (('127.0.0.1', 443), ('127.0.0.2', 443), ('127.0.0.1', 5432),
                ('127.0.0.2', 8008), ('127.0.0.1', 8008)):
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


def policy_manifest(commit, archive_digest, manifest_digest, unit_digest, raw_policy):
    """Canonical, deliberately non-release test envelope with fixed scope."""
    assert re.fullmatch(r"[0-9a-f]{40}", commit)
    assert all(re.fullmatch(r"[0-9a-f]{64}", x) for x in
               (archive_digest, manifest_digest, unit_digest))
    assert type(raw_policy) is bytes and 0 < len(raw_policy) <= 16384
    return (json.dumps({
        "schema": 1, "scope": "isolated-almalinux10-egress-fixture",
        "key_id": "pr237-synthetic", "commit": commit,
        "archive_sha256": archive_digest, "release_manifest_sha256": manifest_digest,
        "signed_unit_sha256": unit_digest, "module": MODULE,
        "policy_sha256": hashlib.sha256(raw_policy).hexdigest(),
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def verify_policy_bytes(raw, envelope, detached, receipt, public_key):
    """Require exact contextual identity AND valid Ed25519 before compilation."""
    expected = policy_manifest(receipt["source_sha"], receipt["archive_sha256"],
                               receipt["manifest_sha256"],
                               receipt["files"]["repocache-nginx.service"], raw)
    if envelope != expected or len(detached) != 64:
        raise ValueError("Isolated policy envelope identity refused")
    with tempfile.TemporaryDirectory(prefix="repocache-ci-policy-auth-") as place:
        root = Path(place)
        manifest = root / "manifest"
        signature = root / "signature"
        manifest.write_bytes(envelope)
        signature.write_bytes(detached)
        outcome = command("/usr/bin/openssl", "pkeyutl", "-verify", "-pubin",
                          "-inkey", str(public_key), "-rawin", "-in", str(manifest),
                          "-sigfile", str(signature), check=False)
        if outcome.returncode:
            raise ValueError("Isolated policy signature refused")
    return raw


def authenticated_policy():
    """Use the unchanged signed-worker verifier and its existing VM trust key."""
    guard()
    sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "src"),
                    str(Path(__file__).resolve().parents[1])]
    from repocache import signatures
    from scripts import stage_native_root_worker as stage
    root = Path("/root/pr237-synthetic-fixture")
    assert root.lstat().st_uid == 0 and stat.S_IMODE(root.lstat().st_mode) == 0o700
    assert not root.is_symlink()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        pins = json.loads(stage._asset_bytes(fd, "pins.json", 1024))
        assert set(pins) == {"commit", "archive_sha256"}
        raw = stage._asset_bytes(fd, "isolated-policy.te", 16384, installed_mode=0o600)
        envelope = stage._asset_bytes(fd, "isolated-policy.json", 2048, installed_mode=0o600)
        detached = stage._asset_bytes(fd, "isolated-policy.sig", 64, installed_mode=0o600)
    finally:
        os.close(fd)
    receipt = stage.verify_installed_worker(root / "assets", **pins)
    assert receipt["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    assert receipt["publisher_key_id"] == "pr237-synthetic"
    key = signatures._trusted_key("pr237-synthetic")
    # Distinguish wrong source, identity, and invalid detached signature.
    for altered, statement, signature in (
            (raw + b"\n", envelope, detached),
            (raw, envelope.replace(receipt["source_sha"].encode(), b"0" * 40), detached),
            (raw, envelope, bytes([detached[0] ^ 1]) + detached[1:])):
        try:
            verify_policy_bytes(altered, statement, signature, receipt, key)
        except ValueError:
            pass
        else:
            raise AssertionError("Unauthenticated fixture policy accepted")
    result = verify_policy_bytes(raw, envelope, detached, receipt, key)
    print("PASS: isolated policy bound to authenticated synthetic archive and signed unit; "
          "changed source/identity/signature refused before compilation", flush=True)
    return result


def installed_modules():
    return command("/usr/sbin/semodule", "-l").stdout


def nft_rules(uid, *, negative_port_probe=False, custom_https=False):
    """The namespace has no external links; deny new nonapproved UID flows.

    5432 is intentionally allowed by the independent packet filter ONLY
    for the negative SELinux probe. The policy must deny its name_connect.
    All other fresh connections by the fixture UID are rejected.
    """
    assert type(uid) is int and 0 < uid < 2**31
    assert type(negative_port_probe) is bool
    assert type(custom_https) is bool
    ports = "{443,5432}" if negative_port_probe else "443"
    custom_rule = (f"meta skuid {uid} ip daddr 127.0.0.2 tcp dport 8008 accept"
                   if custom_https else "")
    return f"""table inet repocache_ci {{
        counter denied {{ }}
        chain output {{
            type filter hook output priority 0; policy accept;
            meta skuid {uid} ct state established,related accept
            meta skuid {uid} ip daddr 127.0.0.1 tcp dport {ports} accept
            {custom_rule}
            meta skuid {uid} counter name denied reject
        }}
    }}
    """


def request(root, path):
    assert path in ("allowed", "other-address", "other-port", "custom",
                    "wrong-pair", "custom-live", "custom-after-withdrawal")
    result = command("/usr/sbin/ip", "netns", "exec", NS, "/usr/bin/curl",
                     "--silent", "--show-error", "--max-time", "8",
                     "--noproxy", "*", "--cacert", str(root / "cert.pem"),
                     "--dump-header", str(root / "headers"),
                     "--output", str(root / "response"),
                     "--write-out", "%{http_code}",
                     f"https://127.0.0.1:{PORT}/{path}")
    return (int(result.stdout), (root / "response").read_bytes(),
            (root / "headers").read_text().lower())


def process_identity(pid, executable, uid, gid):
    """Bind the observed fixture process to its copied package executable."""
    assert type(pid) is int and pid > 1
    proc = Path("/proc") / str(pid)
    expected = executable.stat()
    observed = (proc / "exe").stat()
    assert (observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino)
    context = (proc / "attr/current").read_text().strip("\0\n")
    assert context.split(":", 3)[2] == DOMAIN
    fields = dict(line.split(":", 1) for line in
                  (proc / "status").read_text().splitlines() if ":" in line)
    assert fields["NoNewPrivs"].strip() == "1"
    assert int(fields["CapEff"].strip(), 16) == 0
    assert int(fields["CapPrm"].strip(), 16) == 0
    assert set(fields["Uid"].split()) == {str(uid)}
    assert set(fields["Gid"].split()) == {str(gid)}
    assert (proc / "ns/net").stat().st_ino == Path("/run/netns", NS).stat().st_ino
    # stat field 22 (starttime), after the parenthesized comm field.
    return (pid, (proc / "stat").read_text().rsplit(")", 1)[1].split()[19])


def workers(master, executable, uid, gid):
    children = (Path("/proc") / str(master) / "task" / str(master) / "children")
    result = set()
    for item in children.read_text().split():
        pid = int(item)
        try:
            if (Path("/proc") / item / "cmdline").read_bytes().startswith(
                    b"nginx: worker process"):
                result.add(process_identity(pid, executable, uid, gid))
        except FileNotFoundError:
            # A worker can exit while its replacement starts. Poll again.
            continue
    return result


def probe():
    guard()
    modules_before = installed_modules()
    assert MODULE not in {line.split()[0] for line in modules_before.splitlines() if line}
    assert not Path("/run/netns", NS).exists()
    policy_bytes = authenticated_policy()
    assert installed_modules() == modules_before
    assert not Path("/run/netns", NS).exists()
    assert command("/usr/bin/systemctl", "show", "-p", "LoadState",
                   "--value", UNIT, check=False).stdout.strip() == "not-found"
    booleans = command("/usr/sbin/getsebool", "-a").stdout
    owner = command("/usr/bin/rpm", "-qf", "--queryformat=%{NAME}\\n", str(VENDOR))
    assert owner.stdout.strip() == "nginx-core"
    vendor_info = VENDOR.lstat()
    assert stat.S_ISREG(vendor_info.st_mode) and vendor_info.st_uid == 0
    assert vendor_info.st_nlink == 1 and not vendor_info.st_mode & 0o022
    original = (vendor_info, hashlib.sha256(VENDOR.read_bytes()).hexdigest(),
                os.getxattr(VENDOR, "security.selinux"))
    account = pwd.getpwnam("nginx")
    assert account.pw_uid != 0 and account.pw_gid != 0
    loaded = False
    namespace = False
    started = False
    origin = None
    with tempfile.TemporaryDirectory(prefix=PREFIX, dir="/var/lib") as place:
        root = Path(place)
        assert root.parent == Path("/var/lib") and root.name.startswith(PREFIX)
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
                             ("other-port", "127.0.0.1:5432"),
                             ("custom", "127.0.0.2:8008"),
                             ("wrong-pair", "127.0.0.1:8008"),
                             ("custom-live", "127.0.0.2:8008"),
                             ("custom-after-withdrawal", "127.0.0.2:8008")):
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
    proxy_cache {'fixture' if name in ('allowed', 'custom') else 'off'};
    proxy_cache_valid 200 60s;
    add_header X-Cache $upstream_cache_status always;
}}
"""
        conf.write_text(f"""
daemon off;
master_process on;
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
            # Compile only the bytes authenticated before any policy side effects.
            policy.write_bytes(policy_bytes)
            policy.chmod(0o600)
            assert policy.read_bytes() == policy_bytes
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
                        "-f", "-", input_text=nft_rules(account.pw_uid, negative_port_probe=True))
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
                master = process_identity(pid, executable, account.pw_uid, account.pw_gid)
                assert Path(f"/proc/{pid}/cmdline").read_bytes().startswith(b"nginx: master process")
                for _ in range(100):
                    previous_workers = workers(pid, executable, account.pw_uid, account.pw_gid)
                    if len(previous_workers) == 1:
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("Expected one confined worker")
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
                # Return the packet layer to its exact permitted endpoint
                # in one atomic namespace-local nft transaction.
                command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                        "-f", "-", input_text="delete table inet repocache_ci\n"
                        + nft_rules(account.pw_uid))
                assert request(root, "allowed")[:2] == (200, PAYLOAD)
                assert request(root, "other-address")[0] == 502
                assert request(root, "other-port")[0] == 502
                assert (root / "origin-counts").read_text().splitlines() == ["127.0.0.1:443"]
                # Add exactly one custom HTTPS endpoint, not the Cartesian
                # product of approved addresses and ports. No SELinux changes.
                assert request(root, "custom")[0] == 502
                command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                        "-f", "-", input_text="delete table inet repocache_ci\n"
                        + nft_rules(account.pw_uid, custom_https=True))
                custom_first = request(root, "custom")
                custom_second = request(root, "custom")
                assert custom_first[:2] == custom_second[:2] == (200, PAYLOAD)
                assert "x-cache: miss" in custom_first[2] and "x-cache: hit" in custom_second[2]
                assert request(root, "wrong-pair")[0] == 502
                assert request(root, "other-address")[0] == 502
                assert (root / "origin-counts").read_text().splitlines() == [
                    "127.0.0.1:443", "127.0.0.2:8008"]
                # An invalid replacement must leave the existing table intact.
                invalid = command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                                  "-f", "-", input_text="delete table inet repocache_ci\n"
                                  + "add rule inet repocache_ci missing_chain accept\n",
                                  check=False)
                assert invalid.returncode != 0
                assert request(root, "wrong-pair")[0] == 502
                # A fresh positive connection must still succeed: a cached
                # HIT or a negative alone cannot establish atomic rollback.
                assert request(root, "custom-live")[:2] == (200, PAYLOAD)
                assert (root / "origin-counts").read_text().splitlines() == [
                    "127.0.0.1:443", "127.0.0.2:8008", "127.0.0.2:8008"]
                # Exercise the real master/worker reload without changing
                # executable, domain, capabilities, namespace or filter.
                command("/usr/bin/systemctl", "kill", "--kill-whom=main",
                        "--signal=HUP", UNIT)
                for _ in range(100):
                    assert process_identity(pid, executable, account.pw_uid,
                                            account.pw_gid) == master
                    current_workers = workers(pid, executable, account.pw_uid, account.pw_gid)
                    if len(current_workers) == 1 and not current_workers & previous_workers:
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("Confined worker generation did not converge")
                assert request(root, "custom-live")[:2] == (200, PAYLOAD)
                assert request(root, "wrong-pair")[0] == 502
                assert (root / "origin-counts").read_text().splitlines() == [
                    "127.0.0.1:443", "127.0.0.2:8008", "127.0.0.2:8008",
                    "127.0.0.2:8008"]
                print("PASS: confined nonroot NGINX master/worker reload, executable inode "
                      "and domain continuity; fresh positive/negative egress", flush=True)
                # Withdraw the custom tuple. The uncached location tests a
                # fresh upstream connect, not the already cached response.
                command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                        "-f", "-", input_text="delete table inet repocache_ci\n"
                        + nft_rules(account.pw_uid))
                assert request(root, "custom-after-withdrawal")[0] == 502
                assert request(root, "allowed")[:2] == (200, PAYLOAD)
                assert (root / "origin-counts").read_text().splitlines() == [
                    "127.0.0.1:443", "127.0.0.2:8008", "127.0.0.2:8008",
                    "127.0.0.2:8008"]
                print("PASS: isolated custom HTTPS tuple add, MISS/HIT, crossed tuple refusal, "
                      "failed replacement and fresh-connect withdrawal", flush=True)
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
        print("NOT VERIFIED: signed dedicated service transition, arbitrary custom port labels, "
              "production egress transaction and actual installed cache acceptance", flush=True)


if __name__ == "__main__":
    probe()
