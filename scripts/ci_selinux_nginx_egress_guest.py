#!/usr/bin/env python3
"""Actual NGINX, isolated service SELinux domain and exact egress experiment.

Only the marked booted AlmaLinux VM. This never edits the signed service,
vendor labels, global booleans or host firewall. No production installer.
"""
from __future__ import annotations

import ctypes
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
ROOT_UNIT = "repocache-ci-nginx-root-egress.service"
DERIVED_UNIT = "repocache-ci-nginx-derived-egress.service"
DERIVED_ROOT_UNIT = "repocache-ci-nginx-derived-root-egress.service"
CREDENTIAL_UNIT = "repocache-ci-nginx-credential.service"
NS = "repocache-ci-nginx-egress"
PEER_NS = "repocache-ci-nginx-peer"
SERVICE_LINK = "rcsvc0"
PEER_LINK = "rcpeer0"
SERVICE_ADDR = "192.0.2.1"
APT_PEER = "192.0.2.2"
DNF_PEER = "192.0.2.3"
PREFIX = "repocache-ci-selinux-"
VENDOR = Path("/usr/sbin/nginx")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
PORT = 8443
PAYLOAD = b"REPOCACHE isolated SELinux egress fixture\n" * 32
# CHOWN, KILL, SETGID, SETUID only; no DAC bypass or network administration.
MASTER_CAPS = (1 << 0) | (1 << 5) | (1 << 6) | (1 << 7)
MASTER_CAP_NAMES = "CAP_CHOWN CAP_KILL CAP_SETGID CAP_SETUID"

# Fixed origins and negative canaries inside the new namespace.
# The custom HTTPS port is tested without changing stock port labels.
ORIGIN = r"""
import http.server, ssl, sys, threading
from pathlib import Path
root = Path(sys.argv[1])
assert len(sys.argv) in (2, 3)
remote = len(sys.argv) == 3
assert not remote or sys.argv[2] == "peer"
counts = "peer-origin-counts" if remote else "origin-counts"
ready = "peer-origin-ready" if remote else "origin-ready"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(root / 'cert.pem', root / 'key.pem')
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with (root / counts).open('a') as f:
            f.write(str(self.server.server_address[0]) + ':' +
                    str(self.server.server_address[1]) + '\n')
        if self.path == '/rendered/apt/redirect':
            self.send_response(302)
            self.send_header('Location', 'https://unapproved.example.invalid/')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        payload = b'REPOCACHE isolated SELinux egress fixture\n' * 32
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'public, max-age=600')
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *args):
        pass
servers = []
addresses = (('192.0.2.2', 443), ('192.0.2.3', 443),
             ('192.0.2.3', 8008), ('192.0.2.2', 8008)) if remote else (
                 ('127.0.0.1', 443), ('127.0.0.2', 443), ('127.0.0.1', 5432),
                 ('127.0.0.2', 8008), ('127.0.0.1', 8008))
for address in addresses:
    server = http.server.ThreadingHTTPServer(address, Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    servers.append(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
(root / ready).touch(exist_ok=False)
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
    # This standalone test uses assertions for all of its native boundaries.
    # Reject optimized execution before any system or filesystem mutation.
    if not __debug__:
        raise AssertionError("Native isolated fixture requires assertions enabled")
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


def authenticated_policy(*, include_unit=False):
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
    if include_unit:
        # Re-read only the fixed signed unit through the audited file primitive.
        directory = os.open("/etc/systemd/system", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            stage._protected_directory(directory)
            signed_unit = stage._asset_bytes(directory, "repocache-nginx.service", 8192,
                                             installed_mode=0o644)
        finally:
            os.close(directory)
        assert hashlib.sha256(signed_unit).hexdigest() == receipt["files"]["repocache-nginx.service"]
        return result, signed_unit
    return result


def derive_signed_unit(raw, root, *, root_master=False):
    """Strict fixed transformations of authenticated bytes, never a host unit editor."""
    assert type(raw) is bytes and 0 < len(raw) <= 8192
    assert type(root_master) is bool
    assert root.parent == Path("/var/lib") and re.fullmatch(PREFIX + r"[a-z0-9_]+", root.name)
    # Require exact service contract; unexpected upstream unit changes fail
    # closed and must be reviewed rather than silently inherited.
    expected = {
        "Type": "forking", "RuntimeDirectory": "repocache-nginx",
        "RuntimeDirectoryMode": "0755", "PIDFile": "/run/repocache-nginx/nginx.pid",
        "ExecStartPre": "/usr/sbin/nginx -t -q -c /etc/nginx/repocache.d/repocache.conf",
        "ExecStart": "/usr/sbin/nginx -c /etc/nginx/repocache.d/repocache.conf",
        "ExecReload": "/usr/sbin/nginx -s reload -c /etc/nginx/repocache.d/repocache.conf",
        "ExecStop": "/usr/sbin/nginx -s quit -c /etc/nginx/repocache.d/repocache.conf",
        "TimeoutStartSec": "30s", "TimeoutStopSec": "30s", "KillMode": "mixed",
        "NoNewPrivileges": "yes", "PrivateTmp": "yes", "ProtectHome": "yes",
        "ProtectSystem": "strict",
        "ReadWritePaths": "/run/repocache-nginx /var/cache/nginx/repocache-managed /var/log/nginx/repocache-managed",
        "UMask": "0027",
    }
    import configparser
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(raw.decode("ascii"))
    assert parser.defaults() == {}
    assert parser.sections() == ["Unit", "Service", "Install"]
    assert dict(parser["Unit"]) == {"Description": "REPOCACHE isolated native NGINX service",
                                    "After": "network.target"}
    assert dict(parser["Service"]) == expected
    assert dict(parser["Install"]) == {"WantedBy": "multi-user.target"}
    service = dict(expected)
    del service["RuntimeDirectory"]
    del service["RuntimeDirectoryMode"]
    service["PIDFile"] = str(root / "pid/nginx.pid")
    service["ReadWritePaths"] = str(root / "runtime") + " " + str(root / "pid")
    for key in ("ExecStartPre", "ExecStart", "ExecReload", "ExecStop"):
        service[key] = (service[key].replace("/usr/sbin/nginx", str(root / "nginx") +
                           " -e stderr -p " + str(root))
                        .replace("/etc/nginx/repocache.d/repocache.conf", str(root / "nginx.conf")))
    service.update({"CapabilityBoundingSet": MASTER_CAP_NAMES if root_master else "",
                    "NetworkNamespacePath": "/run/netns/" + NS,
                    "RestrictAddressFamilies": "AF_UNIX AF_INET"})
    if not root_master:
        service.update({"User": "nginx", "Group": "nginx"})
    # For the root variant preserve the signed unit's implicit system-manager
    # identity. With an explicit User=root and seccomp, systemd can consume
    # CAP_SETUID while setting up the credentials before exec. No ambient
    # capabilities, bounding-set extension or NNP relaxation is permitted.
    # No [Install] section: this is a runtime-only, never-enabled unit.
    return ("[Unit]\nDescription=REPOCACHE CI derived signed unit\nAfter=network.target\n"
            "[Service]\n" + "".join(key + "=" + value + "\n" for key, value in service.items())
            ).encode("ascii")


def publish_derived_unit(raw, unit):
    guard()
    assert unit in (DERIVED_UNIT, DERIVED_ROOT_UNIT)
    path = Path("/run/systemd/system") / unit
    assert path.parent.resolve(strict=True) == path.parent
    assert path.parent.stat().st_uid == 0 and not path.parent.stat().st_mode & 0o022
    # The caller records the exact inode and performs scoped cleanup even if
    # daemon-reload/start subsequently fails. Never replace an existing unit.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            info = os.fstat(stream.fileno())
    except Exception:
        named = path.lstat()
        if (named.st_dev, named.st_ino) == (created.st_dev, created.st_ino):
            path.unlink()
        raise
    return (path, info.st_dev, info.st_ino, hashlib.sha256(raw).hexdigest())


def remove_derived_unit(identity):
    guard()
    path, dev, ino, digest = identity
    assert path.parent == Path("/run/systemd/system") and path.name in (DERIVED_UNIT, DERIVED_ROOT_UNIT)
    info = path.lstat()
    assert (info.st_dev, info.st_ino, info.st_uid, info.st_nlink) == (dev, ino, 0, 1)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    path.unlink()
    command("/usr/bin/systemctl", "daemon-reload")
    assert not path.exists()


def authenticated_vendor_digest():
    """Independently verify the installed executable against a signed RPM.

    No package install, system RPMDB import, third-party repo or executable
    extraction. Use the existing distribution-specific signed metadata profile.
    """
    guard()
    sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "src"),
                    str(Path(__file__).resolve().parents[1])]
    from repocache.server_native_package_trust_v1 import _dnf_commands, _trusted_key, _NATIVE
    from repocache.server_stock_nginx_package_owner_v1 import inspect_stock_nginx_package_file_integrity
    from ci_dnf_signed_rpm_fallback import _label_isolated_rpmdb, _rpm_signature_verified
    key = _NATIVE["almalinux"][2]
    assert _trusted_key(key)
    assert inspect_stock_nginx_package_file_integrity()["native_package_file_integrity_verified"]
    fmt = "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"
    installed = command("/usr/bin/rpm", "-q", "--queryformat=" + fmt, "nginx-core").stdout.strip()
    assert re.fullmatch(r"nginx-core-[0-9]+:[A-Za-z0-9._+~-]+-[A-Za-z0-9._+~-]+\.x86_64", installed)
    with tempfile.TemporaryDirectory(prefix="repocache-ci-rpm-payload-", dir="/var/lib") as place:
        work = Path(place)
        update, query = _dnf_commands(work)
        assert query[-4:] == ["repoquery", "--available", "--queryformat=%{name}", "nginx"]
        command(*update, timeout=180)
        locations = command(*query[:-4], "-q", "repoquery", "--available",
                            "--location", installed, timeout=120).stdout.splitlines()
        urls = sorted(set(line.strip() for line in locations if line.strip()))
        assert len(urls) == 1 and re.fullmatch(
            r"https://repo\.almalinux\.org/almalinux/10/(?:AppStream|BaseOS)/"
            r"x86_64/os/Packages/(?:[A-Za-z0-9._+~-]+/)*nginx-core-[A-Za-z0-9._+~-]+\.rpm",
            urls[0]), "Exact signed RPM location unavailable"
        payload = work / "nginx-core.rpm"
        command("/usr/bin/curl", "--fail", "--silent", "--show-error",
                "--proto", "=https", "--tlsv1.2", "--max-filesize", str(32 * 1024 * 1024),
                "--max-time", "90", "--output", str(payload), urls[0], timeout=100)
        payload.chmod(0o600)
        assert payload.is_file() and 0 < payload.stat().st_size <= 32 * 1024 * 1024
        with tempfile.TemporaryDirectory(prefix="repocache-ci-rpmdb-", dir="/var/lib") as db:
            rpmdb = Path(db)
            _label_isolated_rpmdb(rpmdb)
            command("/usr/bin/rpm", "--dbpath", db, "--initdb")
            command("/usr/bin/rpm", "--dbpath", db, "--import", key)
            verified = command("/usr/bin/rpmkeys", "--dbpath", db, "--checksig", "--verbose",
                               str(payload))
            assert _rpm_signature_verified(verified.stdout + verified.stderr)
        identity = command("/usr/bin/rpm", "-qp", "--queryformat=" + fmt,
                           str(payload)).stdout.strip()
        assert identity == installed
        algorithm = command("/usr/bin/rpm", "-qp", "--queryformat=%{FILEDIGESTALGO}",
                            str(payload)).stdout.strip()
        assert algorithm == "8"
        rows = command("/usr/bin/rpm", "-qp", "--queryformat=[%{FILENAMES}\\t%{FILEDIGESTS}\\n]",
                       str(payload)).stdout.splitlines()
        matching = [row.split("\t", 1)[1] for row in rows
                    if row.startswith(str(VENDOR) + "\t")]
        assert len(matching) == 1 and re.fullmatch(r"[0-9a-f]{64}", matching[0])
        digest = hashlib.sha256(VENDOR.read_bytes()).hexdigest()
        assert digest == matching[0], "Installed executable differs from authenticated RPM"
    print("PASS: exact native nginx-core RPM verified by isolated OS key and signed "
          "SHA-256 file digest matches the installed executable", flush=True)
    return digest


def capability_policy(context, permission):
    """Query the loaded enforcing kernel policy, not an optional CLI."""
    if context.split(":")[2:3] != [DOMAIN] or permission not in ("setuid", "setgid"):
        return "NOT_VERIFIED"
    class Decision(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint) for name in
                    ("allowed", "decided", "auditallow", "auditdeny", "seqno", "flags")]
    try:
        lib = ctypes.CDLL("libselinux.so.1")
        lib.security_getenforce.argtypes = ()
        lib.security_getenforce.restype = ctypes.c_int
        lib.string_to_security_class.argtypes = (ctypes.c_char_p,)
        lib.string_to_security_class.restype = ctypes.c_ushort
        lib.string_to_av_perm.argtypes = (ctypes.c_ushort, ctypes.c_char_p)
        lib.string_to_av_perm.restype = ctypes.c_uint
        lib.security_compute_av_flags_raw.argtypes = (
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ushort, ctypes.c_uint,
            ctypes.POINTER(Decision))
        lib.security_compute_av_flags_raw.restype = ctypes.c_int
        klass = lib.string_to_security_class(b"capability")
        perm = lib.string_to_av_perm(klass, permission.encode("ascii")) if klass else 0
        decision = Decision()
        raw = context.encode("ascii")
        if (not perm or lib.security_getenforce() != 1
                or lib.security_compute_av_flags_raw(raw, raw, klass, perm, ctypes.byref(decision))
                or decision.flags & 1):
            return "NOT_VERIFIED"
        return "ALLOW" if decision.allowed & perm else "DENY"
    except (OSError, ValueError, AttributeError):
        return "NOT_VERIFIED"


def start_diagnostics(unit, writable):
    """Bounded fixture-only diagnostics before cleanup removes evidence."""
    status = command("/usr/bin/systemctl", "show", unit, "-p", "ActiveState",
                     "-p", "SubState", "-p", "Result", "-p", "MainPID",
                     "-p", "ExecMainStatus", check=False)
    journal = command("/usr/bin/journalctl", "--unit=" + unit, "--no-pager",
                      "-n", "60", "--output=short-monotonic", check=False)
    log = writable / "error.log"
    print("ISOLATED_START_STATUS: " + status.stdout[-2000:], flush=True)
    context = ""
    main = command("/usr/bin/systemctl", "show", "-p", "MainPID", "--value", unit, check=False).stdout.strip()
    if main.isdigit() and int(main) > 1:
        proc = Path("/proc") / main
        try:
            fields = [line for line in (proc / "status").read_text().splitlines()
                      if line.split(":", 1)[0] in {"Uid", "Gid", "CapInh", "CapPrm", "CapEff",
                                                   "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"}]
            print("ISOLATED_MASTER_CREDENTIALS: " + " | ".join(fields), flush=True)
            context = (proc / "attr/current").read_text().strip("\0\n")
            print("ISOLATED_MASTER_DOMAIN: " + context, flush=True)
            print("ISOLATED_MASTER_UID_MAP: " + (proc / "uid_map").read_text().strip(), flush=True)
        except OSError:
            print("ISOLATED_MASTER_CREDENTIALS: NOT OBSERVED", flush=True)
    for cap in ("setgid", "setuid"):
        print("ISOLATED_CAPABILITY_POLICY_" + cap.upper() + ": "
              + capability_policy(context, cap), flush=True)
    print("ISOLATED_START_JOURNAL: " + journal.stdout[-5000:], flush=True)
    if log.is_file():
        print("ISOLATED_NGINX_ERROR: " + log.read_text(errors="replace")[-5000:], flush=True)
    if Path("/usr/sbin/ausearch").is_file():
        audit = command("/usr/sbin/ausearch", "-m", "AVC,USER_AVC", "-ts", "recent", check=False)
        records = [line for line in audit.stdout.splitlines() if MODULE in line]
        print("ISOLATED_AVC: " + ("\n".join(records[-20:])[-4000:] or "NOT OBSERVED"), flush=True)


def credential_probe(root, account):
    """On root-master failure, reproduce the exact credential drop in the same
    isolated domain and capability set; no change to NNP, booleans or policy.
    """
    guard()
    assert root.parent == Path("/var/lib") and root.name.startswith(PREFIX)
    interpreter = Path("/usr/bin/python3").resolve(strict=True)
    assert interpreter.parent == Path("/usr/bin") and re.fullmatch(r"python3\.[0-9]+", interpreter.name)
    before = interpreter.stat()
    assert stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
    copy = root / "credential-python"
    shutil.copyfile(interpreter, copy)
    copy.chmod(0o755)
    assert hashlib.sha256(copy.read_bytes()).digest() == hashlib.sha256(interpreter.read_bytes()).digest()
    command("/usr/bin/chcon", "-t", MODULE + "_exec_t", str(copy))
    code = r"""
import os, sys
from pathlib import Path
uid, gid = map(int, sys.argv[1:3])
def snapshot(phase):
    rows = [x for x in Path('/proc/self/status').read_text().splitlines()
            if x.split(':', 1)[0] in ('Uid','Gid','CapEff','CapPrm','CapBnd','CapAmb','NoNewPrivs','Seccomp')]
    print(phase, Path('/proc/self/attr/current').read_text().strip('\0\n'), ' | '.join(rows), flush=True)
snapshot('before')
assert os.getresuid() == (0, 0, 0)
try:
    os.setgid(gid)
    os.initgroups('nginx', gid)
    snapshot('after-groups')
    os.setuid(uid)
    snapshot('after-uid')
    assert os.getresuid() == (uid, uid, uid) and os.getresgid() == (gid, gid, gid)
except OSError as e:
    print('CREDENTIAL_DROP_ERRNO', e.errno, flush=True)
    raise
"""
    assert command("/usr/bin/systemctl", "show", "-p", "LoadState", "--value",
                   CREDENTIAL_UNIT, check=False).stdout.strip() == "not-found"
    try:
        result = command("/usr/bin/systemd-run", "--unit=" + CREDENTIAL_UNIT,
                         "--wait", "--pipe", "--collect", "--property=Type=exec",
                         "--property=CapabilityBoundingSet=" + MASTER_CAP_NAMES,
                         "--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict",
                         "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
                         "--property=NetworkNamespacePath=/run/netns/" + NS,
                         "--property=RestrictAddressFamilies=AF_UNIX AF_INET",
                         "--property=TimeoutStartSec=15s", "--property=RuntimeMaxSec=15s",
                         str(copy), "-I", "-B", "-c", code, str(account.pw_uid),
                         str(account.pw_gid), timeout=30, check=False)
        print("ISOLATED_CREDENTIAL_CANARY_EXIT=" + str(result.returncode), flush=True)
        print((result.stdout + result.stderr)[-4500:], flush=True)
    finally:
        command("/usr/bin/systemctl", "stop", CREDENTIAL_UNIT, check=False)
        assert command("/usr/bin/systemctl", "is-active", CREDENTIAL_UNIT,
                       check=False).stdout.strip() in ("inactive", "unknown", "failed")


def installed_modules():
    return command("/usr/sbin/semodule", "-l").stdout


def nft_rules(uid, *, negative_port_probe=False, custom_https=False, root_master=False,
              remote=False):
    """The namespace has no external links; deny new nonapproved UID flows.

    5432 is intentionally allowed by the independent packet filter ONLY
    for the negative SELinux probe. The policy must deny its name_connect.
    All other fresh connections by the fixture UID are rejected.
    """
    assert type(uid) is int and 0 < uid < 2**31
    assert type(negative_port_probe) is bool
    assert type(custom_https) is bool and type(root_master) is bool
    assert type(remote) is bool
    assert not remote or (root_master and not negative_port_probe)
    ports = "{443,5432}" if negative_port_probe else "443"
    first = APT_PEER if remote else "127.0.0.1"
    second = DNF_PEER if remote else "127.0.0.2"
    custom_rule = (f"meta skuid {uid} ip daddr {second} tcp dport 8008 accept"
                   if custom_https else "")
    root_rules = (f"ct state established,related accept\n"
                  f"meta skuid 0 ip daddr 127.0.0.1 tcp dport {PORT} accept"
                  if root_master else "")
    return f"""table inet repocache_ci {{
        counter denied {{ }}
        chain output {{
            type filter hook output priority 0; policy {'drop' if root_master else 'accept'};
            {root_rules}
            meta skuid {uid} ct state established,related accept
            meta skuid {uid} ip daddr {first} tcp dport {ports} accept
            {custom_rule}
            {"" if root_master else f"meta skuid {uid}"} counter name denied reject
        }}
    }}
    """


def request(root, path, *, method="GET", remote=False):
    assert method in ("GET", "POST") and type(remote) is bool
    assert path in ("allowed", "other-address", "other-port", "custom",
                    "wrong-pair", "custom-live", "custom-after-withdrawal",
                    "remote-wrong-pair", "remote-wrong-address") or re.fullmatch(
        r"__repocache/repos/fixture-(?:apt|dnf)/(?:payload|fresh|redirect)", path)
    resolve = ["--resolve", f"cache.example.invalid:{PORT}:{SERVICE_ADDR}"] if remote else []
    host = "cache.example.invalid" if remote else "127.0.0.1"
    result = command("/usr/sbin/ip", "netns", "exec", PEER_NS if remote else NS, "/usr/bin/curl",
                     "--silent", "--show-error", "--max-time", "8",
                     "--noproxy", "*", "--request", method, "--cacert", str(root / "cert.pem"),
                     *resolve, "--dump-header", str(root / "headers"),
                     "--output", str(root / "response"),
                     "--write-out", "%{http_code}",
                     f"https://{host}:{PORT}/{path}")
    return (int(result.stdout), (root / "response").read_bytes(),
            (root / "headers").read_text().lower())


def verify_peer_ruleset(expected):
    """Fixed whole-ruleset listing and signed-worker closed shape check."""
    guard()
    namespace = Path("/run/netns", NS)
    before = namespace.stat()
    host = Path("/proc/self/ns/net").stat()
    peer = Path("/run/netns", PEER_NS).stat()
    identity = (before.st_dev, before.st_ino)
    assert identity not in ((host.st_dev, host.st_ino), (peer.st_dev, peer.st_ino))
    observed = command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                       "--stateless", "--numeric-priority", "list", "ruleset").stdout
    after = namespace.stat()
    assert (after.st_dev, after.st_ino) == identity
    code = """
import json,sys,zipimport
sys.path.insert(0, "/usr/libexec/repocache/server-control-worker")
from repocache import server_native_egress_candidate_v1 as egress
assert isinstance(egress.__loader__, zipimport.zipimporter)
assert egress.__loader__.archive == "/usr/libexec/repocache/server-control-worker"
expected,observed=json.load(sys.stdin)
print(json.dumps(egress.verify_namespace_egress_readback(expected, observed)))
"""
    outcome = command("/usr/bin/python3", "-IS", "-B", "-c", code,
                      input_text=json.dumps([expected, observed]), check=False)
    if outcome.returncode:
        raise AssertionError("Authenticated closed ruleset readback refused: " +
                             observed[-4000:])
    report = json.loads(outcome.stdout)
    assert report["ruleset_shape_matches"] and not report["runtime_egress_verified"]
    assert not report["authorizes_firewall_change"]
    return report


def replace_peer_ruleset(previous, proposed):
    """Only this isolated fixture's already-owned table may be replaced."""
    guard()
    verify_peer_ruleset(previous)
    batch = "delete table inet repocache_egress\n" + proposed
    command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft", "-c", "-f", "-",
            input_text=batch)
    verify_peer_ruleset(previous)
    command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft", "-f", "-",
            input_text=batch)
    verify_peer_ruleset(proposed)
    print("PASS: exact prior and replacement private namespace ruleset readback", flush=True)


def denied_packets():
    """Read only the named kernel counter in the already guarded private netns."""
    guard()
    data = json.loads(command("/usr/sbin/ip", "netns", "exec", NS,
                              "/usr/sbin/nft", "-j", "list", "counter",
                              "inet", "repocache_egress", "denied").stdout)
    return parse_denied_packets(data)


def parse_denied_packets(data):
    rows = [entry["counter"] for entry in data["nftables"] if "counter" in entry]
    assert len(rows) == 1
    row = rows[0]
    assert (row["family"], row["table"], row["name"]) == (
        "inet", "repocache_egress", "denied")
    assert type(row["packets"]) is int and row["packets"] >= 0
    return row["packets"]


def peer_denied(root, path):
    # ICMP reject across veth need not reach the connecting process
    # before proxy_connect_timeout. Require actual packet denial evidence.
    before = denied_packets()
    counts = root / "peer-origin-counts"
    prior = counts.read_bytes() if counts.exists() else None
    code, _, _ = request(root, path, remote=True)
    after = denied_packets()
    assert code in (502, 504) and after > before, (path, code, before, after)
    assert (counts.read_bytes() if counts.exists() else None) == prior
    print("PASS: exact peer denial " + path + " HTTP " + str(code) +
          " kernel denied packets +" + str(after - before), flush=True)


def render_signed_fixture_routes(root, *, dnf_enabled=True, remote=False, worker_uid):
    """Use the authenticated installed zipapp's actual candidate renderer.

    Only the isolated harness substitutes the two loopback tuples after the
    normal validator rejects private pins. No product validator is relaxed.
    """
    guard()
    assert root.parent == Path("/var/lib") and root.name.startswith(PREFIX)
    assert type(dnf_enabled) is bool and type(remote) is bool
    document = json.loads((Path(__file__).resolve().parents[1] /
                           "docs/examples/server-install-v1.json").read_text("ascii"))
    dep = document["deployment"]
    dep["paths"]["cache_root"] = str(root / "runtime/cache")
    dep["paths"]["log_root"] = str(root / "runtime/logs")
    dep["paths"]["state_root"] = str(root / "state")
    dep["paths"]["generated_include"] = str(root / "nginx.conf")
    dep["tls"]["certificate_file"] = str(root / "cert.pem")
    dep["tls"]["private_key_file"] = str(root / "key.pem")
    dep["listen"]["https_port"] = PORT
    document["expected_state_generation"] = 1 if dnf_enabled else 2
    assert sorted(repo["kind"] for repo in document["repositories"]) == ["apt", "dnf"]
    pins = {}
    for repo in document["repositories"]:
        kind = repo["kind"]
        ident = "fixture-" + kind
        repo["id"] = ident
        enabled = kind == "apt" or dnf_enabled
        repo["desired_state"] = "active" if enabled else "disabled"
        port = "" if kind == "apt" else ":8008"
        repo["upstream"] = {"base_url": "https://cache.example.invalid" + port +
                            "/rendered/" + kind + "/",
                            "allowed_hosts": ["cache.example.invalid"]}
        if enabled:
            pins[ident] = {"cache.example.invalid": ["8.8.8.8"]}
    # The surrounding probe has just authenticated the installed worker
    # archive and its bytes against the synthetic release. Assert its loader.
    code = """
import json,sys,zipimport
sys.path.insert(0, "/usr/libexec/repocache/server-control-worker")
from repocache import server_nginx_repository_bundle_v1 as bundle
from repocache import server_native_egress_candidate_v1 as egress
assert isinstance(egress.__loader__, zipimport.zipimporter)
assert egress.__loader__.archive == "/usr/libexec/repocache/server-control-worker"
assert isinstance(bundle.__loader__, zipimport.zipimporter)
assert bundle.__loader__.archive == "/usr/libexec/repocache/server-control-worker"
doc,pins,ca,uid=json.load(sys.stdin)
result=bundle.render_repository_nginx_bundle_candidate(
    doc,expected_state_generation=doc["expected_state_generation"],
    candidate_pins_by_repository=pins,ca_bundle_path=ca)
result["egress"]=egress.render_namespace_egress_candidate(
    doc,generation=doc["expected_state_generation"],
    http_fragment=result["http_upstream_fragment"].encode("ascii"),worker_uid=uid)
print(json.dumps(result))
"""
    outcome = command("/usr/bin/python3", "-IS", "-B", "-c", code,
                      input_text=json.dumps([document, pins, str(root / "cert.pem"), worker_uid]))
    bundle = json.loads(outcome.stdout)
    assert bundle["proposed_repository_ids"] == sorted(pins)
    assert bundle["status"] == "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY"
    assert bundle["authorizes_nginx_activation"] is False
    assert bundle["authorizes_catalog_publication"] is False
    http = bundle["http_upstream_fragment"]
    egress = bundle["egress"]
    assert egress["http_sha256"] == hashlib.sha256(http.encode("ascii")).hexdigest()
    assert egress["generation"] == document["expected_state_generation"]
    assert egress["destinations"] == [["8.8.8.8", 443]] + (
        [["8.8.8.8", 8008]] if dnf_enabled else [])
    assert egress["authorizes_firewall_change"] is False
    assert egress["runtime_egress_verified"] is False
    rules = egress["nft_candidate"]
    assert http.count("server 8.8.8.8:443;") == 1
    assert http.count("server 8.8.8.8:8008;") == int(dnf_enabled)
    first, second = (APT_PEER, DNF_PEER) if remote else ("127.0.0.1", "127.0.0.2")
    http = http.replace("server 8.8.8.8:443;", f"server {first}:443;")
    http = http.replace("server 8.8.8.8:8008;", f"server {second}:8008;")
    # Apply the same exact private-fixture substitution to the authenticated
    # candidate's rules, only within the already guarded peer topology.
    assert rules.count("ip daddr 8.8.8.8 tcp dport 443") == 1
    assert rules.count("ip daddr 8.8.8.8 tcp dport 8008") == int(dnf_enabled)
    rules = rules.replace("ip daddr 8.8.8.8 tcp dport 443",
                          f"ip daddr {first} tcp dport 443").replace(
        "ip daddr 8.8.8.8 tcp dport 8008", f"ip daddr {second} tcp dport 8008")
    assert "8.8.8.8" not in rules
    locations = bundle["server_location_fragment"]
    marker = "    proxy_cache_valid 200 60s;\n"
    assert locations.count(marker) == len(pins)
    locations = locations.replace(marker, marker + "    add_header X-Cache $upstream_cache_status always;\n")
    return http, locations, rules


def process_identity(pid, executable, uid, gid, *, capabilities=0, bounding=None):
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
    assert int(fields["CapEff"].strip(), 16) == capabilities
    assert int(fields["CapPrm"].strip(), 16) == capabilities
    assert int(fields["CapAmb"].strip(), 16) == 0
    if bounding is not None:
        assert int(fields["CapBnd"].strip(), 16) == bounding
    assert set(fields["Uid"].split()) == {str(uid)}
    assert set(fields["Gid"].split()) == {str(gid)}
    assert (proc / "ns/net").stat().st_ino == Path("/run/netns", NS).stat().st_ino
    # stat field 22 (starttime), after the parenthesized comm field.
    return (pid, (proc / "stat").read_text().rsplit(")", 1)[1].split()[19])


def workers(master, executable, uid, gid, *, bounding):
    children = (Path("/proc") / str(master) / "task" / str(master) / "children")
    result = set()
    for item in children.read_text().split():
        pid = int(item)
        try:
            if (Path("/proc") / item / "cmdline").read_bytes().startswith(
                    b"nginx: worker process"):
                result.add(process_identity(pid, executable, uid, gid, bounding=bounding))
        except FileNotFoundError:
            # A worker can exit while its replacement starts. Poll again.
            continue
    return result


def configure_peer_network():
    """Two private namespaces only, with no host link or default route."""
    guard()
    assert all(Path("/run/netns", ns).exists() for ns in (NS, PEER_NS))
    identities = {Path("/run/netns", ns).stat().st_ino for ns in (NS, PEER_NS)}
    assert len(identities) == 2 and Path("/proc/self/ns/net").stat().st_ino not in identities
    for ns in (NS, PEER_NS):
        assert {row["ifname"] for row in json.loads(command(
            "/usr/sbin/ip", "-n", ns, "-j", "link", "show").stdout)} == {"lo"}
    command("/usr/sbin/ip", "-n", NS, "link", "add", SERVICE_LINK, "type", "veth",
            "peer", "name", PEER_LINK, "netns", PEER_NS)
    for ns, link, addresses in ((NS, SERVICE_LINK, (SERVICE_ADDR,)),
                                 (PEER_NS, PEER_LINK, (APT_PEER, DNF_PEER))):
        command("/usr/sbin/ip", "-n", ns, "link", "set", "lo", "up")
        for addr in addresses:
            command("/usr/sbin/ip", "-n", ns, "addr", "add", addr + "/29", "dev", link)
        command("/usr/sbin/ip", "-n", ns, "link", "set", link, "up")
        assert {row["ifname"] for row in json.loads(command(
            "/usr/sbin/ip", "-n", ns, "-j", "link", "show").stdout)} == {"lo", link}
        for family in ("-4", "-6"):
            assert json.loads(command("/usr/sbin/ip", "-n", ns, family, "-j",
                                      "route", "show", "default").stdout) == []
    print("PASS: distinct private client/upstream and service netns linked only by veth, no default routes", flush=True)


def probe(vendor_digest=None, *, root_master=False, signed_derived=False):
    guard()
    assert type(root_master) is bool and type(signed_derived) is bool
    remote = root_master and signed_derived
    if vendor_digest is None:
        vendor_digest = authenticated_vendor_digest()
    assert re.fullmatch(r"[0-9a-f]{64}", vendor_digest)
    unit = (DERIVED_ROOT_UNIT if root_master else DERIVED_UNIT) if signed_derived else (ROOT_UNIT if root_master else UNIT)
    modules_before = installed_modules()
    assert MODULE not in {line.split()[0] for line in modules_before.splitlines() if line}
    assert not any(os.path.lexists(Path("/run/netns", ns)) for ns in (NS, PEER_NS))
    if signed_derived:
        policy_bytes, signed_unit = authenticated_policy(include_unit=True)
    else:
        policy_bytes = authenticated_policy()
    assert installed_modules() == modules_before
    assert not Path("/run/netns", NS).exists()
    assert command("/usr/bin/systemctl", "show", "-p", "LoadState",
                   "--value", unit, check=False).stdout.strip() == "not-found"
    booleans = command("/usr/sbin/getsebool", "-a").stdout
    owner = command("/usr/bin/rpm", "-qf", "--queryformat=%{NAME}\n", str(VENDOR))
    assert owner.stdout.strip() == "nginx-core"
    vendor_info = VENDOR.lstat()
    assert stat.S_ISREG(vendor_info.st_mode) and vendor_info.st_uid == 0
    assert vendor_info.st_nlink == 1 and not vendor_info.st_mode & 0o022
    original = (vendor_info, hashlib.sha256(VENDOR.read_bytes()).hexdigest(),
                os.getxattr(VENDOR, "security.selinux"))
    assert original[1] == vendor_digest
    account = pwd.getpwnam("nginx")
    assert account.pw_uid != 0 and account.pw_gid != 0
    master_uid, master_gid = (0, 0) if root_master else (account.pw_uid, account.pw_gid)
    bounding = MASTER_CAPS if root_master else 0
    def packet_rules(**kwargs):
        return nft_rules(account.pw_uid, root_master=root_master, **kwargs)
    loaded = False
    namespace = False
    peer_namespace = False
    started = False
    derived_identity = None
    origin = None
    peer_origin = None
    with tempfile.TemporaryDirectory(prefix=PREFIX, dir="/var/lib") as place:
        root = Path(place)
        assert root.parent == Path("/var/lib") and root.name.startswith(PREFIX)
        assert root.resolve(strict=True) == root and root.stat().st_uid == 0
        root.chmod(0o755)
        writable = root / "runtime"
        writable.mkdir(mode=0o755 if root_master else 0o750)
        os.chown(writable, master_uid, master_gid)
        for name in ("body", "proxy", "fastcgi", "scgi", "uwsgi", "cache"):
            path = writable / name
            path.mkdir(mode=0o700)
            # Root master must itself perform NGINX native ownership setup.
            os.chown(path, master_uid, account.pw_gid)
        legacy = writable / "cache"
        if signed_derived:
            # Parent is traversal-only for the root-master case. Every
            # actual cache zone is a separate private directory.
            if root_master:
                legacy.chmod(0o755)
            legacy = legacy / "legacy"
            legacy.mkdir(mode=0o700)
            os.chown(legacy, master_uid, account.pw_gid)
        pid_dir = root / "pid" if root_master or signed_derived else writable
        if root_master or signed_derived:
            pid_dir.mkdir(mode=0o750)
            os.chown(pid_dir, master_uid, master_gid)
        pid_file = pid_dir / "nginx.pid"
        executable = root / "nginx"
        if signed_derived:
            # Reuse the authenticated worker's descriptor-bound staging
            # primitive, but only in this guarded private fixture directory.
            code = """
import json,os,sys,zipimport
sys.path.insert(0, "/usr/libexec/repocache/server-control-worker")
from repocache import server_native_nginx_executable_v1 as stage
assert isinstance(stage.__loader__, zipimport.zipimporter)
assert stage.__loader__.archive == "/usr/libexec/repocache/server-control-worker"
root,digest=sys.argv[1:]
directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
vendor=os.open("/usr/sbin/nginx",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    first=stage.stage_verified_nginx_candidate(directory,vendor,authenticated_sha256=digest)
    second=stage.stage_verified_nginx_candidate(directory,vendor,authenticated_sha256=digest,
        previous_inode=(first["device"],first["inode"]))
    assert first["status"].endswith("STAGED") and second["status"].endswith("UNCHANGED")
    assert first["inode"] == second["inode"]
    assert not first["authorizes_nginx_activation"]
    print(json.dumps(first))
finally:
    os.close(vendor)
    os.close(directory)
"""
            placed = json.loads(command("/usr/bin/python3", "-IS", "-B", "-c", code,
                                        str(root), original[1]).stdout)
            assert (placed["device"], placed["inode"]) == (
                executable.stat().st_dev, executable.stat().st_ino)
            assert placed["sha256"] == original[1]
            print("PASS: authenticated worker staged exact native NGINX candidate "
                  "without replacement; repeat retained inode", flush=True)
        else:
            shutil.copyfile(VENDOR, executable)
            executable.chmod(0o755)
        assert hashlib.sha256(executable.read_bytes()).hexdigest() == original[1]
        cert, key = root / "cert.pem", root / "key.pem"
        command("/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-days", "1", "-keyout", str(key), "-out", str(cert),
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,DNS:cache.example.invalid,IP:127.0.0.1")
        os.chown(key, 0, account.pw_gid)
        key.chmod(0o640)
        cert.chmod(0o644)
        conf = root / "nginx.conf"
        locations = ""
        targets = (("allowed", "127.0.0.1:443"),
                             ("other-address", "127.0.0.2:443"),
                             ("other-port", "127.0.0.1:5432"),
                             ("custom", "127.0.0.2:8008"),
                             ("wrong-pair", "127.0.0.1:8008"),
                             ("custom-live", "127.0.0.2:8008"),
                             ("custom-after-withdrawal", "127.0.0.2:8008"))
        if remote:
            targets += (("remote-wrong-pair", APT_PEER + ":8008"),
                        ("remote-wrong-address", DNF_PEER + ":443"))
        for name, target in targets:
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
        rendered_http, rendered_locations = "", ""
        if signed_derived:
            for kind in ("apt", "dnf"):
                directory = writable / "cache" / ("fixture-" + kind)
                directory.mkdir(mode=0o700)
                os.chown(directory, master_uid, account.pw_gid)
            rendered_http, rendered_locations, rendered_rules = render_signed_fixture_routes(
                root, remote=remote, worker_uid=account.pw_uid)
        conf.write_text(f"""
daemon {'on' if root_master or signed_derived else 'off'};
{'user nginx nginx;' if root_master else ''}
master_process on;
worker_processes 1;
pid {pid_file};
error_log {writable}/error.log notice;
events {{ worker_connections 64; }}
http {{
access_log {writable}/access.log;
client_body_temp_path {writable}/body;
proxy_temp_path {writable}/proxy;
fastcgi_temp_path {writable}/fastcgi;
scgi_temp_path {writable}/scgi;
uwsgi_temp_path {writable}/uwsgi;
proxy_cache_path {legacy} levels=1:2 keys_zone=fixture:1m use_temp_path=off;
{rendered_http}
server {{
listen 127.0.0.1:{PORT} ssl;
{f"listen {SERVICE_ADDR}:{PORT} ssl;" if remote else ""}
ssl_certificate {cert};
ssl_certificate_key {key};
location = /health {{ return 204; }}
{locations}
{rendered_locations}
location / {{ return 404; }}
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
                if root_master or signed_derived:
                    command("/usr/bin/chcon", "-t", MODULE + "_pid_t", str(pid_dir))
                command("/usr/sbin/ip", "netns", "add", NS)
                namespace = True
                command("/usr/sbin/ip", "-n", NS, "link", "set", "lo", "up")
                if remote:
                    command("/usr/sbin/ip", "netns", "add", PEER_NS)
                    peer_namespace = True
                    configure_peer_network()
                    peer_origin = subprocess.Popen(
                        ["/usr/sbin/ip", "netns", "exec", PEER_NS, "/usr/bin/python3",
                         "-I", "-c", ORIGIN, str(root), "peer"], env=ENV,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        start_new_session=True)
                    for _ in range(100):
                        assert peer_origin.poll() is None
                        if (root / "peer-origin-ready").is_file():
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError("Peer origin not ready")
                command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                        "-f", "-", input_text=packet_rules(negative_port_probe=True))
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
                # Preserve the zero-capability baseline, then separately test
                # the packaged service's forking root-master lifecycle.
                started = True
                service_properties = [
                    "--property=Type=forking", "--property=PIDFile=" + str(pid_file),
                    "--property=CapabilityBoundingSet=" + MASTER_CAP_NAMES,
                ] if root_master else [
                    "--property=Type=exec", "--property=User=nginx", "--property=Group=nginx",
                    "--property=CapabilityBoundingSet=",
                ]
                if signed_derived:
                    derived_identity = publish_derived_unit(
                        derive_signed_unit(signed_unit, root, root_master=root_master), unit)
                    command("/usr/bin/systemctl", "daemon-reload")
                    assert command("/usr/bin/systemctl", "show", "--value", "-p", "FragmentPath",
                                   unit).stdout.strip() == str(derived_identity[0])
                    command("/usr/bin/systemctl", "start", "--no-block", unit)
                else:
                    command("/usr/bin/systemd-run", "--no-block", "--unit=" + unit, *service_properties,
                            "--property=TimeoutStartSec=25s", "--property=TimeoutStopSec=20s",
                            "--property=NoNewPrivileges=yes", "--property=UMask=0027",
                            "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
                            "--property=ReadWritePaths=" + str(writable) + (" " + str(pid_dir) if root_master else ""),
                            "--property=NetworkNamespacePath=/run/netns/" + NS,
                            "--property=RestrictAddressFamilies=AF_UNIX AF_INET",
                            "--property=PrivateTmp=yes",
                            str(executable), "-e", "stderr", "-p", str(root), "-c", str(conf))
                deadline = time.monotonic() + 30
                ready = None
                while time.monotonic() < deadline:
                    state = command("/usr/bin/systemctl", "show", "--value", "-p",
                                    "ActiveState", unit, check=False).stdout.strip()
                    if state == "failed":
                        break
                    ready = command("/usr/sbin/ip", "netns", "exec", NS, "/usr/bin/curl",
                                    "-sS", "--max-time", "1", "--noproxy", "*",
                                    "--cacert", str(cert), "-o", "/dev/null",
                                    "-w", "%{http_code}",
                                    f"https://127.0.0.1:{PORT}/health", check=False)
                    if state == "active" and ready.returncode == 0 and ready.stdout == "204":
                        break
                    time.sleep(0.1)
                if state != "active" or ready is None or ready.returncode != 0 or ready.stdout != "204":
                    raise AssertionError("Confined fixture did not become active and healthy")
                pid = int(command("/usr/bin/systemctl", "show", "--value",
                                  "-p", "MainPID", unit).stdout)
                master = process_identity(pid, executable, master_uid, master_gid,
                                          capabilities=bounding, bounding=bounding)
                if root_master:
                    assert int(pid_file.read_text()) == pid
                    assert pid_file.stat().st_uid == 0
                    owned = [writable / name for name in ("body", "proxy", "fastcgi", "scgi", "uwsgi")]
                    owned.append(legacy)
                    if signed_derived:
                        owned.extend(writable / "cache" / ("fixture-" + kind)
                                     for kind in ("apt", "dnf"))
                        assert (writable / "cache").stat().st_uid == 0
                    for path in owned:
                        assert (path.stat().st_uid, path.stat().st_gid) == (account.pw_uid, account.pw_gid)
                        assert stat.S_IMODE(path.stat().st_mode) == 0o700
                    # Root cannot bypass the namespace-local egress filter.
                    denied = command("/usr/sbin/ip", "netns", "exec", NS, "/usr/bin/curl",
                                     "--silent", "--max-time", "2", "--noproxy", "*",
                                     "--cacert", str(cert), "https://127.0.0.1:443/fixture",
                                     check=False)
                    assert denied.returncode != 0
                    assert not (root / "origin-counts").exists()
                assert Path(f"/proc/{pid}/cmdline").read_bytes().startswith(b"nginx: master process")
                for _ in range(100):
                    previous_workers = workers(pid, executable, account.pw_uid, account.pw_gid,
                                               bounding=bounding)
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
                        + packet_rules())
                assert request(root, "allowed")[:2] == (200, PAYLOAD)
                assert request(root, "other-address")[0] == 502
                assert request(root, "other-port")[0] == 502
                assert (root / "origin-counts").read_text().splitlines() == ["127.0.0.1:443"]
                # Add exactly one custom HTTPS endpoint, not the Cartesian
                # product of approved addresses and ports. No SELinux changes.
                assert request(root, "custom")[0] == 502
                command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                        "-f", "-", input_text="delete table inet repocache_ci\n"
                        + packet_rules(custom_https=True))
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
                if signed_derived:
                    command("/usr/bin/systemctl", "reload", unit)
                else:
                    command("/usr/bin/systemctl", "kill", "--kill-whom=main",
                            "--signal=HUP", unit)
                for _ in range(100):
                    assert process_identity(pid, executable, master_uid, master_gid,
                                            capabilities=bounding, bounding=bounding) == master
                    current_workers = workers(pid, executable, account.pw_uid, account.pw_gid,
                                              bounding=bounding)
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
                print("PASS: confined " + ("limited-capability root master" if root_master else "nonroot NGINX master") +
                      "/worker reload, executable inode and domain continuity; "
                      "fresh positive/negative egress", flush=True)
                # Withdraw the custom tuple. The uncached location tests a
                # fresh upstream connect, not the already cached response.
                command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                        "-f", "-", input_text="delete table inet repocache_ci\n"
                        + packet_rules())
                assert request(root, "custom-after-withdrawal")[0] == 502
                assert request(root, "allowed")[:2] == (200, PAYLOAD)
                assert (root / "origin-counts").read_text().splitlines() == [
                    "127.0.0.1:443", "127.0.0.2:8008", "127.0.0.2:8008",
                    "127.0.0.2:8008"]
                print("PASS: isolated custom HTTPS tuple add, MISS/HIT, crossed tuple refusal, "
                      "failed replacement and fresh-connect withdrawal", flush=True)
                assert any(p.is_file() for p in (writable / "cache").rglob("*"))
                assert command("/usr/sbin/getenforce").stdout.strip() == "Enforcing"
                if signed_derived:
                    # Actual signed render fragments, same authenticated
                    # executable and native unit. Observe real cache files.
                    counts_path = root / ("peer-origin-counts" if remote else "origin-counts")
                    first_origin = APT_PEER + ":443" if remote else "127.0.0.1:443"
                    second_origin = DNF_PEER + ":8008" if remote else "127.0.0.2:8008"
                    if remote:
                        assert not counts_path.exists()
                        _, _, apt_rules = render_signed_fixture_routes(
                            root, dnf_enabled=False, remote=True, worker_uid=account.pw_uid)
                        command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft",
                                "-f", "-", input_text="delete table inet repocache_ci\n"
                                + apt_rules)
                        verify_peer_ruleset(apt_rules)
                        print("PASS: authenticated closed private namespace ruleset readback", flush=True)
                        before_root = denied_packets()
                        denied = command("/usr/sbin/ip", "netns", "exec", NS, "/usr/bin/curl",
                                         "--silent", "--max-time", "2", "--noproxy", "*",
                                         "--cacert", str(cert), "--resolve", f"localhost:443:{APT_PEER}",
                                         "https://localhost/fixture", check=False)
                        assert denied.returncode != 0 and not counts_path.exists()
                        assert denied_packets() > before_root
                        peer_denied(root, "remote-wrong-pair")
                        peer_denied(root, "remote-wrong-address")
                        assert not counts_path.exists()
                    before_hits = counts_path.read_text().splitlines() if counts_path.exists() else []
                    apt = "__repocache/repos/fixture-apt/"
                    dnf = "__repocache/repos/fixture-dnf/"
                    first, second = request(root, apt + "payload", remote=remote), request(root, apt + "payload", remote=remote)
                    assert first[:2] == second[:2] == (200, PAYLOAD)
                    assert "x-cache: miss" in first[2] and "x-cache: hit" in second[2]
                    assert request(root, apt + "payload", method="POST", remote=remote)[0] == 403
                    assert request(root, apt + "redirect", remote=remote)[0] == 502
                    if remote:
                        peer_denied(root, dnf + "payload")
                    else:
                        assert request(root, dnf + "payload")[0] == 502
                    assert counts_path.read_text().splitlines() == before_hits + [
                        first_origin, first_origin]
                    if remote:
                        replace_peer_ruleset(apt_rules, rendered_rules)
                    else:
                        command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft", "-f", "-",
                                input_text="delete table inet repocache_ci\n"
                                + packet_rules(custom_https=True))
                    first, second = request(root, dnf + "payload", remote=remote), request(root, dnf + "payload", remote=remote)
                    assert first[:2] == second[:2] == (200, PAYLOAD)
                    assert "x-cache: miss" in first[2] and "x-cache: hit" in second[2]
                    assert counts_path.read_text().splitlines() == before_hits + [
                        first_origin, first_origin, second_origin]
                    if remote:
                        peer_denied(root, "remote-wrong-pair")
                        peer_denied(root, "remote-wrong-address")
                        assert counts_path.read_text().splitlines() == before_hits + [
                            first_origin, first_origin, second_origin]
                    for kind in ("apt", "dnf"):
                        assert any(p.is_file() for p in
                                   (writable / "cache" / ("fixture-" + kind)).rglob("*"))
                    # New complete candidate omits DNF. Replace only this
                    # root-owned private config; retain the old file label.
                    next_http, next_locations, next_rules = render_signed_fixture_routes(
                        root, dnf_enabled=False, remote=remote, worker_uid=account.pw_uid)
                    old_conf = conf.read_text("ascii")
                    assert old_conf.count(rendered_http) == old_conf.count(rendered_locations) == 1
                    new_conf = old_conf.replace(rendered_http, next_http).replace(
                        rendered_locations, next_locations)
                    staged = root / ".nginx.conf.next"
                    with staged.open("xb") as stream:
                        os.fchmod(stream.fileno(), 0o644)
                        stream.write(new_conf.encode("ascii"))
                        stream.flush()
                        os.fsync(stream.fileno())
                    command("/usr/bin/chcon", "--reference=" + str(conf), str(staged))
                    assert staged.stat().st_uid == 0 and not staged.is_symlink()
                    os.replace(staged, conf)
                    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                    former = workers(pid, executable, account.pw_uid, account.pw_gid, bounding=bounding)
                    assert len(former) == 1
                    command("/usr/bin/systemctl", "reload", unit)
                    for _ in range(100):
                        assert process_identity(pid, executable, master_uid, master_gid,
                                                capabilities=bounding, bounding=bounding) == master
                        live = workers(pid, executable, account.pw_uid, account.pw_gid, bounding=bounding)
                        if len(live) == 1 and not live & former:
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError("Rendered route withdrawal did not drain old worker")
                    if remote:
                        replace_peer_ruleset(rendered_rules, next_rules)
                    else:
                        command("/usr/sbin/ip", "netns", "exec", NS, "/usr/sbin/nft", "-f", "-",
                                input_text="delete table inet repocache_ci\n" + packet_rules())
                    assert request(root, dnf + "payload", remote=remote)[0] == 404
                    assert request(root, dnf + "fresh", remote=remote)[0] == 404
                    assert request(root, apt + "fresh", remote=remote)[:2] == (200, PAYLOAD)
                    assert counts_path.read_text().splitlines() == before_hits + [
                        first_origin, first_origin, second_origin, first_origin]
                    print("PASS: authenticated installed renderer APT/DNF private routes; TLS MISS/HIT, POST/redirect refusal, DNF withdrawal after worker drain, APT fresh access", flush=True)
                    if remote:
                        peer_denied(root, "remote-wrong-pair")
                        peer_denied(root, "remote-wrong-address")
                        assert counts_path.read_text().splitlines() == before_hits + [
                            first_origin, first_origin, second_origin, first_origin]
                        print("PASS: authenticated worker generation-bound egress candidate used in peer namespace; "
                              "peer client HTTPS ingress and exact remote APT/DNF egress over veth; "
                              "crossed tuples refused, DNF withdrawn after drain, APT still available", flush=True)
                    assert int(pid_file.read_text()) == pid and pid_file.stat().st_uid == master_uid
                    print("PASS: authenticated signed-unit-derived " +
                          ("limited-capability root-master" if root_master else "nonroot") +
                          " forking lifecycle, native ExecStartPre and ExecReload; confined HTTPS cache", flush=True)
                print("PASS: dedicated enforcing NGINX domain, verified HTTPS MISS/HIT, "
                      "SELinux non-HTTP-port refusal and independent exact-address refusal", flush=True)
            except Exception:
                if started:
                    try:
                        start_diagnostics(unit, writable)
                    except Exception as diagnostic:
                        print("ISOLATED_START_DIAGNOSTICS_NOT_VERIFIED: " + type(diagnostic).__name__, flush=True)
                    if root_master:
                        try:
                            credential_probe(root, account)
                        except Exception as diagnostic:
                            print("ISOLATED_CREDENTIAL_CANARY_NOT_VERIFIED: " + type(diagnostic).__name__, flush=True)
                raise
            finally:
                if started:
                    command("/usr/bin/systemctl", "stop", unit, check=derived_identity is not None or not signed_derived)
                    assert command("/usr/bin/systemctl", "is-active", unit,
                                   check=False).stdout.strip() in ("inactive", "unknown")
                if derived_identity is not None:
                    remove_derived_unit(derived_identity)
                    # Reauthenticate the installed unit after removing the derived one.
                    _, unchanged_unit = authenticated_policy(include_unit=True)
                    assert unchanged_unit == signed_unit
                    print("PASS: runtime-only derived unit removed after native ExecStop; signed installed unit untouched", flush=True)
                if origin is not None:
                    if origin.poll() is None:
                        os.killpg(origin.pid, signal.SIGTERM)
                    origin.wait(timeout=10)
                if peer_origin is not None:
                    if peer_origin.poll() is None:
                        os.killpg(peer_origin.pid, signal.SIGTERM)
                    peer_origin.wait(timeout=10)
                if namespace:
                    command("/usr/sbin/ip", "netns", "delete", NS)
                if peer_namespace:
                    command("/usr/sbin/ip", "netns", "delete", PEER_NS)
                # Remove only this new VM fixture tree before policy removal.
                # TemporaryDirectory will then observe an already absent tree.
                if loaded:
                    shutil.rmtree(root)
                    command("/usr/sbin/semodule", "-r", MODULE, timeout=120)
        assert not any(os.path.lexists(Path("/run/netns", ns)) for ns in (NS, PEER_NS))
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
    digest = authenticated_vendor_digest()
    probe(digest)
    probe(digest, signed_derived=True)
    probe(digest, root_master=True)
    probe(digest, root_master=True, signed_derived=True)
