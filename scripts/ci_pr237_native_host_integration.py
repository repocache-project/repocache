#!/usr/bin/env python3
"""PR #237: kernel-booted guest negative tests against ACTUAL stock NGINX.

No publisher trust or REPOCACHE installed-worker acceptance is implied.
All mutation is constrained to the disposable QEMU guest and restored.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

if __name__ == "__main__":
    checkout = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(checkout / "src"), str(checkout)]

from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions
from repocache.server_stock_nginx_package_owner_v1 import (
    inspect_stock_nginx_package_file_integrity, inspect_stock_nginx_package_owner,
)
from repocache.server_native_nginx_service_unit_v1 import inspect_native_nginx_unit


def command(*argv: str, success: bool = True) -> str:
    result = subprocess.run(
        list(argv), check=False, capture_output=True, text=True,
        stdin=subprocess.DEVNULL, timeout=30,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if success and result.returncode:
        raise AssertionError("Expected command success: " + argv[0] + " " + argv[1])
    if not success and result.returncode == 0:
        raise AssertionError("Expected command rejection: " + argv[0] + " " + argv[1])
    return result.stdout.strip()


def http_digest() -> str:
    with urllib.request.urlopen("http://127.0.0.1/", timeout=10) as stream:
        content = stream.read(65537)
        assert 0 < len(content) <= 65536
        return hashlib.sha256(content).hexdigest()


def main(distribution: str) -> None:
    assert distribution in ("debian", "almalinux")
    assert os.getuid() == os.geteuid() == 0
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert command("/usr/bin/systemd-detect-virt", "--vm") in ("qemu", "kvm")
    assert Path("/home/pr237ci/source/scripts/ci_pr237_guest.sh").is_file()
    assert command("/usr/bin/hostname").startswith("pr237-")
    assert not Path("/var/lib/repocache/server").exists()

    observed = require_native_host_preconditions()
    assert observed["initial_root_credentials_observed"] is True
    assert observed["initial_user_namespace_mapping_observed"] is True
    assert observed["pid1_systemd_and_matching_namespaces_observed"] is True
    assert observed["authorizes_host_write"] is False
    print("PASS: actual native kernel/root/systemd/mount namespace preflight; no write authority")

    owner = inspect_stock_nginx_package_owner()
    assert owner["native_package_db_owner_observed"] is True
    integrity = inspect_stock_nginx_package_file_integrity()
    assert integrity["native_package_file_integrity_verified"] is True
    unit = inspect_native_nginx_unit(distribution)
    assert unit.code == "VENDOR_NGINX_UNIT_OBSERVED" and unit.digest is not None
    print("PASS: real APT/DNF package owner, installed file integrity and root-owned vendor unit")
    print("vendor_unit_sha256=" + unit.digest)
    print("document_omissions=" + str(integrity["native_package_documentation_omissions"]))
    print("ghost_log_variations=" + str(integrity["native_package_ghost_log_variations"]))

    shadow_dir = Path("/etc/systemd/system/nginx.service.d")
    if shadow_dir.is_symlink():
        raise AssertionError("Symlinked NGINX drop-in directory; refusing injection")
    created_dir = not shadow_dir.exists()
    if created_dir:
        shadow_dir.mkdir(mode=0o755)
    if not shadow_dir.is_dir() or any(shadow_dir.iterdir()):
        raise AssertionError("Foreign NGINX drop-ins present; refusing injection")
    # A safe *empty* drop-in directory is intentionally accepted by the
    # genuine verifier. A new, nonempty override MUST be refused.
    injected = shadow_dir / "pr237-disposable-foreign.conf"
    fd = os.open(injected, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"[Service]\\nEnvironment=PR237_FOREIGN_DROPIN=1\\n")
            stream.flush()
            os.fsync(stream.fileno())
        assert inspect_native_nginx_unit(distribution).code == "VENDOR_NGINX_SHADOW_REFUSED"
        print("PASS: actual nonempty foreign systemd drop-in detected and refused")
    finally:
        injected.unlink()
        if created_dir:
            shadow_dir.rmdir()
    assert inspect_native_nginx_unit(distribution).code == "VENDOR_NGINX_UNIT_OBSERVED"

    command("/usr/bin/systemctl", "start", "nginx.service")
    baseline = http_digest()
    before_pid = command("/usr/bin/systemctl", "show", "--property=MainPID", "--value", "nginx.service")
    assert before_pid.isdigit() and int(before_pid) > 0

    # Only in this ephemeral VM: make the ACTUAL distro nginx -t and reload
    # reject an invalid include. Do not replace or modify existing NGINX files.
    invalid = Path("/etc/nginx/conf.d/pr237-disposable-invalid.conf")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(invalid, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"pr237_invalid_directive must_fail;\n")
            stream.flush()
            os.fsync(stream.fileno())
        command("/usr/sbin/nginx", "-t", success=False)
        command("/usr/bin/systemctl", "reload", "nginx.service", success=False)
        assert command("/usr/bin/systemctl", "is-active", "nginx.service") == "active"
        assert http_digest() == baseline
        assert command("/usr/bin/systemctl", "show", "--property=MainPID", "--value", "nginx.service") == before_pid
        print("PASS: invalid real NGINX syntax/reload rejected; old master and HTTP still usable")
    finally:
        invalid.unlink()
    command("/usr/sbin/nginx", "-t")
    command("/usr/bin/systemctl", "reload", "nginx.service")
    assert http_digest() == baseline
    print("PASS: restored stock configuration reloaded; real HTTP response preserved")

    # Re-audit after compensation and service reload, not just before faults.
    assert inspect_stock_nginx_package_file_integrity()["native_package_file_integrity_verified"] is True
    assert inspect_native_nginx_unit(distribution).code == "VENDOR_NGINX_UNIT_OBSERVED"
    print("PASS: native NGINX package and vendor systemd audit unchanged after failure")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("debian", "almalinux"):
        raise SystemExit("Specify the exact supported distro identifier")
    main(sys.argv[1])
