#!/usr/bin/env python3
"""PR #237: durable *synthetic* package pending journal across native VM reboot.

The real package manager ran earlier but was not interrupted here. This
deliberately untrusted fixture MUST NOT authorize reconciliation or clearing.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

if __name__ == "__main__":
    source = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(source / "src"), str(source)]

from repocache.server_protected_namespace_bootstrap_v1 import bootstrap_protected_namespace_under_root
from repocache.server_native_nginx_package_journal_v1 import (
    NativePackageJournalError, NATIVE_PENDING_NAME, NATIVE_TMP_NAME,
    _prepare_native_journal_under_root,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME


ROOT = Path("/var/lib/repocache/server")


def facts(distribution: str) -> None:
    assert distribution in ("debian", "almalinux")
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert Path("/home/pr237ci/source/scripts/ci_pr237_guest.sh").exists()
    os_release = Path("/etc/os-release").read_text()
    lines = dict(line.partition("=")[::2] for line in os_release.splitlines()
                 if line and not line.startswith("#") and "=" in line)
    installed_id = lines.get("ID", "").strip("'\"")
    assert installed_id == distribution
    if distribution == "almalinux":
        assert subprocess.check_output(["/usr/sbin/getenforce"], text=True).strip() == "Enforcing"


def marker_bytes() -> bytes:
    marker = ROOT / NATIVE_PENDING_NAME
    info = marker.lstat()
    assert stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
    assert info.st_uid == 0 and info.st_gid == 0
    assert info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
    assert not (ROOT / NATIVE_TMP_NAME).exists()
    assert (ROOT / LOCK_NAME).stat().st_size == 0
    raw = marker.read_bytes()
    assert len(raw) < 2048 and raw
    return raw


def prepare(distribution: str) -> None:
    assert Path("/var/lib/repocache/server").exists()
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        bootstrap = bootstrap_protected_namespace_under_root(root, owner_uid=0, public_catalog=True)
        assert bootstrap["status"] == "EXISTING_PROTECTED_LOCK_VALIDATED"
        result = _prepare_native_journal_under_root(
            root, owner_uid=0, distribution=distribution,
        )
        assert result["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
        assert result["package_transaction_executed"] is False
        assert result["native_package_effects_reconciled"] is False
        assert result["authorizes_package_installation"] is False
        assert result["authorizes_nginx_reload"] is False
    finally:
        os.close(root)
    raw = marker_bytes()
    assert json.loads(raw)["distribution"] == distribution
    # This is a deliberately synthetic pending transaction, NOT an assertion
    # that the native package manager was interrupted.
    subprocess.run(["/usr/bin/systemctl", "mask", "nginx.service"],
                   check=True, timeout=25)
    assert subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "nginx.service"],
                          check=False, timeout=15).returncode != 0
    print("PASS: exact root journal fsynced, protected lock exists and NGINX masked")
    print("synthetic_pending_sha256=" + hashlib.sha256(raw).hexdigest())


def after_reboot(distribution: str) -> None:
    raw = marker_bytes()
    doc = json.loads(raw)
    assert doc == {
        "journal_schema_version": 1,
        "operation": "fresh-native-nginx-package-install",
        "distribution": distribution,
        "manager": "apt" if distribution == "debian" else "dnf",
        "package": "nginx",
        "expected_state_generation": 0,
        "native_package_effects": "REQUIRES_EXPLICIT_RECONCILIATION",
    }
    assert subprocess.run(["/usr/bin/systemctl", "is-enabled", "nginx.service"],
                          capture_output=True, text=True, timeout=15).stdout.strip() == "masked"
    assert subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "nginx.service"],
                          check=False, timeout=15).returncode != 0
    original = ROOT.joinpath(NATIVE_PENDING_NAME).stat()
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for attempt in (1, 2):
            try:
                _prepare_native_journal_under_root(
                    root, owner_uid=0, distribution=distribution,
                )
            except NativePackageJournalError as exc:
                assert str(exc) == "NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED", str(exc)
            else:
                raise AssertionError("Unsafe retry accepted a pending package journal")
            assert marker_bytes() == raw
            current = ROOT.joinpath(NATIVE_PENDING_NAME).stat()
            assert (current.st_ino, current.st_mode, current.st_mtime_ns) == (
                original.st_ino, original.st_mode, original.st_mtime_ns
            )
    finally:
        os.close(root)
    # A second, freshly launched Python process re-authenticates the
    # synthetic candidate against the installed root files after reboot.
    # This is NOT real publisher acceptance or service activation.
    pins_file = Path("/root/pr237-synthetic-fixture/pins.json")
    assert pins_file.stat().st_uid == 0 and stat.S_IMODE(pins_file.stat().st_mode) == 0o600
    pins = json.loads(pins_file.read_bytes())
    assert set(pins) == {"commit", "archive_sha256"}
    check = subprocess.run(
        ["/usr/bin/python3", "-I", "-B",
         "/home/pr237ci/combined/scripts/stage_native_root_worker.py",
         "--assets", "/root/pr237-synthetic-fixture/assets",
         "--verify-installed", "--commit", pins["commit"],
         "--archive-sha256", pins["archive_sha256"]],
        check=False, capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    assert check.returncode == 0 and not check.stderr, "Signed synthetic worker reboot readback refused"
    receipt = json.loads(check.stdout)
    assert receipt["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    assert receipt["authorizes_host_installation"] is False
    assert receipt["authorizes_service_activation"] is False
    for unit_name in ("repocache-control.service", "repocache-control.socket"):
        assert subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", unit_name],
            check=False, timeout=15,
        ).returncode != 0
    print("PASS: native installed worker and units re-authenticated after reboot with synthetic Ed25519")
    print("PASS: both REPOCACHE control units remained inactive after guest reboot")
    print("PASS: real guest reboot retained exact root journal inode and service mask")
    print("PASS: repeated native-package re-entry refused without mutation")
    print("synthetic_pending_sha256=" + hashlib.sha256(raw).hexdigest())
    print("NOT VERIFIED: actual APT/DNF crash or signed installed REPOCACHE recovery")


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in ("debian", "almalinux"):
        raise SystemExit("usage: ci_pr237_native_journal_reboot.py distro prepare|after")
    distro, mode = sys.argv[1:]
    facts(distro)
    if mode == "prepare":
        prepare(distro)
    elif mode == "after":
        after_reboot(distro)
    else:
        raise SystemExit("Unsupported native journal phase")


if __name__ == "__main__":
    main()
