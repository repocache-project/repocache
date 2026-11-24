#!/usr/bin/env python3
"""P0-3 booted VM: verify client fail-closed apply/CLI without altering sources."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from ci_v06_vm_nginx_cache_guest import native_guard

ROOT = Path("/home/pr237ci/source")
CLIENT = ROOT / "client/repocache_client.py"
MAX_SOURCE_BYTES = 1024 * 1024


def source_snapshot(platform: str) -> tuple[tuple[str, int, int, int, str], ...]:
    directory = (Path("/etc/apt/sources.list.d") if platform == "debian13"
                 else Path("/etc/yum.repos.d"))
    if not directory.is_dir() or directory.is_symlink():
        raise AssertionError("unsupported native package source directory")
    files = sorted(p for p in directory.iterdir() if p.suffix in (".list", ".sources", ".repo"))
    if platform == "debian13" and Path("/etc/apt/sources.list").exists():
        files.append(Path("/etc/apt/sources.list"))
    if not files or len(files) > 128:
        raise AssertionError("native package source inventory absent or excessive")
    result = []
    for p in files:
        meta = p.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_SOURCE_BYTES:
            raise AssertionError("unsupported or unsafe native package source inventory")
        blob = p.read_bytes()
        if len(blob) != meta.st_size:
            raise AssertionError("native source changed during observation")
        result.append((str(p), meta.st_ino, meta.st_mode, meta.st_mtime_ns,
                       hashlib.sha256(blob).hexdigest()))
    return tuple(sorted(result))


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["/usr/bin/python3", "-B", str(CLIENT), *args],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, text=True, timeout=15,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent",
             "PYTHONDONTWRITEBYTECODE": "1", "HTTP_PROXY": "", "HTTPS_PROXY": "", "NO_PROXY": "*"},
        check=False,
    )
    if len(proc.stdout) > 65536 or len(proc.stderr) > 65536:
        raise AssertionError("unbounded client CLI output")
    return proc


def main(platform: str) -> None:
    native_guard(platform)
    if not CLIENT.is_file() or CLIENT.is_symlink() or os.geteuid() == 0:
        raise AssertionError("native client test requires nonroot exact source")
    before = source_snapshot(platform)
    for args in (["--help"], ["repos", "--help"], ["repos", "list", "--help"],
                 ["repos", "sync", "--help"], ["check", "--help"]):
        proc = run(list(args))
        if proc.returncode != 0 or "usage:" not in proc.stdout.lower():
            raise AssertionError("native client parser/help failure")
    for args in (["--json", "repos", "sync", "--apply"],
                 ["repos", "sync", "--apply", "--json"]):
        proc = run(list(args))
        if proc.returncode != 2 or proc.stderr:
            raise AssertionError("native client apply refusal must be structured and noninteractive")
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError("invalid structured apply refusal") from exc
        if (payload.get("schema_version") != 1 or payload.get("ok") is not False
                or payload.get("error", {}).get("code") != "OPERATION_FAILED"
                or "Applying changes is disabled" not in payload["error"].get("message", "")):
            raise AssertionError("native client apply refusal contract changed")
    after = source_snapshot(platform)
    if before != after:
        raise AssertionError("native APT/DNF sources changed during read-only CLI probe")
    # Explicit privileged test-only real-manager probe in this disposable VM.
    # The probe uses isolated /tmp APT/DNF source+cache paths and independently
    # test-signed metadata through the native package manager, never --apply
    # or the production server service. The root guest probe itself performs
    # exact before/after host source and installed package inventories.
    guest = ROOT / "scripts/ci_v06_vm_signed_client_guest.py"
    if not guest.is_file() or guest.is_symlink():
        raise AssertionError("signed native client guest probe absent")
    signed = subprocess.run(
        ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", str(guest), platform],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, text=True, timeout=360,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
             "PYTHONDONTWRITEBYTECODE": "1", "HTTP_PROXY": "", "HTTPS_PROXY": "",
             "NO_PROXY": "*"}, check=False,
    )
    if (signed.returncode != 0 or
            "PASS: booted-native-real-manager-signed-fallback-and-host-sources-intact " +
            platform not in signed.stdout):
        raise AssertionError(
            "booted-native signed package-manager integrity probe failed: "
            + signed.stdout[-3000:] + signed.stderr[-1500:]
        )
    print(signed.stdout[-10000:], flush=True)
    if source_snapshot(platform) != before:
        raise AssertionError("native sources modified by real package-manager probe")
    print("PASS: booted native VM client CLI --apply refusal and APT/DNF source integrity")
    print("NOT VERIFIED: approved host source writer, production catalog, "
          "installed REPOCACHE cache route, actual repos sync --apply")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("debian13", "almalinux10"):
        raise SystemExit("Only the two fixed VM targets are supported")
    main(sys.argv[1])
