#!/usr/bin/env python3
"""Run the existing #97 bounded ENOSPC/EROFS exercise inside a booted VM.

The privileged wrapper only mounts two disposable 4 MiB tmpfs filesystems
in its own private mount namespace. The real workload runs without root.
No host/runner filesystem is filled; no installed service is touched.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import pwd
import socket
import subprocess
import sys
import tempfile

from ci_server_nginx_enospc_bypass_native import exercise_bounded_mounts
from ci_v06_vm_nginx_cache_guest import native_guard

SOURCE = Path("/home/pr237ci/source")
SCRIPT = SOURCE / "scripts/ci_v06_vm_cache_pressure_guest.py"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
       "PYTHONPATH": str(SOURCE / "src"), "PYTHONDONTWRITEBYTECODE": "1"}


def run(*args: str, timeout: int = 30) -> None:
    subprocess.run(args, check=True, timeout=timeout, env=ENV)


def output(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=15, env=ENV).stdout.strip()


def root_guard(target: str) -> None:
    if (target not in ("debian13", "almalinux10")
            or os.getuid() != 0 or os.geteuid() != 0
            or platform.machine() != "x86_64"
            or Path(__file__).resolve() != SCRIPT
            or Path("/.dockerenv").exists()
            or Path("/proc/1/comm").read_text("ascii").strip() != "systemd"
            or socket.gethostname() != "pr237-" + target
            or output("/usr/bin/systemd-detect-virt", "--vm") not in ("qemu", "kvm")
            or os.readlink("/proc/self/ns/mnt") == os.readlink("/proc/1/ns/mnt")):
        raise AssertionError("PRIVATE_DISPOSABLE_BOOTED_VM_REQUIRED")
    facts = dict(line.split("=", 1) for line in
                 Path("/etc/os-release").read_text("ascii").splitlines()
                 if "=" in line and not line.startswith("#"))
    distro, major = ("debian", "13") if target == "debian13" else ("almalinux", "10")
    assert facts.get("ID", "").strip('"') == distro
    assert facts.get("VERSION_ID", "").strip('"').split(".")[0] == major
    if target == "almalinux10":
        assert output("/usr/sbin/getenforce") == "Enforcing"
    service = subprocess.run(["/usr/bin/systemctl", "is-active", "nginx.service"],
                             check=False, text=True, capture_output=True, timeout=15, env=ENV)
    assert service.returncode != 0 and service.stdout.strip() == "inactive"
    # Refuse even an isolated mount namespace with shared propagation.
    for line in Path("/proc/self/mountinfo").read_text("utf-8").splitlines():
        fields = line.split(" - ", 1)[0].split()
        assert not any(field.startswith("shared:") for field in fields[6:]), (
            "SHARED_MOUNT_PROPAGATION_FORBIDDEN")


def exercise(target: str, root: Path) -> None:
    native_guard(target)
    assert root.parent == Path("/tmp") and root.name.startswith("repocache-vm-pressure-")
    assert root.resolve() == root and root.stat().st_uid == 0
    writable, readonly = root / "writable", root / "readonly"
    for mount in (writable, readonly):
        assert not mount.is_symlink() and os.path.ismount(mount)
        fs = os.statvfs(mount)
        assert 3 * 1024 * 1024 <= fs.f_blocks * fs.f_frsize <= 8 * 1024 * 1024
    assert os.statvfs(readonly).f_flag & os.ST_RDONLY
    assert not os.statvfs(writable).f_flag & os.ST_RDONLY
    exercise_bounded_mounts(writable, readonly)


def main(target: str) -> None:
    root_guard(target)
    worker = pwd.getpwnam("pr237ci")
    assert worker.pw_uid != 0 and worker.pw_gid != 0
    with tempfile.TemporaryDirectory(prefix="repocache-vm-pressure-", dir="/tmp") as scratch:
        root = Path(scratch)
        root.chmod(0o755)
        writable, readonly = root / "writable", root / "readonly"
        mounted = []
        try:
            for mount in (writable, readonly):
                mount.mkdir(mode=0o700)
                run("/usr/bin/mount", "-t", "tmpfs",
                    "-o", f"size=4m,mode=0700,uid={worker.pw_uid},gid={worker.pw_gid},nosuid,nodev,noexec",
                    "tmpfs", str(mount))
                mounted.append(mount)
                assert os.path.ismount(mount)
                fs = os.statvfs(mount)
                assert 3 * 1024 * 1024 <= fs.f_blocks * fs.f_frsize <= 8 * 1024 * 1024
            for name in ("debian-trixie-main", "almalinux-baseos"):
                (readonly / name).mkdir(mode=0o755)
            (readonly / "debian-trixie-main/fixture").write_bytes(b"preserved cache fixture\n")
            run("/usr/bin/mount", "-o", "remount,ro,nosuid,nodev,noexec", str(readonly))
            assert os.statvfs(readonly).f_flag & os.ST_RDONLY
            run("/usr/sbin/runuser", "-u", "pr237ci", "--", "/usr/bin/env",
                "PATH=" + ENV["PATH"], "PYTHONPATH=" + ENV["PYTHONPATH"],
                "/usr/bin/python3", "-B", str(SCRIPT), "--exercise", target, str(root),
                timeout=300)
        finally:
            for mount in reversed(mounted):
                run("/usr/bin/umount", str(mount))
    root_guard(target)
    print("PASS: booted native VM bounded ENOSPC/EROFS exercise and private mount cleanup",
          flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    elif len(sys.argv) == 4 and sys.argv[1] == "--exercise":
        exercise(sys.argv[2], Path(sys.argv[3]))
    else:
        raise SystemExit("Fixed booted VM target required")
