#!/usr/bin/env python3
"""Booted #29 detached storage/metrics exercise; never installed acceptance.

Debian runs the existing positive runtime and rotation test. AlmaLinux
checks actual labeled-root fail-closed behavior, without stripping SELinux
labels or weakening the storage primitive's fixture-only trust boundary.
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

from ci_v06_owned_storage_metrics_runtime import exercise_owned_runtime
from repocache.server_native_storage_bootstrap_v1 import (
    NativeStorageBootstrapError,
    bootstrap_native_nginx_storage_under_root,
)


def command(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=15).stdout.strip()


def guard(target: str) -> None:
    if target not in ("debian13", "almalinux10"):
        raise AssertionError("UNSUPPORTED_VM_TARGET")
    if (os.getuid() != 0 or os.geteuid() != 0
            or platform.machine() != "x86_64"
            or Path("/.dockerenv").exists()
            or Path("/proc/1/comm").read_text("ascii").strip() != "systemd"
            or socket.gethostname() != "pr237-" + target
            or Path(__file__).resolve() != Path(
                "/home/pr237ci/source/scripts/ci_v06_vm_owned_storage_guest.py")
            or command("/usr/bin/systemd-detect-virt", "--vm") not in ("qemu", "kvm")):
        raise AssertionError("DISPOSABLE_BOOTED_VM_REQUIRED")
    osr = dict(line.split("=", 1) for line in
               Path("/etc/os-release").read_text("ascii").splitlines()
               if "=" in line and not line.lstrip().startswith("#"))
    distro, major = ("debian", "13") if target == "debian13" else ("almalinux", "10")
    assert osr.get("ID", "").strip('"') == distro
    assert osr.get("VERSION_ID", "").strip('"').split(".")[0] == major
    result = subprocess.run(["/usr/bin/systemctl", "is-active", "nginx.service"],
                            check=False, text=True, capture_output=True, timeout=15)
    assert result.returncode != 0 and result.stdout.strip() == "inactive"
    if target == "almalinux10":
        assert command("/usr/sbin/getenforce") == "Enforcing"


def verify_labeled_root_refusal() -> None:
    worker = pwd.getpwnam("nginx")
    assert worker.pw_uid != 0 and worker.pw_gid != 0
    with tempfile.TemporaryDirectory(prefix="repocache-storage-label-refusal-") as temp:
        root = Path(temp)
        root.chmod(0o755)
        for name in ("var", "var/cache", "var/cache/nginx", "var/log", "var/log/nginx"):
            (root / name).mkdir(mode=0o755)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            label = os.getxattr(fd, "security.selinux")
            assert label, "NATIVE_SELINUX_LABEL_NOT_OBSERVED"

            def snapshot() -> dict:
                result = {}
                for path in [root, *root.rglob("*")]:
                    st = path.lstat()
                    result[str(path.relative_to(root))] = (
                        st.st_ino, st.st_mode, st.st_uid, st.st_gid,
                        st.st_mtime_ns, os.getxattr(path, "security.selinux"))
                return result

            before = snapshot()
            for _ in range(2):
                try:
                    bootstrap_native_nginx_storage_under_root(
                        fd, root_uid=0, cache_uid=worker.pw_uid, cache_gid=worker.pw_gid)
                except NativeStorageBootstrapError as exc:
                    assert str(exc) == "NATIVE_STORAGE_XATTR_OR_SELINUX_UNVERIFIED"
                else:
                    raise AssertionError("UNVERIFIED_LABEL_ADOPTED")
                assert snapshot() == before, "LABEL_REFUSAL_MUTATED_FIXTURE"
        finally:
            os.close(fd)
    assert command("/usr/sbin/getenforce") == "Enforcing"
    print("PASS: booted enforcing SELinux labeled storage refused before mutation; "
          "repeat refusal preserved paths, owners, modes, timestamps and labels", flush=True)
    print("NOT VERIFIED: installed SELinux-aware cache/log provisioning and worker access; "
          "the current fixture primitive deliberately refuses unverified labels", flush=True)


def main(target: str) -> None:
    guard(target)
    if target == "almalinux10":
        verify_labeled_root_refusal()
        return
    # Package preparation is confined to this disposable, guarded guest.
    # Use the stock signed distro package path; no source changes.
    if not Path("/usr/sbin/logrotate").is_file():
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        subprocess.run(["/usr/bin/apt-get", "install", "-y", "-qq",
                        "--no-install-recommends", "logrotate"],
                       check=True, timeout=300, env=env)
    assert Path("/usr/sbin/logrotate").is_file()
    exercise_owned_runtime()
    guard(target)
    print("PASS: booted Debian 13 detached owned storage, real NGINX worker, "
          "private metrics and two stock rotations", flush=True)
    print("NOT VERIFIED: installed service/log reopen, real repair, persistence "
          "across reboot, publisher trust or production activation", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Exactly one fixed VM target required")
    main(sys.argv[1])
