#!/usr/bin/env python3
"""Native booted QEMU APT/DNF trust/fallback smoke without host source writes.

Reuse the existing real-manager synthetic signed fixture engine. Test-only
Ed25519/OpenPGP identities are generated inside this disposable guest. This
is not an installed REPOCACHE server route or publisher-signed acceptance.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import stat
import shutil
import subprocess
import sys

ROOT = Path("/home/pr237ci/source")
SOURCE_LIMIT = 1024 * 1024


def command(*args: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), check=False, timeout=timeout,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AssertionError(reason)


def guarded_native_guest(platform: str) -> None:
    require(platform in ("debian13", "almalinux10"), "fixed native target")
    require(os.getresuid() == (0, 0, 0), "root-only local manager test")
    require(not Path("/.dockerenv").exists(), "never run inside a container")
    require(Path("/proc/1/comm").read_text("ascii").strip() == "systemd",
            "booted systemd required")
    require(socket.gethostname() == "pr237-" + platform,
            "disposable CI guest hostname required")
    vm = command("/usr/bin/systemd-detect-virt", "--vm")
    require(vm.returncode == 0 and vm.stdout.strip() in ("qemu", "kvm"),
            "real booted QEMU/KVM guest required")
    values = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text("ascii").splitlines()
        if "=" in line and not line.startswith("#")
    )
    expected_id = "debian" if platform == "debian13" else "almalinux"
    expected_version = "13" if platform == "debian13" else "10"
    require(values.get("ID", "").strip('"') == expected_id
            and values.get("VERSION_ID", "").strip('"').split(".")[0]
            == expected_version, "unexpected native distribution")
    if platform == "almalinux10":
        se = command("/usr/sbin/getenforce")
        require(se.returncode == 0 and se.stdout.strip() == "Enforcing",
                "SELinux must remain enforcing")
    require(ROOT.is_dir() and not ROOT.is_symlink()
            and (ROOT / "scripts/ci_client_native_fallback.py").is_file(),
            "expected fixed source archive")
    # These binaries were obtained via the guest's original native manager,
    # not by pip, untrusted download, system CA change or release publisher.
    bins = ("apt-get", "dpkg-deb", "gpg", "openssl") if platform == "debian13" else (
        "dnf", "createrepo_c", "gpg", "openssl", "rpmbuild", "rpmsign", "rpm",
    )
    for item in bins:
        require(shutil.which(item) is not None,
                "native test tool missing: " + item)


def installed_sources(platform: str) -> tuple[tuple[str, int, int, int, str], ...]:
    directory = (Path("/etc/apt/sources.list.d") if platform == "debian13"
                 else Path("/etc/yum.repos.d"))
    require(directory.is_dir() and not directory.is_symlink(),
            "native sources directory missing")
    names = [p for p in directory.iterdir()
             if p.suffix in (".sources", ".list", ".repo")]
    if platform == "debian13" and Path("/etc/apt/sources.list").exists():
        names.append(Path("/etc/apt/sources.list"))
    require(0 < len(names) <= 128, "native source inventory invalid")
    result = []
    for path in sorted(names):
        meta = path.lstat()
        require(stat.S_ISREG(meta.st_mode)
                and meta.st_size <= SOURCE_LIMIT, "native source is not regular")
        data = path.read_bytes()
        require(len(data) == meta.st_size, "source changed while reading")
        result.append((
            str(path), meta.st_ino, meta.st_mode, meta.st_mtime_ns,
            hashlib.sha256(data).hexdigest(),
        ))
    return tuple(result)


def installed_packages(platform: str) -> tuple[str, ...]:
    args = ("/usr/bin/dpkg-query", "-W", "-f=${Package}=${Version}\\n") if (
        platform == "debian13"
    ) else ("/usr/bin/rpm", "-qa", "--queryformat", "%{NAME}=%{VERSION}-%{RELEASE}\\n")
    result = command(*args, timeout=30)
    require(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024,
            "native package inventory unavailable")
    return tuple(sorted(result.stdout.splitlines()))


def main(platform: str) -> None:
    guarded_native_guest(platform)
    before_sources = installed_sources(platform)
    before_packages = installed_packages(platform)
    sys.path[:0] = [str(ROOT / "scripts")]
    from ci_client_native_fallback import probe

    if platform == "debian13":
        # Actual apt-get with a temporary mirror+file source, independently
        # trusted ephemeral Release signature and real synthetic .deb bytes.
        # Covers preference, 503 fallback, return-to-preferred, both-out,
        # wrong TLS CA, invalid InRelease and modified .deb hash refusal.
        probe("apt", tls=True, package_transfer=True)
    else:
        # Actual DNF5 with temporary repo/config/cache roots. OpenPGP-signed
        # repomd metadata and a guest-local public key must reject tampering.
        probe("dnf", tls=True, signed_dnf=True)
        from ci_dnf_signed_rpm_fallback import probe_booted_vm

        probe_booted_vm()

    require(installed_sources(platform) == before_sources,
            "real system APT/DNF source files were modified")
    require(installed_packages(platform) == before_packages,
            "real installed package inventory changed")
    if platform == "almalinux10":
        require(command("/usr/sbin/getenforce").stdout.strip() == "Enforcing",
                "SELinux was not preserved")
    print("PASS: booted-native-real-manager-signed-fallback-and-host-sources-intact "
          + platform, flush=True)
    print("NOT VERIFIED: installed REPOCACHE NGINX cache HIT, actual client "
          "repos sync --apply, production signed repository metadata or publisher "
          "identity", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: ci_v06_vm_signed_client_guest.py debian13|almalinux10")
    main(sys.argv[1])
