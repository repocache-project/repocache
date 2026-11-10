"""Read-only booted native VM prerequisites (#27); never an installer."""
from __future__ import annotations

import os
import stat
import sys
from typing import Any

from repocache.server_install_v1 import validate_os_identity
from repocache.server_native_nginx_effective_unit_v1 import (
    EffectiveNginxUnitError, inspect_effective_native_nginx_unit,
)


class NativeVMReadOnlyError(ValueError):
    """Fixed error codes only: no host text, paths or private data."""


def _read_fixed(path: str, size: int) -> bytes:
    """Read bounded fixed OS/proc/sysfs paths; never accept a caller path."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK |
                     getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise NativeVMReadOnlyError("FIXED_READ_UNAVAILABLE") from None
    try:
        info = os.fstat(fd)
        # procfs/sysfs regular attributes often advertise a synthetic 4096
        # byte st_size while returning only a few real bytes. Bound the
        # actual read for all probes; bound disk-backed os-release size too.
        if (not stat.S_ISREG(info.st_mode) or info.st_size < 0
                or (path == "/etc/os-release" and info.st_size > size)):
            raise NativeVMReadOnlyError("FIXED_READ_UNSAFE")
        data = os.read(fd, size + 1)
        if not 1 <= len(data) <= size:
            raise NativeVMReadOnlyError("FIXED_READ_INVALID")
        return data
    except OSError:
        raise NativeVMReadOnlyError("FIXED_READ_UNAVAILABLE") from None
    finally:
        os.close(fd)


def _booted_pid1_shape() -> bool:
    try:
        for path in ("/run", "/run/systemd", "/run/systemd/system"):
            info = os.lstat(path)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                return False
        for kind in ("pid", "mnt", "user"):
            first = os.stat("/proc/1/ns/" + kind)
            current = os.stat("/proc/self/ns/" + kind)
            if ((first.st_dev, first.st_ino) !=
                    (current.st_dev, current.st_ino)):
                return False
    except OSError:
        return False
    return True


def _report(distro: str | None, code: str, *,
            booted: bool = False, selinux: bool = False,
            nginx: bool = False) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": ("READ_ONLY_PREREQUISITES_OBSERVED" if nginx
                   else "NOT VERIFIED"),
        "code": code,
        "distribution": distro,
        "supported_distro_python_observed": distro is not None,
        "systemd_pid1_namespace_shape_observed": booted,
        "almalinux_selinux_enforcing_observed": selinux,
        "effective_nginx_master_observed": nginx,
        "host_root_attested": False,
        "installed_repocache_signature_verified": False,
        "complete_server_acceptance_passed": False,
        "live_repository_cache_verified": False,
        "durable_host_recovery_verified": False,
        "authorizes_package_installation": False,
        "authorizes_host_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }


def inspect_booted_vm_nginx_readonly() -> dict[str, Any]:
    """Report necessary host observations, never a native trust decision.

    Privileged containers with systemd may still mimic these properties.
    Read-only observation does not prove installed REPOCACHE provenance,
    effective SELinux policy, package trust or actual NGINX listeners.
    """
    try:
        release = _read_fixed("/etc/os-release", 8192).decode("ascii", "strict")
        distro = validate_os_identity(
            release, (sys.version_info.major, sys.version_info.minor),
        )
    except (NativeVMReadOnlyError, ValueError, TypeError, UnicodeError):
        return _report(None, "SUPPORTED_OS_NOT_OBSERVED")
    if distro not in ("debian", "almalinux"):
        return _report(None, "SUPPORTED_OS_NOT_OBSERVED")
    if os.geteuid() != 0:
        return _report(distro, "ROOT_READ_ONLY_PROBE_REQUIRED")
    try:
        if any(os.path.lexists(path) for path in (
            "/.dockerenv", "/run/.containerenv",
        )):
            return _report(distro, "CONTAINER_CONTEXT_REFUSED")
        if _read_fixed("/proc/1/comm", 64) != b"systemd\n":
            return _report(distro, "SYSTEMD_PID1_NOT_OBSERVED")
    except NativeVMReadOnlyError:
        return _report(distro, "SYSTEMD_PID1_NOT_OBSERVED")
    if not _booted_pid1_shape():
        return _report(distro, "SYSTEMD_NAMESPACE_OR_RUNTIME_NOT_OBSERVED")
    if distro == "almalinux":
        try:
            enforced = _read_fixed("/sys/fs/selinux/enforce", 32).strip() == b"1"
        except NativeVMReadOnlyError:
            enforced = False
        if not enforced:
            return _report(
                distro, "ALMALINUX_SELINUX_ENFORCING_NOT_OBSERVED",
                booted=True,
            )
    try:
        nginx = inspect_effective_native_nginx_unit(distro)
        if (type(nginx) is not dict or
                nginx.get("status") !=
                "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION" or
                nginx.get("kernel_nginx_master_executable_inode_observed")
                is not True or
                nginx.get("effective_unit_shape_observed") is not True or
                nginx.get("authorizes_nginx_reload") is not False):
            raise NativeVMReadOnlyError("NGINX_REPORT_REFUSED")
    except (NativeVMReadOnlyError, EffectiveNginxUnitError,
            OSError, TypeError, ValueError):
        return _report(distro, "EFFECTIVE_NGINX_NOT_OBSERVED",
                       booted=True, selinux=distro == "almalinux")
    return _report(distro, "OBSERVATION_ONLY_NO_HOST_AUTHORITY",
                   booted=True, selinux=distro == "almalinux", nginx=True)
