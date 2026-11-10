"""Read-only, fixed-name NGINX PID1 systemd observation (#27/#64).

A vendor unit on disk can be overridden or bypassed at runtime. This
prerequisite observes only an exact effective nginx.service identity and
reports it with the already verified vendor unit digest. It does NOT
authorize systemctl, unit changes, reloads, package installations or state
writes, and it cannot attest native host-root or SELinux enforcement.
"""
from __future__ import annotations

import os
import stat
import subprocess
from typing import Any

from repocache.server_native_nginx_service_unit_v1 import (
    inspect_native_nginx_unit,
)

_SYSTEMCTL = "/usr/bin/systemctl"
_UNIT = "nginx.service"
_PROPERTIES = (
    "Id", "Names", "FragmentPath", "DropInPaths", "LoadState",
    "ActiveState", "SubState", "MainPID", "CanReload",
    "NeedDaemonReload",
)
_FIXED_ARGS = (
    _SYSTEMCTL, "show", "--no-pager",
    *(f"--property={name}" for name in _PROPERTIES),
    _UNIT,
)


class EffectiveNginxUnitError(ValueError):
    """Fixed codes only; never expose systemctl output or private paths."""


def _deny(code: str) -> None:
    raise EffectiveNginxUnitError("NATIVE_NGINX_EFFECTIVE_" + code)


def _safe_native_systemctl() -> None:
    """Reject user-writable, shadowed, symlinked executable and ancestors."""
    for path, directory in (
        ("/", True), ("/usr", True), ("/usr/bin", True),
        (_SYSTEMCTL, False),
    ):
        try:
            seen = os.lstat(path)
        except OSError:
            _deny("EXECUTABLE_UNAVAILABLE")
        if ((not stat.S_ISDIR(seen.st_mode) if directory
             else not stat.S_ISREG(seen.st_mode))
                or seen.st_uid != 0 or seen.st_gid != 0
                or stat.S_IMODE(seen.st_mode) & 0o022
                or (not directory and seen.st_nlink != 1)):
            _deny("EXECUTABLE_UNSAFE")


def _parse_fixed_unit_status(value: Any) -> dict[str, str]:
    if (type(value) is not str or not 1 <= len(value) <= 8192
            or "\x00" in value or "\r" in value):
        _deny("RESPONSE_INVALID")
    result = {}
    for line in value.splitlines():
        if "=" not in line:
            _deny("RESPONSE_INVALID")
        key, val = line.split("=", 1)
        if key not in _PROPERTIES or key in result or "\n" in val:
            _deny("RESPONSE_INVALID")
        result[key] = val
    if set(result) != set(_PROPERTIES):
        _deny("RESPONSE_INCOMPLETE")
    expected = {
        "Id": _UNIT,
        "Names": _UNIT,
        "FragmentPath": "/usr/lib/systemd/system/nginx.service",
        "DropInPaths": "",
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "CanReload": "yes",
        "NeedDaemonReload": "no",
    }
    if any(result[key] != expected[key] for key in expected):
        _deny("FOREIGN_OR_INACTIVE_UNIT")
    pid = result["MainPID"]
    if (not pid or len(pid) > 10 or not pid.isascii()
            or not pid.isdecimal()
            or not 1 <= int(pid) <= 2**31 - 1):
        _deny("INVALID_MAIN_PID")
    return result


def inspect_effective_native_nginx_unit(distribution: str) -> dict[str, Any]:
    """Observe fixed effective PID1 service only after vendor unit checks.

    Distro userspace CI may mock this check; booted systemd/SELinux
    acceptance is deliberately NOT supplied by a mocked stdout.
    """
    if type(distribution) is not str or distribution not in ("debian", "almalinux"):
        _deny("DISTRIBUTION_INVALID")
    vendor = inspect_native_nginx_unit(distribution)
    if vendor.code != "VENDOR_NGINX_UNIT_OBSERVED" or vendor.digest is None:
        _deny("VENDOR_UNIT_UNVERIFIED")
    _safe_native_systemctl()
    try:
        completed = subprocess.run(
            _FIXED_ARGS, shell=False, check=False, capture_output=True,
            text=True, timeout=5, cwd="/",
            stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            start_new_session=True,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        _deny("SYSTEMCTL_UNAVAILABLE")
    if (completed.returncode != 0 or type(completed.stdout) is not str
            or type(completed.stderr) is not str
            or len(completed.stderr) > 4096):
        _deny("SYSTEMCTL_FAILED")
    observed = _parse_fixed_unit_status(completed.stdout)
    return {
        "schema_version": 1,
        "status": "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION",
        "unit_name": _UNIT,
        "main_pid_observed": int(observed["MainPID"]),
        "vendor_unit_sha256": vendor.digest,
        "effective_unit_shape_observed": True,
        "distro_package_owner_verified": False,
        "real_pid1_and_nginx_process_verified": False,
        "host_root_and_selinux_verified": False,
        "authorizes_systemctl": False,
        "authorizes_nginx_reload": False,
        "authorizes_nginx_install": False,
    }
