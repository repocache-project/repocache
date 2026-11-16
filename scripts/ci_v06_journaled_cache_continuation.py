#!/usr/bin/env python3
"""CI-only root-to-rootless handoff after journaled native NGINX installation.

Never install or execute on a host. The separate trusted fixture runner
installs NGINX inside a fresh disposable Docker image. This script verifies
that the earlier stage actually passed and drops all root credentials BEFORE
executing the independent generated-route HTTPS/cache smoke test.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys

from repocache.server_install_v1 import validate_os_identity

_MARKER = "CONFIRMED_DISPOSABLE_DOCKER_ONLY"
_REPORT = "/tmp/repocache-v06-journaled-result.json"
_CACHE_SMOKE = "/workspace/scripts/ci_generated_nginx_route_cache_smoke.py"


class ContainerContinuationError(ValueError):
    """Never disclose the previous report, filesystem data or environment."""


def _deny(code: str) -> None:
    raise ContainerContinuationError("CONTAINER_CONTINUATION_" + code)


def _require_disposable_native_install() -> None:
    """Reject non-Docker, foreign userspace or an unauthenticated prior stage.

    These safeguards prevent accidental host invocation; container markers
    are NOT cryptographic machine or mount-namespace attestation.
    """
    if (os.environ.get("REPOCACHE_NATIVE_TEST_CONTAINER") != _MARKER
            or os.geteuid() != 0
            or not Path("/.dockerenv").is_file()):
        _deny("DOCKER_ROOT_REQUIRED")
    try:
        if Path("/proc/1/comm").read_text(encoding="ascii").strip() == "systemd":
            _deny("SYSTEMD_PID1_REFUSED")
        distribution = validate_os_identity(
            Path("/etc/os-release").read_text(encoding="ascii"),
            (sys.version_info.major, sys.version_info.minor),
        )
        if distribution not in ("debian", "almalinux"):
            _deny("UNSUPPORTED_USERSPACE")
    except ContainerContinuationError:
        raise
    except (OSError, UnicodeError, ValueError):
        _deny("UNSUPPORTED_USERSPACE")

    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(_REPORT, flags)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) & 0o022
                    or not 0 < info.st_size <= 4096):
                _deny("PRIOR_REPORT_UNTRUSTED")
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
        if len(raw) != info.st_size:
            _deny("PRIOR_REPORT_CHANGED")
        prior = json.loads(raw)
    except ContainerContinuationError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        _deny("PRIOR_REPORT_UNAVAILABLE")
    if (type(prior) is not dict
            or prior.get("schema_version") != 1
            or prior.get("status") != "DISPOSABLE_JOURNALED_NATIVE_INSTALL_PASS"
            or prior.get("distribution") != distribution
            or any(prior.get(key) is not True for key in (
                "actual_distro_package_transaction",
                "real_nginx_syntax_test_passed",
                "real_exclusive_lock_held_during_subprocesses",
                "pending_journal_survived_package_effects",
                "repeated_install_refused_without_reconciliation",
            ))
            or any(prior.get(key) is not False for key in (
                "installed_server_ready", "host_root_provenance_verified",
                "systemd_pid1_verified", "selinux_enforcing_verified",
                "authorizes_host_installation",
            ))):
        _deny("PRIOR_INSTALL_NOT_PROVEN")
    try:
        nginx = os.lstat("/usr/sbin/nginx")
        smoke = os.lstat(_CACHE_SMOKE)
    except OSError:
        _deny("NATIVE_SMOKE_MISSING")
    if (not stat.S_ISREG(nginx.st_mode) or nginx.st_uid != 0
            or stat.S_IMODE(nginx.st_mode) & 0o111 == 0
            or not stat.S_ISREG(smoke.st_mode)):
        _deny("NATIVE_SMOKE_UNTRUSTED")


def run() -> None:
    """Never return success from an elevated interpreter."""
    _require_disposable_native_install()
    try:
        # A positive result from the earlier root stage grants NO privilege to
        # the generated-route smoke. Drop groups, GID and UID before exec.
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
        if os.geteuid() != 65534:
            _deny("PRIVILEGE_DROP_UNVERIFIED")
        env = {
            "PATH": "/usr/sbin:/usr/bin:/bin",
            "HOME": "/tmp", "TMPDIR": "/tmp", "LC_ALL": "C",
            "PYTHONPATH": "/workspace/src",
            "REPOCACHE_DISPOSABLE_NGINX_SMOKE": "1",
        }
        os.execve(
            "/usr/bin/python3",
            ["/usr/bin/python3", "-B", _CACHE_SMOKE],
            env,
        )
    except ContainerContinuationError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("ROOTLESS_SMOKE_UNAVAILABLE")
    _deny("ROOTLESS_EXEC_RETURNED")


def main() -> int:
    if len(sys.argv) != 1:
        print('{"status":"FAIL","code":"CONTAINER_CONTINUATION_ARGUMENTS_REFUSED"}')
        return 2
    try:
        run()
    except ContainerContinuationError as exc:
        print(json.dumps({
            "status": "FAIL", "code": str(exc),
            "authorizes_host_installation": False,
        }, sort_keys=True))
        return 2
    except (OSError, TypeError, ValueError):
        print('{"status":"FAIL","code":"CONTAINER_CONTINUATION_UNVERIFIED"}')
        return 2
    return 2  # os.execve replaces this process on the only success path.


if __name__ == "__main__":
    raise SystemExit(main())
