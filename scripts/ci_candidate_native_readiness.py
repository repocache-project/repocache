#!/usr/bin/env python3
"""Read-only, fail-closed native candidate resource readiness probe (#112/#149).

This is a prerequisite diagnostic, NOT kernel exhaustion, SELinux escape,
SIGKILL/restart, publisher-signature or release acceptance evidence.

Run as the unprivileged candidate service account on a booted disposable
Debian 13 or AlmaLinux 10 lab host. No mounts, kills, downloads or writes.
"""
from __future__ import annotations

import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from repocache import candidate_cgroup, candidate_sandbox, updater  # noqa: E402


class NativeReadinessError(RuntimeError):
    """A required native, non-production candidate prerequisite is missing."""


def _os_release() -> str:
    try:
        fields = {}
        for row in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in row:
                key, value = row.split("=", 1)
                fields[key] = value.strip().strip('"')
    except OSError as exc:
        raise NativeReadinessError("Cannot inspect OS release") from exc
    distro, version = fields.get("ID"), fields.get("VERSION_ID")
    if (distro, version) == ("debian", "13"):
        return "debian13"
    if (distro, version) == ("almalinux", "10"):
        return "almalinux10"
    raise NativeReadinessError("Host is not booted Debian 13 or AlmaLinux 10")


def _systemd_pid1() -> None:
    try:
        pid1 = Path("/proc/1/comm").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise NativeReadinessError("Cannot verify systemd as PID 1") from exc
    if pid1 != "systemd" or not Path("/run/systemd/system").is_dir():
        raise NativeReadinessError("Native booted systemd is required")


def _nonroot() -> None:
    if os.geteuid() == 0:
        raise NativeReadinessError("Service account must not be root")


def _selinux(target: str) -> None:
    if target == "almalinux10":
        try:
            value = Path("/sys/fs/selinux/enforce").read_text(encoding="ascii").strip()
        except OSError as exc:
            raise NativeReadinessError("AlmaLinux SELinux state unavailable") from exc
        if value != "1":
            raise NativeReadinessError("AlmaLinux SELinux is not enforcing")


def run_probe() -> dict[str, object]:
    """Evaluate prerequisites without changing the host state."""
    result: dict[str, object] = {
        "scope": "read-only native readiness only",
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "kernel": platform.release(),
        "target": "NOT_VERIFIED",
        "checks": {},
        "native_resource_exhaustion": "NOT_VERIFIED",
        "supervisor_sigkill_recovery": "NOT_VERIFIED",
        "selinux_escape_tests": "NOT_VERIFIED",
        "real_publisher_signed_candidate": "NOT_VERIFIED",
        "status": "BLOCKED",
    }
    checks: dict[str, str] = result["checks"]  # type: ignore[assignment]

    def verify(name: str, action) -> bool:
        try:
            action()
        except (NativeReadinessError, candidate_cgroup.CgroupGateError,
                candidate_sandbox.SandboxError, updater.UpdateError, OSError) as exc:
            checks[name] = "FAIL: " + str(exc)[:180]
            return False
        checks[name] = "PASS"
        return True

    target = None
    try:
        target = _os_release()
        result["target"] = target
        checks["supported_os"] = "PASS"
    except NativeReadinessError as exc:
        checks["supported_os"] = "FAIL: " + str(exc)
    host_ready = (
        verify("non_root_service", _nonroot)
        and verify("booted_systemd", _systemd_pid1)
    )
    if target is None or not host_ready:
        return result
    if not verify("mandatory_selinux", lambda: _selinux(target)):
        return result
    if not verify("delegated_cgroup_v2", candidate_cgroup.require_delegation):
        return result
    # Read the already-provisioned staging mount; do NOT create directories.
    parent = updater.ROOT / "online-preparations"
    if not verify("bounded_staging_tmpfs",
                  lambda: candidate_cgroup.require_staging_tmpfs(parent)):
        return result
    if not verify("patched_os_bubblewrap", candidate_sandbox.require_executor):
        return result
    result["status"] = "READINESS_ONLY_PASS"
    return result


def main() -> int:
    evidence = run_probe()
    print(json.dumps(evidence, sort_keys=True, indent=2))
    return 0 if evidence["status"] == "READINESS_ONLY_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
