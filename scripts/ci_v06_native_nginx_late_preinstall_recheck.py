#!/usr/bin/env python3
"""Real APT/DNF preinstall race guard under journal lock; disposable CI only.

Use a separate kernel process whose /proc comm is nginx to prove that a
late foreign process, arriving after initial fresh-host preflight and
before the native manager's install call, is refused without invoking the
package manager. Afterwards run an *actual* signed-source native install
with a fresh lock/marker/process check immediately before both refresh
and install. No systemd service, host install, or recovery is authorized.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Callable

from ci_v06_journaled_native_server_install import (
    _require_disposable_context, _verify_pending_lock,
)
from repocache.server_native_nginx_ownership_v1 import (
    NativeNginxPreinstallGuardError,
    _scan_nginx_process_footprint,
    recheck_fresh_native_nginx_before_manager,
)
from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, NativePackageJournalError,
    _prepare_native_journal_under_root,
    _retain_native_package_journal_lock_under_root,
)
from repocache.server_native_package_effects_observe_v1 import (
    inspect_current_namespace_native_package_effects,
)
from repocache.server_protected_namespace_bootstrap_v1 import (
    bootstrap_protected_namespace_under_root,
)
from smoke_server_native_nginx_container_install import run_rehearsal

_ROOT = Path(__file__).resolve().parents[1]
_STATE = Path("/var/lib/repocache/server")
_MANAGER = {"debian": "/usr/bin/apt-get", "almalinux": "/usr/bin/dnf"}
_SUCCESS = "DISPOSABLE_LOCKED_LATE_NGINX_PREINSTALL_REFUSAL_PASS"


class LateNativeConflictTestError(ValueError):
    """Redacted failure identifiers only."""


def _deny(code: str) -> None:
    raise LateNativeConflictTestError(code)


def _require(value: bool, code: str) -> None:
    if not value:
        _deny(code)


def _manager_effect(distribution: str, argv: list[str]) -> bool:
    """A bounded audit classification for the existing fixed native runner.

    No caller-controlled shell/executable reaches this test script; an
    actual host executor must independently pin the full install argv.
    """
    return (
        type(argv) is list and len(argv) < 100
        and all(type(x) is str for x in argv)
        and argv[0] == _MANAGER[distribution]
        and (
            (distribution == "debian" and argv[-1] == "update")
            or (distribution == "debian" and argv[-2:] == ["install", "nginx"])
            or (distribution == "almalinux"
                and argv[-2:] == ["makecache", "--refresh"])
            or (distribution == "almalinux"
                and argv[-2:] == ["install", "nginx"])
        )
    )


def _invoke_native_manager_guarded(
    state_fd: int, *, distribution: str, release: str,
    document: dict[str, Any], seen: list[str], scans: list[str],
    argv: list[str], runner: Callable[..., Any], **kwargs: Any,
) -> Any:
    if _manager_effect(distribution, argv):
        _verify_pending_lock(distribution, seen)
        evidence = recheck_fresh_native_nginx_before_manager(
            state_fd, owner_uid=0, distribution=distribution,
            os_release=release,
            python_version=(sys.version_info.major, sys.version_info.minor),
            document=document,
        )
        _require(
            evidence["status"] == "FRESH_NATIVE_PREINSTALL_RECHECK_OBSERVED_ONLY"
            and evidence["external_lock_contention_observed"] is True
            and evidence["protected_pending_journal_unchanged"] is True
            and evidence["authorizes_native_package_installation"] is False,
            "LATE_RECHECK_WRONG_AUTHORITY",
        )
        scans.append("FRESH_RECHECK_BEFORE_NATIVE_EFFECT")
    else:
        _verify_pending_lock(distribution, seen)
    return runner(argv, **kwargs)


def _simulate_late_process_race(
    state_fd: int, *, distribution: str, release: str,
    document: dict[str, Any], seen: list[str], scans: list[str],
) -> None:
    _require(
        _scan_nginx_process_footprint() == "PROCESS_NGINX_NOT_OBSERVED",
        "PROCESS_BASELINE_NOT_CLEAN",
    )
    # The worker executable remains Python, with a Linux comm name of
    # "nginx". We test the same real /proc conflict scanner used in
    # production, but deliberately do NOT claim this is a real NGINX
    # service or listener. Spawn only inside disposable Docker.
    fake = subprocess.Popen(
        [sys.executable, "-B", "-c",
         "import ctypes,time;"
         "assert ctypes.CDLL(None).prctl(15,ctypes.c_char_p(b'nginx'),0,0,0)==0;"
         "time.sleep(15)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, cwd="/",
    )
    try:
        detected = False
        for _ in range(80):
            _require(fake.poll() is None, "RACE_PROCESS_EXITED_TOO_EARLY")
            if _scan_nginx_process_footprint() == "PROCESS_NGINX_FOUND":
                detected = True
                break
            time.sleep(0.05)
        _require(detected, "LATE_PROCESS_COMM_NOT_OBSERVED")

        # First simulated metadata check happened before the new process.
        # A second check immediately before install must stop *before*
        # running a native package manager. The pending journal is retained.
        invoked = []
        def forbidden(argv: list[str], **kwargs: Any):
            invoked.append(list(argv))
            _deny("NATIVE_INSTALL_EXECUTED_AFTER_PROCESS_CONFLICT")

        command = [_MANAGER[distribution], "install", "nginx"]
        try:
            _invoke_native_manager_guarded(
                state_fd, distribution=distribution, release=release,
                document=document, seen=seen, scans=scans,
                argv=command, runner=forbidden,
            )
        except NativeNginxPreinstallGuardError as exc:
            _require(
                str(exc) == "NATIVE_PREINSTALL_FRESH_NGINX_RUNNING_PROCESS_REFUSED",
                "LATE_PROCESS_WRONG_REFUSAL",
            )
        else:
            _deny("LATE_FOREIGN_PROCESS_ACCEPTED")
        _require(not invoked, "NATIVE_COMMAND_REACHED_ON_PROCESS_CONFLICT")
    finally:
        if fake.poll() is None:
            fake.terminate()
        try:
            fake.wait(timeout=5)
        except subprocess.TimeoutExpired:
            fake.kill()
            fake.wait(timeout=5)

    # A vanished process does not turn an earlier refusal into authority.
    # A new guarded invocation is required under the still-held lock.
    _require(
        _scan_nginx_process_footprint() == "PROCESS_NGINX_NOT_OBSERVED",
        "PROCESS_RACE_LEFTOVER",
    )


def run() -> dict[str, Any]:
    distribution, release = _require_disposable_context()
    document = json.loads(
        (_ROOT / "docs/examples/server-install-v1.json").read_text("utf-8"),
    )
    root_fd = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        boot = bootstrap_protected_namespace_under_root(root_fd, owner_uid=0)
        _require(
            boot["status"] == "FRESH_PROTECTED_LOCK_DURABLE",
            "PROTECTED_JOURNAL_BOOTSTRAP_FAILED",
        )
        seen: list[str] = []
        scans: list[str] = []
        with _retain_native_package_journal_lock_under_root(
            root_fd, owner_uid=0, distribution=distribution,
            allow_native_package_parent_changes=True,
        ) as prepared:
            _require(
                prepared["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
                and prepared["native_package_effects_reconciled"] is False
                and prepared["authorizes_package_installation"] is False,
                "PENDING_MARKER_NOT_DURABLE",
            )
            state_fd = os.open(
                _STATE,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                original_marker = (_STATE / NATIVE_PENDING_NAME).read_bytes()
                _simulate_late_process_race(
                    state_fd, distribution=distribution, release=release,
                    document=document, seen=seen, scans=scans,
                )
                _require(
                    (_STATE / NATIVE_PENDING_NAME).read_bytes()
                    == original_marker,
                    "LATE_CONFLICT_CHANGED_PENDING_MARKER",
                )

                def protected_runner(argv: list[str], **kwargs: Any):
                    return _invoke_native_manager_guarded(
                        state_fd, distribution=distribution, release=release,
                        document=document, seen=seen, scans=scans,
                        argv=argv, runner=subprocess.run, **kwargs,
                    )

                # Real Debian13/Alma10 APT/DNF authenticated metadata and
                # stock NGINX installation, with *fresh* process/path scans
                # immediately before update and before install.
                installed = run_rehearsal(
                    distribution=distribution, runner=protected_runner,
                )
                _require(
                    installed["status"] == "CONTAINER_NATIVE_NGINX_INSTALLED_SYNTAX_OK"
                    and installed["native_transaction_executed_in_disposable_container"]
                    is True
                    and len(scans) == 2
                    and all(
                        x == "FRESH_RECHECK_BEFORE_NATIVE_EFFECT" for x in scans
                    )
                    and len(seen) >= 6
                    and all(x == "CONTENDED" for x in seen)
                    and (_STATE / NATIVE_PENDING_NAME).read_bytes()
                        == original_marker,
                    "ACTUAL_NATIVE_INSTALL_WITH_RECHECK_NOT_VERIFIED",
                )
            finally:
                os.close(state_fd)
        after = inspect_current_namespace_native_package_effects(
            distribution=distribution,
        )
        _require(
            after["status"] == "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION"
            and after["pending_native_effects_block_reentry"] is True
            and after["authorizes_native_marker_removal"] is False,
            "PENDING_JOURNAL_NOT_RETAINED",
        )
        try:
            _prepare_native_journal_under_root(
                root_fd, owner_uid=0, distribution=distribution,
            )
        except NativePackageJournalError as exc:
            _require(
                str(exc) == "NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED",
                "NATIVE_PACKAGE_REENTRY_WRONG_REFUSAL",
            )
        else:
            _deny("NATIVE_PACKAGE_REENTRY_UNSAFE")
        return {
            "schema_version": 1,
            "status": _SUCCESS,
            "distribution": distribution,
            "real_proc_late_process_refused_before_native_install": True,
            "forbidden_native_install_never_invoked": True,
            "native_apt_dnf_update_and_install_each_rechecked": True,
            "exclusive_protected_lock_contended_through_native_effects": True,
            "pending_effects_journal_durable_and_unchanged": True,
            "native_package_reentry_remained_blocked": True,
            "actual_native_nginx_installed_only_in_disposable_container": True,
            "host_root_authenticated": False,
            "systemd_pid1_tested": False,
            "selinux_enforcing_tested": False,
            "package_effects_reconciled": False,
            "authorizes_host_package_install": False,
        }
    finally:
        os.close(root_fd)


def main() -> int:
    try:
        result = run()
    except Exception:
        result = {
            "schema_version": 1, "status": "FAIL",
            "code": "NATIVE_LATE_PREINSTALL_RECHECK_UNVERIFIED",
            "authorizes_host_package_install": False,
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return int(result.get("status") != _SUCCESS)


if __name__ == "__main__":
    raise SystemExit(main())
