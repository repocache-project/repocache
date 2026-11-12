#!/usr/bin/env python3
"""Real *disposable Docker only* v0.6 state/bootstrap/APT-DNF install rehearsal.

This is an executable CI integration test, not an installed server provisioner.
It must never be run on an actual host or given privileged host mount access.
The candidate's root-control, operator, signing and SELinux gates are separate.
"""
from __future__ import annotations

import errno
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

from repocache.server_install_v1 import validate_os_identity
from repocache.server_native_nginx_local_boundary_v1 import (
    inspect_native_nginx_local_boundary,
)
from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, NATIVE_TMP_NAME, NativePackageJournalError,
    _prepare_native_journal_under_root,
    _retain_native_package_journal_lock_under_root,
)
from repocache.server_protected_namespace_bootstrap_v1 import (
    bootstrap_protected_namespace_under_root,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME

from smoke_server_native_nginx_container_install import (
    ContainerInstallRehearsalError, run_rehearsal,
)

_ROOT = Path(__file__).resolve().parents[1]
_STATE = Path("/var/lib/repocache/server")
_CI_MARKER = "CONFIRMED_DISPOSABLE_DOCKER_ONLY"
_STAGE = "UNVERIFIED"  # Static CI-only phase for redacted failure triage.


class NativeIntegrationError(ValueError):
    """Static, secret-free codes for bounded CI failure reporting."""


def _deny(code: str) -> None:
    raise NativeIntegrationError(code)


def _require_disposable_context() -> tuple[str, str]:
    """Stop before any filesystem, subprocess, network or package mutation."""
    if (os.environ.get("REPOCACHE_NATIVE_TEST_CONTAINER") != _CI_MARKER
            or not Path("/.dockerenv").is_file()
            or os.geteuid() != 0
            or Path("/proc/1/comm").read_text(encoding="ascii").strip()
               == "systemd"):
        _deny("DISPOSABLE_NATIVE_CONTAINER_REQUIRED")
    try:
        raw = Path("/etc/os-release").read_text(encoding="ascii")
        distro = validate_os_identity(
            raw, (sys.version_info.major, sys.version_info.minor),
        )
    except (OSError, UnicodeError, ValueError):
        _deny("UNSUPPORTED_NATIVE_USERSPACE")
    if distro not in ("debian", "almalinux"):
        _deny("UNSUPPORTED_NATIVE_USERSPACE")
    # Never change a pre-existing state tree, NGINX instance or package DB
    # except the fresh disposable image explicitly bound by the CI runner.
    if (os.path.lexists("/var/lib/repocache")
            or any(os.path.lexists(name) for name in (
                "/etc/nginx", "/usr/sbin/nginx",
                "/usr/bin/nginx", "/usr/lib/systemd/system/nginx.service",
                "/lib/systemd/system/nginx.service",
                "/var/log/nginx",
            ))):
        _deny("DISPOSABLE_HOST_NOT_FRESH")
    return distro, raw


def _verify_pending_lock(distribution: str, seen: list[str]) -> None:
    """Executed *at each actual native subprocess invocation*.

    Require a durable, single-linked root-owned marker and prove the lock
    excludes another open-file-description while package effects occur.
    """
    marker = _STATE / NATIVE_PENDING_NAME
    lock = _STATE / LOCK_NAME
    if (not marker.is_file() or marker.is_symlink()
            or not lock.is_file() or lock.is_symlink()
            or (_STATE / NATIVE_TMP_NAME).exists()):
        _deny("NATIVE_JOURNAL_NOT_DURABLE")
    info = marker.stat()
    if (info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 2048):
        _deny("NATIVE_JOURNAL_UNTRUSTED")
    try:
        recorded = json.loads(marker.read_bytes())
    except (OSError, UnicodeError, ValueError):
        _deny("NATIVE_JOURNAL_INVALID")
    if recorded != {
        "journal_schema_version": 1,
        "operation": "fresh-native-nginx-package-install",
        "distribution": distribution,
        "manager": "apt" if distribution == "debian" else "dnf",
        "package": "nginx",
        "expected_state_generation": 0,
        "native_package_effects": "REQUIRES_EXPLICIT_RECONCILIATION",
    }:
        _deny("NATIVE_JOURNAL_IDENTITY_CHANGED")
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            seen.append("CONTENDED")
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            _deny("NATIVE_EXCLUSIVE_LOCK_NOT_HELD")
    finally:
        os.close(fd)


def run() -> dict[str, Any]:
    global _STAGE
    _STAGE = "CONTEXT"
    distribution, os_release = _require_disposable_context()
    _STAGE = "DOCUMENT"
    doc = json.loads(
        (_ROOT / "docs/examples/server-install-v1.json").read_text(encoding="utf-8")
    )
    _STAGE = "ROOT_FD"
    root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _STAGE = "BOOTSTRAP"
        try:
            initial = bootstrap_protected_namespace_under_root(
                root_fd, owner_uid=0,
            )
        except (OSError, ValueError, TypeError):
            _deny("PROTECTED_BOOTSTRAP_UNVERIFIED")
        if initial["status"] != "FRESH_PROTECTED_LOCK_DURABLE":
            _deny("PROTECTED_BOOTSTRAP_INCOMPLETE")
        _STAGE = "PREPACKAGE"
        try:
            preflight = inspect_native_nginx_local_boundary(
                os_release=os_release,
                python_version=(sys.version_info.major, sys.version_info.minor),
                document=doc,
            ).to_dict()
        except (OSError, ValueError, TypeError):
            _deny("LOCAL_PREPACKAGE_UNVERIFIED")
        if (preflight["code"] != "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED"
                or preflight["authorizes_package_transaction"]
                or preflight["can_install"]):
            _deny("NATIVE_PREPACKAGE_PROOF_MISSING")

        seen: list[str] = []
        def guarded_runner(command: list[str], **kwargs: Any):
            _verify_pending_lock(distribution, seen)
            return subprocess.run(command, **kwargs)

        _STAGE = "RETAINED_LOCK"
        with _retain_native_package_journal_lock_under_root(
            root_fd, owner_uid=0, distribution=distribution,
        ) as prepared:
            if (prepared["status"] != "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
                    or prepared["authorizes_package_installation"]):
                _deny("NATIVE_PACKAGE_MARKER_NOT_READY")
            _STAGE = "NATIVE_INSTALL"
            try:
                result = run_rehearsal(
                    distribution=distribution, runner=guarded_runner,
                )
            except NativeIntegrationError:
                raise
            except ContainerInstallRehearsalError as exc:
                # The existing disposable-container runner raises only fixed
                # reviewed codes; never print package-manager stderr/stdout.
                _deny("NATIVE_PACKAGE_" + str(exc))
            except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
                # Never include exception messages or native manager output;
                # emit only built-in type categories from a fixed allowlist.
                category = type(exc).__name__
                _deny("NATIVE_PACKAGE_REHEARSAL_" +
                      (category.upper() if category in {
                          "TypeError", "ValueError", "OSError",
                          "SubprocessError", "TimeoutExpired",
                      } else "UNVERIFIED"))
            except Exception as exc:
                category = type(exc).__name__
                _deny("NATIVE_PACKAGE_REHEARSAL_" +
                      (category.upper() if category in {
                          "AttributeError", "AssertionError", "KeyError",
                          "NameError", "RuntimeError", "ImportError",
                      } else "UNVERIFIED"))
        _STAGE = "POST_TRANSACTION"
        if (len(seen) < 4 or any(item != "CONTENDED" for item in seen)
                or not result["native_transaction_executed_in_disposable_container"]
                or not result["nginx_syntax_test_passed_in_container"]
                or not (_STATE / NATIVE_PENDING_NAME).is_file()):
            _deny("NATIVE_PACKAGE_TRANSACTION_NOT_EVIDENCED")
        _STAGE = "REENTRY"
        try:
            _prepare_native_journal_under_root(
                root_fd, owner_uid=0, distribution=distribution,
            )
        except NativePackageJournalError as exc:
            if str(exc) != "NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED":
                _deny("NATIVE_PACKAGE_REENTRY_UNVERIFIED")
        else:
            _deny("NATIVE_PACKAGE_REENTRY_NOT_BLOCKED")
        _STAGE = "COMPLETE"
        return {
            "schema_version": 1,
            "status": "DISPOSABLE_JOURNALED_NATIVE_INSTALL_PASS",
            "distribution": distribution,
            "actual_distro_package_transaction": True,
            "real_nginx_syntax_test_passed": True,
            "real_state_bootstrap_durable": True,
            "real_exclusive_lock_held_during_subprocesses": True,
            "pending_journal_survived_package_effects": True,
            "repeated_install_refused_without_reconciliation": True,
            "installed_server_ready": False,
            "host_root_provenance_verified": False,
            "systemd_pid1_verified": False,
            "selinux_enforcing_verified": False,
            "authorizes_host_installation": False,
        }
    finally:
        os.close(root_fd)


def main() -> int:
    global _STAGE
    _STAGE = "UNVERIFIED"
    try:
        result = run()
    except Exception as exc:
        code = (str(exc) if type(exc) is NativeIntegrationError
                else ("NATIVE_INTEGRATION_" + _STAGE + "_UNVERIFIED"
                      if _STAGE != "UNVERIFIED" else "NATIVE_INTEGRATION_UNVERIFIED"))
        print(json.dumps({
            "schema_version": 1, "status": "FAIL", "code": code,
            "authorizes_host_installation": False,
        }, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
