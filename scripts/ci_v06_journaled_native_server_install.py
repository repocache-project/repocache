#!/usr/bin/env python3
"""Real *disposable Docker only* v0.6 state/bootstrap/APT-DNF install rehearsal.

This is an executable CI integration test, not an installed server provisioner.
It must never be run on an actual host or given privileged host mount access.
The candidate's root-control, operator, signing and SELinux gates are separate.
"""
from __future__ import annotations

import errno
import fcntl
import copy
import hashlib
import json
import os
import platform
from pathlib import Path
import stat
import subprocess
import socket
import sys
import tempfile
from typing import Any

from repocache.server_install_v1 import validate_os_identity, validate_server_architecture
from repocache.server_native_nginx_local_boundary_v1 import (
    inspect_native_nginx_local_boundary,
)
from repocache.server_native_package_effects_observe_v1 import (
    NativeEffectsReconciliationError,
    inspect_current_namespace_native_package_effects,
    inspect_current_namespace_native_postpackage_candidate,
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
_PREFLIGHT_PATHS = (Path("/etc/nginx"), _STATE)


class NativeIntegrationError(ValueError):
    """Static, secret-free codes for bounded CI failure reporting."""


def _deny(code: str) -> None:
    raise NativeIntegrationError(code)


def _preserved_paths() -> dict:
    result = {}
    for root in _PREFLIGHT_PATHS:
        paths = [root]
        if root.is_dir() and not root.is_symlink():
            paths.extend(root.rglob("*"))
        if len(paths) > 1024:
            _deny("PREFLIGHT_PRESERVATION_INVENTORY_TOO_LARGE")
        for path in paths:
            try:
                info = path.lstat()
            except FileNotFoundError:
                result[str(path)] = None
                continue
            digest = None
            if stat.S_ISREG(info.st_mode):
                if info.st_size > 2 * 1024 * 1024:
                    _deny("PREFLIGHT_PRESERVATION_FILE_TOO_LARGE")
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result[str(path)] = (
                info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns, digest,
            )
    return result


def _drop_preflight_identity() -> None:
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


def _run_readonly_preflight(document: dict, *, unprivileged: bool = False) -> dict:
    before = _preserved_paths()
    with tempfile.TemporaryDirectory(prefix="repocache-preflight-acceptance-") as tmp:
        parent = Path(tmp)
        parent.chmod(0o755)
        config = parent / "install.json"
        config.write_text(json.dumps(document), encoding="ascii")
        config.chmod(0o644)
        result = subprocess.run(
            ["/usr/bin/python3", "-I", "-B", str(_ROOT / "scripts/server_v06_preflight.py"),
             "--document", str(config), "--intent", "install"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False, cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            preexec_fn=_drop_preflight_identity if unprivileged else None,
        )
    if result.returncode not in (1, 3) or result.stderr or len(result.stdout) > 65536:
        _deny("PREFLIGHT_COMMAND_UNVERIFIED")
    try:
        report = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        _deny("PREFLIGHT_REPORT_INVALID")
    if (report.get("read_only") is not True
            or report.get("authorizes_installation") is not False
            or report.get("kind") != "repocache.server.vm-preflight.partial"
            or report.get("schema_version") != 1
            or report.get("status") != ("FAIL" if result.returncode == 1 else "NOT VERIFIED")
            or not report.get("checks")
            or any(set(row) != {"check", "status", "code", "guidance"}
                   or not isinstance(row["guidance"], str) or not row["guidance"]
                   for row in report["checks"])):
        _deny("PREFLIGHT_BOUNDARY_INVALID")
    if _preserved_paths() != before:
        _deny("PREFLIGHT_CHANGED_NATIVE_OR_PROTECTED_FILES")
    return {row["check"]: row for row in report["checks"]}


def _verify_readonly_preflight(document: dict, *, installed: bool) -> None:
    first = _run_readonly_preflight(document)
    if _run_readonly_preflight(document) != first:
        _deny("PREFLIGHT_REPEAT_CHANGED")
    if first["supported_os_and_python"]["status"] != "PASS":
        _deny("PREFLIGHT_SUPPORTED_TARGET_REJECTED")
    if (first["architecture_supported"]["code"] != "SUPPORTED_NATIVE_ARCHITECTURE"
            or first["native_python_identity"]["code"] != "NATIVE_PYTHON_INODE_OBSERVED_ONLY"):
        _deny("PREFLIGHT_SUPPORTED_TARGET_REJECTED")
    expected = "NGINX_EXECUTABLE_OBSERVED_ONLY" if installed else "NGINX_EXECUTABLE_MISSING"
    if first["nginx_native_binary"]["code"] != expected:
        _deny("PREFLIGHT_PACKAGE_DIAGNOSTIC_UNVERIFIED")
    allowed_failures = {"SYSTEMD_NATIVE_PID1_NOT_OBSERVED"}
    if not installed:
        allowed_failures.update({"NGINX_EXECUTABLE_MISSING", "REQUIRED_NATIVE_EXECUTABLE_MISSING"})
    if any(row["status"] == "FAIL"
           and row["code"] not in allowed_failures
           for row in first.values()):
        _deny("PREFLIGHT_POSITIVE_LOCAL_CHECK_FAILED")
    if not installed:
        return
    nonroot = _run_readonly_preflight(document, unprivileged=True)
    if (nonroot["effective_uid"]["code"] != "PRIVILEGED_INSTALL_REQUIRES_ROOT"
            or nonroot["effective_uid"]["status"] != "FAIL"):
        _deny("PREFLIGHT_ROOT_DIAGNOSTIC_UNVERIFIED")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        occupied = copy.deepcopy(document)
        occupied["deployment"]["listen"]["https_port"] = listener.getsockname()[1]
        report = _run_readonly_preflight(occupied)
        if (report["listen_port_conflicts"]["code"] != "HTTPS_PORT_ALREADY_LISTENING"
                or report["listen_port_conflicts"]["status"] != "FAIL"):
            _deny("PREFLIGHT_PORT_DIAGNOSTIC_UNVERIFIED")
    cache = Path(document["deployment"]["paths"]["cache_root"])
    while not cache.exists():
        cache = cache.parent
    observed = os.statvfs(cache)
    low = copy.deepcopy(document)
    critical = observed.f_bavail * observed.f_frsize + 1024 * 1024 * 1024
    low["deployment"]["cache_policy"]["disk_pressure"] = {
        "critical_free_bytes": critical, "warning_free_bytes": critical + 1,
    }
    report = _run_readonly_preflight(low)
    if (report["storage_free_space"]["code"] != "STORAGE_SPACE_BELOW_CRITICAL_THRESHOLD"
            or report["storage_free_space"]["status"] != "FAIL"):
        _deny("PREFLIGHT_CAPACITY_DIAGNOSTIC_UNVERIFIED")


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
    try:
        validate_server_architecture(platform.machine())
    except ValueError:
        _deny("UNSUPPORTED_NATIVE_ARCHITECTURE")
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
    _STAGE = "READONLY_PREFLIGHT_BEFORE_PACKAGE"
    _verify_readonly_preflight(doc, installed=False)
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
            # APT/DNF legitimately adds children to /var/lib while holding
            # the fixed lock. Its inode/owner/mode security boundary remains
            # strict; only shared-ancestor timestamps/link counts can drift.
            allow_native_package_parent_changes=True,
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
        _STAGE = "PENDING_RECONCILIATION"
        try:
            effects = inspect_current_namespace_native_package_effects(
                distribution=distribution,
            )
        except NativeEffectsReconciliationError:
            _deny("NATIVE_PACKAGE_POSTEFFECTS_JOURNAL_UNVERIFIED")
        if (effects["status"] != "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION"
                or effects["distribution"] != distribution
                or not effects["journal_identity_verified"]
                or not effects["pending_native_effects_block_reentry"]
                or effects["native_package_effects_reconciled"]
                or effects["authorizes_native_marker_removal"]
                or effects["authorizes_host_mutation"]):
            _deny("NATIVE_PACKAGE_POSTEFFECTS_JOURNAL_UNVERIFIED")
        _STAGE = "POSTPACKAGE_CORRELATION"
        try:
            correlation = inspect_current_namespace_native_postpackage_candidate(
                distribution=distribution,
            )
        except (NativeEffectsReconciliationError, OSError, ValueError, TypeError):
            # CI-only investigation of the distro's stock RPM verifier.
            # This script has already refused all non-disposable hosts.
            # Never execute this diagnostic from the installed root worker.
            if distribution == "almalinux":
                diagnostic = subprocess.run(
                    ["/usr/bin/rpm", "-V", "nginx", "nginx-core"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, text=True, timeout=12,
                    check=False,
                )
                print("DISPOSABLE_RPM_VERIFY_EXIT=" + str(diagnostic.returncode),
                      file=sys.stderr)
                for row in diagnostic.stdout.splitlines()[:30]:
                    print("DISPOSABLE_RPM_VERIFY_ROW=" + row[:160],
                          file=sys.stderr)
            _deny("NATIVE_POSTPACKAGE_CORRELATION_UNVERIFIED")
        if (correlation.get("status") !=
                "NATIVE_POSTPACKAGE_CORRELATION_CANDIDATE_ONLY"
                or correlation.get("distribution") != distribution
                or correlation.get("pending_journal_stable_across_observations") is not True
                or correlation.get("single_protected_lock_spanned_native_package_and_unit_reads") is not True
                or correlation.get("native_package_db_owner_observed") is not True
                or correlation.get("native_vendor_unit_shape_observed") is not True
                or correlation.get("pending_native_effects_block_reentry") is not True
                or any(correlation.get(flag) is not False for flag in (
                    "native_package_signature_verified",
                    "installed_host_root_authenticated",
                    "systemd_pid1_and_service_verified",
                    "selinux_enforcing_verified",
                    "operator_approval_verified",
                    "package_effects_reconciled",
                    "authorizes_native_marker_removal",
                    "authorizes_package_installation",
                    "authorizes_nginx_reload",
                    "authorizes_host_mutation",
                ))):
            _deny("NATIVE_POSTPACKAGE_CORRELATION_UNVERIFIED")
        _STAGE = "READONLY_PREFLIGHT_AFTER_PACKAGE"
        _verify_readonly_preflight(doc, installed=True)
        _STAGE = "COMPLETE"
        return {
            "schema_version": 1,
            "readonly_preflight_before_after_native_packages": True,
            "readonly_preflight_real_uid_port_capacity_and_preservation": True,
            "native_binary_and_vendor_unit_correlated_in_container": True,
            "native_postpackage_correlation_authorizes_no_reentry": True,
            "status": "DISPOSABLE_JOURNALED_NATIVE_INSTALL_PASS",
            "distribution": distribution,
            "actual_distro_package_transaction": True,
            "real_nginx_syntax_test_passed": True,
            "real_state_bootstrap_durable": True,
            "real_exclusive_lock_held_during_subprocesses": True,
            "pending_journal_survived_package_effects": True,
            "repeated_install_refused_without_reconciliation": True,
            "actual_pending_journal_identity_observed_after_install": True,
            "pending_native_effects_remain_unreconciled": True,
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
