#!/usr/bin/env python3
"""Disposable-container native NGINX syntax failure / journal rehearsal (#27).

Runs real fixed-source APT/DNF in a fresh disposable Docker image, then
deliberately corrupts and restores only that image's stock nginx.conf while
the protected package-effects lock is held. This is NEVER a host installer
or a recovery API. Do not execute against a real host or VM.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

from ci_v06_journaled_native_server_install import (
    _require_disposable_context,
    _verify_pending_lock,
)
from repocache.server_native_nginx_local_boundary_v1 import (
    inspect_native_nginx_local_boundary,
)
from repocache.server_native_nginx_package_journal_v1 import (
    NativePackageJournalError,
    NATIVE_PENDING_NAME,
    _prepare_native_journal_under_root,
    _retain_native_package_journal_lock_under_root,
)
from repocache.server_native_package_effects_observe_v1 import (
    inspect_current_namespace_native_package_effects,
)
from repocache.server_native_nginx_service_unit_v1 import inspect_native_nginx_unit
from repocache.server_protected_namespace_bootstrap_v1 import (
    bootstrap_protected_namespace_under_root,
)
from repocache.server_stock_nginx_package_owner_v1 import (
    inspect_stock_nginx_package_owner,
)
from smoke_server_native_nginx_container_install import (
    ContainerInstallRehearsalError, run_rehearsal,
)

_ROOT = Path(__file__).resolve().parents[1]
_STATE = Path("/var/lib/repocache/server")
_NGINX_CONFIG = Path("/etc/nginx/nginx.conf")
_BAD_DIRECTIVE = b"repocache_fixture_invalid_directive;\n"
_EXPECTED_FAILURE = "CONTAINER_NGINX_CONFIG_VALIDATION_FAILED"


class NativeSyntaxFailureTestError(ValueError):
    """Fixed redacted failure identifiers only."""


def _deny(code: str) -> None:
    raise NativeSyntaxFailureTestError(code)


def _restore_after_real_syntax_failure(
    command: list[str], kwargs: dict[str, Any],
) -> bytes:
    """Inject a real nginx -t rejection, then restore the same inode bytes.

    Must only be reachable after _require_disposable_context has refused all
    existing NGINX footprints, under the durable journal and retained lock.
    """
    if command != ["/usr/sbin/nginx", "-t", "-q"]:
        _deny("UNEXPECTED_SYNTAX_COMMAND")
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(_NGINX_CONFIG, flags)
    except OSError:
        _deny("INSTALLED_NGINX_CONFIG_MISSING")
    try:
        initial = os.fstat(descriptor)
        named = os.stat(_NGINX_CONFIG, follow_symlinks=False)
        if (not stat.S_ISREG(initial.st_mode)
                or initial.st_uid != 0
                or initial.st_nlink != 1
                or initial.st_size <= 0 or initial.st_size > 512 * 1024
                or stat.S_IMODE(initial.st_mode) & 0o022
                or (initial.st_dev, initial.st_ino)
                   != (named.st_dev, named.st_ino)):
            _deny("INSTALLED_NGINX_CONFIG_UNSAFE")
        original = os.read(descriptor, 512 * 1024 + 1)
        if len(original) != initial.st_size:
            _deny("INSTALLED_NGINX_CONFIG_CHANGED")
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.write(descriptor, _BAD_DIRECTIVE)
        os.ftruncate(descriptor, len(_BAD_DIRECTIVE))
        os.fsync(descriptor)
        try:
            completed = subprocess.run(command, **kwargs)
        finally:
            # Only undo this CI fixture's own bytes. Never repair or replace
            # an actual installed host NGINX configuration.
            os.lseek(descriptor, 0, os.SEEK_SET)
            view = memoryview(original)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    _deny("SYNTAX_FIXTURE_RESTORE_FAILED")
                view = view[written:]
            os.ftruncate(descriptor, len(original))
            os.fsync(descriptor)
        if completed.returncode == 0:
            _deny("INVALID_NGINX_SYNTAX_ACCEPTED")
        after = os.fstat(descriptor)
        named_after = os.stat(_NGINX_CONFIG, follow_symlinks=False)
        if ((after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode)
            != (initial.st_dev, initial.st_ino, initial.st_uid, initial.st_gid,
                initial.st_mode)
                or (after.st_dev, after.st_ino) != (
                    named_after.st_dev, named_after.st_ino)):
            _deny("INSTALLED_NGINX_CONFIG_REPLACED")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.read(descriptor, len(original) + 1) != original:
            _deny("SYNTAX_FIXTURE_RESTORE_FAILED")
        return hashlib.sha256(original).digest()
    finally:
        os.close(descriptor)


def run() -> dict[str, Any]:
    """Execute once, in an empty disposable distro container only."""
    distribution, os_release = _require_disposable_context()
    document = json.loads(
        (_ROOT / "docs/examples/server-install-v1.json").read_text("utf-8"),
    )
    root_fd = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        bootstrap = bootstrap_protected_namespace_under_root(root_fd, owner_uid=0)
        if bootstrap["status"] != "FRESH_PROTECTED_LOCK_DURABLE":
            _deny("FRESH_LOCK_NOT_DURABLE")
        baseline = inspect_native_nginx_local_boundary(
            os_release=os_release,
            python_version=(sys.version_info.major, sys.version_info.minor),
            document=document,
        ).to_dict()
        if (baseline["code"] != "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED"
                or baseline["authorizes_package_transaction"] is not False):
            _deny("FRESH_OWNERSHIP_NOT_OBSERVED")
        lock_observations: list[str] = []
        injected: list[bytes] = []

        def runner(command: list[str], **kwargs: Any):
            _verify_pending_lock(distribution, lock_observations)
            if command == ["/usr/sbin/nginx", "-t", "-q"]:
                if injected:
                    _deny("SYNTAX_FAILURE_INJECTED_TWICE")
                digest = _restore_after_real_syntax_failure(command, kwargs)
                injected.append(digest)
                # The native runner already attempted real syntax validation,
                # and _run must translate its nonzero status to a refusal.
                return subprocess.CompletedProcess(command, 1, "", "")
            return subprocess.run(command, **kwargs)

        with _retain_native_package_journal_lock_under_root(
            root_fd, owner_uid=0, distribution=distribution,
            allow_native_package_parent_changes=True,
        ) as prepared:
            if (prepared["status"] != "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
                    or prepared["authorizes_package_installation"] is not False):
                _deny("NATIVE_JOURNAL_NOT_DURABLE")
            try:
                run_rehearsal(distribution=distribution, runner=runner)
            except ContainerInstallRehearsalError as exc:
                if str(exc) != _EXPECTED_FAILURE:
                    _deny("WRONG_PACKAGE_FAILURE_STAGE")
            else:
                _deny("SYNTAX_FAILURE_DID_NOT_ABORT_INSTALL")
        if (len(lock_observations) < 4
                or any(x != "CONTENDED" for x in lock_observations)
                or len(injected) != 1
                or not (_STATE / NATIVE_PENDING_NAME).is_file()):
            _deny("FAILED_INSTALL_LOCK_OR_MARKER_MISSING")

        # Actual native installation succeeded before the deliberate
        # verification failure; do not claim package rollback.
        installed = inspect_stock_nginx_package_owner()
        vendor = inspect_native_nginx_unit(distribution)
        if (installed["native_package_db_owner_observed"] is not True
                or vendor.code != "VENDOR_NGINX_UNIT_OBSERVED"):
            _deny("NATIVE_PACKAGE_POSTFAILURE_UNVERIFIED")
        restored = subprocess.run(
            ["/usr/sbin/nginx", "-t", "-q"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, check=False, timeout=15,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, cwd="/",
        )
        if restored.returncode != 0:
            _deny("RESTORED_NGINX_SYNTAX_INVALID")
        if hashlib.sha256(_NGINX_CONFIG.read_bytes()).digest() != injected[0]:
            _deny("RESTORED_NGINX_BYTES_CHANGED")
        effects = inspect_current_namespace_native_package_effects(
            distribution=distribution,
        )
        if (effects["status"] != "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION"
                or effects["pending_native_effects_block_reentry"] is not True
                or effects["native_package_effects_reconciled"] is not False
                or effects["authorizes_native_marker_removal"] is not False):
            _deny("PENDING_EFFECTS_UNVERIFIED")
        try:
            _prepare_native_journal_under_root(
                root_fd, owner_uid=0, distribution=distribution,
            )
        except NativePackageJournalError as exc:
            if str(exc) != "NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED":
                _deny("FAILED_INSTALL_REENTRY_WRONG_REFUSAL")
        else:
            _deny("FAILED_INSTALL_REENTRY_ALLOWED")
        if not (_STATE / NATIVE_PENDING_NAME).is_file():
            _deny("PENDING_EFFECTS_MARKER_DISAPPEARED")
        return {
            "schema_version": 1,
            "status": "DISPOSABLE_NATIVE_SYNTAX_FAILURE_RECOVERY_PASS",
            "distribution": distribution,
            "actual_native_package_installation": True,
            "real_invalid_nginx_syntax_refused": True,
            "stock_nginx_config_restored_after_fixture": True,
            "root_owned_pending_effects_marker_preserved": True,
            "exclusive_lock_retained_during_native_commands": True,
            "retry_blocked_until_independent_reconciliation": True,
            "booted_systemd_tested": False,
            "selinux_enforcing_tested": False,
            "native_package_effects_reconciled": False,
            "real_host_installation_authorized": False,
            "nginx_service_reload_authorized": False,
        }
    finally:
        os.close(root_fd)


def main() -> int:
    try:
        result = run()
    except NativeSyntaxFailureTestError as exc:
        result = {"schema_version": 1, "status": "FAIL", "code": str(exc),
                  "real_host_installation_authorized": False}
    except Exception:
        result = {"schema_version": 1, "status": "FAIL",
                  "code": "NATIVE_SYNTAX_FAILURE_REHEARSAL_UNVERIFIED",
                  "real_host_installation_authorized": False}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "DISPOSABLE_NATIVE_SYNTAX_FAILURE_RECOVERY_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
