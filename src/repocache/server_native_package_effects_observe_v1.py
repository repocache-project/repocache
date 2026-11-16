"""Read-only native NGINX package-effects reconciliation evidence (#27/#31).

A real APT/DNF package transaction is not rolled back by the atomic JSON
state journal. This observer only classifies the *persisted*, root-owned
pending marker after the already-instrumented transaction. It never removes
the marker, adopts foreign NGINX, executes a package manager, grants a
retry, installs/reloads NGINX or claims successful host acceptance.
"""
from __future__ import annotations

import os
from typing import Any

from repocache.server_stock_nginx_package_owner_v1 import (
    StockNginxPackageOwnerError, inspect_stock_nginx_package_owner,
)
from repocache.server_native_nginx_service_unit_v1 import (
    NginxServiceUnitInspectionError, inspect_native_nginx_unit,
)
from repocache.server_locked_manifest_reconcile_v1 import (
    _verify_current_root_fd,
)
from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, NATIVE_TMP_NAME, MAX_NATIVE_JOURNAL_BYTES,
)
from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS
from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME, JOURNAL_TMP_NAME, STAGE_NAME, ROLLBACK_NAME,
    MAX_JOURNAL_BYTES, MAX_STATE_BYTES, STATE_NAME,
    ProtectedStateStoreError, _canonical, _json, _locked, _read_file,
    _read_journal, _read_state,
)


class NativeEffectsReconciliationError(ValueError):
    """Fixed, redacted refusal; no untrusted paths or package-manager output."""


def _deny(code: str) -> None:
    raise NativeEffectsReconciliationError("NATIVE_EFFECTS_" + code)


def _validate_args(distribution: str, owner_uid: int) -> None:
    if (type(distribution) is not str or distribution not in
            ("debian", "almalinux")
            or type(owner_uid) is not int or owner_uid < 0
            or owner_uid > 2**32 - 2):
        _deny("ARGUMENT_INVALID")


def _expected(distribution: str) -> dict[str, Any]:
    return {
        "journal_schema_version": 1,
        "operation": "fresh-native-nginx-package-install",
        "distribution": distribution,
        "manager": "apt" if distribution == "debian" else "dnf",
        "package": "nginx",
        "expected_state_generation": 0,
        "native_package_effects": "REQUIRES_EXPLICIT_RECONCILIATION",
    }


def _inspect_locked(directory: int, *, owner_uid: int,
                    distribution: str) -> dict[str, Any]:
    """Require exactly one canonical pending native-effects journal.

    This is not a check that a package was installed: a durable marker is
    deliberately written *before* native package effects. It must continue
    blocking installer re-entry regardless of package database observations.
    """
    if _read_journal(directory, owner_uid) is not None:
        _deny("STATE_JOURNAL_PENDING")
    for name, maximum in (
        (JOURNAL_TMP_NAME, MAX_JOURNAL_BYTES),
        (STAGE_NAME, MAX_STATE_BYTES),
        (ROLLBACK_NAME, MAX_STATE_BYTES),
    ):
        if _read_file(directory, name, owner_uid, maximum) is not None:
            _deny("STATE_TRANSACTION_PENDING")
    state, raw = _read_state(directory, owner_uid)
    if state is not None or raw is not None:
        _deny("EXISTING_MANAGED_GENERATION")
    temp = _read_file(
        directory, NATIVE_TMP_NAME, owner_uid, MAX_NATIVE_JOURNAL_BYTES,
    )
    # A temp may exist before or after hardlink publication; both forms are
    # incomplete or interrupted. Never silently discard either inode.
    if temp is not None:
        _deny("PARTIAL_NATIVE_JOURNAL")
    pending = _read_file(
        directory, NATIVE_PENDING_NAME, owner_uid, MAX_NATIVE_JOURNAL_BYTES,
    )
    if pending is None:
        _deny("PENDING_MARKER_MISSING")
    actual = _json(pending, limit=MAX_NATIVE_JOURNAL_BYTES)
    expected = _expected(distribution)
    if (type(actual) is not dict or actual != expected
            or pending != _canonical(expected, limit=MAX_NATIVE_JOURNAL_BYTES)):
        _deny("PENDING_MARKER_IDENTITY_INVALID")
    # Pinned second read under the same protected lock detects intervening
    # changes. No autocompletion and no automatic package retry.
    if _read_file(
        directory, NATIVE_PENDING_NAME, owner_uid, MAX_NATIVE_JOURNAL_BYTES,
    ) != pending:
        _deny("PENDING_MARKER_CHANGED")
    return {
        "schema_version": 1,
        "status": "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION",
        "distribution": distribution,
        "manager": expected["manager"],
        "journal_identity_verified": True,
        "state_generation_observed": 0,
        "pending_native_effects_block_reentry": True,
        "native_package_db_identity_verified": False,
        "native_package_effects_reconciled": False,
        "installed_nginx_systemd_verified": False,
        "selinux_enforcing_verified": False,
        "host_namespace_authenticated": False,
        "operator_authorization_verified": False,
        "authorizes_package_installation": False,
        "authorizes_nginx_reload": False,
        "authorizes_native_marker_removal": False,
        "authorizes_host_mutation": False,
    }


def inspect_native_package_effects_under_root(
    root_fd: int, *, owner_uid: int, distribution: str,
) -> dict[str, Any]:
    """Inspect already-created protected journal in a detached test root.

    The caller supplies a descriptor for an actual filesystem *fixture*;
    this function cannot create a state namespace or perform recovery.
    """
    _validate_args(distribution, owner_uid)
    if type(root_fd) is not int or root_fd < 0:
        _deny("ARGUMENT_INVALID")
    try:
        opened = os.fstat(root_fd)
        live = os.stat("/", follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) == (live.st_dev, live.st_ino):
            _deny("LIVE_ROOT_REQUIRES_CURRENT_NAMESPACE_OBSERVER")
        with _locked(root_fd, owner_uid) as directory:
            return _inspect_locked(
                directory, owner_uid=owner_uid, distribution=distribution,
            )
    except NativeEffectsReconciliationError:
        raise
    except (ProtectedStateStoreError, OSError, ValueError, TypeError):
        _deny("PROTECTED_STATE_UNVERIFIED")


def inspect_current_namespace_native_package_effects(
    *, distribution: str,
) -> dict[str, Any]:
    """Explicit privileged read-only observation of current namespace root.

    Root EUID and matching '/' inode do not attest booted host namespace,
    package provenance, systemd, SELinux, operator intent or installation
    approval. The function has no source for write authority or automatic
    recovery and must never clear an uncertain APT/DNF-effects journal.
    """
    _validate_args(distribution, 0)
    if os.geteuid() != 0:
        _deny("ROOT_READ_ONLY_OBSERVATION_REQUIRED")
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _deny("ROOT_OPEN_REFUSED")
    try:
        try:
            _verify_current_root_fd(root_fd)
            with _locked(root_fd, 0) as directory:
                _verify_current_root_fd(root_fd)
                report = _inspect_locked(
                    directory, owner_uid=0, distribution=distribution,
                )
                _verify_current_root_fd(root_fd)
            _verify_current_root_fd(root_fd)
            return report
        except NativeEffectsReconciliationError:
            raise
        except (ProtectedStateStoreError, OSError, ValueError, TypeError):
            _deny("PROTECTED_STATE_UNVERIFIED")
    finally:
        os.close(root_fd)



def inspect_current_namespace_native_postpackage_candidate(
    *, distribution: str,
) -> dict[str, Any]:
    """Correlate three independent read-only native install observations.

    The native package marker is deliberately observed both before and
    after package DB + vendor-unit reads. The in-between window is NOT a
    root-held transaction; this candidate cannot clear the irreversible
    APT/DNF effects marker or authorize NGINX/service activation. It only
    advances diagnostics of an interrupted or freshly installed package.
    """
    _validate_args(distribution, 0)
    try:
        before = inspect_current_namespace_native_package_effects(
            distribution=distribution
        )
        package = inspect_stock_nginx_package_owner()
        unit = inspect_native_nginx_unit(distribution).to_dict()
        after = inspect_current_namespace_native_package_effects(
            distribution=distribution
        )
    except NativeEffectsReconciliationError:
        raise
    except (StockNginxPackageOwnerError, NginxServiceUnitInspectionError,
            OSError, TypeError, ValueError):
        _deny("NATIVE_FACTS_UNVERIFIED")

    expected_platform = ("debian13" if distribution == "debian"
                         else "almalinux10")
    expected_package = "nginx" if distribution == "debian" else "nginx-core"
    if (type(before) is not dict or type(after) is not dict
            or before != after
            or before.get("status")
               != "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION"
            or before.get("distribution") != distribution
            or before.get("journal_identity_verified") is not True
            or before.get("pending_native_effects_block_reentry") is not True
            or before.get("authorizes_native_marker_removal") is not False):
        _deny("PENDING_JOURNAL_CHANGED")

    if (type(package) is not dict
            or package.get("platform") != expected_platform
            or package.get("package_name") != expected_package
            or package.get("binary_path") != "/usr/sbin/nginx"
            or package.get("status")
               != "READ_ONLY_STOCK_NGINX_PACKAGE_OWNER_OBSERVED"
            or package.get("native_package_db_owner_observed") is not True
            or package.get("native_package_signature_verified") is not False
            or package.get("authorizes_nginx_adoption") is not False):
        _deny("PACKAGE_OWNER_UNVERIFIED")

    if (type(unit) is not dict
            or unit.get("unit_name") != "nginx.service"
            or unit.get("code") != "VENDOR_NGINX_UNIT_OBSERVED"
            or unit.get("vendor_unit_bounded_and_owned") is not True
            or unit.get("native_package_file_ownership_verified") is not False
            or unit.get("authorizes_systemctl") is not False
            or unit.get("authorizes_nginx_reload") is not False
            or type(unit.get("vendor_unit_sha256")) is not str
            or len(unit["vendor_unit_sha256"]) != 64
            or any(ch not in "0123456789abcdef"
                   for ch in unit["vendor_unit_sha256"])):
        _deny("VENDOR_UNIT_UNVERIFIED")

    return {
        "schema_version": 1,
        "status": "NATIVE_POSTPACKAGE_CORRELATION_CANDIDATE_ONLY",
        "distribution": distribution,
        "manager": "apt" if distribution == "debian" else "dnf",
        "package": expected_package,
        "vendor_unit_sha256": unit["vendor_unit_sha256"],
        "pending_journal_stable_across_observations": True,
        "native_package_db_owner_observed": True,
        "native_vendor_unit_shape_observed": True,
        "native_package_signature_verified": False,
        "installed_host_root_authenticated": False,
        "systemd_pid1_and_service_verified": False,
        "selinux_enforcing_verified": False,
        "operator_approval_verified": False,
        "package_effects_reconciled": False,
        "pending_native_effects_block_reentry": True,
        "authorizes_native_marker_removal": False,
        "authorizes_package_installation": False,
        "authorizes_nginx_reload": False,
        "authorizes_host_mutation": False,
    }
