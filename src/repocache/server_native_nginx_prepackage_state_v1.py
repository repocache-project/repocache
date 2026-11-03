"""Read-only generation-zero protected-state inspection before native NGINX (#27).

Reuse the journal validation and *same lock* owned by #31. The full #31 live
manifest reconciliation needs /etc/nginx/conf.d, which is absent on a fresh
host; this separate PRE-PACKAGE observation deliberately does not traverse
that missing directory. It never provisions state paths, mutates files, runs
the package manager or returns an installation/activation capability.
"""
from __future__ import annotations

import os
from typing import Any

from repocache.server_locked_manifest_reconcile_v1 import _verify_current_root_fd
from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, NATIVE_TMP_NAME, MAX_NATIVE_JOURNAL_BYTES,
)
from repocache.server_protected_state_inspect_v1 import _DIRECTORY_FLAGS
from repocache.server_protected_state_store_v1 import (
    JOURNAL_TMP_NAME, JOURNAL_NAME, STAGE_NAME, ROLLBACK_NAME,
    MAX_JOURNAL_BYTES, MAX_STATE_BYTES,
    ProtectedStateStoreError, _locked, _read_file, _read_journal, _read_state,
)


class PrepackageStateInspectionError(ValueError):
    """Fixed, redacted codes; never surface native paths or file contents."""


def _deny(code: str) -> None:
    raise PrepackageStateInspectionError(code)


def _check_under_lock(directory: int) -> dict[str, Any]:
    """Internal testable stage, not an OS-root or operator authentication API."""
    # Journal must be validated before refusal. Never invoke #31 recovery
    # implicitly, and never mistake a pending or interrupted transaction for
    # a clean first installation.
    if _read_journal(directory, 0) is not None:
        _deny("PREPACKAGE_STATE_RECOVERY_REQUIRED")
    # Native APT/DNF effects are not atomically reversible like the #31 JSON.
    # Their distinct persisted marker must block pre-package authorization
    # even if the ordinary #31 state generation is still absent.
    for name in (NATIVE_PENDING_NAME, NATIVE_TMP_NAME):
        if _read_file(directory, name, 0, MAX_NATIVE_JOURNAL_BYTES) is not None:
            _deny("PREPACKAGE_NATIVE_EFFECTS_RECONCILIATION_REQUIRED")
    for name, limit in (
        (JOURNAL_TMP_NAME, MAX_JOURNAL_BYTES),
        (STAGE_NAME, MAX_STATE_BYTES),
        (ROLLBACK_NAME, MAX_STATE_BYTES),
    ):
        if _read_file(directory, name, 0, limit) is not None:
            _deny("PREPACKAGE_STATE_RECOVERY_REQUIRED")
    state, raw = _read_state(directory, 0)
    if state is not None or raw is not None:
        # An existing managed generation is never silently adopted as fresh.
        _deny("PREPACKAGE_EXISTING_STATE_REFUSED")
    # Verify absence again while holding the lock, before returning the
    # snapshot. The observation expires when the context manager exits.
    repeated, repeated_raw = _read_state(directory, 0)
    if repeated is not None or repeated_raw is not None:
        _deny("PREPACKAGE_STATE_CHANGED")
    return {
        "schema_version": 1,
        "status": "LOCKED_PREPACKAGE_STATE_ABSENT",
        "state_generation": 0,
        "manifest_entry_present": False,
        "exclusive_state_lock_held_during_inspection": True,
        "current_namespace_root_path_verified": True,
        "operator_authorization_verified": False,
        "host_root_namespace_authenticated": False,
        "protected_state_directory_preprovisioned": True,
        "nginx_include_directory_required": False,
        "nginx_live_manifest_verified": False,
        "native_transaction_journal_prepared": False,
        "authorizes_write": False,
        "authorizes_package_installation": False,
        "authorizes_nginx_reload": False,
    }


def inspect_current_namespace_prepackage_state() -> dict[str, Any]:
    """Read only fixed #31 state under the current mount namespace's root.

    Root EUID and a pinned / descriptor are not host namespace provenance or
    operator authorization. The state directory and lock MUST already exist,
    be protected, and pass #31's checks; this function never creates them.
    """
    if os.geteuid() != 0:
        _deny("PREPACKAGE_ROOT_PRIVILEGE_REQUIRED")
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _deny("PREPACKAGE_ROOT_OPEN_REFUSED")
    try:
        try:
            _verify_current_root_fd(root_fd)
            with _locked(root_fd, 0) as state_dir:
                _verify_current_root_fd(root_fd)
                result = _check_under_lock(state_dir)
                _verify_current_root_fd(root_fd)
            _verify_current_root_fd(root_fd)
        except PrepackageStateInspectionError:
            raise
        except (ProtectedStateStoreError, OSError, ValueError, TypeError):
            _deny("PREPACKAGE_STATE_UNVERIFIED")
        return result
    finally:
        os.close(root_fd)
