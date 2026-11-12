"""Fixture-only durable native NGINX package-effects blocker (#27).

Unlike #31's atomic state JSON journal, APT/DNF have non-atomic effects.
Preparing a package transaction must first persist an unambiguous pending
marker under the *same* #31 state lock. An interrupted or ambiguous marker
is a hard stop requiring a separately designed audited recovery. There is
no privileged host entrypoint, no automatic cleanup, and no package execution.
"""
from __future__ import annotations

from typing import Any, Callable, Iterator
from contextlib import contextmanager
import os

from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME, JOURNAL_TMP_NAME, ROLLBACK_NAME, STAGE_NAME,
    MAX_JOURNAL_BYTES, MAX_STATE_BYTES,
    ProtectedStateStoreError,
    _canonical, _locked, _read_file, _read_journal, _read_state,
    _write_exclusive,
)

NATIVE_PENDING_NAME = ".native-nginx-v1.pending"
NATIVE_TMP_NAME = ".native-nginx-v1.pending-tmp"
MAX_NATIVE_JOURNAL_BYTES = 2048
_NATIVE_MANAGERS = {"debian": "apt", "almalinux": "dnf"}


class NativePackageJournalError(ValueError):
    """Fixed, redacted refusal codes, never untrusted package-manager output."""


def _deny(code: str) -> None:
    raise NativePackageJournalError(code)


def _no_pending_native_effects(directory: int, owner_uid: int) -> None:
    """Hard-block both published and orphaned native package effects markers."""
    for name in (NATIVE_PENDING_NAME, NATIVE_TMP_NAME):
        if _read_file(
            directory, name, owner_uid, MAX_NATIVE_JOURNAL_BYTES
        ) is not None:
            _deny("NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED")


def _prepare_native_journal_under_lock(
    directory: int, *, owner_uid: int, distribution: str,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Persist fixed native package effects marker while #31 lock is held.

    Internal only: no direct caller is allowed to treat a journal as
    package trust, operator authentication or install authorization.
    """
    # Refuse ALL #31 persisted or interrupted state. Generation zero
    # and the default NGINX include are not ownership authorization.
    if _read_journal(directory, owner_uid) is not None:
        _deny("NATIVE_STATE_RECOVERY_REQUIRED")
    for name, limit in (
        (JOURNAL_TMP_NAME, MAX_JOURNAL_BYTES),
        (STAGE_NAME, MAX_STATE_BYTES),
        (ROLLBACK_NAME, MAX_STATE_BYTES),
    ):
        if _read_file(directory, name, owner_uid, limit) is not None:
            _deny("NATIVE_STATE_RECOVERY_REQUIRED")
    state, raw = _read_state(directory, owner_uid)
    if state is not None or raw is not None:
        _deny("NATIVE_EXISTING_STATE_REFUSED")
    _no_pending_native_effects(directory, owner_uid)
    content = _canonical({
        "journal_schema_version": 1,
        "operation": "fresh-native-nginx-package-install",
        "distribution": distribution,
        "manager": _NATIVE_MANAGERS[distribution],
        "package": "nginx",
        "expected_state_generation": 0,
        # Never assert no effects after a crash: an interrupted apt/dnf
        # command can leave partially-installed host packages.
        "native_package_effects": "REQUIRES_EXPLICIT_RECONCILIATION",
    }, limit=MAX_NATIVE_JOURNAL_BYTES)
    # An orphaned temp also blocks future attempts. Never treat it as
    # proof the package manager was not invoked.
    _write_exclusive(
        directory, NATIVE_TMP_NAME, content,
        owner_uid, MAX_NATIVE_JOURNAL_BYTES,
    )
    if inject_fault is not None:
        inject_fault("native_journal_temp_durable")
    # Hard-link publication refuses replacement of a concurrent
    # existing pending inode; then unlink the temp and fsync again.
    # A crash between these two fsyncs is *still a hard stop*.
    try:
        os.link(NATIVE_TMP_NAME, NATIVE_PENDING_NAME,
                src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False)
        os.fsync(directory)
    except OSError:
        _deny("NATIVE_JOURNAL_PUBLISH_REFUSED")
    if inject_fault is not None:
        inject_fault("native_journal_link_durable")
    try:
        os.unlink(NATIVE_TMP_NAME, dir_fd=directory)
        os.fsync(directory)
    except OSError:
        _deny("NATIVE_JOURNAL_CLEANUP_UNVERIFIED")
    if inject_fault is not None:
        inject_fault("native_journal_published")
    if (_read_file(
        directory, NATIVE_PENDING_NAME, owner_uid,
        MAX_NATIVE_JOURNAL_BYTES,
    ) != content or _read_file(
        directory, NATIVE_TMP_NAME, owner_uid,
        MAX_NATIVE_JOURNAL_BYTES,
    ) is not None):
        _deny("NATIVE_JOURNAL_CHANGED")
    return {
        "journal_schema_version": 1,
        "status": "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE",
        "distribution": distribution,
        "native_package_effects_reconciled": False,
        "operator_authorization_authenticated": False,
        "native_package_signature_verified": False,
        "package_transaction_executed": False,
        "nginx_activation_performed": False,
        "authorizes_package_installation": False,
        "authorizes_nginx_reload": False,
    }


@contextmanager
def _retain_native_package_journal_lock_under_root(
    root_fd: int, *, owner_uid: int, distribution: str,
    inject_fault: Callable[[str], None] | None = None,
) -> Iterator[dict[str, Any]]:
    """Fixture-only same-lock scope spanning the future native transaction.

    The marker is durably recorded BEFORE yielding; exiting never silently
    cleans a possibly irreversible APT/DNF package effect. The caller is not
    authenticated and no package command, root helper or service is exposed.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or owner_uid < 0
            or type(distribution) is not str
            or distribution not in _NATIVE_MANAGERS
            or (inject_fault is not None and not callable(inject_fault))):
        _deny("NATIVE_JOURNAL_ARGUMENT_INVALID")
    try:
        with _locked(root_fd, owner_uid) as directory:
            try:
                prepared = _prepare_native_journal_under_lock(
                    directory, owner_uid=owner_uid,
                    distribution=distribution, inject_fault=inject_fault,
                )
            except NativePackageJournalError:
                raise
            except (ProtectedStateStoreError, OSError, ValueError, TypeError):
                _deny("NATIVE_JOURNAL_STATE_UNVERIFIED")
            yield prepared
    except NativePackageJournalError:
        raise
    except (ProtectedStateStoreError, OSError, TypeError):
        _deny("NATIVE_JOURNAL_STATE_UNVERIFIED")


def _prepare_native_journal_under_root(
    root_fd: int, *, owner_uid: int, distribution: str,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Original fixture-only prepare-only API; no package execution.

    The stronger _retain_native_package_journal_lock_under_root context
    allows a future independently authenticated fixed APT/DNF transaction
    to retain the protected lock until the package operation completes.
    Neither function authorizes real root installations or service activation.
    """
    with _retain_native_package_journal_lock_under_root(
        root_fd, owner_uid=owner_uid, distribution=distribution,
        inject_fault=inject_fault,
    ) as report:
        return report
