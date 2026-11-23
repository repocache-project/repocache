"""Private durable native NGINX package-effects journal (#27/#31).

Unlike #31's atomic state JSON journal, APT/DNF have non-atomic effects.
Preparing a transaction persists a pending marker under the SAME #31 state
lock. An interrupted/ambiguous marker remains a hard stop. The signed native
installer can explicitly complete a verified uninterrupted manager operation
under that retained lock; no observer, socket caller or fixture API is thereby
granted host-installation or automatic retry/recovery authority.
"""
from __future__ import annotations

from typing import Any, Callable, Iterator
from contextlib import contextmanager
import hashlib
import os
import re
import stat

from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME, JOURNAL_TMP_NAME, ROLLBACK_NAME, STAGE_NAME, LOCK_NAME,
    MAX_JOURNAL_BYTES, MAX_STATE_BYTES,
    ProtectedStateStoreError,
    _canonical, _json, _locked, _read_file, _read_journal, _read_state,
    _write_exclusive, _unlink_known,
)

NATIVE_PENDING_NAME = ".native-nginx-v1.pending"
NATIVE_TMP_NAME = ".native-nginx-v1.pending-tmp"
MAX_NATIVE_JOURNAL_BYTES = 2048
NATIVE_COMPLETE_NAME = ".native-nginx-v1.completed"
MAX_NATIVE_COMPLETE_BYTES = 2048
_NATIVE_MANAGERS = {"debian": "apt", "almalinux": "dnf"}


class NativePackageJournalError(ValueError):
    """Fixed, redacted refusal codes, never untrusted package-manager output."""


def _deny(code: str) -> None:
    raise NativePackageJournalError(code)


def _read_completed_native_install_under_lock(
    directory: int, *, owner_uid: int, distribution: str | None = None,
) -> dict[str, Any] | None:
    """Validate a root-owned completion receipt, never a host trust token."""
    raw = _read_file(directory, NATIVE_COMPLETE_NAME,
                     owner_uid, MAX_NATIVE_COMPLETE_BYTES)
    if raw is None:
        return None
    try:
        value = _json(raw, limit=MAX_NATIVE_COMPLETE_BYTES)
        if (type(value) is not dict or set(value) != {
            "schema_version", "status", "distribution", "manager",
            "pending_sha256", "vendor_unit_sha256",
            "native_package_file_integrity_verified",
            "publisher_artifact_verified", "booted_native_service_verified",
        } or type(value["schema_version"]) is not int
                or value["schema_version"] != 1
                or value["status"] !=
                   "NATIVE_PACKAGE_EFFECTS_COMPLETED_AFTER_LOCKED_INSTALL"
                or type(value["distribution"]) is not str
                or value["distribution"] not in _NATIVE_MANAGERS
                or (distribution is not None
                    and value["distribution"] != distribution)
                or value["manager"] != _NATIVE_MANAGERS[value["distribution"]]
                or any(type(value[k]) is not str or len(value[k]) != 64
                       or any(ch not in "0123456789abcdef" for ch in value[k])
                       for k in ("pending_sha256", "vendor_unit_sha256"))
                or value["native_package_file_integrity_verified"] is not True
                or value["publisher_artifact_verified"] is not False
                or value["booted_native_service_verified"] is not False
                or _canonical(value, limit=MAX_NATIVE_COMPLETE_BYTES) != raw):
            _deny("NATIVE_COMPLETION_RECEIPT_INVALID")
        return value
    except NativePackageJournalError:
        raise
    except (ProtectedStateStoreError, TypeError, ValueError, KeyError):
        _deny("NATIVE_COMPLETION_RECEIPT_INVALID")


def _no_pending_native_effects(directory: int, owner_uid: int) -> None:
    """Hard-block both published and orphaned native package effects markers."""
    for name in (NATIVE_PENDING_NAME, NATIVE_TMP_NAME, NATIVE_COMPLETE_NAME):
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
    # No prior v2 state, WAL, staged administrator intent or arbitrary file
    # can be adopted as an initial NGINX package install. The one permitted
    # installed worker-placement receipt is immutable, empty, single-linked
    # and root-owned; its contents and release signing are checked by the
    # authenticated caller separately.
    worker_marker = re.compile(
        r"\.native-worker-placement\.complete-[0-9a-f]{64}\Z", re.ASCII,
    )
    owner_gid = os.fstat(directory).st_gid
    for entry in os.listdir(directory):
        if entry == LOCK_NAME:
            continue
        if worker_marker.fullmatch(entry) is not None:
            info = os.stat(entry, dir_fd=directory, follow_symlinks=False)
            if (stat.S_ISREG(info.st_mode) and info.st_uid == owner_uid
                    and info.st_gid == owner_gid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0):
                continue
        _deny("NATIVE_FOREIGN_PROTECTED_STATE")
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


def _complete_native_install_after_verified_manager_under_lock(
    directory: int, *, owner_uid: int, distribution: str,
) -> dict[str, Any]:
    """Commit audit only inside an uninterrupted trusted package-manager scope.

    The original caller MUST have already proved the fixed signed-source
    APT/DNF transaction completed successfully without releasing the lock.
    Reobservation alone is NOT package authorization; this private operation
    is not exposed by the service or root-worker protocol.
    """
    if (type(distribution) is not str
            or distribution not in _NATIVE_MANAGERS
            or type(owner_uid) is not int or owner_uid < 0):
        _deny("NATIVE_COMPLETION_ARGUMENT_INVALID")
    # Imported lazily to avoid a circular import. The strict, pure candidate
    # gate is also reused by the independent read-only post-package observer.
    from repocache.server_native_package_effects_observe_v1 import (
        _collect_postpackage_facts_while_locked,
        _validate_native_postpackage_facts,
        NativeEffectsReconciliationError,
    )
    try:
        facts = _collect_postpackage_facts_while_locked(
            directory, owner_uid=owner_uid, distribution=distribution,
        )
        result = _validate_native_postpackage_facts(distribution, *facts)
        if (result["native_package_file_integrity_verified"] is not True
                or result["pending_native_effects_block_reentry"] is not True
                or result["authorizes_native_marker_removal"] is not False):
            _deny("NATIVE_COMPLETION_AUDIT_UNVERIFIED")
        marker = _read_file(directory, NATIVE_PENDING_NAME, owner_uid,
                            MAX_NATIVE_JOURNAL_BYTES)
        if marker is None or _read_file(directory, NATIVE_TMP_NAME,
                                        owner_uid, MAX_NATIVE_JOURNAL_BYTES) is not None:
            _deny("NATIVE_COMPLETION_JOURNAL_CHANGED")
        if _read_file(directory, NATIVE_COMPLETE_NAME, owner_uid,
                      MAX_NATIVE_COMPLETE_BYTES) is not None:
            _deny("NATIVE_COMPLETION_ALREADY_PRESENT")
        completed = _canonical({
            "schema_version": 1,
            "status": "NATIVE_PACKAGE_EFFECTS_COMPLETED_AFTER_LOCKED_INSTALL",
            "distribution": distribution,
            "manager": _NATIVE_MANAGERS[distribution],
            "pending_sha256": hashlib.sha256(marker).hexdigest(),
            "vendor_unit_sha256": result["vendor_unit_sha256"],
            "native_package_file_integrity_verified": True,
            # This receipt does not attest publisher signing, systemd or SELinux.
            "publisher_artifact_verified": False,
            "booted_native_service_verified": False,
        }, limit=MAX_NATIVE_COMPLETE_BYTES)
        # Durable receipt BEFORE clearing the old marker. On a crash before
        # the final fsynced unlink, BOTH remain, and the old pending marker
        # continues to block staging/re-entry. Never auto-recover ambiguity.
        _write_exclusive(directory, NATIVE_COMPLETE_NAME, completed,
                         owner_uid, MAX_NATIVE_COMPLETE_BYTES)
        _unlink_known(directory, NATIVE_PENDING_NAME, marker,
                      owner_uid, MAX_NATIVE_JOURNAL_BYTES)
        return {
            "status": "NATIVE_PACKAGE_EFFECTS_COMPLETED_AFTER_LOCKED_INSTALL",
            "native_package_effects_reconciled": True,
            "publisher_artifact_verified": False,
            "booted_native_service_verified": False,
            "authorizes_service_activation": False,
            "authorizes_package_installation": False,
        }
    except NativePackageJournalError:
        raise
    except (NativeEffectsReconciliationError, ProtectedStateStoreError,
            OSError, ValueError, TypeError):
        _deny("NATIVE_COMPLETION_AUDIT_UNVERIFIED")


@contextmanager
def _retain_native_package_journal_lock_under_root(
    root_fd: int, *, owner_uid: int, distribution: str,
    inject_fault: Callable[[str], None] | None = None,
    allow_native_package_parent_changes: bool = False,
    expose_audited_completion: bool = False,
    preflight_before_journal: Callable[[], None] | None = None,
) -> Iterator[dict[str, Any]]:
    """Private same-lock scope for the authenticated installer and CI fixtures.

    The marker is durably recorded BEFORE yielding; exiting never silently
    cleans a possibly irreversible APT/DNF package effect. The caller is not
    authenticated and no package command, root helper or service is exposed.

    Only an explicitly reviewed native package-effects scope may set the
    shared-parent-drift flag: APT/DNF can change /var or /var/lib metadata
    without changing their fixed ownership and pinned inodes. The default
    short-lived preparer remains strict. This flag NEVER authenticates root.

    An optional internal refusal-only preflight runs under the same lock,
    BEFORE the first durable package-effects marker. It never grants authority;
    already-foreign hosts must not be left with a spurious pending journal.
    Post-WAL identity checks still detect concurrent changes before effects.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or owner_uid < 0
            or type(distribution) is not str
            or distribution not in _NATIVE_MANAGERS
            or (inject_fault is not None and not callable(inject_fault))
            or type(allow_native_package_parent_changes) is not bool
            or type(expose_audited_completion) is not bool
            or (preflight_before_journal is not None
                and not callable(preflight_before_journal))):
        _deny("NATIVE_JOURNAL_ARGUMENT_INVALID")
    try:
        with _locked(
            root_fd, owner_uid,
            allow_native_package_parent_changes=allow_native_package_parent_changes,
        ) as directory:
            # Under this exact lock, a previous interrupted native install
            # takes precedence over any mask or host-footprint probe. In
            # particular, our own persistent nginx.service mask after a crash
            # must not be misclassified as a fresh foreign service. Refuse
            # before invoking the preflight and without changing the journal.
            if preflight_before_journal is not None:
                _no_pending_native_effects(directory, owner_uid)
            # A genuinely fresh foreign host is still refused before the
            # first durable marker or any package/systemd side effect.
            if (preflight_before_journal is not None
                    and preflight_before_journal() is not None):
                _deny("NATIVE_JOURNAL_PREFLIGHT_INVALID")
            try:
                prepared = _prepare_native_journal_under_lock(
                    directory, owner_uid=owner_uid,
                    distribution=distribution, inject_fault=inject_fault,
                )
            except NativePackageJournalError:
                raise
            except (ProtectedStateStoreError, OSError, ValueError, TypeError):
                _deny("NATIVE_JOURNAL_STATE_UNVERIFIED")
            active = True
            finished = False

            def finish_same_locked_native_package_transaction() -> dict[str, Any]:
                nonlocal finished
                if not active or finished:
                    _deny("NATIVE_COMPLETION_SCOPE_EXPIRED")
                finished = True
                return _complete_native_install_after_verified_manager_under_lock(
                    directory, owner_uid=owner_uid, distribution=distribution,
                )

            if expose_audited_completion:
                # Only a first-party, authenticated native installer may
                # invoke this callback after the fixed package manager and
                # signed-source checks have completed IN THIS SAME scope.
                # It is not returned over CLI/socket/protocol and cannot
                # be replayed after the exclusive lock is released.
                prepared["_complete_under_lock"] = finish_same_locked_native_package_transaction
            try:
                yield prepared
            finally:
                active = False
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
