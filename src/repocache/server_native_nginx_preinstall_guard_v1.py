"""Revalidate fresh NGINX before each native package effect under #31 lock.

A read-only, non-authorizing guard for the gap between signed metadata
refresh and native APT/DNF install (#27). An earlier successful fresh-host
snapshot is never reusable. The actual owner of a future privileged runner
must still authenticate host root, signed artifact and operator, hold the
proper lock, check transaction provenance, and prevent conflicting service
creation across the remaining race window. No CLI or installer is exposed.
"""
from __future__ import annotations

import fcntl
import os
import stat
from typing import Any, Callable

from repocache.server_native_nginx_ownership_v1 import (
    inspect_fresh_nginx_footprint,
)
from repocache.server_native_package_effects_observe_v1 import (
    NativeEffectsReconciliationError, _inspect_locked,
)
from repocache.server_protected_state_inspect_v1 import _FIXED_STATE_ROOT
from repocache.server_protected_state_store_v1 import (
    LOCK_NAME, ProtectedStateStoreError,
)

_LOCK_FLAGS = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
               getattr(os, "O_CLOEXEC", 0))


class NativeNginxPreinstallGuardError(ValueError):
    """Only fixed redacted refusal classes, never a PID or host path."""


def _deny(code: str) -> None:
    raise NativeNginxPreinstallGuardError("NATIVE_PREINSTALL_" + code)


def _require_externally_held_lock(directory_fd: int, uid: int) -> None:
    """Check that the exact protected lock is actually held and single-linked.

    This demonstrates contention from a separately opened file description,
    not *who* holds it, not signed host identity and not operator permission.
    """
    info = os.fstat(directory_fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) & 0o022):
        _deny("DIRECTORY_UNTRUSTED")
    fd = os.open(LOCK_NAME, _LOCK_FLAGS, dir_fd=directory_fd)
    try:
        pinned = os.fstat(fd)
        named = os.stat(
            LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False,
        )
        if (not stat.S_ISREG(pinned.st_mode)
                or pinned.st_dev != info.st_dev
                or pinned.st_uid != uid
                or pinned.st_gid != info.st_gid
                or pinned.st_nlink != 1
                or stat.S_IMODE(pinned.st_mode) != 0o600
                or pinned.st_size != 0
                or (pinned.st_dev, pinned.st_ino, pinned.st_mode,
                    pinned.st_uid, pinned.st_gid, pinned.st_nlink)
                   != (named.st_dev, named.st_ino, named.st_mode,
                       named.st_uid, named.st_gid, named.st_nlink)):
            _deny("LOCK_IDENTITY_UNVERIFIED")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            _deny("LOCK_NOT_HELD")
    finally:
        os.close(fd)


def recheck_fresh_native_nginx_before_manager(
    directory_fd: int, *, owner_uid: int, distribution: str,
    os_release: str, python_version: tuple[int, int],
    document: dict[str, Any],
    lstat: Callable[[str], os.stat_result] = os.lstat,
    process_probe: Callable[[], str] | None = None,
) -> dict[str, Any]:
    """Reject late NGINX and native-journal drift immediately before APT/DNF.

    Directory descriptor is that yielded by the verified #31 protected lock.
    It is NOT an authority token: a foreign process can race the final scan
    and a contended lock does not establish who holds it. The caller must
    treat this as a necessary fail-closed check, not an installation grant.
    """
    if (type(directory_fd) is not int or directory_fd < 0
            or type(owner_uid) is not int or owner_uid < 0
            or owner_uid > 2**32 - 2
            or type(distribution) is not str
            or distribution not in ("debian", "almalinux")
            or not callable(lstat)
            or (process_probe is not None and not callable(process_probe))):
        _deny("ARGUMENT_INVALID")
    try:
        _require_externally_held_lock(directory_fd, owner_uid)
        first = _inspect_locked(
            directory_fd, owner_uid=owner_uid,
            distribution=distribution,
        )
        if (first.get("status")
                != "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION"
                or first.get("journal_identity_verified") is not True
                or first.get("pending_native_effects_block_reentry") is not True
                or first.get("authorizes_native_marker_removal") is not False):
            _deny("JOURNAL_UNVERIFIED")

        # The protected state root is *known to exist* in this transaction.
        # Ignore exactly this formerly foreign marker, but NOT the other
        # NGINX paths or process names. Its actual state and lock are
        # separately checked above and again after the fresh scan.
        def observed_marker(path: str) -> os.stat_result:
            if path == _FIXED_STATE_ROOT:
                raise FileNotFoundError(path)
            return lstat(path)

        footprint = inspect_fresh_nginx_footprint(
            os_release=os_release,
            python_version=python_version,
            document=document,
            lstat=observed_marker,
            process_probe=process_probe,
        )
        if footprint.distribution != distribution:
            _deny("DISTRIBUTION_MISMATCH")
        if not footprint.allows_metadata_probe:
            # The selected code is always from a fixed reviewed allowlist.
            # The process scanner never exposes a PID or cmdline.
            _deny("FRESH_" + footprint.code)

        second = _inspect_locked(
            directory_fd, owner_uid=owner_uid,
            distribution=distribution,
        )
        _require_externally_held_lock(directory_fd, owner_uid)
        if second != first:
            _deny("JOURNAL_CHANGED_DURING_SCAN")
    except NativeNginxPreinstallGuardError:
        raise
    except (NativeEffectsReconciliationError, ProtectedStateStoreError,
            OSError, TypeError, ValueError, OverflowError):
        _deny("PROTECTED_STATE_OR_PROCESS_UNVERIFIED")

    return {
        "schema_version": 1,
        "status": "FRESH_NATIVE_PREINSTALL_RECHECK_OBSERVED_ONLY",
        "distribution": distribution,
        "external_lock_contention_observed": True,
        "protected_pending_journal_unchanged": True,
        "late_foreign_nginx_process_not_observed": True,
        "late_nginx_file_conflict_not_observed": True,
        "installed_host_root_authenticated": False,
        "signed_native_payload_authenticated": False,
        "operator_permission_authenticated": False,
        "transaction_cannot_be_raced": False,
        "authorizes_native_package_installation": False,
        "authorizes_marker_removal": False,
        "authorizes_nginx_reload": False,
        "authorizes_host_mutation": False,
    }
