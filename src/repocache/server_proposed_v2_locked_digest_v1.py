"""Read-only locked whole-state v2 digest and generation check (#31).

This is a necessary prerequisite only, not a signed administrator approval,
root-control dispatcher, host attestation, privileged state writer or
post-lock authorization lease.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any

from repocache.server_install_v1 import MAX_INT
from repocache.server_locked_manifest_reconcile_v1 import (
    LockedManifestInspectionError, _DIRECTORY_FLAGS, _verify_current_root_fd,
)
from repocache.server_protected_state_store_v1 import (
    ProtectedStateStoreError, _locked,
)
from repocache.server_proposed_state_v2_store import (
    ProposedV2PersistenceError, V2_STATE, _legacy_refusal, _pending, _read_v2,
)


class LockedV2DigestError(ValueError):
    """Static redacted failure codes; never report host paths or state."""


def _deny(code: str) -> None:
    raise LockedV2DigestError("LOCKED_V2_DIGEST_" + code)


def _state_inode(directory: int) -> tuple[int, ...]:
    try:
        info = os.stat(V2_STATE, dir_fd=directory, follow_symlinks=False)
    except OSError:
        _deny("STATE_METADATA_UNAVAILABLE")
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_ctime_ns, info.st_mtime_ns,
    )


def _inspect_under_root(
    root_fd: int, *, owner_uid: int,
    expected_generation: int, expected_state_sha256: str,
) -> dict[str, Any]:
    """PRIVATE fixture-FD test seam; no result survives lock as permission.

    Expected hash is an untrusted equality assertion; it is never a signed
    operator intent or an authority to adopt any repository configuration.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or owner_uid < 0
            or type(expected_generation) is not int
            or not 1 <= expected_generation <= MAX_INT
            or type(expected_state_sha256) is not str
            or len(expected_state_sha256) != 64
            or any(c not in "0123456789abcdef"
                   for c in expected_state_sha256)):
        _deny("ARGUMENT_INVALID")
    try:
        with _locked(root_fd, owner_uid) as directory:
            _legacy_refusal(directory, owner_uid)
            if _pending(directory, owner_uid):
                _deny("RECOVERY_REQUIRED")
            old, raw = _read_v2(directory, owner_uid)
            if old is None or raw is None:
                _deny("STATE_ABSENT")
            original_inode = _state_inode(directory)
            if old["state_generation"] != expected_generation:
                _deny("STALE_GENERATION")
            if hashlib.sha256(raw).hexdigest() != expected_state_sha256:
                _deny("STATE_DIGEST_MISMATCH")
            # An independent root actor can ignore flock. Repeat pending,
            # canonical bytes AND inode/ctime metadata under the same lock.
            _legacy_refusal(directory, owner_uid)
            if _pending(directory, owner_uid):
                _deny("RECOVERY_REQUIRED")
            current, current_raw = _read_v2(directory, owner_uid)
            if (current != old or current_raw != raw
                    or _state_inode(directory) != original_inode):
                _deny("STATE_CHANGED_DURING_INSPECTION")
            return {
                "schema_version": 1,
                "status": "LOCKED_PERSISTED_V2_DIGEST_OBSERVED_ONLY",
                "state_generation": expected_generation,
                "canonical_v2_snapshot_observed": True,
                "whole_state_bytes_digest_matches": True,
                "exclusive_owner_pinned_lock_held_during_observation": True,
                "operator_authorization_verified": False,
                "signed_installed_code_verified": False,
                "native_host_root_provenance_verified": False,
                "managed_nginx_unit_verified": False,
                "nginx_exposure_verified": False,
                "active_catalog_publication_verified": False,
                "preflight_remains_valid_after_lock_release": False,
                "authorizes_state_write": False,
                "authorizes_nginx_reload": False,
                "authorizes_catalog_publication": False,
            }
    except LockedV2DigestError:
        raise
    except (ProtectedStateStoreError, ProposedV2PersistenceError,
            LockedManifestInspectionError, OSError, ValueError, TypeError):
        _deny("PROTECTED_STATE_UNVERIFIED")


def inspect_current_namespace_locked_v2_digest(
    *, expected_generation: int, expected_state_sha256: str,
) -> dict[str, Any]:
    """Read only the fixed present-namespace root state; never mutate it.

    The caller cannot choose an FD, pathname or owner. A positive result
    cannot authenticate a native host, a signed executable or an operator.
    """
    if os.geteuid() != 0:
        _deny("ROOT_READ_ONLY_INSPECTION_REQUIRED")
    if (type(expected_generation) is not int
            or type(expected_state_sha256) is not str):
        _deny("ARGUMENT_INVALID")
    try:
        fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _deny("CURRENT_ROOT_UNAVAILABLE")
    try:
        try:
            _verify_current_root_fd(fd)
            observed = _inspect_under_root(
                fd, owner_uid=0, expected_generation=expected_generation,
                expected_state_sha256=expected_state_sha256,
            )
            _verify_current_root_fd(fd)
        except LockedV2DigestError:
            raise
        except (LockedManifestInspectionError, OSError, ValueError, TypeError):
            _deny("CURRENT_ROOT_UNVERIFIED")
        return {**observed, "current_namespace_root_path_observed": True}
    finally:
        os.close(fd)
