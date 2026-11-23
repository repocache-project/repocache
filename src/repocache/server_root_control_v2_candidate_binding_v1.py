"""Read-only same-lock candidate-v2 CAS binding for an eventual root broker (#31).

The #64 fixed root-owned proposal bytes are re-read inside #31's exclusive
protected-state lock and independently validated against the *persisted* v2
generation, whole-state digest and permanent ID reservations. Neither the
data file nor this check is authenticated operator approval, a host-root
attestation, a post-lock lease, or an installed mutation entrypoint.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any

from repocache.server_locked_manifest_reconcile_v1 import (
    LockedManifestInspectionError, _DIRECTORY_FLAGS, _verify_current_root_fd,
    preview_proposed_v2_state_transition,
)
from repocache.server_proposed_state_v2_store import (
    ProposedV2PersistenceError, _legacy_refusal, _pending, _read_v2,
)
from repocache.server_proposed_v2_locked_digest_v1 import _state_inode
from repocache.server_protected_state_store_v1 import (
    ProtectedStateStoreError, _json, _locked,
)
from repocache.server_root_control_fixed_candidate_v1 import (
    FixedAdminCandidateError, _load_private_under_root,
)

_MAX_V2 = 4 * 1024 * 1024


class LockedRootCandidateBindingError(ValueError):
    """Fixed, redacted errors; never return proposal bytes or host paths."""


def _deny(code: str) -> None:
    raise LockedRootCandidateBindingError("LOCKED_ROOT_CANDIDATE_" + code)


def _bind_under_root(root_fd: int, *, owner_uid: int,
                     owner_gid: int) -> dict[str, Any]:
    """Private fixture-root check with no authorization after lock release.

    This callable has no user-chosen command/NGINX path/approval token. The
    caller-provided root FD is *not* independent host-root provenance.
    A future installed worker must verify native signed code and operator
    credentials and perform apply entirely within this lock, not after it.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or owner_uid < 0
            or type(owner_gid) is not int or owner_gid < 0):
        _deny("ARGUMENT_INVALID")
    try:
        with _locked(root_fd, owner_uid) as directory:
            _legacy_refusal(directory, owner_uid)
            if _pending(directory, owner_uid):
                _deny("RECOVERY_REQUIRED")
            state, old_bytes = _read_v2(directory, owner_uid)
            inode = None if old_bytes is None else _state_inode(directory)
            gen = 0 if state is None else state["state_generation"]
            report, private_next = _load_private_under_root(
                root_fd, owner_uid=owner_uid, owner_gid=owner_gid,
            )
            if (report.get("status") != "FIXED_ROOT_OWNED_CANDIDATE_BYTES_ONLY"
                    or report.get("authorizes_state_write") is not False
                    or report.get("state_lock_held") is not False
                    or report.get("kernel_administrator_approved") is not False):
                _deny("CANDIDATE_CLAIM_UNTRUSTED")
            if report["expected_generation"] != gen:
                _deny("STALE_GENERATION")
            expected_sha = (None if old_bytes is None
                            else hashlib.sha256(old_bytes).hexdigest())
            if report["expected_state_sha256"] != expected_sha:
                _deny("PREDECESSOR_DIGEST_MISMATCH")
            proposed = _json(private_next, limit=_MAX_V2)
            if type(proposed) is not dict:
                _deny("NEXT_STATE_INVALID")
            pure = preview_proposed_v2_state_transition(
                proposed, expected_generation=gen,
                previous_snapshot=state,
            )
            if (pure["proposed_generation"] != gen + 1
                    or pure["authorizes_write"] is not False
                    or pure["authorizes_nginx_reload"] is not False
                    or pure["authorizes_catalog_publication"] is not False):
                _deny("TRANSITION_CLAIM_UNTRUSTED")
            # Detect changed bytes and ordinary replacement while the lock
            # is held. Another root actor can ignore advisory flock: this is
            # not an immutable authorization or post-lock lease.
            _legacy_refusal(directory, owner_uid)
            if _pending(directory, owner_uid):
                _deny("RECOVERY_REQUIRED")
            later_state, later_bytes = _read_v2(directory, owner_uid)
            if (later_state != state or later_bytes != old_bytes
                    or (None if later_bytes is None else _state_inode(directory))
                       != inode):
                _deny("PREDECESSOR_CHANGED")
            later_report, later_next = _load_private_under_root(
                root_fd, owner_uid=owner_uid, owner_gid=owner_gid,
            )
            if later_report != report or later_next != private_next:
                _deny("CANDIDATE_CHANGED")
            return {
                "schema_version": 1,
                "status": "LOCKED_ROOT_CANDIDATE_V2_VALIDATED_PREVIEW_ONLY",
                "current_generation": gen,
                "proposed_generation": gen + 1,
                "whole_previous_state_sha256": expected_sha,
                "proposed_state_sha256": report["next_state_sha256"],
                "proposed_repository_count": pure["repository_count"],
                "proposed_reserved_id_count": pure["reserved_id_count"],
                "candidate_and_canonical_v2_transition_consistent": True,
                "exclusive_state_lock_held_during_inspection": True,
                "candidate_staged_by_root_observed": True,
                "signed_installed_root_actor_verified": False,
                "independent_kernel_administrator_approved": False,
                "native_host_provenance_verified": False,
                "nginx_syntax_and_exposure_verified": False,
                "catalog_publication_verified": False,
                "lock_still_held_after_return": False,
                "authorizes_state_write": False,
                "authorizes_nginx_reload": False,
                "authorizes_catalog_publication": False,
            }
    except LockedRootCandidateBindingError:
        raise
    except (FixedAdminCandidateError, ProtectedStateStoreError,
            ProposedV2PersistenceError, LockedManifestInspectionError,
            OSError, ValueError, TypeError, OverflowError, RecursionError):
        _deny("PROTECTED_CANDIDATE_UNVERIFIED")


def inspect_current_namespace_fixed_root_v2_candidate() -> dict[str, Any]:
    """Read-only native-namespace wrapper, not a production dispatcher."""
    if (os.getuid() != 0 or os.geteuid() != 0
            or os.getresuid() != (0, 0, 0)):
        _deny("ROOT_REQUIRED")
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _deny("CURRENT_ROOT_UNAVAILABLE")
    try:
        _verify_current_root_fd(root_fd)
        report = _bind_under_root(root_fd, owner_uid=0, owner_gid=0)
        _verify_current_root_fd(root_fd)
        return {**report, "current_namespace_root_observed": True}
    finally:
        os.close(root_fd)
