"""Locked, non-authorizing live managed-include drift inspection (#31).

The public root-UID entry is READ-ONLY and anchors '/' only in the current
mount namespace. It cannot authenticate host-root context or an operator.
No function in this module grants authority to write, reload or publish.
The caller-FD entry remains private and intended only for Linux fixtures.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from typing import Any

from repocache.server_install_v1 import MAX_INT
from repocache.server_managed_include_v1 import MAX_CANDIDATE_BYTES
from repocache.server_managed_include_fd_v1 import observe_managed_include_at
from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _INCLUDE_SEGMENTS, _identity,
    _recheck, _safe_directory, _walk,
)
from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME, JOURNAL_TMP_NAME, MAX_JOURNAL_BYTES,
    MAX_STATE_BYTES, ROLLBACK_NAME, STAGE_NAME,
    _locked, _read_file, _read_journal, _read_state,
)

_COMPARE_FIELDS = ("sha256", "uid", "gid", "mode", "dev", "ino")


class LockedManifestInspectionError(ValueError):
    """Fixed symbolic refusal; no host paths, metadata, or file bytes."""


def _deny(code: str) -> None:
    raise LockedManifestInspectionError(code)


def _match_manifest(
    manifest: list[dict[str, Any]],
    observation: dict[str, Any] | None,
    *,
    expected_owner_uid: int,
) -> str:
    """Compare only the already validated fixed-path manifest and live inode.

    This pure inner step does not establish the caller's filesystem ancestry,
    root privilege, ACL or operator approval. It never returns content/hashes.
    """
    if not manifest:
        if observation is not None:
            _deny("FOREIGN_MANAGED_INCLUDE_REFUSED")
        return "NO_MANAGED_INCLUDE"
    if observation is None:
        _deny("RECORDED_MANAGED_INCLUDE_MISSING")
    if observation["uid"] != expected_owner_uid:
        _deny("MANAGED_INCLUDE_OWNER_MISMATCH")
    recorded = manifest[0]
    if any(recorded[k] != observation[k] for k in _COMPARE_FIELDS):
        _deny("MANAGED_INCLUDE_DRIFT")
    if observation["kind"] != "regular" or observation["nlink"] != 1:
        _deny("MANAGED_INCLUDE_UNSAFE")
    return "MANIFEST_MATCHES_OBSERVED_INCLUDE"


def _validate_candidate_bytes(value: Any) -> None:
    """Bounded input validation, not an NGINX syntax check."""
    if (type(value) is not bytes
            or not 1 <= len(value) <= MAX_CANDIDATE_BYTES
            or b"\x00" in value):
        _deny("MANAGED_CANDIDATE_INVALID")
    try:
        value.decode("utf-8", "strict")
    except UnicodeError:
        _deny("MANAGED_CANDIDATE_NOT_UTF8")


def _candidate_action(candidate: bytes, observation: dict[str, Any] | None) -> str:
    """Inert comparison after live manifest checks under a held lock."""
    if observation is None:
        return "WOULD_CREATE"
    return ("UNCHANGED" if hashlib.sha256(candidate).hexdigest()
            == observation["sha256"] else "WOULD_REPLACE")


def _inspect_locked_under_root(
    root_fd: int, *, owner_uid: int, expected_generation: int,
    candidate_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Private fixture-only entry, never a privileged authorization oracle.

    A caller-provided FD is NOT evidence of the OS root. The caller must not
    use the result as authority for mutation or NGINX/certificate operations.
    """
    if (type(root_fd) is not int or root_fd < 0 or type(owner_uid) is not int
            or owner_uid < 0 or type(expected_generation) is not int
            or not 0 <= expected_generation <= MAX_INT):
        _deny("MANIFEST_INSPECTION_ARGUMENT_INVALID")
    if candidate_bytes is not None:
        _validate_candidate_bytes(candidate_bytes)
    with _locked(root_fd, owner_uid) as state_dir:
        # Never silently recover on a read-only check. If an interrupted
        # transaction exists, the designated recovery operation must run first.
        if _read_journal(state_dir, owner_uid) is not None:
            _deny("PROTECTED_STATE_RECOVERY_REQUIRED")
        for name, limit in (
            (JOURNAL_TMP_NAME, MAX_JOURNAL_BYTES),
            (STAGE_NAME, MAX_STATE_BYTES),
            (ROLLBACK_NAME, MAX_STATE_BYTES),
        ):
            if _read_file(state_dir, name, owner_uid, limit) is not None:
                _deny("PROTECTED_STATE_RECOVERY_REQUIRED")
        state, raw = _read_state(state_dir, owner_uid)
        generation = 0 if state is None else state["state_generation"]
        if generation != expected_generation:
            _deny("PROTECTED_STATE_GENERATION_STALE")

        with ExitStack() as stack:
            include_dir, chain = _walk(
                root_fd, _INCLUDE_SEGMENTS, stack, owner_uid
            )
            include = observe_managed_include_at(include_dir)
            observation = include["observation"]
            if observation is not None and observation["uid"] != owner_uid:
                _deny("MANAGED_INCLUDE_OWNER_MISMATCH")
            manifest = [] if state is None else state["ownership_manifest"]
            status = _match_manifest(
                manifest, observation, expected_owner_uid=owner_uid
            )
            action = (_candidate_action(candidate_bytes, observation)
                      if candidate_bytes is not None else None)
            # Re-read the exact same protected content under the held lock,
            # even if another root-capable actor modified it without flock.
            _, after = _read_state(state_dir, owner_uid)
            if raw != after:
                _deny("PROTECTED_STATE_CHANGED_DURING_INSPECTION")
            _recheck(chain, owner_uid)
            _safe_directory(root_fd, owner_uid)
        report = {
            "schema_version": 1,
            "status": "LOCKED_READ_ONLY_RECONCILIATION",
            "include_status": status,
            "state_generation": generation,
            "manifest_entry_present": bool(manifest),
            "include_file_present": observation is not None,
            "exclusive_state_lock_held_during_inspection": True,
            # The presence of a stored record or its SHA-256 is NOT trusted
            # administrator provenance, user consent, or NGINX live exposure.
            "operator_authorization_verified": False,
            "protected_manifest_provenance_verified": False,
            "mount_namespace_acl_selinux_verified": False,
            "nginx_syntax_verified": False,
            "nginx_live_exposure_verified": False,
            "authorizes_write": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }
        if candidate_bytes is not None:
            # Never return an inode lease or authorization beyond the lock.
            report["candidate_action"] = action
            report["candidate_preview_only"] = True
        return report



def _verify_current_root_fd(root_fd: int) -> None:
    """Require identity with '/' in the *current mount namespace*.

    This is not a host namespace attestation or an operator authorization.
    """
    try:
        opened = _safe_directory(root_fd, 0)
        named = os.stat("/", follow_symlinks=False)
        if _identity(opened) != _identity(named):
            _deny("CURRENT_NAMESPACE_ROOT_CHANGED")
    except LockedManifestInspectionError:
        raise
    except (OSError, ValueError):
        _deny("CURRENT_NAMESPACE_ROOT_UNVERIFIED")


def inspect_current_namespace_locked_manifest(
    *, expected_generation: int
) -> dict[str, Any]:
    """Read only the current namespace's fixed root-owned NGINX/state paths.

    Unlike _inspect_locked_under_root, no caller supplies an arbitrary root
    FD or UID. Even a successful read never authenticates an administrator,
    proves host mount namespace isolation, or authorizes root writes/reloads.
    """
    if type(expected_generation) is not int or not 0 <= expected_generation <= MAX_INT:
        _deny("MANIFEST_INSPECTION_ARGUMENT_INVALID")
    if os.geteuid() != 0:
        _deny("CURRENT_NAMESPACE_ROOT_PRIVILEGE_REQUIRED")
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _deny("CURRENT_NAMESPACE_ROOT_OPEN_REFUSED")
    try:
        _verify_current_root_fd(root_fd)
        result = _inspect_locked_under_root(
            root_fd, owner_uid=0, expected_generation=expected_generation
        )
        _verify_current_root_fd(root_fd)
        # Only describes the root path opened in this process's namespace.
        # It does not prove trusted host ancestry, privilege delegation,
        # SELinux/ACL correctness or operator provenance.
        return {**result, "current_namespace_root_path_verified": True}
    finally:
        os.close(root_fd)


def preview_current_namespace_locked_candidate(
    *, expected_generation: int, candidate_bytes: bytes
) -> dict[str, Any]:
    """Preview only; root UID in a container is not trusted host authority."""
    _validate_candidate_bytes(candidate_bytes)
    if type(expected_generation) is not int or not 0 <= expected_generation <= MAX_INT:
        _deny("MANIFEST_INSPECTION_ARGUMENT_INVALID")
    if os.geteuid() != 0:
        _deny("CURRENT_NAMESPACE_ROOT_PRIVILEGE_REQUIRED")
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _deny("CURRENT_NAMESPACE_ROOT_OPEN_REFUSED")
    try:
        _verify_current_root_fd(root_fd)
        result = _inspect_locked_under_root(
            root_fd, owner_uid=0, expected_generation=expected_generation,
            candidate_bytes=candidate_bytes,
        )
        _verify_current_root_fd(root_fd)
        return {**result, "current_namespace_root_path_verified": True}
    finally:
        os.close(root_fd)
