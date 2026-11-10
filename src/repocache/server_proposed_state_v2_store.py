"""Proposed v2 protected snapshot durability, fixture-only (#31).

NO operator entry, CLI, migration, native service activation or production root
helper. Reuses the v1 owner-pinned descriptor lock to serialize private Linux
fixture writes. Never treats an approval digest as authorization.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any, Callable

from repocache.server_locked_manifest_reconcile_v1 import (
    _DIRECTORY_FLAGS, _verify_current_root_fd,
    _validate_proposed_v2_snapshot, preview_proposed_v2_state_transition,
)
from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME as LEGACY_JOURNAL,
    JOURNAL_TMP_NAME as LEGACY_JOURNAL_TMP,
    MAX_JOURNAL_BYTES as LEGACY_MAX_JOURNAL,
    MAX_STATE_BYTES as LEGACY_MAX_STATE,
    ROLLBACK_NAME as LEGACY_ROLLBACK,
    STAGE_NAME as LEGACY_STAGE,
    STATE_NAME as LEGACY_STATE,
    _canonical, _closed, _hash, _json, _locked, _read_file, _read_state,
    _unlink_known, _write_exclusive,
)
from repocache.server_install_v1 import MAX_INT, parse_install_bytes
from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError, render_repository_nginx_bundle_candidate,
)

V2_STATE = "state-v2.json"
V2_JOURNAL = ".state-v2.pending"
V2_JOURNAL_TMP = ".state-v2.pending-tmp"
V2_STAGE = ".state-v2.stage"
V2_ROLLBACK = ".state-v2.rollback"
MAX_V2_STATE_BYTES = 4 * 1024 * 1024
MAX_V2_JOURNAL_BYTES = 6 * 1024 * 1024


class ProposedV2PersistenceError(ValueError):
    """Fixed, non-disclosing refusal code for private v2 fixture operations."""


def _refuse(code: str) -> None:
    raise ProposedV2PersistenceError("PROPOSED_V2_PERSISTENCE_" + code)


def _refuse_actual_root_fixture_write(root_fd: int) -> None:
    """Block accidental use of private fixture writers on the live '/'.

    This comparison is only a negative safety interlock. A different FD is
    NOT proof of a disposable sandbox, host provenance or authorization.
    Production must use a separate, explicitly authenticated entrypoint.
    """
    if type(root_fd) is not int or root_fd < 0:
        _refuse("FIXTURE_ROOT_INVALID")
    try:
        supplied = os.fstat(root_fd)
        current = os.stat("/", follow_symlinks=False)
    except OSError:
        _refuse("FIXTURE_ROOT_UNVERIFIED")
    if (supplied.st_dev, supplied.st_ino) == (current.st_dev, current.st_ino):
        _refuse("CURRENT_NAMESPACE_ROOT_WRITES_REFUSED")


def _report(status: str, generation: int) -> dict[str, Any]:
    return {
        "status": status,
        "state_generation": generation,
        "fixture_only": True,
        "operator_authorization_verified": False,
        "host_root_provenance_verified": False,
        "authorizes_installation": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
    }


def _freeze(candidate: Any) -> tuple[dict[str, Any], bytes]:
    # Freeze before locking, without trusting mutable caller objects again.
    try:
        raw = _canonical(candidate, limit=MAX_V2_STATE_BYTES)
        frozen = _json(raw, limit=MAX_V2_STATE_BYTES)
        _validate_proposed_v2_snapshot(frozen)
    except (ValueError, TypeError, OverflowError, RecursionError):
        _refuse("SNAPSHOT_INVALID")
    return frozen, raw


def _read_v2(directory: int, uid: int) -> tuple[dict[str, Any] | None, bytes | None]:
    raw = _read_file(directory, V2_STATE, uid, MAX_V2_STATE_BYTES)
    if raw is None:
        return None, None
    try:
        value = _json(raw, limit=MAX_V2_STATE_BYTES)
        _validate_proposed_v2_snapshot(value)
    except (ValueError, TypeError, OverflowError, RecursionError):
        _refuse("STATE_INVALID")
    return value, raw


def _legacy_refusal(directory: int, uid: int) -> None:
    # Both generations must never silently cohabit. A real v1 migration needs
    # separate authorization, conflict resolution and crash-tested journal.
    for name, bound in (
        (LEGACY_JOURNAL, LEGACY_MAX_JOURNAL),
        (LEGACY_JOURNAL_TMP, LEGACY_MAX_JOURNAL),
        (LEGACY_STAGE, LEGACY_MAX_STATE),
        (LEGACY_ROLLBACK, LEGACY_MAX_STATE),
    ):
        if _read_file(directory, name, uid, bound) is not None:
            _refuse("LEGACY_RECOVERY_REQUIRED")
    if _read_file(directory, LEGACY_STATE, uid, LEGACY_MAX_STATE) is not None:
        _refuse("LEGACY_MIGRATION_REQUIRED")


def _journal_bytes(previous: bytes | None, next_raw: bytes) -> bytes:
    record = {
        "journal_schema_version": 2,
        "previous_sha256": _hash(previous),
        "previous_base64": (
            None if previous is None
            else base64.b64encode(previous).decode("ascii")
        ),
        "next_sha256": _hash(next_raw),
    }
    return _canonical(record, limit=MAX_V2_JOURNAL_BYTES)


def _read_v2_journal(
    directory: int, uid: int, *, name: str = V2_JOURNAL,
) -> tuple[bytes | None, str, bytes] | None:
    """Validate either the published journal or its unpublished temporary file."""
    raw = _read_file(directory, name, uid, MAX_V2_JOURNAL_BYTES)
    if raw is None:
        return None
    try:
        entry = _json(raw, limit=MAX_V2_JOURNAL_BYTES)
        _closed(entry, {
            "journal_schema_version", "previous_sha256",
            "previous_base64", "next_sha256",
        })
        if type(entry["journal_schema_version"]) is not int or entry["journal_schema_version"] != 2:
            _refuse("JOURNAL_INVALID")
        digest = entry["next_sha256"]
        if (type(digest) is not str or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            _refuse("JOURNAL_INVALID")
        encoded = entry["previous_base64"]
        if encoded is None:
            if entry["previous_sha256"] is not None:
                _refuse("JOURNAL_INVALID")
            previous = None
        else:
            if (type(encoded) is not str
                    or len(encoded) > 4 * ((MAX_V2_STATE_BYTES + 2) // 3)):
                _refuse("JOURNAL_INVALID")
            try:
                previous = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                _refuse("JOURNAL_INVALID")
            if (not 1 <= len(previous) <= MAX_V2_STATE_BYTES
                    or base64.b64encode(previous).decode("ascii") != encoded
                    or entry["previous_sha256"] != _hash(previous)):
                _refuse("JOURNAL_INVALID")
            _validate_proposed_v2_snapshot(
                _json(previous, limit=MAX_V2_STATE_BYTES)
            )
    except ProposedV2PersistenceError:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError):
        _refuse("JOURNAL_INVALID")
    return previous, digest, raw


def _verify_recovery_next(
    raw: bytes, next_digest: str, previous: bytes | None, *, kind: str,
) -> None:
    """Validate journal-linked bytes and their actual prior-state transition.

    A journal digest is not enough to adopt a staged or replaced fixture
    state without checking generation and retired-ID continuity.
    """
    if _hash(raw) != next_digest:
        _refuse(kind + "_DRIFT")
    try:
        proposed = _json(raw, limit=MAX_V2_STATE_BYTES)
        old = None if previous is None else _json(
            previous, limit=MAX_V2_STATE_BYTES,
        )
        _validate_proposed_v2_snapshot(proposed)
        generation = 0 if old is None else old["state_generation"]
        preview_proposed_v2_state_transition(
            proposed, expected_generation=generation,
            previous_snapshot=old,
        )
    except (ValueError, TypeError, OverflowError, RecursionError):
        _refuse(kind + "_INVALID")


def _multi_resource_pending(directory: int, uid: int) -> bool:
    # An ordinary v2 fixture operation may not bypass an incomplete
    # multi-resource WAL. This is an interlock, not authorization.
    return any(
        _read_file(directory, name, uid, 16 * 1024 * 1024) is not None
        for name in (".state-v2-multi.pending", ".state-v2-multi.pending-tmp",
                     ".state-v2-multi.stage")
    )


def _pending(directory: int, uid: int, *, include_multi: bool = True) -> bool:
    if include_multi and _multi_resource_pending(directory, uid):
        return True
    if _read_v2_journal(directory, uid) is not None:
        return True
    return any(
        _read_file(directory, name, uid, bound) is not None
        for name, bound in (
            (V2_JOURNAL_TMP, MAX_V2_JOURNAL_BYTES),
            (V2_STAGE, MAX_V2_STATE_BYTES),
            (V2_ROLLBACK, MAX_V2_STATE_BYTES),
        )
    )


def _no_change(old: dict[str, Any], new: dict[str, Any]) -> bool:
    # The strictly required expected generation and approval-reference CAS
    # advance even for a repeat. Compare complete policy + identities + refs,
    # not the version-stamped envelope or resulting generation-specific hash.
    if (old["repository_records"] != new["repository_records"]
            or old["id_reservations"] != new["id_reservations"]
            or old["approval_reference"]["source"]
            != new["approval_reference"]["source"]
            or old["approval_reference"]["decision_sha256"]
            != new["approval_reference"]["decision_sha256"]):
        return False
    a = json.loads(base64.b64decode(old["configuration_base64"]))
    b = json.loads(base64.b64decode(new["configuration_base64"]))
    a.pop("expected_state_generation")
    b.pop("expected_state_generation")
    return a == b


def _commit_locked_proposed_v2(
    directory: int, frozen: dict[str, Any], raw: bytes, *,
    owner_uid: int, expected_generation: int,
    inject_fault: Callable[[str], None] | None = None,
    require_previous_bytes: bool = False,
    previous_bytes: bytes | None = None,
    verify_fixture_after_replace: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Private fixture transaction body; caller must hold the pinned FD lock.

    A prospective future host-root writer must independently authenticate
    caller/ownership and service/catalog effects. This helper does neither.
    """
    _legacy_refusal(directory, owner_uid)
    if _pending(directory, owner_uid):
        _refuse("RECOVERY_REQUIRED")
    existing, old_raw = _read_v2(directory, owner_uid)
    if require_previous_bytes and old_raw != previous_bytes:
        _refuse("STATE_CHANGED_DURING_PREFLIGHT")
    generation = 0 if existing is None else existing["state_generation"]
    if generation != expected_generation:
        _refuse("STALE_GENERATION")
    # The pure transition checker never grants authorization.
    preview_proposed_v2_state_transition(
        frozen, expected_generation=generation,
        previous_snapshot=existing,
    )
    if existing is not None and _no_change(existing, frozen):
        return _report("NO_CHANGE_INERT_V2", generation)
    journal = _journal_bytes(old_raw, raw)
    _write_exclusive(
        directory, V2_JOURNAL_TMP, journal,
        owner_uid, MAX_V2_JOURNAL_BYTES,
    )
    if inject_fault is not None:
        inject_fault("journal_tmp_durable")
    if _read_file(directory, V2_JOURNAL, owner_uid, MAX_V2_JOURNAL_BYTES) is not None:
        _refuse("JOURNAL_CONFLICT")
    try:
        os.replace(
            V2_JOURNAL_TMP, V2_JOURNAL,
            src_dir_fd=directory, dst_dir_fd=directory,
        )
        os.fsync(directory)
    except OSError:
        _refuse("JOURNAL_IO_REFUSED")
    if inject_fault is not None:
        inject_fault("journal_durable")
    _write_exclusive(directory, V2_STAGE, raw, owner_uid, MAX_V2_STATE_BYTES)
    if inject_fault is not None:
        inject_fault("stage_durable")
    _, observed_old = _read_v2(directory, owner_uid)
    if observed_old != old_raw:
        _refuse("CONCURRENT_DRIFT")
    try:
        os.replace(
            V2_STAGE, V2_STATE,
            src_dir_fd=directory, dst_dir_fd=directory,
        )
        os.fsync(directory)
    except OSError:
        _refuse("COMMIT_IO_REFUSED")
    if inject_fault is not None:
        inject_fault("replace_durable")
    if _read_file(directory, V2_JOURNAL, owner_uid, MAX_V2_JOURNAL_BYTES) != journal:
        _refuse("JOURNAL_CHANGED")
    # PRIVATE fixture-only post-replace barrier: a future native transaction
    # must keep a durable multi-resource journal until the actual service and
    # derived catalog are consistently activated. This callback is NEVER a
    # host authorization or a production execution API. A failed check leaves
    # the v2 journal durable for explicit recovery, rather than silently
    # reporting a committed generation as an activated deployment.
    if verify_fixture_after_replace is not None:
        try:
            if verify_fixture_after_replace() is not None:
                _refuse("ACTIVATION_FIXTURE_REFUSED")
        except Exception:
            _refuse("ACTIVATION_FIXTURE_REFUSED")
        if _read_file(directory, V2_JOURNAL, owner_uid, MAX_V2_JOURNAL_BYTES) != journal:
            _refuse("JOURNAL_CHANGED_AFTER_FIXTURE_ACTIVATION")
        _, after_activation = _read_v2(directory, owner_uid)
        if after_activation != raw:
            _refuse("STATE_CHANGED_DURING_FIXTURE_ACTIVATION")
    _unlink_known(
        directory, V2_JOURNAL, journal,
        owner_uid, MAX_V2_JOURNAL_BYTES,
    )
    return _report("COMMITTED_INERT_V2", frozen["state_generation"])


def _commit_proposed_v2_under_root(
    root_fd: int, candidate: dict[str, Any], *, owner_uid: int,
    expected_generation: int,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """PRIVATE Linux fixture durability only. Never call from a host CLI."""
    _refuse_actual_root_fixture_write(root_fd)
    if (type(expected_generation) is not int
            or not 0 <= expected_generation < MAX_INT):
        _refuse("EXPECTED_GENERATION_INVALID")
    frozen, raw = _freeze(candidate)
    with _locked(root_fd, owner_uid) as directory:
        return _commit_locked_proposed_v2(
            directory, frozen, raw, owner_uid=owner_uid,
            expected_generation=expected_generation, inject_fault=inject_fault,
        )



def _commit_preflighted_proposed_v2_under_root(
    root_fd: int, proposed_snapshot: dict[str, Any], *, owner_uid: int,
    expected_generation: int,
    candidate_pins_by_repository: Any,
    ca_bundle_path: str,
    inject_fault: Callable[[str], None] | None = None,
    validate_nginx_candidate: Callable[[dict[str, Any]], None] | None = None,
    verify_fixture_activation: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """PRIVATE fixture: render candidate and commit v2 under one FD lock.

    An optional test-only callback can validate a detached copy of the
    rendered candidate (including a disposable full-context nginx -t) while
    this same lock is held, *before* any state journal is created. Callback
    success is not host authority, production NGINX verification or approval.
    This does not authenticate an administrator, stage a live include, reload
    nginx or publish a catalog. Never wire this fixture helper to a host CLI.
    """
    _refuse_actual_root_fixture_write(root_fd)
    if (type(expected_generation) is not int
            or not 0 <= expected_generation < MAX_INT):
        _refuse("EXPECTED_GENERATION_INVALID")
    if validate_nginx_candidate is not None and not callable(validate_nginx_candidate):
        _refuse("NGINX_VALIDATOR_INVALID")
    if verify_fixture_activation is not None and not callable(verify_fixture_activation):
        _refuse("FIXTURE_ACTIVATION_VALIDATOR_INVALID")
    frozen, raw = _freeze(proposed_snapshot)
    try:
        pin_raw = _canonical(candidate_pins_by_repository, limit=1024 * 1024)
        pins = _json(pin_raw, limit=1024 * 1024)
    except (ValueError, TypeError, OverflowError, RecursionError):
        _refuse("PINS_INVALID")
    with _locked(root_fd, owner_uid) as directory:
        _legacy_refusal(directory, owner_uid)
        if _pending(directory, owner_uid):
            _refuse("RECOVERY_REQUIRED")
        existing, before = _read_v2(directory, owner_uid)
        generation = 0 if existing is None else existing["state_generation"]
        if generation != expected_generation:
            _refuse("STALE_GENERATION")
        try:
            preview_proposed_v2_state_transition(
                frozen, expected_generation=generation,
                previous_snapshot=existing,
            )
        except (ValueError, TypeError, OverflowError, RecursionError):
            _refuse("TRANSITION_INVALID")
        no_change = existing is not None and _no_change(existing, frozen)
        render_state = existing if no_change else frozen
        render_generation = generation if no_change else generation + 1
        try:
            document = parse_install_bytes(
                base64.b64decode(render_state["configuration_base64"]),
                for_apply=True,
            )
            candidate = render_repository_nginx_bundle_candidate(
                document, expected_state_generation=render_generation,
                candidate_pins_by_repository=pins,
                ca_bundle_path=ca_bundle_path,
            )
        except (NginxRepositoryBundleError, ValueError, TypeError,
                OverflowError, RecursionError):
            _refuse("NGINX_CANDIDATE_REFUSED")
        # This callback is a disposable test seam, not a privileged service
        # runner. Give it detached data so it cannot change what we return;
        # it cannot change the independently validated frozen state either.
        if validate_nginx_candidate is not None:
            try:
                detached = _json(
                    _canonical(candidate, limit=1024 * 1024),
                    limit=1024 * 1024,
                )
                # Contract: successful fixture validation returns exactly
                # None; an accidental bool/CompletedProcess result must not
                # silently turn a failed nginx -t into an accepted commit.
                if validate_nginx_candidate(detached) is not None:
                    _refuse("NGINX_FIXTURE_VALIDATION_REFUSED")
            except Exception:
                _refuse("NGINX_FIXTURE_VALIDATION_REFUSED")
        # Re-check state *after* validation: even a test callback may race a
        # non-cooperating writer that ignored our advisory state lock.
        _, after = _read_v2(directory, owner_uid)
        if before != after:
            _refuse("STATE_CHANGED_DURING_PREFLIGHT")
        def verify_after_replace() -> None:
            if verify_fixture_activation is None:
                return None
            # Separate detached copy: a test callback may not rewrite the
            # candidate later returned to the caller. A failed test-only
            # activation leaves the protected v2 journal pending.
            detached = _json(
                _canonical(candidate, limit=1024 * 1024),
                limit=1024 * 1024,
            )
            return verify_fixture_activation(detached)

        written = _commit_locked_proposed_v2(
            directory, frozen, raw, owner_uid=owner_uid,
            expected_generation=generation, inject_fault=inject_fault,
            require_previous_bytes=True, previous_bytes=before,
            verify_fixture_after_replace=(
                verify_after_replace if verify_fixture_activation is not None
                else None
            ),
        )
        # Return a candidate, NEVER an observed active mapping or permission.
        return {
            **candidate,
            "status": "LOCKED_FIXTURE_V2_STATE_ONLY_COMMIT_NGINX_NOT_ACTIVATED",
            "state_commit_status": written["status"],
            "state_generation": written["state_generation"],
            "expected_previous_generation": generation,
            "candidate_generation": render_generation,
            "state_preflight_and_commit_share_exclusive_lock": True,
            "fixture_validation_callback_executed": (
                validate_nginx_candidate is not None
            ),
            "fixture_activation_barrier_executed": (
                verify_fixture_activation is not None
                and written["status"] != "NO_CHANGE_INERT_V2"
            ),
            "fixture_only": True,
            "operator_authorization_verified": False,
            "trusted_host_root_verified": False,
            "nginx_syntax_verified": False,
            "active_exposure_verified": False,
            "authorizes_state_commit": False,
            "authorizes_nginx_activation": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
            "authorizes_cache_cleanup": False,
        }


def _preview_proposed_v2_recovery_under_root(
    root_fd: int, *, owner_uid: int,
) -> dict[str, Any]:
    """PRIVATE read-only preview of a fixture v2 journal, never recovery.

    No caller-provided snapshot, approval, migration or NGINX command is
    accepted. The same exclusive file lock as commit/recovery is held for
    every observation. A valid snapshot/journal establishes neither host
    privilege nor operator provenance; do not expose this as a host CLI.
    """
    with _locked(root_fd, owner_uid) as directory:
        _legacy_refusal(directory, owner_uid)
        journal = _read_v2_journal(directory, owner_uid)
        temp_entry = _read_v2_journal(
            directory, owner_uid, name=V2_JOURNAL_TMP,
        )
        temp = None if temp_entry is None else temp_entry[2]
        stage = _read_file(
            directory, V2_STAGE, owner_uid, MAX_V2_STATE_BYTES,
        )
        rollback = _read_file(
            directory, V2_ROLLBACK, owner_uid, MAX_V2_STATE_BYTES,
        )
        state, current = _read_v2(directory, owner_uid)
        if journal is None:
            if stage is not None or rollback is not None:
                _refuse("ORPHAN_STAGE_OR_ROLLBACK")
            if temp_entry is not None and current != temp_entry[0]:
                _refuse("STATE_DRIFT")
            status = ("UNPUBLISHED_V2_JOURNAL_ONLY"
                      if temp is not None else "CLEAN")
            rollback_temp_needs_rebuild = False
        else:
            if temp is not None:
                _refuse("CONFLICTING_JOURNAL_TEMP")
            previous, next_digest, _ = journal
            if _hash(current) not in (next_digest, _hash(previous)):
                _refuse("STATE_DRIFT")
            # An unconsumed stage alongside the replacement state is drift,
            # even when the pending digest matches. Never infer authority.
            if stage is not None:
                if current != previous:
                    _refuse("STATE_DRIFT")
                _verify_recovery_next(
                    stage, next_digest, previous, kind="STAGE",
                )
            if current != previous:
                _verify_recovery_next(
                    current, next_digest, previous, kind="REPLACED_STATE",
                )
            if rollback is not None and previous is None:
                _refuse("ROLLBACK_CONFLICT")
            if rollback is not None and rollback != previous:
                _refuse("ROLLBACK_DRIFT")
            rollback_temp_needs_rebuild = False
            status = ("INTERRUPTED_BEFORE_V2_REPLACE"
                      if current == previous else
                      "INTERRUPTED_AFTER_V2_REPLACE")
        return {
            **_report(
                status, 0 if state is None else state["state_generation"],
            ),
            "read_only_under_exclusive_lock": True,
            "v2_recovery_pending": status != "CLEAN",
            "v2_published_journal_present": journal is not None,
            "rollback_temp_requires_rebuild": rollback_temp_needs_rebuild,
            "host_service_recovery_verified": False,
            "authorizes_v2_recovery": False,
            "authorizes_v1_migration": False,
        }


def _recover_proposed_v2_under_root(
    root_fd: int, *, owner_uid: int,
) -> dict[str, Any]:
    """PRIVATE fixture-only explicit rollback. Never performs NGINX recovery."""
    _refuse_actual_root_fixture_write(root_fd)
    with _locked(root_fd, owner_uid) as directory:
        _legacy_refusal(directory, owner_uid)
        if _multi_resource_pending(directory, owner_uid):
            _refuse("MULTI_RESOURCE_RECOVERY_REQUIRED")
        journal = _read_v2_journal(directory, owner_uid)
        temp_entry = _read_v2_journal(
            directory, owner_uid, name=V2_JOURNAL_TMP,
        )
        temp = None if temp_entry is None else temp_entry[2]
        stage = _read_file(directory, V2_STAGE, owner_uid, MAX_V2_STATE_BYTES)
        rollback = _read_file(directory, V2_ROLLBACK, owner_uid, MAX_V2_STATE_BYTES)
        if journal is None:
            if stage is not None or rollback is not None:
                _refuse("ORPHAN_STAGE_OR_ROLLBACK")
            state, current = _read_v2(directory, owner_uid)
            # A temporary journal is only discardable if it describes the
            # exact pre-transaction state still present under the lock.
            if temp_entry is not None and current != temp_entry[0]:
                _refuse("STATE_DRIFT")
            if temp is not None:
                _unlink_known(
                    directory, V2_JOURNAL_TMP, temp,
                    owner_uid, MAX_V2_JOURNAL_BYTES,
                )
                status = "DISCARDED_UNPUBLISHED_V2_JOURNAL"
            else:
                status = "CLEAN"
        else:
            if temp is not None:
                _refuse("CONFLICTING_JOURNAL_TEMP")
            previous, next_digest, journal_raw = journal
            current = _read_file(directory, V2_STATE, owner_uid, MAX_V2_STATE_BYTES)
            if _hash(current) not in (next_digest, _hash(previous)):
                _refuse("STATE_DRIFT")
            if stage is not None:
                if current != previous:
                    _refuse("STATE_DRIFT")
                _verify_recovery_next(
                    stage, next_digest, previous, kind="STAGE",
                )
            if current != previous:
                _verify_recovery_next(
                    current, next_digest, previous, kind="REPLACED_STATE",
                )
            if rollback is not None and previous is None:
                _refuse("ROLLBACK_CONFLICT")
            # A mismatched rollback inode may belong to another writer or
            # reflect damaged bytes. Never delete it as a repair shortcut.
            if rollback is not None and rollback != previous:
                _refuse("ROLLBACK_DRIFT")
            if current != previous:
                if previous is None:
                    if current is None:
                        _refuse("STATE_DRIFT")
                    _unlink_known(
                        directory, V2_STATE, current,
                        owner_uid, MAX_V2_STATE_BYTES,
                    )
                else:
                    if rollback is None:
                        _write_exclusive(
                            directory, V2_ROLLBACK, previous,
                            owner_uid, MAX_V2_STATE_BYTES,
                        )
                    try:
                        os.replace(
                            V2_ROLLBACK, V2_STATE,
                            src_dir_fd=directory, dst_dir_fd=directory,
                        )
                        os.fsync(directory)
                    except OSError:
                        _refuse("ROLLBACK_IO_REFUSED")
            if stage is not None:
                _unlink_known(
                    directory, V2_STAGE, stage,
                    owner_uid, MAX_V2_STATE_BYTES,
                )
            if rollback is not None and current == previous:
                _unlink_known(
                    directory, V2_ROLLBACK, rollback,
                    owner_uid, MAX_V2_STATE_BYTES,
                )
            _unlink_known(
                directory, V2_JOURNAL, journal_raw,
                owner_uid, MAX_V2_JOURNAL_BYTES,
            )
            status = "ROLLED_BACK_INERT_V2"
            state, _ = _read_v2(directory, owner_uid)
        return _report(
            status, 0 if state is None else state["state_generation"]
        )


def _preview_proposed_v2_nginx_before_commit_under_root(
    root_fd: int, proposed_snapshot: dict[str, Any], *, owner_uid: int,
    expected_generation: int,
    candidate_pins_by_repository: Any,
    ca_bundle_path: str,
) -> dict[str, Any]:
    """PRIVATE read-only v2 transition + NGINX preflight before fixture commit.

    A read-only preflight does not hold a lock after returning and MUST NOT
    be mistaken for an authorization lease. Any future native transaction
    has to recheck the actual state/IDs, approved source bytes, pins and
    NGINX under an independently authenticated host-root lock.
    """
    if (type(expected_generation) is not int
            or not 0 <= expected_generation < MAX_INT):
        _refuse("EXPECTED_GENERATION_INVALID")
    # Freeze all caller-controlled structures before acquiring the lock.
    frozen, _ = _freeze(proposed_snapshot)
    try:
        pin_raw = _canonical(candidate_pins_by_repository, limit=1024 * 1024)
        pins = _json(pin_raw, limit=1024 * 1024)
    except (ValueError, TypeError, OverflowError, RecursionError):
        _refuse("PINS_INVALID")
    with _locked(root_fd, owner_uid) as directory:
        _legacy_refusal(directory, owner_uid)
        if _pending(directory, owner_uid):
            _refuse("RECOVERY_REQUIRED")
        existing, before = _read_v2(directory, owner_uid)
        generation = 0 if existing is None else existing["state_generation"]
        if generation != expected_generation:
            _refuse("STALE_GENERATION")
        try:
            preview_proposed_v2_state_transition(
                frozen, expected_generation=generation,
                previous_snapshot=existing,
            )
        except (ValueError, TypeError, OverflowError, RecursionError):
            _refuse("TRANSITION_INVALID")
        # Mirror the *existing* private writer's idempotent comparison.
        # A no-op must render the actually persisted generation, never a
        # speculative generation that would not be committed.
        no_change = existing is not None and _no_change(existing, frozen)
        render_state = existing if no_change else frozen
        render_generation = generation if no_change else generation + 1
        try:
            document = parse_install_bytes(
                base64.b64decode(render_state["configuration_base64"]),
                for_apply=True,
            )
            candidate = render_repository_nginx_bundle_candidate(
                document,
                expected_state_generation=render_generation,
                candidate_pins_by_repository=pins,
                ca_bundle_path=ca_bundle_path,
            )
        except (NginxRepositoryBundleError, ValueError, TypeError,
                OverflowError, RecursionError):
            _refuse("NGINX_CANDIDATE_REFUSED")
        # An out-of-band root actor may ignore flock. Refuse a changed
        # authoritative v2 file before releasing even this read-only report.
        _, after = _read_v2(directory, owner_uid)
        if before != after:
            _refuse("STATE_CHANGED_DURING_PREVIEW")
        return {
            **candidate,
            "status": "LOCKED_FIXTURE_V2_PRECOMMIT_NGINX_CANDIDATE_ONLY",
            "expected_state_generation": generation,
            "proposed_state_generation": render_generation,
            "would_change_v2_state": not no_change,
            "v2_canonical_transition_validated": True,
            "persisted_predecessor_rechecked_under_lock": True,
            "fixture_only": True,
            "trusted_host_root_verified": False,
            "operator_authorization_verified": False,
            "live_include_manifest_verified": False,
            "nginx_syntax_verified": False,
            "active_exposure_verified": False,
            "authorizes_state_commit": False,
            "authorizes_nginx_activation": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
            "authorizes_cache_cleanup": False,
        }


def _preview_persisted_v2_nginx_candidate_under_root(
    root_fd: int, *, owner_uid: int,
    expected_generation: int,
    candidate_pins_by_repository: Any,
    ca_bundle_path: str,
) -> dict[str, Any]:
    """Fixture-only locked persisted config → existing #28 renderer.

    This is NOT an approval oracle, native validator, public host writer or
    service activation path. It returns untrusted candidate NGINX fragments.
    """
    if (type(expected_generation) is not int
            or not 1 <= expected_generation <= MAX_INT):
        _refuse("EXPECTED_GENERATION_INVALID")
    # Freeze untrusted input within a bound before taking the state lock.
    try:
        pin_raw = _canonical(candidate_pins_by_repository, limit=1024 * 1024)
        pins = _json(pin_raw, limit=1024 * 1024)
    except (ValueError, TypeError, OverflowError, RecursionError):
        _refuse("PINS_INVALID")
    with _locked(root_fd, owner_uid) as directory:
        _legacy_refusal(directory, owner_uid)
        if _pending(directory, owner_uid):
            _refuse("RECOVERY_REQUIRED")
        state, before = _read_v2(directory, owner_uid)
        if state is None:
            _refuse("STATE_ABSENT")
        if state["state_generation"] != expected_generation:
            _refuse("STALE_GENERATION")
        # _read_v2 validated the full canonical payload/digest and exact
        # record/ledger correspondence, but NOT operator approval or host root.
        document = parse_install_bytes(
            base64.b64decode(state["configuration_base64"]), for_apply=True
        )
        try:
            candidate = render_repository_nginx_bundle_candidate(
                document,
                expected_state_generation=expected_generation,
                candidate_pins_by_repository=pins,
                ca_bundle_path=ca_bundle_path,
            )
        except (NginxRepositoryBundleError, ValueError, TypeError):
            _refuse("NGINX_CANDIDATE_REFUSED")
        _, after = _read_v2(directory, owner_uid)
        if before != after:
            _refuse("STATE_CHANGED_DURING_RENDER")
        return {
            **candidate,
            "status": "LOCKED_FIXTURE_V2_NGINX_CANDIDATE_ONLY",
            "persisted_config_bytes_and_digest_consistent": True,
            "exclusive_state_lock_held_during_preview": True,
            "fixture_only": True,
            "trusted_host_root_verified": False,
            "operator_authorization_verified": False,
            "live_include_manifest_verified": False,
            "nginx_syntax_verified": False,
            "active_exposure_verified": False,
            "authorizes_nginx_activation": False,
            "authorizes_catalog_publication": False,
        }



def _preview_v1_migration_blockers_under_root(
    root_fd: int, *, owner_uid: int,
) -> dict[str, Any]:
    """Read-only v1 fixture diagnosis, NEVER an actual migration/approval.

    V1 lacks canonical configuration bytes and historic tombstones. A v1
    digest and repository list cannot authenticate or reconstruct these.
    No proposed v2 data, arbitrary caller document or approval is accepted.
    """
    with _locked(root_fd, owner_uid) as directory:
        # The legacy validated reader refuses any proposed-v2 coexistence,
        # including an incomplete stage or symlink, under the shared lock.
        legacy, before = _read_state(directory, owner_uid)
        # Unpublished/unfinished legacy bootstrap may have no current state:
        # recovery takes precedence over reporting a clean absence.
        # No reading a snapshot as migratable while prior v1 recovery is
        # pending, even if the current state bytes remain valid.
        for name, limit in (
            (LEGACY_JOURNAL, LEGACY_MAX_JOURNAL),
            (LEGACY_JOURNAL_TMP, LEGACY_MAX_JOURNAL),
            (LEGACY_STAGE, LEGACY_MAX_STATE),
            (LEGACY_ROLLBACK, LEGACY_MAX_STATE),
        ):
            if _read_file(directory, name, owner_uid, limit) is not None:
                _refuse("LEGACY_RECOVERY_REQUIRED")
        if legacy is None:
            _refuse("LEGACY_STATE_ABSENT")
        _, after = _read_state(directory, owner_uid)
        if before != after:
            _refuse("LEGACY_STATE_CHANGED")
        return {
            **_report("LEGACY_V1_MIGRATION_BLOCKED", legacy["state_generation"]),
            "legacy_repository_count": len(legacy["repositories"]),
            "legacy_manifest_entry_count": len(legacy["ownership_manifest"]),
            "v1_snapshot_read_under_exclusive_lock": True,
            "v1_recovery_pending": False,
            "independent_configuration_bytes_verified": False,
            "historic_id_reservations_verified": False,
            "live_nginx_include_verified": False,
            "versioned_migration_protocol_approved": False,
            "authorizes_migration": False,
        }


def inspect_current_namespace_v1_migration_blockers() -> dict[str, Any]:
    """Diagnose v1 migration blockers under the current namespace root only.

    This is a read-only diagnostic, not a migration, trusted host-root proof,
    administrator authentication or native NGINX transaction. A root UID in a
    container does not prove access to the real host. No caller may provide a
    substitute root descriptor, path, UID, state or configuration document.
    """
    if os.geteuid() != 0:
        _refuse("CURRENT_NAMESPACE_ROOT_PRIVILEGE_REQUIRED")
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _refuse("CURRENT_NAMESPACE_ROOT_OPEN_REFUSED")
    try:
        _verify_current_root_fd(root_fd)
        report = _preview_v1_migration_blockers_under_root(
            root_fd, owner_uid=0,
        )
        _verify_current_root_fd(root_fd)
        return {
            **report,
            "current_namespace_root_path_verified": True,
            "trusted_host_root_verified": False,
            "operator_authorization_verified": False,
            "authorizes_migration": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }
    finally:
        os.close(root_fd)
