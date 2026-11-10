"""Private, non-activating, multi-resource v2 WAL for Linux fixtures (#31).

This persistently protects only fixed-name, 0600 *shadow* NGINX/catalog
files in the owner-pinned state directory, NOT real /etc/nginx or client
discovery. It exercises a single durable state/include/catalog rollback
contract for crash tests. A future installed native root worker MUST NOT
call this fixture module or use test-owned callbacks as host authority.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
from typing import Any, Callable

from repocache.server_locked_manifest_reconcile_v1 import (
    _validate_proposed_v2_snapshot, preview_proposed_v2_state_transition,
)
from repocache.server_proposed_state_v2_store import (
    MAX_V2_STATE_BYTES, V2_STATE, _freeze, _legacy_refusal, _no_change,
    _pending, _read_v2, _refuse_actual_root_fixture_write,
    _verify_recovery_next, ProposedV2PersistenceError,
)
from repocache.server_protected_state_store_v1 import (
    _canonical, _json, _locked, _read_file, _unlink_known,
    _write_exclusive,
)

# These exact names are PRIVATE SHADOW files, not live nginx or a public catalog.
INCLUDE = ".fixture-managed-nginx.conf"
CATALOG = ".fixture-derived-catalog.json"
MANIFEST = ".fixture-active-manifest.json"
JOURNAL = ".state-v2-multi.pending"
JOURNAL_TMP = ".state-v2-multi.pending-tmp"
STAGE = ".state-v2-multi.stage"
LIMITS = {
    V2_STATE: MAX_V2_STATE_BYTES,
    INCLUDE: 1024 * 1024,
    CATALOG: 512 * 1024,
    MANIFEST: 4096,
}
ORDER = (V2_STATE, INCLUDE, CATALOG, MANIFEST)
MAX_JOURNAL_BYTES = 16 * 1024 * 1024


class FixtureMultiResourceError(ValueError):
    """Static, non-secret error codes only."""


def _refuse(code: str) -> None:
    raise FixtureMultiResourceError("FIXTURE_MULTI_" + code)


def _digest(raw: bytes | None) -> str | None:
    return None if raw is None else hashlib.sha256(raw).hexdigest()


def _encode(raw: bytes | None) -> str | None:
    return None if raw is None else base64.b64encode(raw).decode("ascii")


def _decode(value: Any, limit: int) -> bytes | None:
    if value is None:
        return None
    if type(value) is not str or len(value) > 4 * ((limit + 2) // 3):
        _refuse("JOURNAL_INVALID")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        _refuse("JOURNAL_INVALID")
    if not 1 <= len(raw) <= limit or _encode(raw) != value:
        _refuse("JOURNAL_INVALID")
    return raw


def _read(directory: int, uid: int, name: str) -> bytes | None:
    return _read_file(directory, name, uid, LIMITS[name])


def _read_all(directory: int, uid: int) -> dict[str, bytes | None]:
    return {name: _read(directory, uid, name) for name in ORDER}


def _manifest(state: bytes, include: bytes, catalog: bytes) -> bytes:
    return _canonical({
        "schema_version": 1,
        "status": "FIXTURE_ONLY_NO_HOST_AUTHORITY",
        "state_sha256": _digest(state),
        "include_sha256": _digest(include),
        "catalog_sha256": _digest(catalog),
    }, limit=LIMITS[MANIFEST])



def _catalog_matches_state(catalog_bytes: bytes, state: dict[str, Any]) -> bool:
    """Refuse ambiguous or noncanonical fixture discovery bytes.

    The JSON parser must reject duplicate keys, nonfinite numbers and
    noncanonical spellings before comparing the exact desired-active set.
    This validates test-only data, never grants real catalog authority.
    """
    try:
        catalog = _json(catalog_bytes, limit=LIMITS[CATALOG])
        if (type(catalog) is not dict
                or set(catalog) != {"schema_version", "status", "active_ids"}
                or type(catalog["schema_version"]) is not int
                or catalog["schema_version"] != 1
                or catalog["status"] != "fixture-only-observed-candidate"
                or type(catalog["active_ids"]) is not list):
            return False
        ids = catalog["active_ids"]
        return (all(type(identifier) is str for identifier in ids)
                and ids == sorted(set(ids))
                and ids == sorted(
                    item["id"] for item in state["repository_records"]
                    if item["desired_state"] == "active"
                ))
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        return False


def _validate_old(old: dict[str, bytes | None]) -> None:
    if old[V2_STATE] is None:
        if any(old[name] is not None for name in (INCLUDE, CATALOG, MANIFEST)):
            _refuse("FOREIGN_BOOTSTRAP_RESOURCE")
        return
    if (old[INCLUDE] is None or old[CATALOG] is None
            or old[MANIFEST] is None
            or old[MANIFEST] != _manifest(
                old[V2_STATE], old[INCLUDE], old[CATALOG],
            )):
        _refuse("OWNER_MANIFEST_MISSING_OR_DRIFT")
    # A matching owner digest is insufficient if the underlying bytes are
    # structurally invalid or the catalog disagrees with the state it names.
    try:
        old_state = _json(old[V2_STATE], limit=LIMITS[V2_STATE])
        _validate_proposed_v2_snapshot(old_state)
    except (ValueError, TypeError, OverflowError, RecursionError):
        _refuse("OWNER_MANIFEST_MISSING_OR_DRIFT")
    if not _catalog_matches_state(old[CATALOG], old_state):
        _refuse("OWNER_MANIFEST_MISSING_OR_DRIFT")


def _write_target(
    directory: int, uid: int, name: str,
    previous: bytes | None, proposed: bytes | None,
) -> None:
    """Atomic same-directory replace; caller rechecks exact bytes first."""
    if _read(directory, uid, name) != previous:
        _refuse("RESOURCE_DRIFT")
    if proposed is None:
        if previous is not None:
            _unlink_known(directory, name, previous, uid, LIMITS[name])
        return
    if _read_file(directory, STAGE, uid, max(LIMITS.values())) is not None:
        _refuse("ORPHAN_STAGE")
    _write_exclusive(directory, STAGE, proposed, uid, max(LIMITS.values()))
    try:
        os.replace(STAGE, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except OSError:
        _refuse("REPLACE_IO_REFUSED")


def _record(old: dict[str, bytes | None],
            next_bytes: dict[str, bytes]) -> bytes:
    return _canonical({
        "journal_schema_version": 1,
        "old_base64": {name: _encode(old[name]) for name in ORDER},
        "old_sha256": {name: _digest(old[name]) for name in ORDER},
        "next_sha256": {name: _digest(next_bytes[name]) for name in ORDER},
    }, limit=MAX_JOURNAL_BYTES)


def _read_record(directory: int, uid: int, name: str
                 ) -> tuple[dict[str, bytes | None], dict[str, str], bytes] | None:
    raw = _read_file(directory, name, uid, MAX_JOURNAL_BYTES)
    if raw is None:
        return None
    try:
        data = _json(raw, limit=MAX_JOURNAL_BYTES)
        if type(data) is not dict or set(data) != {
            "journal_schema_version", "old_base64",
            "old_sha256", "next_sha256",
        } or type(data["journal_schema_version"]) is not int or data["journal_schema_version"] != 1:
            _refuse("JOURNAL_INVALID")
        for key in ("old_base64", "old_sha256", "next_sha256"):
            if type(data[key]) is not dict or set(data[key]) != set(ORDER):
                _refuse("JOURNAL_INVALID")
        old = {n: _decode(data["old_base64"][n], LIMITS[n]) for n in ORDER}
        for n in ORDER:
            if data["old_sha256"][n] != _digest(old[n]):
                _refuse("JOURNAL_INVALID")
            digest = data["next_sha256"][n]
            if type(digest) is not str or len(digest) != 64 or any(
                c not in "0123456789abcdef" for c in digest
            ):
                _refuse("JOURNAL_INVALID")
        _validate_old(old)
        return old, data["next_sha256"], raw
    except FixtureMultiResourceError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError):
        _refuse("JOURNAL_INVALID")


def _check_known(directory: int, uid: int,
                 old: dict[str, bytes | None],
                 next_sha: dict[str, str], *, require_old: bool) -> None:
    for name in ORDER:
        current = _read(directory, uid, name)
        if require_old:
            if current != old[name]:
                _refuse("PREPARE_DRIFT")
        elif _digest(current) not in (next_sha[name], _digest(old[name])):
            _refuse("FOREIGN_RESOURCE_DRIFT")


def _check_no_auxiliary_pending(directory: int, uid: int) -> None:
    # Ignore only the multi-resource domain's *committed owner files*:
    # those are expected across future multi-resource generations. Native
    # state-only journals are still hard conflicts; this helper checks its
    # own WAL and stage names independently below.
    if _pending(directory, uid, include_multi=False):
        _refuse("RECOVERY_REQUIRED")
    if any(_read_file(directory, n, uid, MAX_JOURNAL_BYTES) is not None
           for n in (JOURNAL, JOURNAL_TMP)):
        _refuse("RECOVERY_REQUIRED")
    if _read_file(directory, STAGE, uid, max(LIMITS.values())) is not None:
        _refuse("ORPHAN_STAGE")


def _commit_fixture_multi_resource_under_root(
    root_fd: int, proposed_snapshot: dict[str, Any], *,
    owner_uid: int, expected_generation: int,
    include_bytes: bytes, catalog_bytes: bytes,
    inject_fault: Callable[[str], None] | None = None,
    verify_fixture_effects: Callable[[], None] | None = None,
    verify_fixture_exposure_before_publish: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """One protected fixture lock, one persistent WAL, three fixed resources.

    NEVER supply an executable, host path, validator or callback from a
    privileged service. This private API is strictly for disposable tests.
    The optional prepublication callback runs only after candidate include
    and v2 state are durable, while the old catalog and owner manifest remain
    intact under the same lock and live WAL. Its return value NEVER proves
    actual NGINX exposure or grants publication authority.
    """
    _refuse_actual_root_fixture_write(root_fd)
    frozen, state = _freeze(proposed_snapshot)
    if (type(expected_generation) is not int
            or not 0 <= expected_generation < 2**63
            or type(include_bytes) is not bytes
            or not 1 <= len(include_bytes) <= LIMITS[INCLUDE]
            or b"\x00" in include_bytes
            or type(catalog_bytes) is not bytes
            or not 1 <= len(catalog_bytes) <= LIMITS[CATALOG]):
        _refuse("CANDIDATE_INVALID")
    try:
        include_bytes.decode("utf-8", "strict")
    except UnicodeError:
        _refuse("CANDIDATE_INVALID")
    if not _catalog_matches_state(catalog_bytes, frozen):
        _refuse("CATALOG_INVALID")
    if inject_fault is not None and not callable(inject_fault):
        _refuse("FAULT_HOOK_INVALID")
    if verify_fixture_effects is not None and not callable(verify_fixture_effects):
        _refuse("FIXTURE_CALLBACK_INVALID")
    if (verify_fixture_exposure_before_publish is not None
            and not callable(verify_fixture_exposure_before_publish)):
        _refuse("FIXTURE_PREPUBLICATION_CALLBACK_INVALID")

    with _locked(root_fd, owner_uid) as directory:
        _legacy_refusal(directory, owner_uid)
        _check_no_auxiliary_pending(directory, owner_uid)
        existing, old_state = _read_v2(directory, owner_uid)
        old = _read_all(directory, owner_uid)
        _validate_old(old)
        generation = 0 if existing is None else existing["state_generation"]
        if generation != expected_generation:
            _refuse("STALE_GENERATION")
        try:
            preview_proposed_v2_state_transition(
                frozen, expected_generation=generation,
                previous_snapshot=existing,
            )
        except (ValueError, TypeError, RecursionError):
            _refuse("TRANSITION_INVALID")
        if (existing is not None and _no_change(existing, frozen)
                and old[INCLUDE] == include_bytes
                and old[CATALOG] == catalog_bytes):
            return {"status": "NO_CHANGE_INERT_FIXTURE",
                    "state_generation": generation,
                    "host_activation_verified": False}
        next_bytes = {
            V2_STATE: state, INCLUDE: include_bytes, CATALOG: catalog_bytes,
            MANIFEST: _manifest(state, include_bytes, catalog_bytes),
        }
        journal = _record(old, next_bytes)
        _write_exclusive(directory, JOURNAL_TMP, journal,
                         owner_uid, MAX_JOURNAL_BYTES)
        if inject_fault is not None:
            inject_fault("journal_tmp_durable")
        if _read_all(directory, owner_uid) != old:
            _refuse("PREPARE_DRIFT")
        try:
            os.replace(JOURNAL_TMP, JOURNAL,
                       src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        except OSError:
            _refuse("JOURNAL_IO_REFUSED")
        if inject_fault is not None:
            inject_fault("journal_durable")
        # The inert candidate include and protected state must be durable
        # while the previously published catalog and manifest remain intact.
        # A real host transaction MUST independently verify service exposure
        # before publishing; this callback is only a disposable test seam.
        for name, phase in (
            (INCLUDE, "include_durable"),
            (V2_STATE, "state_durable"),
        ):
            _write_target(directory, owner_uid, name, old[name], next_bytes[name])
            if inject_fault is not None:
                inject_fault(phase)
        if verify_fixture_exposure_before_publish is not None:
            try:
                if verify_fixture_exposure_before_publish() is not None:
                    _refuse("FIXTURE_PREPUBLICATION_REFUSED")
            except Exception:
                _refuse("FIXTURE_PREPUBLICATION_REFUSED")
            # A callback can mutate fake files in this process despite the
            # advisory lock. It cannot bypass the pending WAL or publish an
            # unverified catalog by racing the fixture's own observer.
            if (any(_read(directory, owner_uid, n) != next_bytes[n]
                    for n in (INCLUDE, V2_STATE))
                    or any(_read(directory, owner_uid, n) != old[n]
                           for n in (CATALOG, MANIFEST))
                    or _read_file(directory, JOURNAL, owner_uid,
                                  MAX_JOURNAL_BYTES) != journal
                    or _read_file(directory, STAGE, owner_uid,
                                  max(LIMITS.values())) is not None):
                _refuse("FIXTURE_PREPUBLICATION_DRIFT")
        for name, phase in (
            (CATALOG, "catalog_durable"),
            (MANIFEST, "manifest_durable"),
        ):
            _write_target(directory, owner_uid, name, old[name], next_bytes[name])
            if inject_fault is not None:
                inject_fault(phase)
        if verify_fixture_effects is not None:
            try:
                if verify_fixture_effects() is not None:
                    _refuse("FIXTURE_EFFECTS_REFUSED")
            except Exception:
                _refuse("FIXTURE_EFFECTS_REFUSED")
        _check_known(directory, owner_uid, old,
                     {n: _digest(next_bytes[n]) for n in ORDER},
                     require_old=False)
        if _read_all(directory, owner_uid) != next_bytes:
            _refuse("POST_COMMIT_DRIFT")
        if _read_file(directory, JOURNAL, owner_uid, MAX_JOURNAL_BYTES) != journal:
            _refuse("JOURNAL_DRIFT")
        _unlink_known(directory, JOURNAL, journal,
                      owner_uid, MAX_JOURNAL_BYTES)
        return {
            "status": "COMMITTED_INERT_FIXTURE_MULTI_RESOURCE",
            "state_generation": frozen["state_generation"],
            "fixture_only": True,
            "durable_shadow_wal_exercised": True,
            "prepublication_fixture_barrier_executed": (
                verify_fixture_exposure_before_publish is not None
            ),
            "host_activation_verified": False,
            "operator_authorization_verified": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }


def _recover_fixture_multi_resource_under_root(
    root_fd: int, *, owner_uid: int,
) -> dict[str, Any]:
    """Recover exactly known shadow bytes; refuse any unexpected drift."""
    _refuse_actual_root_fixture_write(root_fd)
    with _locked(root_fd, owner_uid) as directory:
        _legacy_refusal(directory, owner_uid)
        if _pending(directory, owner_uid, include_multi=False):
            _refuse("FOREIGN_STATE_JOURNAL_PENDING")
        journal = _read_record(directory, owner_uid, JOURNAL)
        temp = _read_record(directory, owner_uid, JOURNAL_TMP)
        if journal is not None and temp is not None:
            _refuse("CONFLICTING_JOURNALS")
        if journal is None and temp is None:
            if _read_file(directory, STAGE, owner_uid, max(LIMITS.values())) is not None:
                _refuse("ORPHAN_STAGE")
            # A missing WAL is not evidence of a healthy generation:
            # verify the complete closed manifest, even in read-only clean
            # recovery mode. Never report CLEAN for an unowned or externally
            # modified NGINX/catalog/state file.
            _validate_old(_read_all(directory, owner_uid))
            return {"status": "CLEAN_INERT_FIXTURE", "fixture_only": True,
                    "host_recovery_verified": False}
        old, next_sha, journal_raw = journal if journal is not None else temp
        # A temp journal alone must never authorize a resource replacement.
        _check_known(directory, owner_uid, old, next_sha,
                     require_old=journal is None)
        # Validate the exact old->new v2 schema, retired IDs and generation
        # BEFORE restoring any resource. A forged next digest alone is not
        # sufficient proof that an observed state file is a legitimate
        # transition, even for a fixture recovery.
        current_state = _read(directory, owner_uid, V2_STATE)
        if journal is not None and current_state != old[V2_STATE]:
            try:
                _verify_recovery_next(
                    current_state, next_sha[V2_STATE], old[V2_STATE],
                    kind="MULTI_RESOURCE_REPLACED_STATE",
                )
            except (ProposedV2PersistenceError, ValueError, TypeError):
                _refuse("NEXT_STATE_INVALID")
        # Stage is a fixed temporary inode, not a completed resource. Only
        # a complete known next-resource digest can be cleaned up.
        stage = _read_file(directory, STAGE, owner_uid, max(LIMITS.values()))
        if stage is not None and _digest(stage) not in set(next_sha.values()):
            _refuse("FOREIGN_STAGE")
        if stage is not None:
            _unlink_known(directory, STAGE, stage,
                          owner_uid, max(LIMITS.values()))
        # Invalidate the active marker FIRST. After this point new attempts
        # always see a pending journal until every prior byte is restored.
        for name in (MANIFEST, CATALOG, INCLUDE, V2_STATE):
            current = _read(directory, owner_uid, name)
            if current != old[name]:
                _write_target(directory, owner_uid, name,
                              current, old[name])
        _validate_old(_read_all(directory, owner_uid))
        _unlink_known(directory, JOURNAL if journal is not None else JOURNAL_TMP,
                      journal_raw, owner_uid, MAX_JOURNAL_BYTES)
        return {
            "status": ("ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE"
                       if journal is not None
                       else "DISCARDED_UNPUBLISHED_INERT_FIXTURE_JOURNAL"),
            "fixture_only": True, "host_recovery_verified": False,
            "nginx_service_reloaded": False,
            "catalog_publication_verified": False,
        }
