"""Read-only protected source-pair recovery record shared with the lab.

No write engine, arbitrary path/URL, CLI operation, native lock acquisition,
network operation or privilege escalation is included. An authenticated
installed candidate can inspect exact local evidence without asserting
revocation of previously acquired routes or granting source-write authority.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
from pathlib import Path
import stat

import native_fallback_plan as compiler
import root_source_boundary as boundary
import source_preflight as pre
import source_metadata_lab as security_metadata

JOURNAL_MAX = 5 * 1024 * 1024


class PairRefused(RuntimeError):
    """Unsafe, ambiguous or foreign transaction state requires intervention."""


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _blob(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode(value: str) -> bytes:
    if type(value) is not str or len(value) > 2 * pre.MAX_SOURCE_BYTES:
        raise PairRefused("Invalid protected journal payload")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PairRefused("Corrupt protected journal payload") from exc


def _pack(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii")


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise PairRefused("Duplicate journal key")
        obj[key] = value
    return obj


def _journal_name(ident: str) -> str:
    if type(ident) is not str or not boundary.IDENT.fullmatch(ident):
        raise PairRefused("Invalid transaction identifier")
    return "pair-" + ident + ".json"


def _pending_journal_name(ident: str) -> str:
    _journal_name(ident)  # Validate the ID before constructing a leaf.
    return ".pair-" + ident + ".pending"


def _refuse_pending_journal(fd: int, ident: str) -> None:
    """Never mistake interrupted journal publication for a clean state.

    Called under the existing exclusive state lock, before reading an old
    journal or staging any new source. Even a dangling symlink, empty
    file or matching payload is uncertain; preserve it for manual review.
    """
    try:
        os.stat(_pending_journal_name(ident), dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PairRefused("Pending journal state cannot be verified") from exc
    raise PairRefused("Pending journal requires manual recovery")


def _source_attrs(journal: dict) -> tuple[tuple[str, bytes], ...]:
    if journal["schema"] in (2, 4):
        return ()
    encoded = journal["source_attributes"]
    if type(encoded) is not list or len(encoded) > security_metadata.MAX_ATTRS:
        raise PairRefused("Protected attribute snapshot refused")
    parsed = []
    total = 0
    for item in encoded:
        if (type(item) is not list or len(item) != 2 or type(item[0]) is not str
                or len(item[0].encode("utf-8")) > 255
                or not (security_metadata._allowed_attribute(item[0])
                        or (item[0] == "security.selinux"
                            and security_metadata.policy_active()))):
            raise PairRefused("Protected attribute namespace refused")
        value = _decode(item[1])
        total += len(value)
        if (len(value) > security_metadata.MAX_ATTRIBUTE_BYTES
                or total > security_metadata.MAX_TOTAL_ATTRIBUTE_BYTES):
            raise PairRefused("Protected attribute snapshot too large")
        parsed.append((item[0], value))
    if [name for name, _ in parsed] != sorted({name for name, _ in parsed}):
        raise PairRefused("Duplicate or unordered protected attributes")
    attrs = tuple(parsed)
    if security_metadata.attribute_digest(attrs) != journal["approval"].get("source_attributes_sha256"):
        raise PairRefused("Protected attribute snapshot differs from approval")
    return attrs


def _get_journal(fd: int, ident: str) -> dict | None:
    name = _journal_name(ident)
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    raw = boundary._read_pinned(fd, name, JOURNAL_MAX)
    try:
        j = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PairRefused("Malformed protected journal") from exc
    required = {
        "schema", "id", "phase", "source", "companion",
        "original", "proposed", "mirror", "original_id",
        "proposed_id", "mirror_id", "restore_id", "mode", "gid",
        "original_digest", "proposed_digest", "mirror_digest",
        "approval", "approval_sha256",
    }
    if type(j) is dict and j.get("schema") in (3, 5):
        required.add("source_attributes")
    if type(j) is dict and j.get("schema") in (4, 5):
        required.add("retained_id")
    if (type(j) is not dict or set(j) != required
            or type(j["schema"]) is not int or j["schema"] not in (2, 3, 4, 5)
            or type(j["id"]) is not str or j["id"] != ident
            or type(j["approval"]) is not dict
            or type(j["approval_sha256"]) is not str
            or not boundary.DIGEST.fullmatch(j["approval_sha256"])
            or j["phase"] not in ("armed", "installed", "restore-armed", "restored")
            or type(j["source"]) is not str or
            not pre.SOURCE_PATH.fullmatch(j["source"])
            or type(j["companion"]) not in (str, type(None))
            or (j["companion"] is not None and
                not j["companion"].startswith("etc/apt/mirrors/repocache-"))
            or type(j["mode"]) is not int or j["mode"] not in (0o600, 0o640, 0o644)
            or type(j["gid"]) is not int or j["gid"] < 0
            # Original and proposed inode IDs are mandatory. A missing
            # identity is NOT equivalent to an absent optional mirror.
            or any(type(j[key]) is not list or len(j[key]) != 2
                   or any(type(x) is not int or x < 0 for x in j[key])
                   for key in ("original_id", "proposed_id"))
            or (j["mirror_id"] is not None and (
                type(j["mirror_id"]) is not list or len(j["mirror_id"]) != 2
                or any(type(x) is not int or x < 0
                       for x in j["mirror_id"])))
            or (j["restore_id"] is not None and (
                type(j["restore_id"]) is not list or len(j["restore_id"]) != 2
                or any(type(x) is not int or x < 0 for x in j["restore_id"])))):
        raise PairRefused("Unexpected protected journal schema")
    if j["schema"] in (4, 5):
        retained = j["retained_id"]
        if (j["companion"] is None or j["gid"] != 0 or j["mode"] != 0o644
                or (retained is not None and (
                    type(retained) is not list or len(retained) != 2
                    or any(type(x) is not int or x < 0 for x in retained)
                    or retained == j["mirror_id"]
                    or j["phase"] in ("armed", "installed")))
                or (j["restore_id"] is not None and retained is None)):
            raise PairRefused("Invalid retained companion journal identity")
    original, proposed = _decode(j["original"]), _decode(j["proposed"])
    mirror = _decode(j["mirror"])
    if (_hash(original) != j["original_digest"] or
            _hash(proposed) != j["proposed_digest"] or
            _hash(mirror) != j["mirror_digest"] or
            len(original) > pre.MAX_SOURCE_BYTES or
            len(proposed) > pre.MAX_SOURCE_BYTES or
            (j["companion"] is None) != (j["mirror_id"] is None) or
            (j["companion"] is None and mirror)):
        raise PairRefused("Protected journal digest mismatch")
    if j["companion"] is not None:
        if (j["companion"] !=
                "etc/apt/mirrors/repocache-" + ident + ".list"):
            raise PairRefused("Journal companion path mismatches managed ID")
    # A protected snapshot binds recovery to the exact authorized compiler
    # inputs. Local rollback never depends on a reachable catalog or the
    # continued existence of an approval file, and never grants a new apply.
    try:
        snapshot = _pack(j["approval"])
        approval = boundary._decode_manifest(snapshot, ident)
        if (_hash(snapshot) != j["approval_sha256"]
                or approval["source"] != j["source"]
                or approval["source_sha256"] != j["original_digest"]
                or _hash(approval["cache"].encode("ascii")) != approval["route_sha256"]):
            raise PairRefused("Journal approval identity mismatch")
        if (approval["schema"] == 3) != (j["schema"] in (3, 5)):
            raise PairRefused("Journal attribute schema differs from approval")
        _source_attrs(j)
        if approval["schema"] in (2, 3):
            identity = approval["source_identity"]
            if ([identity["device"], identity["inode"]] != j["original_id"]
                    or identity["uid"] != 0 or identity["gid"] != j["gid"]
                    or identity["mode"] != j["mode"]
                    or identity["size"] != len(original)):
                raise PairRefused("Journal source identity mismatch")
        compiled = compiler.compile_fallback(
            source=j["source"], original=original,
            expected_source_sha256=approval["source_sha256"],
            selected_entry_sha256=approval["entry_sha256"],
            managed_id=ident, upstream=approval["upstream"], cache=approval["cache"])
        expected_companion = (j["companion"], mirror) if j["companion"] else None
        if compiled.proposed != proposed or compiled.companion != expected_companion:
            raise PairRefused("Journal differs from exact approved proposal")
    except (boundary.BoundaryRefused, compiler.FallbackRefused,
            UnicodeError, ValueError, RecursionError) as exc:
        raise PairRefused("Protected journal approval refused") from exc
    return j


def _retained_bytes(j: dict) -> bytes:
    # _get_journal has recompiled the exact approval and original source.
    # Never accept a new URI, user-supplied neutralization bytes or a cache.
    return (j["approval"]["upstream"] + "\tpriority:1\n").encode("ascii")


def _observe_source(root: Path, record: dict) -> str:
    observed = pre.inspect_source(record["source"], root=root)
    attrs = []
    raw = boundary._source_bytes(root, record["source"], observed, attrs_out=attrs)
    if (tuple(attrs) != _source_attrs(record)
            or observed["uid"] != 0 or observed["gid"] != record["gid"]
            or observed["mode"] != record["mode"]):
        raise PairRefused("Recovery source metadata differs")
    identity = [observed["device"], observed["inode"]]
    original = _decode(record["original"])
    proposed = _decode(record["proposed"])
    return _classify_source(record, identity, raw, original, proposed)


def _classify_source(record, identity, raw, original, proposed):
    # Linux may recycle the original inode after its unlink. A journal
    # containing identical original/restore identities cannot establish
    # which historical inode incarnation we are observing. Report that
    # ambiguity explicitly, never turn it into a stronger recovery claim.
    if identity == record["original_id"] and raw == original:
        return ("original-or-restored" if identity == record["restore_id"]
                else "original")
    if identity == record["proposed_id"] and raw == proposed:
        return "proposed"
    if identity == record["restore_id"] and raw == original:
        return "restored"
    raise PairRefused("Recovery source is not a recorded inode")


def _observe_companion(root: Path, record: dict) -> str:
    if record["companion"] is None:
        return "not-applicable"
    # The decoder has already verified this exact companion is derived
    # from the managed ID and approved original bytes. Never accept paths
    # from the caller, and retain/recheck each trusted parent descriptor.
    name = "repocache-" + record["id"] + ".list"
    with boundary._root(root) as (parent, owner), contextlib.ExitStack() as stack:
        witnesses = []
        for component in ("etc", "apt", "mirrors"):
            child = os.open(component, boundary.DIR, dir_fd=parent)
            stack.callback(os.close, child)
            witnesses.append((parent, component, child))
            parent = child
        def recheck():
            for p, component, fd in witnesses:
                boundary._checked_directory(fd, owner, private=False)
                actual = os.fstat(fd)
                named = os.stat(component, dir_fd=p, follow_symlinks=False)
                if (actual.st_gid != 0 or (actual.st_dev, actual.st_ino)
                        != (named.st_dev, named.st_ino)):
                    raise PairRefused("Recovery companion parent changed")
        recheck()
        try:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            recheck()
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return "absent"
            raise PairRefused("Recovery companion appeared")
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o644):
            raise PairRefused("Recovery companion metadata differs")
        raw = boundary._read_pinned(parent, name, pre.MAX_SOURCE_BYTES, mode=0o644)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        recheck()
        # Do not rely on atime, which reading can change.
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise PairRefused("Recovery companion changed during inspection")
        identity = [after.st_dev, after.st_ino]
        if identity == record["mirror_id"] and raw == _decode(record["mirror"]):
            return "cache-bearing"
        if identity == record["retained_id"] and raw == _retained_bytes(record):
            return "upstream-only"
        raise PairRefused("Recovery companion is not a recorded inode")


def _check_observed_phase(record: dict, source: str, companion: str) -> None:
    # Reachability of the read-only evidence, not permission to recover.
    # A proposed inode and its predecessor coexist during staging; the
    # restore and proposed inodes also coexist. Only the freed original
    # identity may be recycled for a later restore.
    original, proposed, restored = (
        record["original_id"], record["proposed_id"], record["restore_id"])
    apt = record["companion"] is not None
    retained = record.get("retained_id")
    if (original == proposed or original[0] != proposed[0]
            or (restored is not None and
                (restored == proposed or restored[0] != original[0]))):
        raise PairRefused("Impossible source journal identity")
    if apt and (record["mirror_id"] is None or
                (retained is not None and
                 retained[0] != record["mirror_id"][0])):
        raise PairRefused("Impossible companion journal identity")
    if not apt and companion != "not-applicable":
        raise PairRefused("Unexpected companion evidence")
    phase = record["phase"]
    if phase in ("armed", "installed"):
        if restored is not None or retained is not None:
            raise PairRefused("Unexpected rollback intent")
        if phase == "installed":
            if source != "proposed" or companion != (
                    "cache-bearing" if apt else "not-applicable"):
                raise PairRefused("Installed journal evidence differs")
        elif (source not in ("original", "proposed")
              or (apt and companion not in ("absent", "cache-bearing"))
              or (source == "proposed" and companion == "absent")):
            raise PairRefused("Armed journal evidence differs")
    elif phase == "restored":
        expected = ("not-applicable" if not apt else
                    "upstream-only" if retained is not None else "absent")
        sources = ("original",) if restored is None else ("restored", "original-or-restored")
        if source not in sources or companion != expected:
            raise PairRefused("Restored journal evidence differs")
    elif phase == "restore-armed":
        if apt:
            if retained is None or companion not in ("cache-bearing", "upstream-only"):
                raise PairRefused("Rollback companion evidence differs")
            if restored is None:
                if source not in ("original", "proposed"):
                    raise PairRefused("Rollback source evidence differs")
            elif (source not in ("proposed", "restored", "original-or-restored")
                  or companion != "upstream-only"):
                raise PairRefused("Rollback source evidence differs")
        elif restored is None or source not in ("proposed", "restored", "original-or-restored"):
            raise PairRefused("Rollback source evidence differs")
    else:
        raise PairRefused("Unknown recovery phase")


def _stage_specifications(record: dict, source: str, companion: str):
    """Derive the only permissible staged identities from a verified phase.

    A known initial stage can already have been removed during cancellation.
    A durable rollback intent that still needs publication, however, requires
    its exact staged inode. Terminal phases must have no staged resources.
    """
    phase = record["phase"]
    source_stage = companion_stage = None
    if phase in ("armed", "restore-armed") and source == "original":
        source_stage = (record["proposed_id"], _decode(record["proposed"]),
                        _source_attrs(record), False)
    elif (phase == "restore-armed" and source == "proposed"
          and record["restore_id"] is not None):
        source_stage = (record["restore_id"], _decode(record["original"]),
                        _source_attrs(record), True)
    if record["companion"] is not None:
        if phase == "armed" and companion == "absent":
            companion_stage = (record["mirror_id"], _decode(record["mirror"]), (), False)
        elif phase == "restore-armed" and companion == "cache-bearing":
            companion_stage = (record["retained_id"], _retained_bytes(record), (), True)
    return source_stage, companion_stage


def _observe_stage(root: Path, record: dict, relative: str, expected) -> str:
    """Read one fixed journal-derived staging leaf; never create or remove it."""
    if (not pre.SOURCE_PATH.fullmatch(relative)
            or not boundary.IDENT.fullmatch(record["id"])):
        raise PairRefused("Recovery stage path refused")
    name = ".repocache-atomic-" + record["id"]
    with boundary._root(root) as (parent, owner), contextlib.ExitStack() as stack:
        witnesses = []
        for component in relative.split("/")[:-1]:
            child = os.open(component, boundary.DIR, dir_fd=parent)
            stack.callback(os.close, child)
            witnesses.append((parent, component, child))
            parent = child

        def recheck():
            for p, component, child in witnesses:
                boundary._checked_directory(child, owner, private=False)
                actual = os.fstat(child)
                named = os.stat(component, dir_fd=p, follow_symlinks=False)
                if (actual.st_gid != 0 or (actual.st_dev, actual.st_ino)
                        != (named.st_dev, named.st_ino)):
                    raise PairRefused("Recovery stage parent changed")

        recheck()
        try:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            recheck()
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if expected is not None and expected[3]:
                    raise PairRefused("Required recovery stage missing")
                return "absent"
            raise PairRefused("Recovery stage appeared")
        if expected is None:
            raise PairRefused("Unexpected recovery stage")
        identity, payload, attrs, _ = expected
        if (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                or [named.st_dev, named.st_ino] != identity
                or named.st_uid != 0 or named.st_gid != record["gid"]
                or stat.S_IMODE(named.st_mode) != record["mode"]
                or named.st_size != len(payload)):
            raise PairRefused("Recovery stage is not a recorded inode")
        opened = os.open(name, boundary.REG, dir_fd=parent)
        stack.callback(os.close, opened)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")

        def fingerprint(info):
            return tuple(getattr(info, field) for field in fields)

        before = fingerprint(named)
        if fingerprint(os.fstat(opened)) != before:
            raise PairRefused("Recovery stage changed during open")
        metadata, actual_attrs = security_metadata._metadata(opened)
        raw = os.read(opened, pre.MAX_SOURCE_BYTES + 1)
        if (raw != payload or actual_attrs != attrs
                or security_metadata._metadata(opened) != (metadata, actual_attrs)):
            raise PairRefused("Recovery stage bytes or attributes differ")
        recheck()
        if (fingerprint(os.fstat(opened)) != before or fingerprint(
                os.stat(name, dir_fd=parent, follow_symlinks=False)) != before):
            raise PairRefused("Recovery stage changed during inspection")
        return "recorded"


def _observe_stages(root: Path, record: dict, source: str, companion: str):
    source_expected, companion_expected = _stage_specifications(record, source, companion)
    source_stage = _observe_stage(root, record, record["source"], source_expected)
    companion_stage = ("not-applicable" if record["companion"] is None else
                       _observe_stage(root, record, record["companion"], companion_expected))
    return source_stage, companion_stage


def inspect_local_recovery_record(ident: str, *, _test_root: Path | None = None) -> dict:
    """Internal root-only readback; no recovery, native exclusion or revocation proof.

    Only the exact ID under the fixed private state and existing client lock
    is accepted. The private test root parameter is never an installed CLI
    option. Legacy schema-1 approvals and nonretaining APT records cannot
    become installable candidate evidence. No live catalog request is made.
    """
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise PairRefused("Recovery record requires root")
    root = Path("/") if _test_root is None else Path(_test_root)
    flags = {
        "local_rollback_verified": False,
        "route_revocation_verified": False,
        "native_exclusion_verified": False,
        "write_eligible": False,
    }
    try:
        with boundary._native_metadata_scope(root), boundary._state(root) as (fd, owner):
            with boundary._exclusive_lock(fd, owner):
                _refuse_pending_journal(fd, ident)
                journal_name = _journal_name(ident)
                try:
                    initial = os.stat(journal_name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    _refuse_pending_journal(fd, ident)
                    if _get_journal(fd, ident) is not None:
                        raise PairRefused("Recovery journal appeared")
                    _refuse_pending_journal(fd, ident)
                    return {"status": "no-journal-read-only",
                            "journal_record_verified": False, **flags}
                if initial.st_gid != 0:
                    raise PairRefused("Recovery journal group differs")
                record = _get_journal(fd, ident)
                if record is None:
                    raise PairRefused("Recovery journal disappeared")
                if (record["approval"]["schema"] not in (2, 3)
                        or (record["companion"] is not None and record["schema"] not in (4, 5))):
                    raise PairRefused("Legacy recovery evidence not eligible")
                source = _observe_source(root, record)
                companion = _observe_companion(root, record)
                _check_observed_phase(record, source, companion)
                stages = _observe_stages(root, record, source, companion)
                _refuse_pending_journal(fd, ident)
                if (_get_journal(fd, ident) != record
                        or _observe_source(root, record) != source
                        or _observe_companion(root, record) != companion
                        or _observe_stages(root, record, source, companion) != stages):
                    raise PairRefused("Recovery evidence changed")
                final = os.stat(journal_name, dir_fd=fd, follow_symlinks=False)
                if (initial.st_dev, initial.st_ino, initial.st_ctime_ns) != (
                        final.st_dev, final.st_ino, final.st_ctime_ns):
                    raise PairRefused("Recovery journal identity changed")
                _refuse_pending_journal(fd, ident)
                return {
                    "status": "record-verified-read-only",
                    "journal_record_verified": True,
                    "phase": record["phase"], "source_state": source,
                    "companion_state": companion,
                    "source_stage_state": stages[0],
                    "companion_stage_state": stages[1], **flags,
                }
    except (boundary.BoundaryRefused, pre.PreflightError, OSError,
            ValueError, TypeError, RecursionError) as exc:
        raise PairRefused("Recovery record inspection refused") from exc
