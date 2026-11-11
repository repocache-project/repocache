"""Recoverable native APT mirror + source transaction in a root-only test root.

This is an explicitly sandbox-gated engineering implementation for #24.
It never touches the installed host's /etc, does not add an installed CLI
entry point and does not constitute an authenticated production writer.
The real root boundary, native package manager exclusion, live SELinux
metadata and full publisher/catalog approval are separate mandatory gates.

A protected journal is fsynced BEFORE the first of two independent rename
operations. Recovery compares both inode identity and bytes for every
resource. It refuses foreign edits instead of force-restoring them.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from pathlib import Path

import native_fallback_plan as compiler
import root_source_boundary as boundary
import source_preflight as pre
import transaction_atomic_lab as atom

MARKER = ".repocache-recoverable-pair-test"
MAGIC = b"REPOCACHE_PAIR_SANDBOX_ONLY_V1\n"
JOURNAL_MAX = 5 * 1024 * 1024
REG = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class PairRefused(RuntimeError):
    """Unsafe, ambiguous or foreign transaction state requires intervention."""


class InjectedCrash(PairRefused):
    """Controlled simulated crash after the named durable boundary."""


def _identity(info: dict | os.stat_result) -> list[int]:
    if isinstance(info, dict):
        return [info["device"], info["inode"]]
    return [info.st_dev, info.st_ino]


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


def _sandbox(root: Path, statefd: int) -> None:
    root = Path(root)
    if root == Path("/") or not root.is_absolute() or ".." in root.parts:
        raise PairRefused("No production filesystem writes are permitted")
    if (root in (Path("/tmp"), Path("/var/tmp"))
            or not any(parent in (Path("/tmp"), Path("/var/tmp"))
                       for parent in root.parents)
            or root.resolve(strict=True) != root):
        raise PairRefused("Only private disposable test roots are permitted")
    fd = os.open(root, boundary.DIR)
    try:
        if boundary._read_pinned(fd, MARKER, len(MAGIC)) != MAGIC:
            raise PairRefused("Missing root-only paired-transaction marker")
    finally:
        os.close(fd)
    # A statefd that holds a known root-owned 0700 directory is mandatory.
    boundary._checked_directory(statefd, 0, private=True)


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


def _get_journal(fd: int, ident: str) -> dict | None:
    name = _journal_name(ident)
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    raw = boundary._read_pinned(fd, name, JOURNAL_MAX)
    try:
        j = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, ValueError) as exc:
        raise PairRefused("Malformed protected journal") from exc
    required = {
        "schema", "id", "phase", "source", "companion",
        "original", "proposed", "mirror", "original_id",
        "proposed_id", "mirror_id", "restore_id", "mode", "gid",
        "original_digest", "proposed_digest", "mirror_digest",
    }
    if (type(j) is not dict or set(j) != required
            or type(j["schema"]) is not int or j["schema"] != 1
            or type(j["id"]) is not str or j["id"] != ident
            or j["phase"] not in ("armed", "installed", "restore-armed", "restored")
            or type(j["source"]) is not str or
            not pre.SOURCE_PATH.fullmatch(j["source"])
            or type(j["companion"]) not in (str, type(None))
            or (j["companion"] is not None and
                not j["companion"].startswith("etc/apt/mirrors/repocache-"))
            or type(j["mode"]) is not int or j["mode"] not in (0o600, 0o640, 0o644)
            or type(j["gid"]) is not int or j["gid"] < 0
            or any(type(j[key]) is not list or len(j[key]) != 2
                   or any(type(x) is not int or x < 0 for x in j[key])
                   for key in ("original_id", "proposed_id", "mirror_id")
                   if j[key] is not None)
            or (j["restore_id"] is not None and (
                type(j["restore_id"]) is not list or len(j["restore_id"]) != 2
                or any(type(x) is not int or x < 0 for x in j["restore_id"])))):
        raise PairRefused("Unexpected protected journal schema")
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
    return j


def _put_journal(fd: int, ident: str, j: dict) -> None:
    name = _journal_name(ident)
    temp = ".pair-" + ident + ".pending"
    data = _pack(j)
    if len(data) > JOURNAL_MAX:
        raise PairRefused("Journal too large")
    try:
        out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                      os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    except OSError as exc:
        raise PairRefused("Pending journal requires manual recovery") from exc
    try:
        try:
            os.write(out, data)
            os.fsync(out)
        finally:
            os.close(out)
        # Any existing journal must be a known, valid, pinned inode.
        _get_journal(fd, ident)
        os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    except BaseException:
        # Unknown partial state stays on disk for manual inspection.
        raise


def _read_named(fd: int, name: str) -> tuple[bytes, dict] | None:
    try:
        data, metadata = atom._target_state(fd, name)
        return data, metadata
    except FileNotFoundError:
        return None
    except Exception as exc:
        # The atomic helper reports missing files as StageError, so check
        # the path separately before calling it for correct absence policy.
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        raise PairRefused("Unsafe resource inode or metadata") from exc


def _matches(state: tuple[bytes, dict] | None, content: bytes,
             identity: list[int]) -> bool:
    return (state is not None and
            state[0] == content and
            _identity(state[1]) == identity)


def _stat_required(fd: int, name: str, expected: list[int]) -> None:
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except OSError as exc:
        raise PairRefused("Expected transaction resource missing") from exc
    if (not stat.S_ISREG(info.st_mode)
            or _identity(info) != expected or info.st_nlink != 1):
        raise PairRefused("Foreign transaction inode detected")


def _remove_known(fd: int, name: str, payload: bytes,
                  ident: list[int] | None) -> None:
    current = _read_named(fd, name)
    if current is None:
        return
    if ident is None or not _matches(current, payload, ident):
        raise PairRefused("Unknown transaction resource; no deletion")
    _stat_required(fd, name, ident)
    os.unlink(name, dir_fd=fd)
    os.fsync(fd)


def _metadata(current: dict, journal: dict) -> None:
    if (current["uid"] != 0 or current["gid"] != journal["gid"]
            or current["mode"] != journal["mode"]):
        raise PairRefused("Native source metadata drift")


def _fixture_approval(statefd: int, root: Path, ident: str):
    approval = boundary._manifest(statefd, ident)
    if _hash(approval["cache"].encode("ascii")) != approval["route_sha256"]:
        raise PairRefused("Stale route approval")
    before = pre.inspect_source(approval["source"], root=root)
    if before["sha256"] != approval["source_sha256"]:
        raise PairRefused("Source baseline changed")
    raw = boundary._source_bytes(root, approval["source"], before)
    compiled = compiler.compile_fallback(
        source=approval["source"], original=raw,
        expected_source_sha256=approval["source_sha256"],
        selected_entry_sha256=approval["entry_sha256"],
        managed_id=ident, upstream=approval["upstream"], cache=approval["cache"])
    if pre.inspect_source(approval["source"], root=root) != before:
        raise PairRefused("Source drift during proposal validation")
    return approval, compiled


def _paths(root: Path, j: dict):
    """Acquire only strict source and companion dirfds (never arbitrary URLs)."""
    return atom._source_directory(root, j["source"])


def _crash(where: str | None, phase: str) -> None:
    if where == phase:
        raise InjectedCrash("Injected transaction interruption: " + phase)


def apply_sandbox(root: Path, ident: str, *, crash: str | None = None) -> dict:
    """Apply only in a root-owned private disposable marker tree.

    Successful repeated calls are exact no-ops, but not production idempotence.
    """
    root = Path(root)
    if root == Path("/"):
        raise PairRefused("Production root is forbidden")
    try:
        with boundary._state(root) as (statefd, owner):
            _sandbox(root, statefd)
            with boundary._exclusive_lock(statefd, owner):
                journal = _get_journal(statefd, ident)
                if journal is not None:
                    if journal["phase"] != "installed":
                        raise PairRefused("Interrupted or restored transaction needs review")
                    with _paths(root, journal) as (fd, leaf):
                        curr = _read_named(fd, leaf)
                        if not _matches(curr, _decode(journal["proposed"]),
                                        journal["proposed_id"]):
                            raise PairRefused("Installed source externally modified")
                    if journal["companion"] is not None:
                        with atom._source_directory(root, journal["companion"]) as (fd, leaf):
                            if not _matches(_read_named(fd, leaf),
                                            _decode(journal["mirror"]),
                                            journal["mirror_id"]):
                                raise PairRefused("Installed mirror externally modified")
                    return {"status": "unchanged", "write_eligible": False}
                approval, proposal = _fixture_approval(statefd, root, ident)
                with atom._source_directory(root, proposal.source) as (fd, leaf):
                    source = _read_named(fd, leaf)
                    if source is None or source[0] != proposal.original:
                        raise PairRefused("Source changed before stage")
                    mode, gid = source[1]["mode"], source[1]["gid"]
                    if source[1]["uid"] != 0 or mode not in (0o600, 0o640, 0o644):
                        raise PairRefused("Unsafe source ownership or mode")
                    source_temp, new_id = atom._write_new(
                        fd, leaf, ident, proposal.proposed, source[1])
                    # All current permissions and metadata must still match.
                    if not _matches(_read_named(fd, leaf),
                                    proposal.original, _identity(source[1])):
                        raise PairRefused("Source replaced during staging")
                companion = None
                companion_id = None
                if proposal.companion is not None:
                    path, bytes_ = proposal.companion
                    with atom._source_directory(root, path) as (fd, leaf):
                        if _read_named(fd, leaf) is not None:
                            raise PairRefused("Unexpected existing mirror companion")
                        temp, c_id = atom._write_new(
                            fd, leaf, ident, bytes_, source[1])
                        companion = path
                        companion_id = list(c_id)
                j = {
                    "schema": 1, "id": ident, "phase": "armed",
                    "source": proposal.source, "companion": companion,
                    "original": _blob(proposal.original),
                    "proposed": _blob(proposal.proposed),
                    "mirror": _blob(proposal.companion[1]
                                     if proposal.companion else b""),
                    "original_id": _identity(source[1]),
                    "proposed_id": list(new_id),
                    "mirror_id": companion_id, "restore_id": None,
                    "mode": mode, "gid": gid,
                    "original_digest": _hash(proposal.original),
                    "proposed_digest": _hash(proposal.proposed),
                    "mirror_digest": _hash(proposal.companion[1]
                                           if proposal.companion else b""),
                }
                _put_journal(statefd, ident, j)
                _crash(crash, "armed")
                if companion is not None:
                    with atom._source_directory(root, companion) as (fd, leaf):
                        temp = ".repocache-atomic-" + ident
                        _stat_required(fd, temp, companion_id)
                        if _read_named(fd, leaf) is not None:
                            raise PairRefused("Mirror destination appeared during commit")
                        os.rename(temp, leaf, src_dir_fd=fd, dst_dir_fd=fd)
                        os.fsync(fd)
                    _crash(crash, "companion")
                with atom._source_directory(root, proposal.source) as (fd, leaf):
                    atom._replace(fd, source_temp, leaf, _identity(source[1]))
                _crash(crash, "source")
                j["phase"] = "installed"
                _put_journal(statefd, ident, j)
                return {"status": "installed-sandbox", "write_eligible": False}
    except (OSError, ValueError, compiler.FallbackRefused,
            boundary.BoundaryRefused, pre.PreflightError) as exc:
        raise PairRefused("Paired transaction refused") from exc


def _restore_locked(root: Path, fdstate: int, ident: str, j: dict,
                    *, crash: str | None = None) -> dict:
    original, proposed, mirror = (
        _decode(j["original"]), _decode(j["proposed"]), _decode(j["mirror"]))
    with atom._source_directory(root, j["source"]) as (fd, leaf):
        current = _read_named(fd, leaf)
        if current is None:
            raise PairRefused("Source missing in transaction recovery")
        _metadata(current[1], j)
        from_original = _matches(current, original, j["original_id"])
        from_proposed = _matches(current, proposed, j["proposed_id"])
        from_restored = j["restore_id"] is not None and _matches(
            current, original, j["restore_id"])
        if not (from_original or from_proposed or from_restored):
            raise PairRefused("Foreign source during transaction recovery")
    if j["companion"] is not None:
        with atom._source_directory(root, j["companion"]) as (fd, leaf):
            mirror_state = _read_named(fd, leaf)
            if (mirror_state is not None and
                    not _matches(mirror_state, mirror, j["mirror_id"])):
                raise PairRefused("Foreign mirror during transaction recovery")
    else:
        mirror_state = None

    # For successful installations, recover() preserves the committed state
    # unless explicitly asked to restore. For armed partial commits, revert.
    if j["phase"] == "restored":
        if not (from_original or from_restored) or mirror_state is not None:
            raise PairRefused("Restored transaction modified externally")
        return {"status": "restored", "write_eligible": False}
    if j["phase"] == "installed" and crash is None:
        if not from_proposed or (j["companion"] is not None and mirror_state is None):
            raise PairRefused("Committed transaction not intact")
        return {"status": "installed-sandbox", "write_eligible": False}
    if j["phase"] == "armed" and (from_proposed and
                                  j["companion"] is not None and
                                  mirror_state is None):
        raise PairRefused("Source committed without its required mirror")

    if from_proposed:
        with atom._source_directory(root, j["source"]) as (fd, leaf):
            if j["restore_id"] is None:
                temp, new_id = atom._write_new(fd, leaf, ident, original, current[1])
                j["restore_id"] = list(new_id)
                j["phase"] = "restore-armed"
                _put_journal(fdstate, ident, j)
                _crash(crash, "restore-armed")
            else:
                temp = ".repocache-atomic-" + ident
                _stat_required(fd, temp, j["restore_id"])
                pending = _read_named(fd, temp)
                if not _matches(pending, original, j["restore_id"]):
                    raise PairRefused("Foreign rollback temp")
            atom._replace(fd, temp, leaf, j["proposed_id"])
            _crash(crash, "source-restored")
    elif not (from_original or from_restored):
        raise PairRefused("Unrecognized restore state")
    if j["companion"] is not None:
        with atom._source_directory(root, j["companion"]) as (fd, leaf):
            _remove_known(fd, leaf, mirror, j["mirror_id"])
    _crash(crash, "companion-removed")
    if from_original:
        # No source replacement happened: only a journalled temp can go.
        with atom._source_directory(root, j["source"]) as (fd, _):
            _remove_known(fd, ".repocache-atomic-" + ident,
                          proposed, j["proposed_id"])
    if j["companion"] is not None:
        with atom._source_directory(root, j["companion"]) as (fd, _):
            _remove_known(fd, ".repocache-atomic-" + ident,
                          mirror, j["mirror_id"])
    j["phase"] = "restored"
    _put_journal(fdstate, ident, j)
    return {"status": "restored", "write_eligible": False}


def restore_sandbox(root: Path, ident: str, *,
                    crash: str | None = None) -> dict:
    """Manually reverse an exact installed sandbox transaction, preserving proof."""
    root = Path(root)
    if root == Path("/"):
        raise PairRefused("Production root forbidden")
    with boundary._state(root) as (fd, owner):
        _sandbox(root, fd)
        with boundary._exclusive_lock(fd, owner):
            j = _get_journal(fd, ident)
            if j is None or j["phase"] not in ("installed", "restore-armed"):
                raise PairRefused("No committed sandbox transaction to restore")
            return _restore_locked(root, fd, ident, j, crash=crash or "manual")


def recover_sandbox(root: Path, ident: str) -> dict:
    """Rollback interrupted sandbox apply/restore only at exact journalled inodes."""
    root = Path(root)
    if root == Path("/"):
        raise PairRefused("Production root forbidden")
    with boundary._state(root) as (fd, owner):
        _sandbox(root, fd)
        with boundary._exclusive_lock(fd, owner):
            j = _get_journal(fd, ident)
            if j is None:
                return {"status": "no-intent", "write_eligible": False}
            if j["phase"] == "installed":
                return _restore_locked(root, fd, ident, j)
            if j["phase"] == "restored":
                return _restore_locked(root, fd, ident, j)
            return _restore_locked(root, fd, ident, j, crash="recover")
