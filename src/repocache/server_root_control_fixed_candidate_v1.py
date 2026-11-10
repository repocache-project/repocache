"""Fixed root-owned administrator candidate intake, read-only and inert (#64).

No installed entry point or privileged worker calls this module. The fixed
local candidate is *data*, not an approval token. A future installed worker
must independently authenticate a kernel-credentialed administrator, secure
the signed installed code and native host, take #31's exclusive lock, validate
the complete v2 transition and real owned resources, then recoverably apply.
Only fixed OS-root paths are supported; no arbitrary request-body paths.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from typing import Any

_SEGMENTS = ("var", "lib", "repocache", "server")
_NAME = ".admin-candidate-v2.json"
_MAX_STATE = 4 * 1024 * 1024
_MAX_ENVELOPE = 6 * 1024 * 1024
_MAX_GEN = 2**63 - 1
_DIR_FLAGS = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
              | getattr(os, "O_CLOEXEC", 0))
_FILE_FLAGS = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
               | getattr(os, "O_CLOEXEC", 0))


class FixedAdminCandidateError(ValueError):
    """Fixed error codes; never include proposal, files or host paths."""


def _deny(code: str) -> None:
    raise FixedAdminCandidateError("FIXED_ADMIN_CANDIDATE_" + code)


def _id(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _safe_dir(fd: int, uid: int, gid: int) -> os.stat_result:
    try:
        info = os.fstat(fd)
    except OSError:
        _deny("DIRECTORY_UNAVAILABLE")
    if (not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_nlink < 1):
        _deny("DIRECTORY_UNSAFE")
    return info


def _read_exact(fd: int, limit: int) -> bytes:
    pieces = []
    remaining = limit + 1
    while remaining:
        try:
            chunk = os.read(fd, min(65536, remaining))
        except OSError:
            _deny("READ_UNAVAILABLE")
        if not chunk:
            break
        pieces.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(pieces)
    if not 1 <= len(raw) <= limit:
        _deny("SIZE_REFUSED")
    return raw


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _deny("JSON_INVALID")
        result[key] = value
    return result


def _bad_constant(_value: str) -> None:
    _deny("JSON_INVALID")


def _canonical_json(raw: bytes, limit: int) -> dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= limit:
        _deny("SIZE_REFUSED")
    try:
        value = json.loads(raw.decode("ascii", "strict"),
                           object_pairs_hook=_no_duplicates,
                           parse_constant=_bad_constant)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
    except FixedAdminCandidateError:
        raise
    except (UnicodeError, ValueError, TypeError, OverflowError,
            RecursionError):
        _deny("JSON_INVALID")
    if type(value) is not dict or encoded != raw:
        _deny("JSON_NONCANONICAL")
    return value


def _hex(value: Any) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _proposal(raw: bytes) -> dict[str, Any]:
    """Validate format only; not the approved full #31 transition or intent."""
    envelope = _canonical_json(raw, _MAX_ENVELOPE)
    if set(envelope) != {
        "request_schema_version", "expected_generation",
        "expected_state_sha256", "next_state_base64", "next_state_sha256",
    } or type(envelope["request_schema_version"]) is not int or (
        envelope["request_schema_version"] != 1
    ):
        _deny("ENVELOPE_INVALID")
    generation = envelope["expected_generation"]
    previous = envelope["expected_state_sha256"]
    next_digest = envelope["next_state_sha256"]
    b64 = envelope["next_state_base64"]
    if (type(generation) is not int or not 0 <= generation < _MAX_GEN
            or (previous is not None and not _hex(previous))
            or (generation == 0) != (previous is None)
            or not _hex(next_digest)
            or type(b64) is not str
            or not 1 <= len(b64) <= 4 * ((_MAX_STATE + 2) // 3)):
        _deny("ENVELOPE_INVALID")
    try:
        next_bytes = base64.b64decode(b64, validate=True)
    except (ValueError, binascii.Error):
        _deny("STATE_BASE64_INVALID")
    if (not 1 <= len(next_bytes) <= _MAX_STATE
            or base64.b64encode(next_bytes).decode("ascii") != b64
            or hashlib.sha256(next_bytes).hexdigest() != next_digest):
        _deny("STATE_DIGEST_INVALID")
    snapshot = _canonical_json(next_bytes, _MAX_STATE)
    if (set(snapshot) != {
        "state_schema_version", "state_generation",
        "configuration_base64", "configuration_sha256",
        "repository_records", "id_reservations", "approval_reference",
    } or type(snapshot["state_schema_version"]) is not int
            or snapshot["state_schema_version"] != 2
            or type(snapshot["state_generation"]) is not int
            or snapshot["state_generation"] != generation + 1):
        _deny("STATE_VERSION_INVALID")
    # Intentionally do not expose the snapshot in the observable report.
    # The future root transaction must *re-read* the exact bytes under lock,
    # validate #31 full schema/CAS/IDs and require authenticated operator intent.
    return {
        "schema_version": 1,
        "status": "FIXED_ROOT_OWNED_CANDIDATE_BYTES_ONLY",
        "expected_generation": generation,
        "expected_state_sha256": previous,
        "next_state_sha256": next_digest,
        "next_state_size_bytes": len(next_bytes),
        "fixed_candidate_read_and_rechecked": True,
        "complete_v2_transition_verified": False,
        "kernel_administrator_approved": False,
        "signed_installed_worker_verified": False,
        "native_host_root_verified": False,
        "state_lock_held": False,
        "preflight_remains_valid_after_return": False,
        "authorizes_state_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }


def _inspect_under_root(root_fd: int, *, owner_uid: int, owner_gid: int
                        ) -> dict[str, Any]:
    """Private fixture seam; a caller-provided root FD is never host authority."""
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or owner_uid < 0
            or type(owner_gid) is not int or owner_gid < 0):
        _deny("ARGUMENT_INVALID")
    parents: list[tuple[int, str, int, tuple[int, ...]]] = []
    child_fds: list[int] = []
    try:
        parent = root_fd
        origin = _safe_dir(parent, owner_uid, owner_gid)
        for segment in _SEGMENTS:
            before = _id(_safe_dir(parent, owner_uid, owner_gid))
            try:
                named = os.stat(segment, dir_fd=parent, follow_symlinks=False)
                child = os.open(segment, _DIR_FLAGS, dir_fd=parent)
            except OSError:
                _deny("DIRECTORY_UNAVAILABLE")
            child_fds.append(child)
            checked = _safe_dir(child, owner_uid, owner_gid)
            if (_id(named) != _id(checked)
                    or _id(_safe_dir(parent, owner_uid, owner_gid)) != before
                    or checked.st_dev != origin.st_dev):
                _deny("DIRECTORY_CHANGED")
            parents.append((parent, segment, child, _id(checked)))
            parent = child
        try:
            fd = os.open(_NAME, _FILE_FLAGS, dir_fd=parent)
        except OSError:
            _deny("FILE_UNAVAILABLE")
        try:
            first = os.fstat(fd)
            if (not stat.S_ISREG(first.st_mode)
                    or first.st_uid != owner_uid or first.st_gid != owner_gid
                    or stat.S_IMODE(first.st_mode) != 0o600
                    or first.st_nlink != 1
                    or first.st_dev != origin.st_dev
                    or not 1 <= first.st_size <= _MAX_ENVELOPE):
                _deny("FILE_UNSAFE")
            raw = _read_exact(fd, _MAX_ENVELOPE)
            if len(raw) != first.st_size:
                _deny("FILE_CHANGED")
            # A second bounded read refuses changed bytes even if metadata
            # was deliberately restored by a non-cooperating root process.
            try:
                os.lseek(fd, 0, os.SEEK_SET)
            except OSError:
                _deny("READ_UNAVAILABLE")
            if _read_exact(fd, _MAX_ENVELOPE) != raw:
                _deny("FILE_CHANGED")
            try:
                later = os.fstat(fd)
                named = os.stat(_NAME, dir_fd=parent, follow_symlinks=False)
            except OSError:
                _deny("FILE_CHANGED")
            if _id(first) != _id(later) or _id(later) != _id(named):
                _deny("FILE_CHANGED")
            report = _proposal(raw)
            for ancestor, segment, checked, identity in parents:
                try:
                    now = os.stat(segment, dir_fd=ancestor,
                                  follow_symlinks=False)
                except OSError:
                    _deny("DIRECTORY_CHANGED")
                if (_id(now) != identity
                        or _id(_safe_dir(checked, owner_uid, owner_gid))
                           != identity):
                    _deny("DIRECTORY_CHANGED")
            return report
        finally:
            os.close(fd)
    finally:
        for fd in reversed(child_fds):
            os.close(fd)


def inspect_fixed_current_namespace_admin_candidate() -> dict[str, Any]:
    """Root-only observational wrapper, never installed or broker-dispatched."""
    if (os.getuid() != 0 or os.geteuid() != 0
            or os.getresuid() != (0, 0, 0)):
        _deny("ROOT_REQUIRED")
    try:
        root = os.open("/", _DIR_FLAGS)
    except OSError:
        _deny("ROOT_UNAVAILABLE")
    try:
        return _inspect_under_root(root, owner_uid=0, owner_gid=0)
    finally:
        os.close(root)
