"""Private managed NGINX include promote/validate/restore fixture (#27).

This deliberately NON-ACTIVATING, SAME-DIRECTORY file transaction makes
future #31/#64 host integration testable without exposing a root-install API.
Callers supply a test root dirfd and test-only syntax callback. Neither their
identity, their expected digest, nor callback success authenticates a
production manifest, a host namespace, a state lock or an operator.

After a syntax rehearsal the previous file/inode (or absence) is restored.
Interrupted or unsafe intermediates refuse re-entry; they are never adopted
or deleted on the assumption that a crashed NGINX operation is harmless.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
import re
import stat
from typing import Any, Callable

from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _INCLUDE_SEGMENTS, _recheck, _safe_directory, _walk,
)

MANAGED_NAME = "repocache-managed.conf"
_STAGE = ".repocache-managed.stage"
_ROLLBACK = ".repocache-managed.rollback"
_MAX_BYTES = 256 * 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_CREATE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 getattr(os, "O_CLOEXEC", 0))
_FILE_MODE = 0o640
_ALLOWED_OLD_MODES = frozenset({0o600, 0o640, 0o644})


class ManagedIncludeRehearsalError(ValueError):
    """Static machine-readable refusal, never file bytes or callback exceptions."""


def _deny(code: str) -> None:
    raise ManagedIncludeRehearsalError(code)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_size, info.st_nlink)


def _read_stability(info: os.stat_result) -> tuple[int, ...]:
    # Content may be rewritten to the same size and inode while a bounded
    # read is in flight. Do not accept that as a stable snapshot.
    return _file_identity(info) + (info.st_mtime_ns, info.st_ctime_ns)


def _present(directory: int, basename: str) -> bool:
    try:
        os.stat(basename, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _read_owned(
    directory: int, basename: str, owner: int, group: int,
) -> tuple[bytes, tuple[int, ...]] | None:
    try:
        fd = os.open(basename, _READ_FLAGS, dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        named = os.stat(basename, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                or before.st_gid != group or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in _ALLOWED_OLD_MODES
                or before.st_size <= 0 or before.st_size > _MAX_BYTES
                or _read_stability(before) != _read_stability(named)):
            _deny("MANAGED_INCLUDE_OWNER_OR_INODE_UNVERIFIED")
        chunks = bytearray()
        while len(chunks) <= _MAX_BYTES:
            part = os.read(fd, _MAX_BYTES + 1 - len(chunks))
            if not part:
                break
            chunks.extend(part)
        after = os.fstat(fd)
        named_after = os.stat(basename, dir_fd=directory, follow_symlinks=False)
        if (len(chunks) != before.st_size
                or _read_stability(before) != _read_stability(after)
                or _read_stability(after) != _read_stability(named_after)):
            _deny("MANAGED_INCLUDE_CHANGED_DURING_READ")
        return bytes(chunks), _file_identity(after)
    finally:
        os.close(fd)


def _write_staged(directory: int, candidate: bytes, owner: int, group: int) -> tuple[int, ...]:
    fd = os.open(_STAGE, _CREATE_FLAGS, 0o600, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_gid != group or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            _deny("MANAGED_INCLUDE_STAGE_OWNER_UNVERIFIED")
        view = memoryview(candidate)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _deny("MANAGED_INCLUDE_STAGE_WRITE_FAILED")
            view = view[written:]
        os.fchmod(fd, _FILE_MODE)
        os.fsync(fd)
        after = os.fstat(fd)
        named = os.stat(_STAGE, dir_fd=directory, follow_symlinks=False)
        if (_file_identity(after) != _file_identity(named)
                or after.st_uid != owner or after.st_gid != group
                or after.st_nlink != 1
                or stat.S_IMODE(after.st_mode) != _FILE_MODE
                or after.st_size != len(candidate)):
            _deny("MANAGED_INCLUDE_STAGE_UNVERIFIED")
        return _file_identity(after)
    finally:
        os.close(fd)


def rehearse_managed_include_under_root(
    root_fd: int, candidate: bytes, *, owner_uid: int,
    expected_previous_sha256: str | None,
    syntax_check: Callable[[], None],
) -> dict[str, Any]:
    """Promote a candidate, call test syntax checker, restore prior inode.

    Caller MUST already hold a correctly authenticated external transaction
    lock and own a disposable fixture root. Neither is proved by this method.
    No host entrypoint, systemctl, reload, process/port check, state commit,
    catalog publication or persistent candidate activation is provided.

    On any unexpected crash/intermediate, reserved stage/rollback entries
    block the next attempt rather than being silently treated as safe.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or not 0 <= owner_uid < 2**32 - 1
            or type(candidate) is not bytes or not 0 < len(candidate) <= _MAX_BYTES
            or any(octet not in (9, 10) and not 32 <= octet <= 126
                   for octet in candidate)
            or not candidate.endswith(b"\n")
            or (expected_previous_sha256 is not None
                and (type(expected_previous_sha256) is not str
                     or not _HEX.fullmatch(expected_previous_sha256)))
            or not callable(syntax_check)):
        _deny("MANAGED_INCLUDE_ARGUMENT_INVALID")
    try:
        with ExitStack() as stack:
            directory, ancestry = _walk(
                root_fd, _INCLUDE_SEGMENTS, stack, owner_uid,
            )
            metadata = _safe_directory(directory, owner_uid)
            group = metadata.st_gid
            if _present(directory, _STAGE) or _present(directory, _ROLLBACK):
                _deny("MANAGED_INCLUDE_INTERRUPTED_TRANSACTION_REFUSED")

            previous = _read_owned(directory, MANAGED_NAME, owner_uid, group)
            if expected_previous_sha256 is None:
                if previous is not None:
                    _deny("FOREIGN_MANAGED_INCLUDE_REFUSED")
            elif (previous is None
                  or hashlib.sha256(previous[0]).hexdigest()
                     != expected_previous_sha256):
                _deny("MANAGED_INCLUDE_PREVIOUS_DIGEST_MISMATCH")
            _write_staged(directory, candidate, owner_uid, group)
            os.fsync(directory)

            if previous is not None:
                current = _read_owned(directory, MANAGED_NAME, owner_uid, group)
                if current != previous:
                    _deny("MANAGED_INCLUDE_PREVIOUS_CHANGED")
                os.link(
                    MANAGED_NAME, _ROLLBACK, src_dir_fd=directory,
                    dst_dir_fd=directory, follow_symlinks=False,
                )
                os.fsync(directory)
                # Both names refer to one hard-linked inode until the
                # candidate replaces the target. Before that replacement
                # st_nlink is 2: do not misclassify the pinned source as
                # a normal standalone file (nlink == 1 only afterwards).
                backup_stat = os.stat(
                    _ROLLBACK, dir_fd=directory, follow_symlinks=False,
                )
                if (not stat.S_ISREG(backup_stat.st_mode)
                        or backup_stat.st_dev != previous[1][0]
                        or backup_stat.st_ino != previous[1][1]
                        or backup_stat.st_uid != owner_uid
                        or backup_stat.st_gid != group
                        or backup_stat.st_nlink != 2):
                    _deny("MANAGED_INCLUDE_ROLLBACK_SOURCE_UNVERIFIED")
            else:
                if _present(directory, MANAGED_NAME):
                    _deny("FOREIGN_MANAGED_INCLUDE_REFUSED")

            # Published only inside a caller-supplied sandbox root; a
            # real NGINX parser can now read the exact candidate.
            stage = _read_owned(directory, _STAGE, owner_uid, group)
            if stage is None or stage[0] != candidate:
                _deny("MANAGED_INCLUDE_STAGE_CHANGED")
            os.replace(_STAGE, MANAGED_NAME,
                       src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)

            syntax_valid = False
            restore_verified = False
            try:
                published = _read_owned(directory, MANAGED_NAME, owner_uid, group)
                if published != stage:
                    _deny("MANAGED_INCLUDE_PROMOTION_CHANGED")
                try:
                    syntax_valid = syntax_check() is None
                except Exception:
                    syntax_valid = False
            finally:
                # Even a passing NGINX syntax check is NEVER an activation
                # decision. Restore before the caller sees any success.
                published = _read_owned(directory, MANAGED_NAME, owner_uid, group)
                if published != stage:
                    _deny("MANAGED_INCLUDE_ROLLBACK_TARGET_CHANGED")
                if previous is None:
                    os.unlink(MANAGED_NAME, dir_fd=directory)
                else:
                    backup = _read_owned(directory, _ROLLBACK, owner_uid, group)
                    if backup != previous:
                        _deny("MANAGED_INCLUDE_ROLLBACK_SOURCE_CHANGED")
                    os.replace(_ROLLBACK, MANAGED_NAME,
                               src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
                restored = _read_owned(directory, MANAGED_NAME, owner_uid, group)
                restore_verified = (
                    restored == previous
                    and not _present(directory, _STAGE)
                    and not _present(directory, _ROLLBACK)
                )
            if not restore_verified:
                _deny("MANAGED_INCLUDE_ROLLBACK_UNVERIFIED")
            _recheck(ancestry[:-1], owner_uid)
            if (os.fstat(directory).st_dev != metadata.st_dev
                    or os.fstat(directory).st_ino != metadata.st_ino
                    or _safe_directory(directory, owner_uid).st_mode
                       != metadata.st_mode):
                _deny("MANAGED_INCLUDE_PARENT_CHANGED")
            if not syntax_valid:
                _deny("MANAGED_INCLUDE_SYNTAX_REJECTED_RESTORED")
            return {
                "schema_version": 1,
                "status": "FIXTURE_CANDIDATE_SYNTAX_REHEARSED_AND_RESTORED",
                "previous_file_restored": True,
                "previous_file_was_present": previous is not None,
                "test_callback_reported_syntax_success": True,
                "transaction_fixture_only": True,
                "external_state_lock_authenticated": False,
                "protected_manifest_authenticated": False,
                "host_root_authenticated": False,
                "authorizes_host_installation": False,
                "authorizes_nginx_reload": False,
                "authorizes_catalog_publication": False,
            }
    except ManagedIncludeRehearsalError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("MANAGED_INCLUDE_TRANSACTION_UNVERIFIED")
