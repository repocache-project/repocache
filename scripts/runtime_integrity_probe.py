"""Read-only installed-runtime measurement primitive for issue #53.

PROTOTYPE ONLY. This module neither creates nor authenticates an inventory.
A trusted, separately installed supervisor must provide the already
authenticated expected entries and a securely opened generation directory FD.
No installed REPOCACHE Python package is imported and no candidate is run.
The observed tree must be quiescent; this is NOT a race-free launch gate.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import stat
from typing import Mapping


class IntegrityMismatch(RuntimeError):
    """Fail-closed read-only measurement refusal."""


@dataclass(frozen=True)
class ExpectedRegularFile:
    sha256: str
    mode: int


@dataclass(frozen=True)
class Measurement:
    files: int
    bytes_hashed: int


def _identity(entry: os.stat_result) -> tuple[int, ...]:
    return (
        entry.st_dev, entry.st_ino, entry.st_mode, entry.st_uid,
        entry.st_gid, entry.st_nlink, entry.st_size,
        entry.st_mtime_ns, entry.st_ctime_ns,
    )


def _checked_directory(entry: os.stat_result, uid: int, device: int) -> None:
    if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != uid
            or entry.st_dev != device or entry.st_mode & 0o022):
        raise IntegrityMismatch("Untrusted runtime directory metadata")


def _expected_paths(
    expected: Mapping[str, ExpectedRegularFile], max_entries: int,
) -> set[str]:
    if (not isinstance(expected, Mapping) or not expected
            or len(expected) > max_entries):
        raise IntegrityMismatch("Invalid or unbounded expected inventory")
    directories: set[str] = set()
    for path, item in expected.items():
        if not isinstance(path, str):
            raise IntegrityMismatch("Invalid expected inventory path")
        try:
            # Surrogates cannot denote canonical UTF-8 inventory paths.
            # Reject them as an integrity mismatch rather than leaking an
            # unchecked UnicodeEncodeError from untrusted input.
            encoded_size = len(path.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as exc:
            raise IntegrityMismatch("Invalid expected inventory path encoding") from exc
        if (not path or encoded_size > 1024
                or any(part in ("", ".", "..") or "\x00" in part
                       for part in path.split("/"))
                or not isinstance(item, ExpectedRegularFile)
                or not isinstance(item.sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", item.sha256) is None
                or type(item.mode) is not int or not (0 <= item.mode <= 0o777)
                or item.mode & 0o022):
            raise IntegrityMismatch("Invalid expected inventory entry")
        parts = path.split("/")
        directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
    if len(directories) > max_entries:
        raise IntegrityMismatch("Expected directory count exceeded")
    if any(path in directories for path in expected):
        raise IntegrityMismatch("Inventory file/directory collision")
    return directories


def verify_regular_tree(
    root_fd: int,
    expected: Mapping[str, ExpectedRegularFile],
    *,
    owner_uid: int,
    max_entries: int = 8192,
    max_file_bytes: int = 128 * 1024 * 1024,
    max_total_bytes: int = 512 * 1024 * 1024,
) -> Measurement:
    """Compare every entry under a pinned FD against an external inventory.

    For an intentionally narrow proof of measurement, all payload entries
    must be regular, single-link files or expected directories. Real Python
    venvs may contain legitimate interpreter symlinks and mutable bytecode:
    neither is silently allowed by this prototype. Do not wire into launch,
    repair, rollback or a privileged helper without separate approval.

    The caller owns root_fd and must independently authenticate the inventory,
    the verifier executable and root_fd's trusted pathname/ancestry. This
    routine does not close root_fd and does not execute inspected files.
    """
    if (type(owner_uid) is not int or owner_uid < 0
            or type(max_entries) is not int or not 1 <= max_entries <= 65536
            or type(max_file_bytes) is not int or not 1 <= max_file_bytes <= 1 << 34
            or type(max_total_bytes) is not int
            or not 1 <= max_total_bytes <= 1 << 36):
        raise IntegrityMismatch("Invalid inspection bounds")
    if not isinstance(expected, Mapping):
        raise IntegrityMismatch("Invalid expected inventory")
    try:
        # The external mapping is assumed to have been authenticated by the
        # trusted caller, but may still be mutable. Pin its entries before any
        # runtime I/O; never mix multiple revisions of the expectation set.
        if len(expected) > max_entries:
            raise IntegrityMismatch("Unbounded expected inventory")
        expected_snapshot = dict(expected)
    except (RuntimeError, ValueError, TypeError) as exc:
        raise IntegrityMismatch("Cannot snapshot expected inventory") from exc
    directories = _expected_paths(expected_snapshot, max_entries)
    try:
        root = os.fstat(root_fd)
        _checked_directory(root, owner_uid, root.st_dev)
        observed: set[str] = set()
        visited_directories: set[str] = set()
        total = 0
        count = 0

        def bounded_names(directory_fd: int) -> list[str]:
            # os.listdir(fd) would allocate an unbounded list from hostile
            # directories before we could check its size.
            names: list[str] = []
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if len(names) >= 2 * max_entries:
                        raise IntegrityMismatch("Runtime directory entry limit exceeded")
                    names.append(entry.name)
            return names

        def walk(directory_fd: int, prefix: str, depth: int) -> None:
            nonlocal count, total
            if depth > 32:
                raise IntegrityMismatch("Runtime directory depth exceeded")
            initial = bounded_names(directory_fd)
            if len(initial) + count + len(visited_directories) > 2 * max_entries + 1:
                raise IntegrityMismatch("Runtime entry count exceeded")
            if len(set(initial)) != len(initial):
                raise IntegrityMismatch("Duplicate runtime directory entry")
            for name in initial:
                if name in ("", ".", "..") or "/" in name or "\x00" in name:
                    raise IntegrityMismatch("Unsafe runtime name")
                rel = prefix + name
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(before.st_mode):
                    if rel not in directories:
                        raise IntegrityMismatch("Unexpected runtime directory")
                    _checked_directory(before, owner_uid, root.st_dev)
                    child_fd = os.open(
                        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                        | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory_fd,
                    )
                    try:
                        opened = os.fstat(child_fd)
                        if _identity(opened) != _identity(before):
                            raise IntegrityMismatch("Runtime directory replaced")
                        visited_directories.add(rel)
                        walk(child_fd, rel + "/", depth + 1)
                        if _identity(os.fstat(child_fd)) != _identity(opened):
                            raise IntegrityMismatch("Runtime directory changed")
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(before.st_mode):
                    item = expected_snapshot.get(rel)
                    if (item is None or before.st_uid != owner_uid
                            or before.st_dev != root.st_dev
                            or before.st_nlink != 1
                            or stat.S_IMODE(before.st_mode) != item.mode
                            or before.st_size > max_file_bytes
                            or total + before.st_size > max_total_bytes):
                        raise IntegrityMismatch("Untrusted runtime file metadata")
                    file_fd = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                        | os.O_NONBLOCK, dir_fd=directory_fd,
                    )
                    try:
                        opened = os.fstat(file_fd)
                        if _identity(opened) != _identity(before):
                            raise IntegrityMismatch("Runtime file replaced")
                        digest = hashlib.sha256()
                        length = 0
                        while True:
                            chunk = os.read(file_fd, 256 * 1024)
                            if not chunk:
                                break
                            length += len(chunk)
                            if length > max_file_bytes or total + length > max_total_bytes:
                                raise IntegrityMismatch("Runtime byte limit exceeded")
                            digest.update(chunk)
                        if (length != before.st_size
                                or digest.hexdigest() != item.sha256
                                or _identity(os.fstat(file_fd)) != _identity(opened)):
                            raise IntegrityMismatch("Runtime file bytes changed")
                        count += 1
                        total += length
                        observed.add(rel)
                    finally:
                        os.close(file_fd)
                else:
                    raise IntegrityMismatch("Unexpected runtime entry type")
                if _identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)) != _identity(before):
                    raise IntegrityMismatch("Runtime path changed during measurement")
            if set(bounded_names(directory_fd)) != set(initial):
                raise IntegrityMismatch("Runtime directory changed during measurement")

        walk(root_fd, "", 0)
        if observed != set(expected_snapshot) or visited_directories != directories:
            raise IntegrityMismatch("Runtime inventory is incomplete")
        if _identity(os.fstat(root_fd)) != _identity(root):
            raise IntegrityMismatch("Runtime root changed during measurement")
        return Measurement(files=count, bytes_hashed=total)
    except OSError as exc:
        raise IntegrityMismatch("Read-only runtime inspection failed") from exc
