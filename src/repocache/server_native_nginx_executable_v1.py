"""Descriptor-bound staging of a separately authenticated native NGINX binary.

Internal candidate primitive only. No path from an operator, package download,
policy installation, relabel, execution, service activation or host permission.
The caller must independently authenticate the exact distribution payload and
hold the owned placement transaction. The digest alone is not a trust token.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat

_MAX = 32 * 1024 * 1024
_LEAF = "nginx"
_PENDING = ".repocache-nginx-executable.pending"
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class NativeExecutableCandidateError(ValueError):
    """Redacted placement refusal."""


def _deny(code: str) -> None:
    raise NativeExecutableCandidateError("NGINX_EXECUTABLE_" + code)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _named(directory, name):
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _safe_file(info, *, mode=0o755):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode
            or not 0 < info.st_size <= _MAX):
        _deny("METADATA_REFUSED")


def _read_verified(fd, digest, *, mode=0o755):
    before = os.fstat(fd)
    _safe_file(before, mode=mode)
    # Copy bytes, never package file capabilities, ACLs or other xattrs.
    # A native SELinux label may already exist; never change it here.
    attrs = tuple(sorted(os.listxattr(fd)))
    if any(name != "security.selinux" for name in attrs):
        _deny("ATTRIBUTE_REFUSED")
    data = bytearray()
    while len(data) < before.st_size:
        block = os.pread(fd, min(65536, before.st_size - len(data)), len(data))
        if not block:
            _deny("READ_CHANGED")
        data.extend(block)
    if (os.pread(fd, 1, len(data)) or _identity(os.fstat(fd)) != _identity(before)
            or tuple(sorted(os.listxattr(fd))) != attrs
            or hashlib.sha256(data).hexdigest() != digest):
        _deny("DIGEST_OR_IDENTITY_REFUSED")
    return bytes(data), _identity(before)


def _directory(directory):
    info = os.fstat(directory)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) not in (0o700, 0o755)):
        _deny("DIRECTORY_REFUSED")
    if any(name != "security.selinux" for name in os.listxattr(directory)):
        _deny("DIRECTORY_ATTRIBUTE_REFUSED")
    return info.st_dev, info.st_ino


def _verify_leaf(directory, digest):
    fd = os.open(_LEAF, _READ, dir_fd=directory)
    try:
        _, identity = _read_verified(fd, digest)
        named = _named(directory, _LEAF)
        if named is None or _identity(named) != identity:
            _deny("DESTINATION_CHANGED")
        if identity[0] != os.fstat(directory).st_dev:
            _deny("DESTINATION_DEVICE_REFUSED")
        return identity
    finally:
        os.close(fd)


def stage_verified_nginx_candidate(
    directory: int, vendor_fd: int, *, authenticated_sha256: str,
    previous_inode: tuple[int, int] | None = None,
) -> dict:
    """Place fixed leaf in a retained owned directory without overwrite.

    Root-only; input fd and hash must come from the independently verified
    package identity, not a request. The caller retains namespace and
    placement lock authority, independently verifies the directory path,
    and must never execute before checking the service policy and receipt.
    Repeat staging requires the caller's previously owned device/inode;
    equal bytes alone cannot establish ownership. Unexpected pending
    evidence is preserved for manual reconciliation.
    """
    if (os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
            or type(directory) is not int or type(vendor_fd) is not int
            or directory == vendor_fd or type(authenticated_sha256) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", authenticated_sha256)
            or (previous_inode is not None and (
                type(previous_inode) is not tuple or len(previous_inode) != 2
                or any(type(x) is not int or x < 0 for x in previous_inode)))):
        _deny("INPUT_REFUSED")
    try:
        dir_id = _directory(directory)
        if _named(directory, _PENDING) is not None:
            _deny("PENDING_REFUSED")
        raw, source_id = _read_verified(vendor_fd, authenticated_sha256)
        existed = _named(directory, _LEAF) is not None
        if existed:
            if previous_inode is None or _verify_leaf(directory, authenticated_sha256)[:2] != previous_inode:
                _deny("FOREIGN_DESTINATION")
        elif previous_inode is not None:
            _deny("OWNED_DESTINATION_MISSING")
        if not existed:
            fd = os.open(_PENDING, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            try:
                with os.fdopen(os.dup(fd), "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                os.fchmod(fd, 0o755)
                os.fsync(fd)
                _, staged = _read_verified(fd, authenticated_sha256)
                named = _named(directory, _PENDING)
                if (named is None or _identity(named) != staged
                        or staged[0] != dir_id[0]
                        or _directory(directory) != dir_id
                        or _identity(os.fstat(vendor_fd)) != source_id):
                    _deny("STAGING_CHANGED")
                # Atomic no-replace publication. If interrupted between
                # link/unlink, preserve the pending name and refuse replay.
                os.link(_PENDING, _LEAF, src_dir_fd=directory,
                        dst_dir_fd=directory, follow_symlinks=False)
                linked = os.fstat(fd)
                target = _named(directory, _LEAF)
                pending = _named(directory, _PENDING)
                if (linked.st_nlink != 2 or target is None or pending is None
                        or _identity(target) != _identity(linked)
                        or _identity(pending) != _identity(linked)):
                    _deny("PUBLICATION_CHANGED")
                os.unlink(_PENDING, dir_fd=directory)
                os.fsync(directory)
            finally:
                os.close(fd)
        copy_id = _verify_leaf(directory, authenticated_sha256)
        if (_directory(directory) != dir_id
                or _identity(os.fstat(vendor_fd)) != source_id
                or copy_id[:2] == source_id[:2]
                or (previous_inode is not None and copy_id[:2] != previous_inode)
                or _named(directory, _PENDING) is not None):
            _deny("PLACEMENT_CHANGED")
        return {
            "status": "NGINX_EXECUTABLE_CANDIDATE_UNCHANGED" if existed else
                      "NGINX_EXECUTABLE_CANDIDATE_STAGED",
            "sha256": authenticated_sha256,
            "device": copy_id[0], "inode": copy_id[1],
            "authorizes_nginx_activation": False,
            "native_payload_authenticity_verified_by_primitive": False,
            "selinux_domain_verified": False,
        }
    except NativeExecutableCandidateError:
        raise
    except (OSError, OverflowError, ValueError, TypeError):
        _deny("PLACEMENT_REFUSED")
