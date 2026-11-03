"""Read-only descriptor-bound NGINX include observation for server recovery (#31).

A directory file descriptor comes from the caller; this module does NOT prove
its trusted ancestry, the intended absolute path or an authoritative manifest.
It only observes the fixed managed-include basename relative to that descriptor.
No observation grants authority to write files, change services or publish a
catalog. The future privileged engine must independently verify all ancestry,
mounts, manifest provenance and generation while holding a transaction lock.
"""
from __future__ import annotations

import hashlib
import os
import stat
from typing import Any

MAX_INCLUDE_BYTES = 256 * 1024
MANAGED_INCLUDE_NAME = "repocache-managed.conf"
_FILE_FLAGS = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
               | getattr(os, "O_CLOEXEC", 0))
_MODES = frozenset({0o600, 0o640, 0o644})


class ManagedIncludeObservationError(ValueError):
    """Fixed diagnostic codes; never embed host paths or file contents."""


def _deny(code: str) -> None:
    raise ManagedIncludeObservationError(code)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    """Fields that must remain stable around the bounded read."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _parent_info(fd: int) -> os.stat_result:
    try:
        info = os.fstat(fd)
    except OSError:
        _deny("INCLUDE_PARENT_UNAVAILABLE")
    if (not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_ino <= 0):
        _deny("INCLUDE_PARENT_UNSAFE")
    return info


def observe_managed_include_at(parent_fd: int) -> dict[str, Any]:
    """Hash a fixed-name regular include without writing or following links.

    Caller must supply an already opened directory descriptor. The directory
    has no proven connection to an absolute path or trusted protected state.
    A privileged caller must establish those properties independently; it may
    never promote this untrusted snapshot to approval for file replacement.
    """
    if type(parent_fd) is not int or parent_fd < 0:
        _deny("INCLUDE_PARENT_INVALID")
    parent_before = _parent_info(parent_fd)
    try:
        file_fd = os.open(MANAGED_INCLUDE_NAME, _FILE_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        # An absent target is not authorization to create one; nor does it
        # prove that the supplied directory points at the live NGINX tree.
        if _identity(_parent_info(parent_fd)) != _identity(parent_before):
            _deny("INCLUDE_PARENT_CHANGED")
        return {
            "schema_version": 1, "status": "FD_SNAPSHOT_ONLY",
            "file_present": False, "observation": None,
            "trusted_parent_ancestry_verified": False,
            "protected_manifest_provenance_verified": False,
            "authorizes_write": False, "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }
    except OSError:
        _deny("INCLUDE_OPEN_UNSAFE_OR_UNAVAILABLE")
    try:
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                _deny("INCLUDE_NOT_REGULAR")
            if before.st_nlink != 1:
                _deny("INCLUDE_HARDLINK_REFUSED")
            if (stat.S_IMODE(before.st_mode) not in _MODES
                    or before.st_ino <= 0 or before.st_size < 1
                    or before.st_dev != parent_before.st_dev):
                _deny("INCLUDE_METADATA_UNSAFE")
            if before.st_size > MAX_INCLUDE_BYTES:
                _deny("INCLUDE_TOO_LARGE")
            digest = hashlib.sha256()
            size = 0
            while size <= MAX_INCLUDE_BYTES:
                chunk = os.read(file_fd, min(65536, MAX_INCLUDE_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
            if size != before.st_size or size > MAX_INCLUDE_BYTES:
                _deny("INCLUDE_CHANGED_DURING_READ")
            after = os.fstat(file_fd)
            named = os.stat(MANAGED_INCLUDE_NAME, dir_fd=parent_fd,
                            follow_symlinks=False)
            if (_identity(before) != _identity(after)
                    or _identity(after) != _identity(named)
                    or _identity(parent_before) != _identity(_parent_info(parent_fd))):
                _deny("INCLUDE_CHANGED_DURING_READ")
        except ManagedIncludeObservationError:
            raise
        except OSError:
            _deny("INCLUDE_READ_OR_IDENTITY_UNAVAILABLE")
        return {
            "schema_version": 1, "status": "FD_SNAPSHOT_ONLY",
            "file_present": True,
            "observation": {
                "kind": "regular", "sha256": digest.hexdigest(),
                "uid": after.st_uid, "gid": after.st_gid,
                "mode": stat.S_IMODE(after.st_mode),
                "dev": after.st_dev, "ino": after.st_ino,
                "nlink": after.st_nlink,
            },
            "trusted_parent_ancestry_verified": False,
            "protected_manifest_provenance_verified": False,
            "authorizes_write": False, "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }
    finally:
        os.close(file_fd)
