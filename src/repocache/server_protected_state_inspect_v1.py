"""Read-only, descriptor-bound inspection of fixed server-managed paths (#31).

This deliberately does not create or authenticate persisted repository state.
Even a successful inspection is not a lock, an authorization, an inode lease,
or a proof of crash safety. Never use its result to authorize a root write.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
import stat
from typing import Any

from repocache.server_install_v1 import validate_install_document
from repocache.server_managed_include_fd_v1 import observe_managed_include_at

STATE_FILE_NAME = "state-v1.json"  # Provisional read-only envelope; NOT adopted state schema.
MAX_STATE_BYTES = 1024 * 1024
_STATE_SEGMENTS = ("var", "lib", "repocache", "server")
_INCLUDE_SEGMENTS = ("etc", "nginx", "conf.d")
_FIXED_STATE_ROOT = "/var/lib/repocache/server"
_FIXED_INCLUDE = "/etc/nginx/conf.d/repocache-managed.conf"
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class ProtectedStateInspectionError(ValueError):
    """Symbolic, value-redacted failure of a read-only inspection."""


def _refuse(code: str) -> None:
    raise ProtectedStateInspectionError(code)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _safe_directory(fd: int, owner: int) -> os.stat_result:
    try:
        info = os.fstat(fd)
    except OSError:
        _refuse("MANAGED_DIRECTORY_UNAVAILABLE")
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_ino <= 0):
        _refuse("MANAGED_DIRECTORY_UNSAFE")
    return info


def _walk(root_fd: int, segments: tuple[str, ...], stack: ExitStack,
          owner: int) -> tuple[int, list[tuple[int, str, int, tuple[int, ...]]]]:
    """Walk only audited static segments; reject symlinks and mount changes."""
    parent = root_fd
    recorded: list[tuple[int, str, int, tuple[int, ...]]] = []
    for segment in segments:
        # No caller input reaches the basename. Traversal is intentionally
        # not a general-purpose root helper or an arbitrary pathname reader.
        try:
            before = _safe_directory(parent, owner)
            seen = os.stat(segment, dir_fd=parent, follow_symlinks=False)
            child = os.open(segment, _DIRECTORY_FLAGS, dir_fd=parent)
            stack.callback(os.close, child)
            after = _safe_directory(child, owner)
            again = os.stat(segment, dir_fd=parent, follow_symlinks=False)
            if (_identity(seen) != _identity(after)
                    or _identity(after) != _identity(again)
                    or _identity(before) != _identity(_safe_directory(parent, owner))):
                _refuse("MANAGED_DIRECTORY_CHANGED")
            # A separate mount at /var (or a bind mount) is not implicitly
            # trusted. Explicit, reviewed mount handling is a later feature.
            if after.st_dev != before.st_dev:
                _refuse("MANAGED_MOUNT_BOUNDARY_UNVERIFIED")
        except ProtectedStateInspectionError:
            raise
        except OSError:
            _refuse("MANAGED_DIRECTORY_UNAVAILABLE_OR_SYMLINK")
        recorded.append((parent, segment, child, _identity(after)))
        parent = child
    return parent, recorded


def _recheck(recorded: list[tuple[int, str, int, tuple[int, ...]]],
             owner: int) -> None:
    for parent, name, child, original in recorded:
        try:
            now = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (_identity(now) != original
                    or _identity(_safe_directory(child, owner)) != original):
                _refuse("MANAGED_DIRECTORY_CHANGED")
        except ProtectedStateInspectionError:
            raise
        except OSError:
            _refuse("MANAGED_DIRECTORY_CHANGED")


def _read_state_at(state_fd: int, owner: int) -> dict[str, Any]:
    """Read a single fixed-size protected state *identity*, not JSON authority."""
    try:
        opened = os.open(STATE_FILE_NAME, _FILE_FLAGS, dir_fd=state_fd)
    except FileNotFoundError:
        # Absence is a diagnostic fact, not proof of an empty installation or
        # permission to initialize protected state.
        return {"present": False, "sha256": None, "size": None}
    except OSError:
        _refuse("PROTECTED_STATE_OPEN_REFUSED")
    try:
        try:
            before = os.fstat(opened)
            parent = _safe_directory(state_fd, owner)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                    or before.st_nlink != 1 or before.st_dev != parent.st_dev
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_size < 1):
                _refuse("PROTECTED_STATE_METADATA_UNSAFE")
            if before.st_size > MAX_STATE_BYTES:
                _refuse("PROTECTED_STATE_OVERSIZE")
            digest = hashlib.sha256()
            size = 0
            while size <= MAX_STATE_BYTES:
                data = os.read(opened, min(65536, MAX_STATE_BYTES + 1 - size))
                if not data:
                    break
                digest.update(data)
                size += len(data)
            after = os.fstat(opened)
            named = os.stat(STATE_FILE_NAME, dir_fd=state_fd,
                            follow_symlinks=False)
            if (size != before.st_size or size > MAX_STATE_BYTES
                    or _identity(before) != _identity(after)
                    or _identity(after) != _identity(named)
                    or _identity(parent) != _identity(_safe_directory(state_fd, owner))):
                _refuse("PROTECTED_STATE_CHANGED")
        except ProtectedStateInspectionError:
            raise
        except OSError:
            _refuse("PROTECTED_STATE_READ_REFUSED")
        return {"present": True, "sha256": digest.hexdigest(), "size": size}
    finally:
        os.close(opened)


def _inspect_under_root(root_fd: int, *, owner_uid: int) -> dict[str, Any]:
    """Internal fixture entry: its caller-supplied root FD is NOT authenticated.

    An unprivileged test can use its own UID; the production entry below fixes
    owner UID 0 and starts from an OS-opened root directory. Never expose this
    helper via the server CLI or a privileged generic file-access endpoint.
    """
    if type(root_fd) is not int or root_fd < 0 or type(owner_uid) is not int:
        _refuse("MANAGED_INSPECTION_ARGUMENT_INVALID")
    _safe_directory(root_fd, owner_uid)
    with ExitStack() as stack:
        state_fd, state_chain = _walk(root_fd, _STATE_SEGMENTS, stack, owner_uid)
        include_fd, include_chain = _walk(root_fd, _INCLUDE_SEGMENTS, stack, owner_uid)
        protected = _read_state_at(state_fd, owner_uid)
        include = observe_managed_include_at(include_fd)
        if include["observation"] is not None and include["observation"]["uid"] != owner_uid:
            _refuse("MANAGED_INCLUDE_OWNER_MISMATCH")
        _recheck(state_chain, owner_uid)
        _recheck(include_chain, owner_uid)
        _safe_directory(root_fd, owner_uid)
        return {
            "schema_version": 1,
            "status": "READ_ONLY_INSPECTION",
            "state_file": protected,
            "include_file": {"present": include["file_present"],
                             "sha256": (include["observation"] or {}).get("sha256")},
            "verified_static_segments": True,
            "protected_state_schema_verified": False,
            "protected_manifest_provenance_verified": False,
            "mount_namespace_and_acl_verified": False,
            "transaction_lock_held": False,
            "authorizes_write": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }


def inspect_default_server_state(document: dict[str, Any]) -> dict[str, Any]:
    """Read-only inspect the fixed initial installation layout, never mutate.

    All other valid configured layouts are unsupported by this first, bounded
    diagnostic increment; refusing them does not invalidate the v1 schema.
    """
    validated = validate_install_document(document, for_apply=True)
    paths = validated["deployment"]["paths"]
    if (paths["state_root"] != _FIXED_STATE_ROOT
            or paths["generated_include"] != _FIXED_INCLUDE):
        _refuse("MANAGED_LAYOUT_NOT_YET_SUPPORTED")
    try:
        fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _refuse("MANAGED_ROOT_UNAVAILABLE")
    try:
        return _inspect_under_root(fd, owner_uid=0)
    finally:
        os.close(fd)
