"""Fixed, durable, fixture-bound bootstrap of the #31 protected state lock.

This mutates a passed-in isolated Linux root directory; it is NOT a public
installer, trusted host-root entry point or OS authorization mechanism.
A future signed privileged installer must independently authenticate its
root namespace/manifest before calling any state mutation.
"""
from __future__ import annotations

from contextlib import ExitStack
import fcntl
import json
import os
import re
import stat
from typing import Any, Callable

from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _identity, _recheck, _safe_directory, _walk,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME, _locked, _read_file
from repocache.server_native_installed_storage_v1 import _mount, _rename_directory_noreplace

_PARENT = ("var", "lib")
_ROOT_NAME = "repocache"
_STATE_NAME = "server"
_PUBLIC_NAME = "public"
_DIRECTORY_MODE = 0o700
_PUBLIC_PARENT_MODE = 0o711
_PUBLIC_DIRECTORY_MODE = 0o755
_LOCK_MODE = 0o600
_DEDICATED_PUBLIC_CONTEXT = b"system_u:object_r:repocache_nginx_ro_t:s0"
_CREATE_LOCK = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0))


class ProtectedBootstrapError(ValueError):
    """Static error codes only, no caller values or filesystem paths."""


def _deny(code: str) -> None:
    raise ProtectedBootstrapError("PROTECTED_BOOTSTRAP_" + code)


def _structural(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink)


def _verified_directory(parent_fd: int, name: str, expected_uid: int,
                        stack: ExitStack, *, mode: int) -> tuple[int, tuple[int, ...]]:
    """Pin one existing strict root-owned component and reject races/links."""
    before = os.fstat(parent_fd)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    stack.callback(os.close, fd)
    pinned = os.fstat(fd)
    again = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(pinned.st_mode)
            or pinned.st_uid != expected_uid or pinned.st_gid != os.fstat(parent_fd).st_gid
            or stat.S_IMODE(pinned.st_mode) != mode
            or pinned.st_dev != before.st_dev
            or _structural(named) != _structural(pinned)
            or _structural(again) != _structural(pinned)
            or _structural(before) != _structural(os.fstat(parent_fd))):
        _deny("OWNERSHIP_OR_MOUNT_UNVERIFIED")
    return fd, _structural(pinned)


def _lock_identity(directory_fd: int, uid: int) -> tuple[int, ...]:
    fd = os.open(LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                 getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    try:
        pinned = os.fstat(fd)
        named = os.stat(LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISREG(pinned.st_mode) or pinned.st_uid != uid
                or pinned.st_gid != os.fstat(directory_fd).st_gid
                or stat.S_IMODE(pinned.st_mode) != _LOCK_MODE
                or pinned.st_nlink != 1 or pinned.st_size != 0
                or pinned.st_dev != os.fstat(directory_fd).st_dev
                or _identity(pinned) != _identity(named)):
            _deny("LOCK_UNTRUSTED")
        return _structural(pinned)
    finally:
        os.close(fd)


def _dedicated_public_directory(fd: int, *, fresh: bool = False) -> None:
    """Fixed read-only context; only an exclusively created inode is labelled."""
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0)
            or stat.S_IMODE(info.st_mode) != (0o700 if fresh else 0o755)
            or set(os.listxattr(fd)) != {"security.selinux"}):
        _deny("DEDICATED_PUBLIC_METADATA_UNVERIFIED")
    if fresh:
        if os.listdir(fd):
            _deny("DEDICATED_PUBLIC_NOT_EMPTY")
        if os.getxattr(fd, "security.selinux").rstrip(b"\0") != _DEDICATED_PUBLIC_CONTEXT:
            os.setxattr(fd, "security.selinux", _DEDICATED_PUBLIC_CONTEXT + b"\0")
    if (set(os.listxattr(fd)) != {"security.selinux"}
            or (fresh and os.listdir(fd))
            or os.getxattr(fd, "security.selinux").rstrip(b"\0") != _DEDICATED_PUBLIC_CONTEXT):
        _deny("DEDICATED_PUBLIC_LABEL_UNVERIFIED")


def _dedicated_ancestry(root_fd: int, chain) -> None:
    for fd in (root_fd, *(child for _, _, child, _ in chain)):
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0)
                or info.st_mode & 0o022 or set(os.listxattr(fd)) != {"security.selinux"}
                or _mount(fd) != _mount(root_fd)):
            _deny("DEDICATED_PUBLIC_ANCESTRY_UNVERIFIED")


def _publish_directory_mode(parent: int, name: str, owner: int,
                            stack: ExitStack, *, mode: int,
                            dedicated_public: bool = False) -> None:
    os.mkdir(name, mode=_DIRECTORY_MODE, dir_fd=parent)
    fd, original = _verified_directory(parent, name, owner, stack, mode=_DIRECTORY_MODE)
    if dedicated_public:
        if name != _PUBLIC_NAME or _mount(fd) != _mount(parent):
            _deny("DEDICATED_PUBLIC_ANCESTRY_UNVERIFIED")
        _dedicated_public_directory(fd, fresh=True)
        if (_structural(os.fstat(fd)) != original
                or _structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) != original):
            _deny("DEDICATED_PUBLIC_CHANGED")
    os.fchmod(fd, mode)
    os.fsync(fd)
    os.fsync(parent)


def bootstrap_protected_namespace_under_root(
    root_fd: int, *, owner_uid: int,
    public_catalog: bool = False,
    _dedicated_public: bool = False,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Create ONLY /var/lib/repocache/server and its fixed lock in a fixture.

    Existing complete structure is verified, never replaced. Interrupted
    *incomplete* installation is refused, not silently adopted or cleaned.
    Caller-provided root FDs and UIDs are not proof of root or approval.
    The v0.6 layout optionally reserves an empty public catalog directory.
    Private dedicated mode is for a separately authenticated enforcing
    AlmaLinux candidate whose exact policy was already verified by its
    caller. It labels only a newly created public directory, never an
    existing inode. Neither mode establishes host or policy authority.
    No OS package, server state, NGINX, service, cache or TLS is modified.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or not 0 <= owner_uid <= 2**32 - 2
            or type(public_catalog) is not bool
            or type(_dedicated_public) is not bool
            or (_dedicated_public and (owner_uid != 0 or not public_catalog))
            or (inject_fault is not None and not callable(inject_fault))):
        _deny("ARGUMENT_INVALID")
    try:
        with ExitStack() as stack:
            lib_fd, chain = _walk(root_fd, _PARENT, stack, owner_uid)
            if not _dedicated_public and any(
                    name.startswith(_DEDICATED_WORKER_STAGE) for name in os.listdir(lib_fd)):
                _deny("DEDICATED_WORKER_STAGE_CONFLICT")
            if _dedicated_public:
                _dedicated_ancestry(root_fd, chain)
            # Existing /var/lib is an owned, non-world-writable native anchor.
            lib_before = _structural(_safe_directory(lib_fd, owner_uid))
            anchor_mode = _PUBLIC_PARENT_MODE if public_catalog else _DIRECTORY_MODE
            try:
                os.stat(_ROOT_NAME, dir_fd=lib_fd, follow_symlinks=False)
                fresh = False
            except FileNotFoundError:
                fresh = True
                _publish_directory_mode(lib_fd, _ROOT_NAME, owner_uid, stack,
                                        mode=anchor_mode)
                if inject_fault is not None:
                    inject_fault("root_dir_durable")
            repocache_fd, _ = _verified_directory(
                lib_fd, _ROOT_NAME, owner_uid, stack, mode=anchor_mode,
            )
            if _dedicated_public:
                _dedicated_ancestry(root_fd, [*chain, (lib_fd, _ROOT_NAME, repocache_fd, ())])
            if fresh:
                # A concurrent parent or preexisting child never becomes
                # an implicit third-party adoption.
                os.mkdir(_STATE_NAME, mode=_DIRECTORY_MODE, dir_fd=repocache_fd)
                os.fsync(repocache_fd)
                if inject_fault is not None:
                    inject_fault("state_dir_durable")
            state_fd, state_initial = _verified_directory(
                repocache_fd, _STATE_NAME, owner_uid, stack, mode=_DIRECTORY_MODE,
            )
            if public_catalog:
                if fresh:
                    _publish_directory_mode(repocache_fd, _PUBLIC_NAME,
                                            owner_uid, stack, mode=_PUBLIC_DIRECTORY_MODE,
                                            dedicated_public=_dedicated_public)
                public_fd, public_identity = _verified_directory(
                    repocache_fd, _PUBLIC_NAME, owner_uid, stack, mode=_PUBLIC_DIRECTORY_MODE)
                if _dedicated_public:
                    if _mount(public_fd) != _mount(repocache_fd):
                        _deny("DEDICATED_PUBLIC_ANCESTRY_UNVERIFIED")
                    _dedicated_public_directory(public_fd)
            if fresh:
                fd = os.open(LOCK_NAME, _CREATE_LOCK, _LOCK_MODE, dir_fd=state_fd)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(state_fd)
                if inject_fault is not None:
                    inject_fault("lock_durable")
            lock = _lock_identity(state_fd, owner_uid)
            # A newly created child directory legitimately increments its
            # parent's st_nlink on traditional Unix filesystems; some Linux
            # filesystems report a constant link count instead. Only this
            # narrowly accounted-for change is permitted for a fresh create.
            lib_after = _structural(_safe_directory(lib_fd, owner_uid))
            allowed_links = ({lib_before[5], lib_before[5] + 1}
                             if fresh else {lib_before[5]})
            if (_structural(os.fstat(state_fd)) != state_initial
                    or lib_after[:5] != lib_before[:5]
                    or lib_after[5] not in allowed_links):
                _deny("ANCESTRY_CHANGED")
            _recheck(chain[:-1], owner_uid)
            # Use exactly the real #31 state lock/identity checks; a second
            # writer cannot skip the existing serialized state boundary.
            with _locked(root_fd, owner_uid):
                if _lock_identity(state_fd, owner_uid) != lock:
                    _deny("LOCK_CHANGED")
                if not _dedicated_public and _DEDICATED_WORKER_CLAIM in os.listdir(state_fd):
                    _deny("DEDICATED_WORKER_CLAIM_REFUSED")
                if _dedicated_public:
                    _dedicated_ancestry(root_fd, [*chain, (lib_fd, _ROOT_NAME, repocache_fd, ()),
                                                 (repocache_fd, _STATE_NAME, state_fd, ())])
                    if (_mount(public_fd) != _mount(repocache_fd)
                            or _structural(os.fstat(public_fd)) != public_identity
                            or _structural(os.stat(_PUBLIC_NAME, dir_fd=repocache_fd,
                                                   follow_symlinks=False)) != public_identity):
                        _deny("DEDICATED_PUBLIC_CHANGED")
                    _dedicated_public_directory(public_fd)
            return {
                "schema_version": 1,
                "status": ("FRESH_PROTECTED_LOCK_DURABLE"
                           if fresh else "EXISTING_PROTECTED_LOCK_VALIDATED"),
                "state_directory_created": fresh,
                "state_lock_validated": True,
                **({"dedicated_public_label_verified": True} if _dedicated_public else {}),
                "host_root_provenance_authenticated": False,
                "operator_authorization_authenticated": False,
                "installed_release_authenticated": False,
                "authorizes_installation": False,
                "authorizes_state_write": False,
                "authorizes_nginx_activation": False,
            }
    except ProtectedBootstrapError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("UNVERIFIED_STATE")

# Private signed-worker placement composition. Neither namespace helper
# authenticates a release or a host.
_DEDICATED_WORKER_CLAIM = ".native-worker-dedicated-namespace-v1.json"
_DEDICATED_WORKER_STAGE = ".repocache-worker-namespace.stage-"
_WORKER_PLACEMENT_PREFIX = ".native-worker-placement."


def _dedicated_worker_claim_bytes(root, anchor, state, public, receipt_sha256):
    def inode(fd):
        info = os.fstat(fd)
        return [info.st_dev, info.st_ino]

    return (json.dumps({
        "schema": 1,
        "worker_receipt_sha256": receipt_sha256,
        "root": inode(root),
        "namespace": inode(anchor),
        "state": inode(state),
        "public": inode(public),
        "lock": list(_lock_identity(state, 0)[:2]),
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _require_dedicated_worker_claim(root, anchor, state, public, receipt_sha256, *, staged=False):
    """Require the exact durable claim, and any placement marker that exists."""
    if (type(receipt_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", receipt_sha256) is None
            or type(staged) is not bool):
        _deny("DEDICATED_WORKER_CLAIM_INVALID")
    for fd in (root, anchor, state, public):
        _dedicated_ancestry(root, [(None, None, fd, ())])
    if (stat.S_IMODE(os.fstat(anchor).st_mode) not in ((0o700, 0o711) if staged else (0o711,))
            or stat.S_IMODE(os.fstat(state).st_mode) != 0o700
            or _structural(os.stat(_STATE_NAME, dir_fd=anchor, follow_symlinks=False))
               != _structural(os.fstat(state))
            or _structural(os.stat(_PUBLIC_NAME, dir_fd=anchor, follow_symlinks=False))
               != _structural(os.fstat(public))):
        _deny("DEDICATED_WORKER_NAMESPACE_CHANGED")
    _dedicated_public_directory(public)
    expected = _dedicated_worker_claim_bytes(root, anchor, state, public, receipt_sha256)
    if (_read_file(state, _DEDICATED_WORKER_CLAIM, 0, 1024) != expected
            or os.stat(_DEDICATED_WORKER_CLAIM, dir_fd=state, follow_symlinks=False).st_gid != 0):
        _deny("DEDICATED_WORKER_CLAIM_REFUSED")
    pending = _WORKER_PLACEMENT_PREFIX + "pending-" + receipt_sha256
    complete = _WORKER_PLACEMENT_PREFIX + "complete-" + receipt_sha256
    names = set(os.listdir(state))
    markers = {name for name in names if name.startswith(_WORKER_PLACEMENT_PREFIX)}
    if markers - {pending, complete} or (staged and markers):
        _deny("DEDICATED_WORKER_MARKER_REFUSED")
    for marker in markers:
        if (_read_file(state, marker, 0, 0) != b""
                or os.stat(marker, dir_fd=state, follow_symlinks=False).st_gid != 0):
            _deny("DEDICATED_WORKER_MARKER_REFUSED")
    if staged or complete not in markers:
        # The namespace claim is deliberately distinct from the placement
        # pending marker. A retry before worker placement still has to prove
        # that all worker/unit destinations are absent under the lock.
        allowed = {LOCK_NAME, _DEDICATED_WORKER_CLAIM}
        if markers == {pending}:
            allowed |= {pending, ".native-worker-receipt-v1.json",
                        ".repocache-worker-part-.native-worker-receipt-v1.json"}
        if (names - allowed or os.listdir(public)
                or set(os.listdir(anchor)) != {_STATE_NAME, _PUBLIC_NAME}):
            _deny("DEDICATED_WORKER_FOREIGN_NAMESPACE")


def _prepare_dedicated_worker_namespace_under_root(root_fd, *, receipt_sha256, inject_fault=None):
    """Atomically publish a fresh labelled namespace with its durable receipt claim.

    A complete staged namespace can resume publication. An incomplete or
    foreign stage, legacy namespace or unmatched claim is never adopted,
    relabelled, replaced or removed. Actual host/release/policy authentication
    belongs to the caller; this private descriptor seam grants no authority.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(receipt_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", receipt_sha256) is None
            or (inject_fault is not None and not callable(inject_fault))):
        _deny("ARGUMENT_INVALID")
    stage = _DEDICATED_WORKER_STAGE + receipt_sha256
    def point(step):
        if inject_fault is not None:
            inject_fault(step)

    def write_private(directory, name, raw):
        fd = os.open(name, _CREATE_LOCK, _LOCK_MODE, dir_fd=directory)
        try:
            os.fchmod(fd, _LOCK_MODE)
            if os.write(fd, raw) != len(raw):
                _deny("DEDICATED_WORKER_CLAIM_WRITE_FAILED")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)

    try:
        with ExitStack() as stack:
            lib, chain = _walk(root_fd, _PARENT, stack, 0)
            original_lib = _structural(os.fstat(lib))

            def recheck_lib():
                _recheck(chain[:-1], 0)
                _dedicated_ancestry(root_fd, chain)
                parent, name, _, _ = chain[-1]
                if (_structural(os.fstat(lib))[:5] != original_lib[:5]
                        or _structural(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5]
                           != original_lib[:5]):
                    _deny("DEDICATED_WORKER_PARENT_CHANGED")

            recheck_lib()
            names = set(os.listdir(lib))
            stages = {name for name in names if name.startswith(_DEDICATED_WORKER_STAGE)}
            if stages - {stage} or (stages and _ROOT_NAME in names):
                _deny("DEDICATED_WORKER_STAGE_CONFLICT")
            published = _ROOT_NAME in names
            selected = _ROOT_NAME if published else stage
            if not published and not stages:
                os.mkdir(stage, 0o700, dir_fd=lib)
                os.fsync(lib)
                point("stage_directory_durable")
                anchor, _ = _verified_directory(lib, stage, 0, stack, mode=0o700)
                _dedicated_ancestry(root_fd, [*chain, (lib, stage, anchor, ())])
                os.mkdir(_STATE_NAME, 0o700, dir_fd=anchor)
                os.fsync(anchor)
                state, _ = _verified_directory(anchor, _STATE_NAME, 0, stack, mode=0o700)
                _dedicated_ancestry(root_fd, [*chain, (lib, stage, anchor, ()),
                                             (anchor, _STATE_NAME, state, ())])
                _publish_directory_mode(anchor, _PUBLIC_NAME, 0, stack,
                                        mode=0o755, dedicated_public=True)
                public, _ = _verified_directory(anchor, _PUBLIC_NAME, 0, stack, mode=0o755)
                write_private(state, LOCK_NAME, b"")
                write_private(state, _DEDICATED_WORKER_CLAIM, _dedicated_worker_claim_bytes(
                    root_fd, anchor, state, public, receipt_sha256))
                os.fsync(anchor)
                point("stage_claim_durable")
            else:
                mode = stat.S_IMODE(os.stat(selected, dir_fd=lib, follow_symlinks=False).st_mode)
                if mode not in ((0o711,) if published else (0o700, 0o711)):
                    _deny("DEDICATED_WORKER_STAGE_MODE_REFUSED")
                anchor, _ = _verified_directory(lib, selected, 0, stack, mode=mode)
                state, _ = _verified_directory(anchor, _STATE_NAME, 0, stack, mode=0o700)
                public, _ = _verified_directory(anchor, _PUBLIC_NAME, 0, stack, mode=0o755)

            lock = os.open(LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                           os.O_CLOEXEC, dir_fd=state)
            stack.callback(os.close, lock)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            stack.callback(fcntl.flock, lock, fcntl.LOCK_UN)
            if _structural(os.fstat(lock)) != _lock_identity(state, 0):
                _deny("DEDICATED_WORKER_LOCK_CHANGED")

            def verify(name, *, staged):
                recheck_lib()
                present = set(os.listdir(lib))
                stages = {entry for entry in present if entry.startswith(_DEDICATED_WORKER_STAGE)}
                if stages != ({stage} if staged else set()) or (staged and _ROOT_NAME in present):
                    _deny("DEDICATED_WORKER_STAGE_CONFLICT")
                if (_structural(os.stat(name, dir_fd=lib, follow_symlinks=False))
                        != _structural(os.fstat(anchor))
                        or _structural(os.fstat(lock)) != _lock_identity(state, 0)):
                    _deny("DEDICATED_WORKER_NAMESPACE_CHANGED")
                _require_dedicated_worker_claim(root_fd, anchor, state, public,
                                                receipt_sha256, staged=staged)

            verify(selected, staged=not published)
            if not published:
                # Set the final traversal mode only after verifying the
                # complete private claim. No existing unclaimed inode changes.
                if stat.S_IMODE(os.fstat(anchor).st_mode) != 0o711:
                    os.fchmod(anchor, 0o711)
                    os.fsync(anchor)
                verify(stage, staged=True)
                point("before_namespace_publish")
                verify(stage, staged=True)
                _rename_directory_noreplace(lib, stage, lib, _ROOT_NAME)
                os.fsync(lib)
                point("namespace_published")
                if stage in os.listdir(lib):
                    _deny("DEDICATED_WORKER_STAGE_CONFLICT")
            verify(_ROOT_NAME, staged=False)
            return {
                "status": ("EXISTING_DEDICATED_WORKER_NAMESPACE_VERIFIED" if published
                           else "FRESH_DEDICATED_WORKER_NAMESPACE_DURABLE"),
                "dedicated_public_label_verified": True,
                "worker_receipt_claim_verified": True,
                "authorizes_host_installation": False,
                "authorizes_nginx_activation": False,
            }
    except ProtectedBootstrapError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("DEDICATED_WORKER_NAMESPACE_REFUSED")
