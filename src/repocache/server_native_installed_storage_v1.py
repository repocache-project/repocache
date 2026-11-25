"""Fixed installed NGINX storage, for the signed installer under its state lock.

This is not a socket operation. The caller must authenticate the release,
package, owned configuration and operator, and retain the existing state lock.
No existing object is relabeled, chowned, deleted or adopted without a marker.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
import os
import pwd
import stat
import subprocess

_CACHE = ("var", "cache", "nginx")
_LOG = ("var", "log", "nginx")
_LEAF = "repocache-managed"
_MARKER = ".repocache-managed.owner-v1"
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC


class InstalledStorageError(ValueError):
    """Fixed refusal code; never expose host paths or labels."""


def _deny(code):
    raise InstalledStorageError("INSTALLED_NGINX_STORAGE_" + code)


def _identity(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid


def _mount(fd):
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
        rows = [line.split()[1] for line in stream if line.startswith("mnt_id:")]
    if len(rows) != 1 or not rows[0].isascii() or not rows[0].isdecimal():
        _deny("MOUNT_UNVERIFIED")
    return rows[0]


def _same(parent, name, fd):
    st = os.fstat(fd)
    if (_identity(st) != _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
            or _mount(fd) != _mount(parent)):
        _deny("PATH_OR_MOUNT_CHANGED")
    return st


def _named(parent, name):
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


class _Labels:
    def __init__(self, distribution):
        if distribution not in ("debian", "almalinux"):
            _deny("TARGET_UNVERIFIED")
        self.enforcing = distribution == "almalinux"
        if self.enforcing and self._command("/usr/sbin/getenforce") != b"Enforcing":
            _deny("SELINUX_NOT_ENFORCING")

    @staticmethod
    def _command(*args):
        result = subprocess.run(args, check=True, capture_output=True, timeout=10,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                                stdin=subprocess.DEVNULL, cwd="/")
        return result.stdout.strip()

    def check(self, fd, path=None, expected_type=None, *, fresh=False):
        names = set(os.listxattr(fd))
        if not self.enforcing:
            if names:
                _deny("XATTR_UNVERIFIED")
            return
        if names != {"security.selinux"}:
            _deny("XATTR_UNVERIFIED")
        current = os.getxattr(fd, "security.selinux").rstrip(b"\x00")
        if not current:
            _deny("SELINUX_LABEL_UNVERIFIED")
        if path is None:
            return  # Root-owned ancestry: reject additional xattrs, never relabel.
        expected = self._command("/usr/sbin/matchpathcon", "-n", path)
        parts = expected.split(b":", 3)
        if (len(parts) != 4 or parts[2] != expected_type or len(expected) > 1024
                or any(c < 33 or c > 126 for c in expected)):
            _deny("SELINUX_POLICY_UNSUPPORTED")
        if fresh and current != expected:
            # Descriptor-pinned label assignment, only to a newly created inode.
            os.setxattr(fd, "security.selinux", expected + b"\x00")
            current = os.getxattr(fd, "security.selinux").rstrip(b"\x00")
        if current != expected:
            _deny("SELINUX_LABEL_UNVERIFIED")

    def finish(self):
        if self.enforcing and self._command("/usr/sbin/getenforce") != b"Enforcing":
            _deny("SELINUX_NOT_ENFORCING")


def _root_owned(fd, owner, labels):
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != owner or st.st_mode & 0o022:
        _deny("PARENT_UNSAFE")
    labels.check(fd)
    return _identity(st)


def _walk(root, segments, owner, labels, stack):
    chain = []
    parent = root
    for name in segments:
        fd = os.open(name, _DIR, dir_fd=parent)
        stack.callback(os.close, fd)
        _same(parent, name, fd)
        chain.append((parent, name, fd, _root_owned(fd, owner, labels)))
        parent = fd
    return parent, chain


def _recheck(chain, owner, labels):
    for parent, name, fd, identity in chain:
        if (_identity(_same(parent, name, fd)) != identity
                or _root_owned(fd, owner, labels) != identity):
            _deny("PARENT_CHANGED")


def _record(kind, st):
    return json.dumps({"schema": 1, "kind": kind, "dev": st.st_dev, "ino": st.st_ino,
                       "uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)},
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def _verify(parent, kind, uid, gid, mode, owner, owner_gid, labels, path, label_type):
    fd = os.open(_LEAF, _DIR, dir_fd=parent)
    try:
        st = _same(parent, _LEAF, fd)
        if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, mode):
            _deny("ROOT_METADATA_UNSAFE")
        labels.check(fd, path, label_type)
        if os.fstatvfs(fd).f_flag & os.ST_RDONLY:
            _deny("READ_ONLY")
        marker = os.open(_MARKER, _READ, dir_fd=parent)
        try:
            before = _same(parent, _MARKER, marker)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
                    != (owner, owner_gid, 0o600) or not 1 <= before.st_size <= 1024):
                _deny("MARKER_UNSAFE")
            labels.check(marker)
            raw = os.read(marker, 1025)
            after = _same(parent, _MARKER, marker)
            if (raw != _record(kind, st) or before.st_size != len(raw)
                    or before.st_ctime_ns != after.st_ctime_ns
                    or before.st_mtime_ns != after.st_mtime_ns
                    or _identity(before) != _identity(after) or after.st_nlink != 1):
                _deny("MARKER_MISMATCH")
        finally:
            os.close(marker)
        if _identity(_same(parent, _LEAF, fd)) != _identity(st):
            _deny("ROOT_CHANGED")
        labels.check(fd, path, label_type)
    finally:
        os.close(fd)


def _create(parent, kind, uid, gid, mode, owner, owner_gid, labels, path, label_type):
    # O_EXCL marker and mkdir; partial progress is never adopted on retry.
    os.mkdir(_LEAF, 0o700, dir_fd=parent)
    os.fsync(parent)
    fd = os.open(_LEAF, _DIR, dir_fd=parent)
    try:
        st = _same(parent, _LEAF, fd)
        if st.st_uid != owner or stat.S_IMODE(st.st_mode) != 0o700:
            _deny("FRESH_ROOT_UNSAFE")
        labels.check(fd, path, label_type, fresh=True)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        os.fsync(fd)
        st = _same(parent, _LEAF, fd)
        if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, mode):
            _deny("ROOT_METADATA_UNSAFE")
        marker = os.open(_MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            os.fchown(marker, owner, owner_gid)
            os.fchmod(marker, 0o600)
            labels.check(marker)
            raw = _record(kind, st)
            if os.write(marker, raw) != len(raw):
                _deny("MARKER_WRITE_INCOMPLETE")
            os.fsync(marker)
        finally:
            os.close(marker)
        os.fsync(parent)
    finally:
        os.close(fd)
    _verify(parent, kind, uid, gid, mode, owner, owner_gid, labels, path, label_type)


def _prepare_under_root(root, *, owner, owner_gid, uid, gid, labels, allow_create):
    """Private descriptor seam; the production entry always opens real root."""
    if type(allow_create) is not bool:
        _deny("ARGUMENT_INVALID")
    try:
        identity = _root_owned(root, owner, labels)
        with ExitStack() as stack:
            targets = []
            for kind, segments, leaf_uid, leaf_gid, mode, label_type in (
                ("cache", _CACHE, uid, gid, 0o700, b"httpd_cache_t"),
                ("log", _LOG, owner, owner_gid, 0o750, b"httpd_log_t"),
            ):
                parent, chain = _walk(root, segments, owner, labels, stack)
                path = "/" + "/".join((*segments, _LEAF))
                labels.check(parent, "/" + "/".join(segments), label_type)
                args = (parent, kind, leaf_uid, leaf_gid, mode, owner, owner_gid,
                        labels, path, label_type)
                leaf, marker = _named(parent, _LEAF), _named(parent, _MARKER)
                if (leaf is None) != (marker is None):
                    _deny("PARTIAL_OR_FOREIGN_ROOT")
                if leaf is not None:
                    _verify(*args)
                elif not allow_create:
                    _deny("OWNED_ROOT_MISSING")
                targets.append((chain, args, leaf is None))
            # Inspect both targets before creating either; never adopt foreign data.
            for chain, args, fresh in targets:
                _recheck(chain, owner, labels)
                if fresh:
                    _create(*args)
                _recheck(chain, owner, labels)
            for chain, args, _ in targets:
                _verify(*args)
                _recheck(chain, owner, labels)
        if _root_owned(root, owner, labels) != identity:
            _deny("ROOT_CHANGED")
        labels.finish()
        return {"cache_root_verified": True, "log_root_verified": True,
                "selinux_enforcing_labels_verified": labels.enforcing,
                "actual_service_write_verified": False}
    except InstalledStorageError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _deny("UNVERIFIED")


def prepare_installed_storage(distribution, *, allow_create):
    """Only called inside the existing authenticated installer/state lock."""
    if os.getresuid() != (0, 0, 0) or distribution not in ("debian", "almalinux"):
        _deny("HOST_UNVERIFIED")
    try:
        worker = pwd.getpwnam("www-data" if distribution == "debian" else "nginx")
        if not (0 < worker.pw_uid < 2**32 - 1 and 0 < worker.pw_gid < 2**32 - 1):
            _deny("WORKER_IDENTITY_UNVERIFIED")
        labels = _Labels(distribution)
        fd = os.open("/", _DIR)
        try:
            return _prepare_under_root(fd, owner=0, owner_gid=0, uid=worker.pw_uid,
                                       gid=worker.pw_gid, labels=labels, allow_create=allow_create)
        finally:
            os.close(fd)
    except InstalledStorageError:
        raise
    except (OSError, KeyError, ValueError, subprocess.SubprocessError):
        _deny("UNVERIFIED")


def verify_control_storage(distribution):
    """Read-only fixed storage proof for the authenticated confined broker.

    The caller retains the original state lock and has already authenticated
    initial-root, installed worker/unit and package provenance. The broker's
    bind-mounted view is not the installer's original mount namespace.
    Never enter another namespace, create, relabel or adopt storage here.
    """
    if (os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
            or distribution not in ("debian", "almalinux")):
        _deny("HOST_UNVERIFIED")
    try:
        worker = pwd.getpwnam("www-data" if distribution == "debian" else "nginx")
        if not (0 < worker.pw_uid < 2**32 - 1 and 0 < worker.pw_gid < 2**32 - 1):
            _deny("WORKER_IDENTITY_UNVERIFIED")
        labels = _Labels(distribution)
        namespace = _identity(os.stat("/proc/1/ns/mnt"))
        # The one fixed kernel-owned proc link is intentionally followed.
        # All descendants are opened through _walk/_verify without symlinks.
        fd = os.open("/proc/1/root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            if _identity(os.fstat(fd)) != _identity(os.stat("/")):
                _deny("HOST_ROOT_CHANGED")
            result = _prepare_under_root(
                fd, owner=0, owner_gid=0, uid=worker.pw_uid,
                gid=worker.pw_gid, labels=labels, allow_create=False,
            )
            if (_identity(os.stat("/proc/1/root")) != _identity(os.fstat(fd))
                    or _identity(os.stat("/proc/1/ns/mnt")) != namespace):
                _deny("HOST_ROOT_CHANGED")
            return result
        finally:
            os.close(fd)
    except InstalledStorageError:
        raise
    except (OSError, KeyError, ValueError, TypeError, subprocess.SubprocessError):
        _deny("UNVERIFIED")


def verify_service_storage_mounts(pid):
    """Confirm the owned master's view of fixed paths, without entering its namespace."""
    if type(pid) is not int or not 2 <= pid < 2**31 or os.getresuid() != (0, 0, 0):
        _deny("SERVICE_IDENTITY_UNVERIFIED")
    try:
        with ExitStack() as stack:
            namespace = os.stat(f"/proc/{pid}/ns/mnt")
            if _identity(namespace) == _identity(os.stat("/proc/self/ns/mnt")):
                _deny("SERVICE_MOUNT_NAMESPACE_UNVERIFIED")
            root = os.open(f"/proc/{pid}/root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, root)
            for segments in (_CACHE, _LOG, ("etc", "nginx")):
                parent = root
                for name in segments:
                    fd = os.open(name, _DIR, dir_fd=parent)
                    stack.callback(os.close, fd)
                    parent = fd
                if not os.fstatvfs(parent).f_flag & os.ST_RDONLY:
                    _deny("SERVICE_PARENT_WRITABLE")
                if segments in (_CACHE, _LOG):
                    leaf = os.open(_LEAF, _DIR, dir_fd=parent)
                    stack.callback(os.close, leaf)
                    if os.fstatvfs(leaf).f_flag & os.ST_RDONLY:
                        _deny("SERVICE_STORAGE_READ_ONLY")
                    host = os.stat("/" + "/".join((*segments, _LEAF)), follow_symlinks=False)
                    if _identity(host) != _identity(os.fstat(leaf)):
                        _deny("SERVICE_STORAGE_IDENTITY_CHANGED")
            if _identity(namespace) != _identity(os.stat(f"/proc/{pid}/ns/mnt")):
                _deny("SERVICE_MOUNT_NAMESPACE_CHANGED")
    except InstalledStorageError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("SERVICE_MOUNT_UNVERIFIED")
