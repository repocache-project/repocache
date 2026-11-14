"""Read-only native package-manager lock observation for #24.

This is a conservative diagnostic, not a lock acquisition, package manager
interlock, authorization to write /etc or protection against a later race.
It never creates, truncates, unlinks or acquires native package lock files.
A future root transaction must obtain its own exclusive lock and prove native
package-manager exclusion again at the actual protected commit boundary.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import re
import stat
from pathlib import Path

APT = (
    "var/lib/dpkg/lock-frontend",
    "var/lib/dpkg/lock",
    "var/lib/apt/lists/lock",
    "var/cache/apt/archives/lock",
)
DNF5 = (
    "run/dnf/rpmtransaction.lock",
    "usr/lib/sysimage/rpm/.rpm.lock",
)
_LINE = re.compile(
    r"^\s*\d+:\s*(?:->\s*)?(?:POSIX|FLOCK|OFDLCK|LEASE)\s+"
    r"(?:ADVISORY|MANDATORY)\s+(?:READ|WRITE|UNLCK)\s+"
    r"(?:-?\d+)\s+([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)\s+"
    r"(?:\d+|EOF)\s+(?:\d+|EOF)\s*$"
)


class LockInspectionRefused(ValueError):
    """A required lock cannot be inspected without ambiguity."""


def _active_records(text: str) -> set[tuple[int, int, int]]:
    """Parse Linux /proc/locks strictly; uncertain entries refuse the probe."""
    if type(text) is not str or len(text) > 1_000_000:
        raise LockInspectionRefused("Native lock table unavailable")
    observed = set()
    for line in text.splitlines():
        match = _LINE.fullmatch(line)
        if match is None:
            raise LockInspectionRefused("Unrecognized native lock table record")
        observed.add((int(match[1], 16), int(match[2], 16), int(match[3])))
    return observed


def _pinned_lock_stat(root: Path, relative: str, *, owner: int):
    """Inspect a native lock leaf through pinned nofollow parent dirfds."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    opened = []
    try:
        current = os.open(root, flags)
        opened.append(current)
        for part in relative.split("/")[:-1]:
            parent = os.fstat(current)
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner
                    or stat.S_IMODE(parent.st_mode) & 0o022):
                raise LockInspectionRefused("Unsafe native lock parent")
            current = os.open(part, flags, dir_fd=current)
            opened.append(current)
        parent = os.fstat(current)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner
                or stat.S_IMODE(parent.st_mode) & 0o022):
            raise LockInspectionRefused("Unsafe native lock directory")
        return os.stat(relative.rsplit("/", 1)[-1], dir_fd=current,
                       follow_symlinks=False)
    finally:
        for fd in reversed(opened):
            os.close(fd)


def inspect_native_locks(manager: str, *, root: Path = Path("/"),
                         proc_locks: str | None = None) -> dict:
    """Inspect fixed native lock-file inodes without writing or assuming safety.

    For the native host, read /proc/locks. An explicit proc_locks value is
    accepted *only for non-root test fixtures* and cannot certify a host.
    A missing lock path is NOT VERIFIED, not proof that the manager is idle.
    """
    if manager not in ("apt", "dnf5") or type(manager) is not str:
        raise LockInspectionRefused("Unsupported package manager")
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts:
        raise LockInspectionRefused("Invalid inspection root")
    native = root == Path("/")
    if native:
        if proc_locks is not None:
            raise LockInspectionRefused("Cannot override native lock table")
        try:
            table = Path("/proc/locks").read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise LockInspectionRefused("Native lock observation unavailable") from exc
    else:
        # The caller may pass an explicit synthetic lock table only in tests.
        if proc_locks is None:
            raise LockInspectionRefused("Non-native inspection needs test data")
        table = proc_locks
    locked = _active_records(table)
    identities = set()
    missing = []
    busy = []
    checked = APT if manager == "apt" else DNF5
    for relative in checked:
        try:
            observed = _pinned_lock_stat(
                root, relative, owner=0 if native else os.geteuid())
        except FileNotFoundError:
            missing.append(relative)
            continue
        except OSError as exc:
            raise LockInspectionRefused("Native lock inode unavailable") from exc
        if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1
                or observed.st_uid != (0 if native else os.geteuid())):
            raise LockInspectionRefused("Unsafe package-manager lock inode")
        identity = (os.major(observed.st_dev), os.minor(observed.st_dev),
                    observed.st_ino)
        if identity in identities:
            raise LockInspectionRefused("Aliased package-manager lock inode")
        identities.add(identity)
        if identity in locked:
            busy.append(relative)
    # This is a snapshot only. Never emit a write_eligible=True result.
    return {
        "manager": manager,
        "observed_files": len(identities),
        "expected_files": len(checked),
        "missing": tuple(missing),
        "busy": tuple(busy),
        "status": ("BUSY" if busy else "NOT_VERIFIED" if missing
                   else "OBSERVED_UNCONTENDED"),
        "snapshot_only": True,
        "native_host": native,
        "exclusive_lock_held": False,
        "write_eligible": False,
    }



@contextlib.contextmanager
def hold_existing_native_package_locks(
    manager: str, *, root: Path = Path("/"),
):
    """Hold real nonblocking POSIX and BSD locks on fixed existing inodes.

    This is a narrowly scoped *kernel synchronization primitive*, not
    package-manager lock ownership attestation or client write permission.
    It does not create files or accept caller paths. Only an already trusted
    root-owned installer can invoke it on /, and it must separately verify
    its approval, package-manager state, SELinux and source transaction.
    Tests may use a private non-native root to exercise real lock contention.
    No call to this function is wired into the installed client CLI.
    """
    if type(manager) is not str or manager not in ("apt", "dnf5"):
        raise LockInspectionRefused("Unsupported package manager")
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts or root.is_symlink():
        raise LockInspectionRefused("Invalid native lock root")
    native = root == Path("/")
    if native and os.geteuid() != 0:
        raise LockInspectionRefused("Native lock scope requires root")
    if not native and (
        root in (Path("/tmp"), Path("/var/tmp"))
        or not any(parent in (Path("/tmp"), Path("/var/tmp"))
                   for parent in root.parents)
        or root.resolve(strict=True) != root
    ):
        raise LockInspectionRefused("Only private disposable roots are supported")
    expected_owner = 0 if native else os.geteuid()
    expected_group = 0 if native else os.getegid()
    targets = APT if manager == "apt" else DNF5
    directories = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    held: list[int] = []
    identities: set[tuple[int, int]] = set()
    try:
        for relative in targets:
            parents: list[int] = []
            try:
                fd = os.open(root, directories)
                parents.append(fd)
                for segment in relative.split("/")[:-1]:
                    info = os.fstat(fd)
                    if (not stat.S_ISDIR(info.st_mode)
                            or info.st_uid != expected_owner
                            or stat.S_IMODE(info.st_mode) & 0o022):
                        raise LockInspectionRefused("Unsafe native lock parent")
                    fd = os.open(segment, directories, dir_fd=fd)
                    parents.append(fd)
                pstat = os.fstat(fd)
                if (not stat.S_ISDIR(pstat.st_mode)
                        or pstat.st_uid != expected_owner
                        or stat.S_IMODE(pstat.st_mode) & 0o022):
                    raise LockInspectionRefused("Unsafe native lock directory")
                leaf = relative.rsplit("/", 1)[-1]
                lockfd = os.open(leaf, flags, dir_fd=fd)
                held.append(lockfd)
                named = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
                before = os.fstat(lockfd)
                identity = (before.st_dev, before.st_ino)
                if (not stat.S_ISREG(before.st_mode)
                        or before.st_nlink != 1
                        or before.st_uid != expected_owner
                        or before.st_gid != expected_group
                        or stat.S_IMODE(before.st_mode) & 0o022
                        or before.st_size > 4096
                        or identity != (named.st_dev, named.st_ino)
                        or identity in identities):
                    raise LockInspectionRefused("Unsafe native lock inode")
                identities.add(identity)
                # Linux flock and POSIX byte-range locks are independent.
                # Holding both covers cooperating tools using either family.
                # A lock conflict is a hard refusal, never a retry or wait.
                fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.lockf(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                after = os.fstat(lockfd)
                named_after = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
                if ((after.st_dev, after.st_ino, after.st_uid, after.st_gid,
                     after.st_mode, after.st_nlink, after.st_size)
                    != (before.st_dev, before.st_ino, before.st_uid,
                        before.st_gid, before.st_mode, before.st_nlink,
                        before.st_size)
                    or (named_after.st_dev, named_after.st_ino) != identity):
                    raise LockInspectionRefused("Native lock inode changed")
            finally:
                for parent in reversed(parents):
                    os.close(parent)
        # Do not return an eternal write_eligible token. The only proof
        # of locks is their lifetime inside this context manager.
        yield
    except (OSError, OverflowError, TypeError) as exc:
        raise LockInspectionRefused("Native package lock scope unavailable") from exc
    finally:
        # Closing each fd releases both of its kernel lock families.
        # Attempt every close even if one fails; never leak held lock FDs.
        close_error = False
        for lockfd in reversed(held):
            try:
                os.close(lockfd)
            except OSError:
                close_error = True
        if close_error:
            raise LockInspectionRefused("Native package lock release unverified")
