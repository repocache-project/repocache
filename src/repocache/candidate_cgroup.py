"""Strict cgroup-v2 delegation/resource preflight for online candidates (#112).

This is deliberately NOT a candidate launcher. A future executor must attach
the entire child process tree to a freshly limited cgroup before *any*
untrusted exec and kill/drain it afterward. The current bwrap prototype is
NON-ACTIVATING; no absence of cgroups may be interpreted as permission to
run an online candidate in production.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path


class CgroupGateError(RuntimeError):
    """A mandatory resource-containment prerequisite is missing or untrusted."""


CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_CGROUP = Path("/proc/self/cgroup")
PROC_MOUNTINFO = Path("/proc/self/mountinfo")
MANAGER_LEAF = "repocache-manager"
CANDIDATE_SUBTREE = "repocache-candidates"
REQUIRED_CONTROLLERS = frozenset(("cpu", "memory", "pids"))
# These are aggregate limits for an eventual dedicated *candidate* leaf,
# not per-process RLIMITs or staging filesystem quotas.
LEAF_LIMITS = {
    "cpu.max": "200000 100000",
    "memory.max": str(1024 * 1024 * 1024),
    "memory.swap.max": "0",
    "pids.max": "64",
}


@dataclass(frozen=True)
class Delegation:
    """Preflight-verified manager path and dedicated empty candidate subtree."""
    service: Path
    manager: Path
    candidates: Path


def _read(path: Path) -> str:
    try:
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            raise CgroupGateError("Untrusted cgroup control file")
        return path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise CgroupGateError("Cannot inspect required cgroup control") from exc


def _directory(path: Path, *, owned: bool = False) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CgroupGateError("Missing cgroup-v2 service delegation") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CgroupGateError("Untrusted cgroup delegation path")
    if owned and (metadata.st_uid != os.geteuid()
                  or metadata.st_mode & 0o022):
        raise CgroupGateError("Shared or unowned candidate cgroup delegation")


def _mount_is_v2(root: Path, mountinfo: str) -> bool:
    # Kernel mountinfo has exactly one ' - ' separator per entry.
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        left, right = before.split(), after.split()
        if (separator and len(left) > 5 and len(right) >= 3
                and left[4] == str(root) and right[0] == "cgroup2"):
            return True
    return False


def _service_from_self(root: Path, proc_cgroup: str) -> tuple[Path, Path]:
    lines = proc_cgroup.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise CgroupGateError("Unified cgroup v2 service identity is unavailable")
    relative = lines[0][4:]
    # Never accept a proc-cgroup path with ambiguous or traversal components.
    components = relative.split("/")
    if (len(components) < 3 or components[-1] != MANAGER_LEAF
            or any(not part or part in (".", "..") or
                   not re.fullmatch(r"[A-Za-z0-9_.@-]+", part)
                   for part in components)):
        raise CgroupGateError("Unexpected cgroup service manager location")
    if not re.fullmatch(r"repocache(?:-[a-z0-9-]+)?\.service",
                        components[-2]):
        raise CgroupGateError("Candidate runner is outside its dedicated service")
    manager = root.joinpath(*components)
    return manager.parent, manager


def require_delegation(*, root: Path = CGROUP_ROOT,
                       proc_cgroup: Path = PROC_CGROUP,
                       mountinfo: Path = PROC_MOUNTINFO) -> Delegation:
    """Read-only gate for an explicitly provisioned delegated systemd service.

    The service manager must already be in the 'repocache-manager' leaf,
    leaving its sibling 'repocache-candidates' empty with cpu/memory/pids
    controllers enabled by its service manager. Never change systemd or
    parent cgroup permissions from the unprivileged updater.
    """
    if os.geteuid() == 0:
        raise CgroupGateError("Online candidate resource manager cannot run as root")
    if not _mount_is_v2(root, _read(mountinfo)):
        raise CgroupGateError("Unified cgroup v2 mount is required")
    service, manager = _service_from_self(root, _read(proc_cgroup))
    candidates = service / CANDIDATE_SUBTREE
    _directory(root)
    current = root
    for part in manager.relative_to(root).parts:
        current = current / part
        _directory(current)
    _directory(service, owned=True)
    _directory(manager, owned=True)
    _directory(candidates, owned=True)
    for node in (service, candidates):
        available = set(_read(node / "cgroup.subtree_control").split())
        if not REQUIRED_CONTROLLERS.issubset(available):
            raise CgroupGateError("Missing delegated cpu/memory/pids controllers")
    if _read(candidates / "cgroup.procs").strip():
        raise CgroupGateError("Candidate cgroup parent contains processes")
    # cgroup-v2 controller files and cgroup.kill must exist before accepting
    # a delegated subtree. Group limits will be applied to individual leaves.
    for control in (*LEAF_LIMITS, "cgroup.kill", "cgroup.procs"):
        _read(candidates / control)
    if not os.access(candidates, os.W_OK):
        raise CgroupGateError("Candidate cgroup subtree is read-only")
    return Delegation(service=service, manager=manager, candidates=candidates)


def write_leaf_limits(leaf: Path) -> None:
    """Configure an *empty* new leaf; never claim it launches a process.

    A future supervised launcher must create this leaf under an accepted
    Delegation, attach before exec, and fail closed on any write/readback
    mismatch. No caller may use this as a standalone isolation mechanism.
    """
    _directory(leaf, owned=True)
    if _read(leaf / "cgroup.procs").strip():
        raise CgroupGateError("Cannot configure a populated candidate leaf")
    for filename, value in LEAF_LIMITS.items():
        target = leaf / filename
        try:
            if not stat.S_ISREG(target.lstat().st_mode):
                raise CgroupGateError("Untrusted candidate resource controller")
            descriptor = os.open(target, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if os.write(descriptor, value.encode("ascii")) != len(value):
                    raise CgroupGateError("Incomplete cgroup controller write")
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise CgroupGateError("Cannot impose mandatory cgroup limits") from exc
        if _read(target).strip() != value:
            raise CgroupGateError("Cgroup controller did not enforce requested limit")
