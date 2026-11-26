"""Recoverable native APT mirror + source transaction in a root-only test root.

This is an explicitly sandbox-gated engineering implementation for #24.
It never touches the installed host's /etc, does not add an installed CLI
entry point and does not constitute an authenticated production writer.
The real root boundary, native package manager exclusion, live SELinux
metadata and full publisher/catalog approval are separate mandatory gates.

A protected journal is fsynced BEFORE the first of two independent rename
operations. Recovery compares both inode identity and bytes for every
resource. It refuses foreign edits instead of force-restoring them.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import native_fallback_plan as compiler
import native_package_lock_observation as locks
import root_source_boundary as boundary
import source_preflight as pre
import source_metadata_lab as security_metadata
import transaction_atomic_lab as atom

MARKER = ".repocache-recoverable-pair-test"
MAGIC = b"REPOCACHE_PAIR_SANDBOX_ONLY_V1\n"
JOURNAL_MAX = 5 * 1024 * 1024
REG = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class PairRefused(RuntimeError):
    """Unsafe, ambiguous or foreign transaction state requires intervention."""


class InjectedCrash(PairRefused):
    """Controlled simulated crash after the named durable boundary."""


def _identity(info: dict | os.stat_result) -> list[int]:
    if isinstance(info, dict):
        return [info["device"], info["inode"]]
    return [info.st_dev, info.st_ino]


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _blob(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode(value: str) -> bytes:
    if type(value) is not str or len(value) > 2 * pre.MAX_SOURCE_BYTES:
        raise PairRefused("Invalid protected journal payload")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PairRefused("Corrupt protected journal payload") from exc


def _sandbox(root: Path, statefd: int) -> None:
    root = Path(root)
    if root == Path("/") or not root.is_absolute() or ".." in root.parts:
        raise PairRefused("No production filesystem writes are permitted")
    if (root in (Path("/tmp"), Path("/var/tmp"))
            or not any(parent in (Path("/tmp"), Path("/var/tmp"))
                       for parent in root.parents)
            or root.resolve(strict=True) != root):
        raise PairRefused("Only private disposable test roots are permitted")
    fd = os.open(root, boundary.DIR)
    try:
        if boundary._read_pinned(fd, MARKER, len(MAGIC)) != MAGIC:
            raise PairRefused("Missing root-only paired-transaction marker")
    finally:
        os.close(fd)
    # A statefd that holds a known root-owned 0700 directory is mandatory.
    boundary._checked_directory(statefd, 0, private=True)


def _pack(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii")


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise PairRefused("Duplicate journal key")
        obj[key] = value
    return obj


def _journal_name(ident: str) -> str:
    if type(ident) is not str or not boundary.IDENT.fullmatch(ident):
        raise PairRefused("Invalid transaction identifier")
    return "pair-" + ident + ".json"


def _pending_journal_name(ident: str) -> str:
    _journal_name(ident)  # Validate the ID before constructing a leaf.
    return ".pair-" + ident + ".pending"


def _refuse_pending_journal(fd: int, ident: str) -> None:
    """Never mistake interrupted journal publication for a clean state.

    Called under the existing exclusive state lock, before reading an old
    journal or staging any new source. Even a dangling symlink, empty
    file or matching payload is uncertain; preserve it for manual review.
    """
    try:
        os.stat(_pending_journal_name(ident), dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PairRefused("Pending journal state cannot be verified") from exc
    raise PairRefused("Pending journal requires manual recovery")


def _source_attrs(journal: dict) -> tuple[tuple[str, bytes], ...]:
    if journal["schema"] in (2, 4):
        return ()
    encoded = journal["source_attributes"]
    if type(encoded) is not list or len(encoded) > security_metadata.MAX_ATTRS:
        raise PairRefused("Protected attribute snapshot refused")
    parsed = []
    total = 0
    for item in encoded:
        if (type(item) is not list or len(item) != 2 or type(item[0]) is not str
                or len(item[0].encode("utf-8")) > 255
                or not (security_metadata._allowed_attribute(item[0])
                        or (item[0] == "security.selinux"
                            and security_metadata.policy_active()))):
            raise PairRefused("Protected attribute namespace refused")
        value = _decode(item[1])
        total += len(value)
        if (len(value) > security_metadata.MAX_ATTRIBUTE_BYTES
                or total > security_metadata.MAX_TOTAL_ATTRIBUTE_BYTES):
            raise PairRefused("Protected attribute snapshot too large")
        parsed.append((item[0], value))
    if [name for name, _ in parsed] != sorted({name for name, _ in parsed}):
        raise PairRefused("Duplicate or unordered protected attributes")
    attrs = tuple(parsed)
    if security_metadata.attribute_digest(attrs) != journal["approval"].get("source_attributes_sha256"):
        raise PairRefused("Protected attribute snapshot differs from approval")
    return attrs


def _get_journal(fd: int, ident: str) -> dict | None:
    name = _journal_name(ident)
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    raw = boundary._read_pinned(fd, name, JOURNAL_MAX)
    try:
        j = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, ValueError) as exc:
        raise PairRefused("Malformed protected journal") from exc
    required = {
        "schema", "id", "phase", "source", "companion",
        "original", "proposed", "mirror", "original_id",
        "proposed_id", "mirror_id", "restore_id", "mode", "gid",
        "original_digest", "proposed_digest", "mirror_digest",
        "approval", "approval_sha256",
    }
    if type(j) is dict and j.get("schema") in (3, 5):
        required.add("source_attributes")
    if type(j) is dict and j.get("schema") in (4, 5):
        required.add("retained_id")
    if (type(j) is not dict or set(j) != required
            or type(j["schema"]) is not int or j["schema"] not in (2, 3, 4, 5)
            or type(j["id"]) is not str or j["id"] != ident
            or type(j["approval"]) is not dict
            or type(j["approval_sha256"]) is not str
            or not boundary.DIGEST.fullmatch(j["approval_sha256"])
            or j["phase"] not in ("armed", "installed", "restore-armed", "restored")
            or type(j["source"]) is not str or
            not pre.SOURCE_PATH.fullmatch(j["source"])
            or type(j["companion"]) not in (str, type(None))
            or (j["companion"] is not None and
                not j["companion"].startswith("etc/apt/mirrors/repocache-"))
            or type(j["mode"]) is not int or j["mode"] not in (0o600, 0o640, 0o644)
            or type(j["gid"]) is not int or j["gid"] < 0
            # Original and proposed inode IDs are mandatory. A missing
            # identity is NOT equivalent to an absent optional mirror.
            or any(type(j[key]) is not list or len(j[key]) != 2
                   or any(type(x) is not int or x < 0 for x in j[key])
                   for key in ("original_id", "proposed_id"))
            or (j["mirror_id"] is not None and (
                type(j["mirror_id"]) is not list or len(j["mirror_id"]) != 2
                or any(type(x) is not int or x < 0
                       for x in j["mirror_id"])))
            or (j["restore_id"] is not None and (
                type(j["restore_id"]) is not list or len(j["restore_id"]) != 2
                or any(type(x) is not int or x < 0 for x in j["restore_id"])))):
        raise PairRefused("Unexpected protected journal schema")
    if j["schema"] in (4, 5):
        retained = j["retained_id"]
        if (j["companion"] is None or j["gid"] != 0 or j["mode"] != 0o644
                or (retained is not None and (
                    type(retained) is not list or len(retained) != 2
                    or any(type(x) is not int or x < 0 for x in retained)
                    or retained == j["mirror_id"]
                    or j["phase"] in ("armed", "installed")))
                or (j["restore_id"] is not None and retained is None)):
            raise PairRefused("Invalid retained companion journal identity")
    original, proposed = _decode(j["original"]), _decode(j["proposed"])
    mirror = _decode(j["mirror"])
    if (_hash(original) != j["original_digest"] or
            _hash(proposed) != j["proposed_digest"] or
            _hash(mirror) != j["mirror_digest"] or
            len(original) > pre.MAX_SOURCE_BYTES or
            len(proposed) > pre.MAX_SOURCE_BYTES or
            (j["companion"] is None) != (j["mirror_id"] is None) or
            (j["companion"] is None and mirror)):
        raise PairRefused("Protected journal digest mismatch")
    if j["companion"] is not None:
        if (j["companion"] !=
                "etc/apt/mirrors/repocache-" + ident + ".list"):
            raise PairRefused("Journal companion path mismatches managed ID")
    # A protected snapshot binds recovery to the exact authorized compiler
    # inputs. Local rollback never depends on a reachable catalog or the
    # continued existence of an approval file, and never grants a new apply.
    try:
        snapshot = _pack(j["approval"])
        approval = boundary._decode_manifest(snapshot, ident)
        if (_hash(snapshot) != j["approval_sha256"]
                or approval["source"] != j["source"]
                or approval["source_sha256"] != j["original_digest"]
                or _hash(approval["cache"].encode("ascii")) != approval["route_sha256"]):
            raise PairRefused("Journal approval identity mismatch")
        if (approval["schema"] == 3) != (j["schema"] in (3, 5)):
            raise PairRefused("Journal attribute schema differs from approval")
        _source_attrs(j)
        if approval["schema"] in (2, 3):
            identity = approval["source_identity"]
            if ([identity["device"], identity["inode"]] != j["original_id"]
                    or identity["uid"] != 0 or identity["gid"] != j["gid"]
                    or identity["mode"] != j["mode"]
                    or identity["size"] != len(original)):
                raise PairRefused("Journal source identity mismatch")
        compiled = compiler.compile_fallback(
            source=j["source"], original=original,
            expected_source_sha256=approval["source_sha256"],
            selected_entry_sha256=approval["entry_sha256"],
            managed_id=ident, upstream=approval["upstream"], cache=approval["cache"])
        expected_companion = (j["companion"], mirror) if j["companion"] else None
        if compiled.proposed != proposed or compiled.companion != expected_companion:
            raise PairRefused("Journal differs from exact approved proposal")
    except (boundary.BoundaryRefused, compiler.FallbackRefused,
            UnicodeError, ValueError, RecursionError) as exc:
        raise PairRefused("Protected journal approval refused") from exc
    return j


def _put_journal(fd: int, ident: str, j: dict) -> None:
    name = _journal_name(ident)
    temp = _pending_journal_name(ident)
    data = _pack(j)
    if len(data) > JOURNAL_MAX:
        raise PairRefused("Journal too large")
    try:
        out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                      os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    except OSError as exc:
        raise PairRefused("Pending journal requires manual recovery") from exc
    try:
        try:
            security_metadata.initialize_exclusive_file_context(out, fd, temp, name)
            with os.fdopen(out, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                security_metadata.private_state_attributes(out)
                os.fsync(out)
        finally:
            os.close(out)
        # A first journal must not overwrite an unexpected destination.
        # Updating an existing journal remains a private sandbox operation.
        if _get_journal(fd, ident) is None:
            boundary._rename_noreplace(fd, temp, name)
        else:
            os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    except BaseException:
        # Unknown partial state stays on disk for manual inspection.
        raise


def _read_named(fd: int, name: str, attrs: tuple = ()) -> tuple[bytes, dict] | None:
    try:
        data, metadata = atom._target_state(fd, name, attrs)
        return data, metadata
    except FileNotFoundError:
        return None
    except Exception as exc:
        # The atomic helper reports missing files as StageError, so check
        # the path separately before calling it for correct absence policy.
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        raise PairRefused("Unsafe resource inode or metadata") from exc


def _matches(state: tuple[bytes, dict] | None, content: bytes,
             identity: list[int]) -> bool:
    return (state is not None and
            state[0] == content and
            _identity(state[1]) == identity)


def _stat_required(fd: int, name: str, expected: list[int]) -> None:
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except OSError as exc:
        raise PairRefused("Expected transaction resource missing") from exc
    if (not stat.S_ISREG(info.st_mode)
            or _identity(info) != expected or info.st_nlink != 1):
        raise PairRefused("Foreign transaction inode detected")


def _remove_known(fd: int, name: str, payload: bytes,
                  ident: list[int] | None, attrs: tuple = ()) -> None:
    current = _read_named(fd, name, attrs)
    if current is None:
        return
    if ident is None or not _matches(current, payload, ident):
        raise PairRefused("Unknown transaction resource; no deletion")
    _stat_required(fd, name, ident)
    os.unlink(name, dir_fd=fd)
    os.fsync(fd)


def _metadata(current: dict, journal: dict) -> None:
    if (current["uid"] != 0 or current["gid"] != journal["gid"]
            or current["mode"] != journal["mode"]):
        raise PairRefused("Native source metadata drift")


def _fixture_approval(statefd: int, root: Path, ident: str, *, current_catalog: bool = False):
    approval = boundary._manifest(statefd, ident)
    compiled, _ = boundary._validate_record(
        root, statefd, ident, approval, current_catalog=current_catalog)
    captured = []
    if approval["schema"] == 3:
        before = pre.inspect_source(approval["source"], root=root)
        raw = boundary._source_bytes(root, approval["source"], before, attrs_out=captured)
        if (raw != compiled.original or security_metadata.attribute_digest(tuple(captured))
                != approval["source_attributes_sha256"]):
            raise PairRefused("Source attributes changed before stage")
    return approval, compiled, tuple(captured)



def _paths(root: Path, j: dict):
    """Acquire only strict source and companion dirfds (never arbitrary URLs)."""
    return atom._source_directory(root, j["source"])


def _manager(source: str) -> str:
    if not pre.SOURCE_PATH.fullmatch(source) or source.startswith("etc/apt/mirrors/"):
        raise PairRefused("Unsupported transaction source family")
    return "dnf5" if source.startswith("etc/yum.repos.d/") else "apt"


DNF4_MARKER = ".repocache-dnf4-lock-test"
DNF4_MAGIC = b"REPOCACHE_DNF4_PRIVATE_LOCK_LAB_V1\n"
DNF4_PAIR_PREFIX = "repocache-booted-dnf4-"


def _is_dnf4_pair_root(root: Path) -> bool:
    return root.parent == Path("/var/tmp") and root.name.startswith(DNF4_PAIR_PREFIX)


def _require_dnf4(condition: bool) -> None:
    # This module is part of the source archive, though not the installed
    # helper. Refuse even if Python is invoked with -O.
    if not condition:
        raise locks.LockInspectionRefused("Unsafe private DNF4 lock scope")


def _dnf4_fixture_guard(root: Path) -> None:
    """Only fixed root-owned native VM fixtures; no host locks or override."""
    root = Path(root)
    _require_dnf4(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
    _require_dnf4(os.uname().nodename == "pr237-almalinux10")
    _require_dnf4(not Path("/.dockerenv").exists())
    _require_dnf4(Path("/proc/1/comm").read_text("ascii").strip() == "systemd")
    _require_dnf4(_is_dnf4_pair_root(root) or (
        root.parent == Path("/var/lib") and root.name.startswith("repocache-ci-dnf-root-")))
    _require_dnf4(root.resolve(strict=True) == root)
    parent = root.parent.lstat()
    _require_dnf4(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0)
    if root.parent == Path("/var/tmp"):
        _require_dnf4(parent.st_mode & stat.S_ISVTX)
    else:
        _require_dnf4(not parent.st_mode & 0o022)
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

    def native(*argv):
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env, timeout=15)
        _require_dnf4(result.returncode == 0)
        return result.stdout.strip()

    _require_dnf4(native("/usr/bin/systemd-detect-virt", "--vm") in ("qemu", "kvm"))
    _require_dnf4(native("/usr/sbin/getenforce") == "Enforcing")
    release = Path("/etc/os-release").read_text("ascii")
    _require_dnf4(re.search(r'^ID="?almalinux"?$', release, re.M))
    _require_dnf4(re.search(r'^VERSION_ID="?10(?:\.[0-9]+)?"?$', release, re.M))
    _require_dnf4(not Path("/usr/bin/dnf5").is_file())
    _require_dnf4(native("/usr/bin/dnf", "--version").splitlines()[0].startswith("4."))
    fd = os.open(root, boundary.DIR)
    try:
        info = os.fstat(fd)
        _require_dnf4(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
        mark = os.open(DNF4_MARKER, REG, dir_fd=fd)
        try:
            found = os.fstat(mark)
            _require_dnf4(stat.S_ISREG(found.st_mode) and found.st_uid == found.st_gid == 0)
            _require_dnf4(found.st_nlink == 1 and stat.S_IMODE(found.st_mode) == 0o600)
            _require_dnf4(os.read(mark, len(DNF4_MAGIC) + 1) == DNF4_MAGIC)
            named = os.stat(DNF4_MARKER, dir_fd=fd, follow_symlinks=False)
            _require_dnf4((found.st_dev, found.st_ino) == (named.st_dev, named.st_ino))
        finally:
            os.close(mark)
        if _is_dnf4_pair_root(root):
            _require_dnf4(boundary._read_pinned(fd, MARKER, len(MAGIC)) == MAGIC)
    finally:
        os.close(fd)


@contextlib.contextmanager
def _dnf4_private_claim(root: Path):
    """Fixture-only atomic live-PID publication plus real RPMDB kernel locks.

    Unlike DNF5, DNF4's PID file is created/removed, not a stable inode.
    Never steal an existing (even stale) PID record. This does not exclude
    metadata/config readers or prove an installed source-writer lease.
    """
    _dnf4_fixture_guard(root)
    lock_dir = root / "var/lib/dnf"
    rpm_dir = root / "usr/lib/sysimage/rpm"
    for directory in (lock_dir, rpm_dir):
        _require_dnf4(directory.resolve(strict=True) == directory)
        # The sticky /var/tmp parent is outside this protected private root.
        for parent in (directory, *directory.parents):
            if parent == root.parent:
                break
            info = parent.lstat()
            _require_dnf4(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    leaf = "rpmdb_lock.pid"
    staged = ".repocache-ci-rpmdb-lock.stage"
    expected = str(os.getpid()).encode("ascii")
    dirfd = rpmfd = fd = kernel = None
    published = False
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                info.st_gid, info.st_nlink, info.st_size)
    def recheck():
        _require_dnf4(os.getpid() == int(expected))
        _require_dnf4(identity(os.fstat(fd)) == claim)
        _require_dnf4(identity(os.stat(leaf, dir_fd=dirfd, follow_symlinks=False)) == claim)
        _require_dnf4(os.pread(fd, 32, 0) == expected)
        _require_dnf4(identity(os.fstat(kernel)) == rpm_identity)
        _require_dnf4(identity(os.stat(".rpm.lock", dir_fd=rpmfd, follow_symlinks=False)) == rpm_identity)
        for path, pinned in ((lock_dir, dirfd), (rpm_dir, rpmfd)):
            actual = path.lstat()
            held = os.fstat(pinned)
            _require_dnf4((actual.st_dev, actual.st_ino) == (held.st_dev, held.st_ino))
    try:
        dirfd = os.open(lock_dir, flags)
        rpmfd = os.open(rpm_dir, flags)
        # Atomic no-replace avoids publishing an empty PID file for another
        # native process to claim before our live owner bytes are durable.
        if os.path.lexists(lock_dir / leaf) or os.path.lexists(lock_dir / staged):
            raise FileExistsError("Existing DNF4 lock evidence; no takeover")
        fd = os.open(staged, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600, dir_fd=dirfd)
        _require_dnf4(os.write(fd, expected) == len(expected))
        os.fsync(fd)
        claim = identity(os.fstat(fd))
        _require_dnf4(claim[3:6] == (0, 0, 1))
        boundary._rename_noreplace(dirfd, staged, leaf)
        published = True
        os.fsync(dirfd)
        # Native RPM creates this inode during the preceding key import.
        kernel = os.open(".rpm.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC |
                         os.O_NONBLOCK, dir_fd=rpmfd)
        info = os.fstat(kernel)
        _require_dnf4(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0)
        _require_dnf4(info.st_nlink == 1 and not info.st_mode & 0o022)
        fcntl.flock(kernel, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.lockf(kernel, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rpm_identity = identity(os.fstat(kernel))
        recheck()
        yield recheck
        recheck()
    finally:
        # If anything is ambiguous, preserve the published/staged evidence.
        # Remove only this process's exact PID record; no stale-lock GC.
        try:
            if published and fd is not None:
                named = os.stat(leaf, dir_fd=dirfd, follow_symlinks=False)
                if identity(named) != claim or os.pread(fd, 32, 0) != expected:
                    raise RuntimeError("Foreign DNF4 PID record; retained for review")
                os.unlink(leaf, dir_fd=dirfd)
                os.fsync(dirfd)
        finally:
            for held in (kernel, fd, rpmfd, dirfd):
                if held is not None:
                    os.close(held)


@contextlib.contextmanager
def _package_scope(root: Path, source: str):
    """Reserved DNF4 VM root always uses DNF4; no fallback to fake DNF5 locks."""
    manager = _manager(source)
    if not _is_dnf4_pair_root(root):
        with locks.hold_existing_native_package_locks(
                manager, root=root, revalidation=True) as recheck:
            yield recheck
        return
    if manager != "dnf5":
        raise locks.LockInspectionRefused("DNF4 fixture cannot write an APT source")
    with contextlib.ExitStack() as scope:
        try:
            recheck = scope.enter_context(_dnf4_private_claim(root))
        except (OSError, ValueError, AssertionError) as exc:
            raise locks.LockInspectionRefused("Private DNF4 lock scope refused") from exc

        def checked():
            try:
                recheck()
            except (OSError, AssertionError) as exc:
                raise locks.LockInspectionRefused("Private DNF4 lock scope drift") from exc

        yield checked


def _crash(where: str | None, phase: str) -> None:
    if where == phase:
        raise InjectedCrash("Injected transaction interruption: " + phase)


def apply_sandbox(root: Path, ident: str, *, crash: str | None = None) -> dict:
    """Legacy offline lab test only; never an installed writer."""
    return _apply_sandbox(root, ident, crash=crash, current_catalog=False)


def apply_catalog_bound_sandbox(root: Path, ident: str, *, crash: str | None = None) -> dict:
    """Rehearse the mandatory live-route gate under held locks.

    Only the private marked fixture is writable. Unlike the offline lab
    entry, both first apply and idempotent retry require the exact currently
    active route. Recovery remains catalog-independent.
    """
    return _apply_sandbox(root, ident, crash=crash, current_catalog=True)


def apply_retaining_apt_companion_sandbox(
        root: Path, ident: str, *, crash: str | None = None,
        current_catalog: bool = True) -> dict:
    """New APT-only rollback semantics in marked disposable roots.

    The offline option is exclusively for synthetic root fixtures. Existing
    lab schemas are not silently migrated; neither entry is installed.
    """
    if type(current_catalog) is not bool:
        raise PairRefused("Invalid fixture catalog mode")
    return _apply_sandbox(root, ident, crash=crash,
                          current_catalog=current_catalog, retain_companion=True)


def _apply_sandbox(root: Path, ident: str, *, crash: str | None,
                   current_catalog: bool, retain_companion: bool = False) -> dict:
    root = Path(root)
    if root == Path("/"):
        raise PairRefused("Production root is forbidden")
    try:
        with boundary._state(root) as (statefd, owner):
            _sandbox(root, statefd)
            with boundary._exclusive_lock(statefd, owner), contextlib.ExitStack() as scope:
                _refuse_pending_journal(statefd, ident)
                journal = _get_journal(statefd, ident)
                approved = boundary._manifest(statefd, ident)
                source = journal["source"] if journal is not None else approved["source"]
                recheck = scope.enter_context(
                    _package_scope(root, source))
                if retain_companion and _manager(source) != "apt":
                    raise PairRefused("Retained companion is APT-only")
                if journal is not None:
                    if retain_companion != (journal["schema"] in (4, 5)):
                        raise PairRefused("Existing transaction uses a different rollback contract")
                    if journal["phase"] != "installed":
                        raise PairRefused("Interrupted or restored transaction needs review")
                    approval = boundary._manifest(statefd, ident)
                    if (approved != approval or approval != journal["approval"]
                            or _hash(_pack(approval)) != journal["approval_sha256"]):
                        raise PairRefused("Installed approval identity changed")
                    with _paths(root, journal) as (fd, leaf):
                        curr = _read_named(fd, leaf, _source_attrs(journal))
                        if not _matches(curr, _decode(journal["proposed"]),
                                        journal["proposed_id"]):
                            raise PairRefused("Installed source externally modified")
                        _metadata(curr[1], journal)
                    if journal["companion"] is not None:
                        with atom._source_directory(root, journal["companion"]) as (fd, leaf):
                            observed_mirror = _read_named(fd, leaf)
                            if not _matches(observed_mirror, _decode(journal["mirror"]),
                                            journal["mirror_id"]):
                                raise PairRefused("Installed mirror externally modified")
                            _metadata(observed_mirror[1], journal)
                    if current_catalog:
                        if approval["schema"] not in (2, 3):
                            raise PairRefused("Native consent identity missing")
                        boundary._current_route(approval, root)
                        if boundary._manifest(statefd, ident) != approval:
                            raise PairRefused("Approval changed during retry")
                        recheck()
                    return {"status": "unchanged", "write_eligible": False}
                approval, proposal, attrs = _fixture_approval(
                    statefd, root, ident, current_catalog=current_catalog)
                if approved != approval:
                    raise PairRefused("Approval changed during lock acquisition")
                recheck()
                # Label-aware APT companion placement needs its own policy
                # context; current supported enforcing platform uses DNF.
                if proposal.companion and any(name == "security.selinux" for name, _ in attrs):
                    raise PairRefused("Labelled APT companion not supported")
                with atom._source_directory(root, proposal.source) as (fd, leaf):
                    source = _read_named(fd, leaf, attrs)
                    if source is None or source[0] != proposal.original:
                        raise PairRefused("Source changed before stage")
                    if approval["schema"] in (2, 3) and approval["source_identity"] != {
                            **{key: source[1][key] for key in boundary.SOURCE_IDENTITY_FIELDS
                               if key != "size"}, "size": len(source[0])}:
                        raise PairRefused("Approved source inode identity changed before stage")
                    mode, gid = source[1]["mode"], source[1]["gid"]
                    if (source[1]["uid"] != 0 or mode not in (0o600, 0o640, 0o644)
                            or (proposal.companion and (mode != 0o644 or gid != 0))):
                        raise PairRefused("Unsafe source or APT mirror ownership or mode")
                    source_temp, new_id = atom._write_new(
                        fd, leaf, ident, proposal.proposed, source[1], attrs)
                    # All current permissions and metadata must still match.
                    if _read_named(fd, leaf, attrs) != source:
                        raise PairRefused("Source replaced during staging")
                companion = None
                companion_id = None
                if proposal.companion is not None:
                    path, bytes_ = proposal.companion
                    with atom._source_directory(root, path) as (fd, leaf):
                        if _read_named(fd, leaf) is not None:
                            raise PairRefused("Unexpected existing mirror companion")
                        temp, c_id = atom._write_new(
                            fd, leaf, ident, bytes_, source[1])
                        companion = path
                        companion_id = list(c_id)
                j = {
                    "schema": 2, "id": ident, "phase": "armed",
                    "approval": approval, "approval_sha256": _hash(_pack(approval)),
                    "source": proposal.source, "companion": companion,
                    "original": _blob(proposal.original),
                    "proposed": _blob(proposal.proposed),
                    "mirror": _blob(proposal.companion[1]
                                     if proposal.companion else b""),
                    "original_id": _identity(source[1]),
                    "proposed_id": list(new_id),
                    "mirror_id": companion_id, "restore_id": None,
                    "mode": mode, "gid": gid,
                    "original_digest": _hash(proposal.original),
                    "proposed_digest": _hash(proposal.proposed),
                    "mirror_digest": _hash(proposal.companion[1]
                                           if proposal.companion else b""),
                }
                if approval["schema"] == 3:
                    j["schema"] = 3
                    j["source_attributes"] = [[name, _blob(value)] for name, value in attrs]
                if retain_companion:
                    if companion is None:
                        raise PairRefused("Retained companion requires an APT proposal")
                    j["schema"] += 2
                    j["retained_id"] = None
                recheck()
                _put_journal(statefd, ident, j)
                _crash(crash, "armed")
                if current_catalog:
                    # Durable journal already exists, so failure here is
                    # recoverable offline without using a withdrawn route.
                    boundary._current_route(approval, root)
                    if boundary._manifest(statefd, ident) != approval:
                        raise PairRefused("Approval changed before publication")
                    recheck()
                if companion is not None:
                    with atom._source_directory(root, companion) as (fd, leaf):
                        temp = ".repocache-atomic-" + ident
                        _stat_required(fd, temp, companion_id)
                        if _read_named(fd, leaf) is not None:
                            raise PairRefused("Mirror destination appeared during commit")
                        recheck()
                        boundary._rename_noreplace(fd, temp, leaf)
                        os.fsync(fd)
                    _crash(crash, "companion")
                with atom._source_directory(root, proposal.source) as (fd, leaf):
                    if _read_named(fd, leaf, attrs) != source:
                        raise PairRefused("Source changed before transaction commit")
                    staged = _read_named(fd, source_temp, attrs)
                    if not _matches(staged, proposal.proposed, list(new_id)):
                        raise PairRefused("Staged source changed before transaction commit")
                    _metadata(staged[1], j)
                    if boundary._manifest(statefd, ident) != approval:
                        raise PairRefused("Approval changed before transaction commit")
                    recheck()
                    atom._replace(fd, source_temp, leaf, tuple(_identity(source[1])))
                _crash(crash, "source")
                with atom._source_directory(root, proposal.source) as (fd, leaf):
                    installed = _read_named(fd, leaf, attrs)
                    if not _matches(installed, proposal.proposed, list(new_id)):
                        raise PairRefused("Installed source readback mismatch")
                    _metadata(installed[1], j)
                j["phase"] = "installed"
                recheck()
                _put_journal(statefd, ident, j)
                return {"status": "installed-sandbox", "write_eligible": False}
    except (OSError, ValueError, compiler.FallbackRefused,
            boundary.BoundaryRefused, pre.PreflightError) as exc:
        raise PairRefused("Paired transaction refused") from exc


def _retained_bytes(j: dict) -> bytes:
    # _get_journal has recompiled the exact approval and original source.
    # Never accept a new URI, user-supplied neutralization bytes or a cache.
    return (j["approval"]["upstream"] + "\tpriority:1\n").encode("ascii")


def _neutralize_companion(root, fdstate, ident, j, *, recheck, crash):
    """Journal a new inode, publish only original upstream, then restore source."""
    payload = _retained_bytes(j)
    mirror = _decode(j["mirror"])
    with atom._source_directory(root, j["companion"]) as (fd, leaf):
        current = _read_named(fd, leaf)
        if j["retained_id"] is not None and _matches(current, payload, j["retained_id"]):
            _metadata(current[1], j)
            return
        if not _matches(current, mirror, j["mirror_id"]):
            raise PairRefused("Retained companion baseline differs")
        _metadata(current[1], j)
        temp = ".repocache-atomic-" + ident
        if j["retained_id"] is None:
            recheck()
            temp, new_id = atom._write_new(fd, leaf, ident, payload, current[1])
            j["retained_id"] = list(new_id)
            j["phase"] = "restore-armed"
            recheck()
            _put_journal(fdstate, ident, j)
            _crash(crash, "retention-armed")
        staged = _read_named(fd, temp)
        if not _matches(staged, payload, j["retained_id"]):
            raise PairRefused("Foreign retained companion temporary inode")
        _metadata(staged[1], j)
        if _read_named(fd, leaf) != current:
            raise PairRefused("Companion changed before neutralization")
        recheck()
        atom._replace(fd, temp, leaf, tuple(j["mirror_id"]))
        verified = _read_named(fd, leaf)
        if not _matches(verified, payload, j["retained_id"]):
            raise PairRefused("Retained companion readback mismatch")
        _metadata(verified[1], j)
        _crash(crash, "companion-neutralized")


def _restore_locked(root: Path, fdstate: int, ident: str, j: dict,
                    *, recheck, crash: str | None = None) -> dict:
    recheck()
    original, proposed, mirror = (
        _decode(j["original"]), _decode(j["proposed"]), _decode(j["mirror"]))
    attrs = _source_attrs(j)
    with atom._source_directory(root, j["source"]) as (fd, leaf):
        current = _read_named(fd, leaf, attrs)
        if current is None:
            raise PairRefused("Source missing in transaction recovery")
        _metadata(current[1], j)
        from_original = _matches(current, original, j["original_id"])
        from_proposed = _matches(current, proposed, j["proposed_id"])
        from_restored = j["restore_id"] is not None and _matches(
            current, original, j["restore_id"])
        if not (from_original or from_proposed or from_restored):
            raise PairRefused("Foreign source during transaction recovery")
    retained_contract = j["schema"] in (4, 5)
    neutral = False
    if j["companion"] is not None:
        with atom._source_directory(root, j["companion"]) as (fd, leaf):
            mirror_state = _read_named(fd, leaf)
            neutral = (retained_contract and j["retained_id"] is not None
                       and _matches(mirror_state, _retained_bytes(j), j["retained_id"]))
            if (mirror_state is not None and not neutral and
                    not _matches(mirror_state, mirror, j["mirror_id"])):
                raise PairRefused("Foreign mirror during transaction recovery")
            if mirror_state is not None:
                _metadata(mirror_state[1], j)
            if retained_contract and (from_proposed or j["retained_id"] is not None):
                if mirror_state is None or (from_restored and not neutral):
                    raise PairRefused("Required retained companion missing or changed")
    else:
        mirror_state = None

    # For successful installations, recover() preserves the committed state
    # unless explicitly asked to restore. For armed partial commits, revert.
    if j["phase"] == "restored":
        expected_mirror = (neutral if retained_contract and j["retained_id"] is not None
                           else mirror_state is None)
        if not (from_original or from_restored) or not expected_mirror:
            raise PairRefused("Restored transaction modified externally")
        return {"status": "restored", "write_eligible": False}
    if (j["phase"] == "installed" and
            (not from_proposed or
             (j["companion"] is not None and mirror_state is None))):
        raise PairRefused("Committed transaction not intact")
    if j["phase"] == "installed" and crash is None:
        return {"status": "installed-sandbox", "write_eligible": False}
    if j["phase"] == "armed" and (from_proposed and
                                  j["companion"] is not None and
                                  mirror_state is None):
        raise PairRefused("Source committed without its required mirror")

    if retained_contract and mirror_state is not None:
        # Even an interrupted companion-only publication is retained.
        # APT may have parsed the old source before the native lists lock.
        _neutralize_companion(root, fdstate, ident, j, recheck=recheck, crash=crash)

    if from_proposed:
        with atom._source_directory(root, j["source"]) as (fd, leaf):
            if j["restore_id"] is None:
                temp, new_id = atom._write_new(fd, leaf, ident, original, current[1], attrs)
                j["restore_id"] = list(new_id)
                j["phase"] = "restore-armed"
                recheck()
                _put_journal(fdstate, ident, j)
                _crash(crash, "restore-armed")
            else:
                temp = ".repocache-atomic-" + ident
                _stat_required(fd, temp, j["restore_id"])
                pending = _read_named(fd, temp, attrs)
                if not _matches(pending, original, j["restore_id"]):
                    raise PairRefused("Foreign rollback temp")
            if _read_named(fd, leaf, attrs) != current:
                raise PairRefused("Source changed before rollback commit")
            staged = _read_named(fd, temp, attrs)
            if not _matches(staged, original, j["restore_id"]):
                raise PairRefused("Staged rollback source changed")
            _metadata(staged[1], j)
            recheck()
            atom._replace(fd, temp, leaf, tuple(j["proposed_id"]))
            restored = _read_named(fd, leaf, attrs)
            if not _matches(restored, original, j["restore_id"]):
                raise PairRefused("Restored source readback mismatch")
            _metadata(restored[1], j)
            _crash(crash, "source-restored")
    elif not (from_original or from_restored):
        raise PairRefused("Unrecognized restore state")
    if j["companion"] is not None and not retained_contract:
        with atom._source_directory(root, j["companion"]) as (fd, leaf):
            recheck()
            _remove_known(fd, leaf, mirror, j["mirror_id"])
    if not retained_contract:
        _crash(crash, "companion-removed")
    if from_original:
        # No source replacement happened: only a journalled temp can go.
        with atom._source_directory(root, j["source"]) as (fd, _):
            recheck()
            _remove_known(fd, ".repocache-atomic-" + ident,
                          proposed, j["proposed_id"], attrs)
    if j["companion"] is not None:
        with atom._source_directory(root, j["companion"]) as (fd, _):
            recheck()
            _remove_known(fd, ".repocache-atomic-" + ident,
                          mirror, j["mirror_id"])
    if retained_contract:
        with atom._source_directory(root, j["companion"]) as (fd, leaf):
            observed = _read_named(fd, leaf)
            if j["retained_id"] is None:
                if observed is not None:
                    raise PairRefused("Unexpected companion after cancelled publication")
            elif not _matches(observed, _retained_bytes(j), j["retained_id"]):
                raise PairRefused("Retained companion changed before completion")
            else:
                _metadata(observed[1], j)
    j["phase"] = "restored"
    recheck()
    _put_journal(fdstate, ident, j)
    return {"status": "restored", "write_eligible": False}


def restore_sandbox(root: Path, ident: str, *,
                    crash: str | None = None) -> dict:
    """Manually reverse an exact installed sandbox transaction, preserving proof."""
    root = Path(root)
    if root == Path("/"):
        raise PairRefused("Production root forbidden")
    with boundary._state(root) as (fd, owner):
        _sandbox(root, fd)
        with boundary._exclusive_lock(fd, owner):
            _refuse_pending_journal(fd, ident)
            j = _get_journal(fd, ident)
            if j is None or j["phase"] not in ("installed", "restore-armed"):
                raise PairRefused("No committed sandbox transaction to restore")
            try:
                with _package_scope(root, j["source"]) as recheck:
                    return _restore_locked(root, fd, ident, j, recheck=recheck, crash=crash or "manual")
            except locks.LockInspectionRefused as exc:
                raise PairRefused("Native lock scope refused rollback") from exc


def recover_sandbox(root: Path, ident: str) -> dict:
    """Rollback interrupted sandbox apply/restore only at exact journalled inodes."""
    root = Path(root)
    if root == Path("/"):
        raise PairRefused("Production root forbidden")
    with boundary._state(root) as (fd, owner):
        _sandbox(root, fd)
        with boundary._exclusive_lock(fd, owner):
            _refuse_pending_journal(fd, ident)
            j = _get_journal(fd, ident)
            if j is None:
                return {"status": "no-intent", "write_eligible": False}
            try:
                with _package_scope(root, j["source"]) as recheck:
                    if j["phase"] in ("installed", "restored"):
                        return _restore_locked(root, fd, ident, j, recheck=recheck)
                    return _restore_locked(root, fd, ident, j, recheck=recheck, crash="recover")
            except locks.LockInspectionRefused as exc:
                raise PairRefused("Native lock scope refused recovery") from exc
