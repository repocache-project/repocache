"""Fixed, root-owned read-only client approval/transaction validation boundary.

This module is intentionally NOT installed or called by repocache-client.
No commit, restore, recover, source changes, root escalation, network requests
or manifest-creation operations exist. It prepares a privileged validation
boundary while real APT/DNF, native package-manager exclusivity, SELinux and
durable multi-file transaction requirements remain unsatisfied (#24).
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Iterator

import native_fallback_plan as fallback
import source_preflight as pre
import source_entry_boundaries as entries

DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
REG = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
MAX_MANIFEST = 4096
MARKER = ".repocache-root-boundary-test"
MAGIC = b"REPOCACHE_PRIVATE_ROOT_BOUNDARY_TEST_V1\n"
IDENT = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
MANIFEST_FIELDS = frozenset({
    "schema", "id", "source", "source_sha256", "entry_sha256",
    "upstream", "cache", "route_sha256",
})


class BoundaryRefused(RuntimeError):
    """Protected state, source or approval failed closed."""


class BoundaryBusy(BoundaryRefused):
    """Another operation holds the exclusive client transaction lock."""


def _read_pinned(directory_fd: int, name: str, max_size: int,
                 *, owner: int = 0, mode: int = 0o600) -> bytes:
    """Read protected regular single-link bytes; verify stable inode identity."""
    try:
        fd = os.open(name, REG, dir_fd=directory_fd)
    except OSError as exc:
        raise BoundaryRefused("Missing or unsafe protected state") from exc
    try:
        before = os.fstat(fd)
        try:
            pointed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise BoundaryRefused("Protected state pathname changed") from exc
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != owner or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode
                or before.st_size > max_size
                or (before.st_dev, before.st_ino) !=
                   (pointed.st_dev, pointed.st_ino)):
            raise BoundaryRefused("Unsafe protected state inode")
        body = os.read(fd, max_size + 1)
        after = os.fstat(fd)
        try:
            pointed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise BoundaryRefused("Protected state pathname changed") from exc
        if (len(body) > max_size
                or (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns) !=
                   (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)
                or (after.st_dev, after.st_ino) !=
                   (pointed.st_dev, pointed.st_ino)):
            raise BoundaryRefused("Protected state changed during read")
        try:
            if os.listxattr(fd):
                raise BoundaryRefused("Unreviewed protected state attributes")
        except OSError as exc:
            raise BoundaryRefused("Cannot inspect protected state attributes") from exc
        return body
    finally:
        os.close(fd)


def _checked_directory(fd: int, owner: int, *, private: bool) -> None:
    record = os.fstat(fd)
    mode = stat.S_IMODE(record.st_mode)
    if (not stat.S_ISDIR(record.st_mode) or record.st_uid != owner
            or (mode != 0o700 if private else bool(mode & 0o022))):
        raise BoundaryRefused("Unsafe protected directory")


@contextlib.contextmanager
def _root(root: Path) -> Iterator[tuple[int, int]]:
    """Resolve only fixed trusted dirs, no user paths/redirects."""
    if os.geteuid() != 0:
        raise BoundaryRefused("Root OS authorization required")
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts:
        raise BoundaryRefused("Invalid protected inspection root")
    if root != Path("/"):
        # Privilege cannot be overridden via command-line, environment or
        # a symlinked private fixture. This is test-only and still root-only.
        if (root in (Path("/tmp"), Path("/var/tmp"))
                or not any(p in (Path("/tmp"), Path("/var/tmp"))
                           for p in root.parents)
                or root.resolve(strict=True) != root):
            raise BoundaryRefused("Private test root refused")
    try:
        fd = os.open(root, DIR)
    except OSError as exc:
        raise BoundaryRefused("Protected root unavailable") from exc
    try:
        _checked_directory(fd, 0, private=root != Path("/"))
        if root != Path("/"):
            if _read_pinned(fd, MARKER, len(MAGIC)) != MAGIC:
                raise BoundaryRefused("Invalid private test marker")
        yield fd, 0
    finally:
        os.close(fd)


@contextlib.contextmanager
def _state(root: Path) -> Iterator[tuple[int, int]]:
    """Read preprovisioned root-owned state; never mkdir/touch."""
    with _root(root) as (root_fd, owner):
        current = os.dup(root_fd)
        try:
            for component, private in (
                ("var", False), ("lib", False),
                ("repocache-client", True),
                ("approved-entries", True),
            ):
                try:
                    child = os.open(component, DIR, dir_fd=current)
                except OSError as exc:
                    raise BoundaryRefused("Protected client state missing") from exc
                try:
                    _checked_directory(child, owner, private=private)
                except BaseException:
                    os.close(child)
                    raise
                os.close(current)
                current = child
            yield current, owner
        finally:
            os.close(current)


@contextlib.contextmanager
def _exclusive_lock(state_fd: int, owner: int) -> Iterator[None]:
    """Acquire an existing root-owned lock inode without creating it."""
    try:
        fd = os.open(".transaction.lock", os.O_RDWR | os.O_NOFOLLOW |
                     os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=state_fd)
    except OSError as exc:
        raise BoundaryRefused("Protected transaction lock missing") from exc
    try:
        info = os.fstat(fd)
        named = os.stat(".transaction.lock", dir_fd=state_fd,
                        follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise BoundaryRefused("Unsafe transaction lock inode")
        try:
            if os.listxattr(fd):
                raise BoundaryRefused("Unexpected protected lock attributes")
        except OSError as exc:
            raise BoundaryRefused("Cannot inspect transaction lock attributes") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            raise BoundaryBusy("Protected transaction already locked") from exc
        try:
            # Verify the named lock is still the one we hold.
            later = os.stat(".transaction.lock", dir_fd=state_fd,
                            follow_symlinks=False)
            if (later.st_dev, later.st_ino) != (info.st_dev, info.st_ino):
                raise BoundaryRefused("Transaction lock name changed")
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _no_duplicate_fields(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise BoundaryRefused("Duplicate approval field")
        obj[key] = value
    return obj


def _manifest(state_fd: int, ident: str) -> dict:
    if not isinstance(ident, str) or not IDENT.fullmatch(ident):
        raise BoundaryRefused("Invalid protected candidate identifier")
    name = "candidate-" + ident + ".json"
    raw = _read_pinned(state_fd, name, MAX_MANIFEST)
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_fields)
    except (UnicodeError, ValueError) as exc:
        raise BoundaryRefused("Malformed protected approval") from exc
    if (type(obj) is not dict or set(obj) != MANIFEST_FIELDS
            or type(obj["schema"]) is not int or obj["schema"] != 1
            or type(obj["id"]) is not str or obj["id"] != ident
            or type(obj["source"]) is not str
            or not pre.SOURCE_PATH.fullmatch(obj["source"])
            or obj["source"].startswith("etc/apt/mirrors/")
            or any(type(obj[k]) is not str or not DIGEST.fullmatch(obj[k])
                   for k in ("source_sha256", "entry_sha256", "route_sha256"))
            or any(type(obj[k]) is not str for k in ("upstream", "cache"))):
        raise BoundaryRefused("Protected approval schema refused")
    return obj


def _source_bytes(root: Path, relative: str, observed: dict) -> bytes:
    """Read exact allowlisted source through stable anchored file descriptors."""
    fd = None
    try:
        fd = os.open(root, DIR)
        _checked_directory(fd, 0, private=root != Path("/"))
        for component in relative.split("/")[:-1]:
            child = os.open(component, DIR, dir_fd=fd)
            try:
                _checked_directory(child, 0, private=False)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        leaf = relative.rsplit("/", 1)[-1]
        source_fd = os.open(leaf, REG, dir_fd=fd)
        try:
            before = os.fstat(source_fd)
            named = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) & 0o022
                    or (before.st_dev, before.st_ino) !=
                       (named.st_dev, named.st_ino)
                    or before.st_dev != observed["device"]
                    or before.st_ino != observed["inode"]
                    or before.st_mtime_ns != observed["mtime_ns"]
                    or before.st_ctime_ns != observed["ctime_ns"]
                    or before.st_size > pre.MAX_SOURCE_BYTES):
                raise BoundaryRefused("Protected source baseline changed")
            raw = os.read(source_fd, pre.MAX_SOURCE_BYTES + 1)
            after = os.fstat(source_fd)
            named = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            if (len(raw) > pre.MAX_SOURCE_BYTES
                    or hashlib.sha256(raw).hexdigest() != observed["sha256"]
                    or (before.st_dev, before.st_ino, before.st_size,
                        before.st_ctime_ns, before.st_mtime_ns) !=
                       (after.st_dev, after.st_ino, after.st_size,
                        after.st_ctime_ns, after.st_mtime_ns)
                    or (after.st_dev, after.st_ino) !=
                       (named.st_dev, named.st_ino)):
                raise BoundaryRefused("Source changed during protected inspection")
            return raw
        finally:
            os.close(source_fd)
    except OSError as exc:
        raise BoundaryRefused("Unsafe protected source path") from exc
    finally:
        if fd is not None:
            os.close(fd)


def validate(ident: str, *, _test_root: Path | None = None) -> dict:
    """Verify one immutable local approval and source in a root-only boundary.

    No manifest value or proposed source URL becomes authority to commit.
    """
    root = Path("/") if _test_root is None else Path(_test_root)
    with _state(root) as (state_fd, owner):
        with _exclusive_lock(state_fd, owner):
            record = _manifest(state_fd, ident)
            if hashlib.sha256(record["cache"].encode("utf-8")).hexdigest() != record["route_sha256"]:
                raise BoundaryRefused("Exact cache route approval is stale")
            try:
                before = pre.inspect_source(record["source"], root=root)
                if before["sha256"] != record["source_sha256"]:
                    raise BoundaryRefused("Original source baseline does not match")
                # Until native SELinux/ACL preservation is proven, even a
                # read-only positive does not bless a labelled host writer.
                if before["extended_attributes_present"]:
                    raise BoundaryRefused("Unreviewed source security metadata")
                raw = _source_bytes(root, record["source"], before)
                chunks = entries.boundaries(record["source"], raw)
                if len([x for x in chunks
                        if x["sha256"] == record["entry_sha256"]
                        and x["structure_subset_pass"]]) != 1:
                    raise BoundaryRefused("Approved source entry not unique")
                proposal = fallback.compile_fallback(
                    source=record["source"], original=raw,
                    expected_source_sha256=record["source_sha256"],
                    selected_entry_sha256=record["entry_sha256"],
                    managed_id=ident, upstream=record["upstream"],
                    cache=record["cache"])
                after = pre.inspect_source(record["source"], root=root)
                if before != after:
                    raise BoundaryRefused("Source drift during protected validation")
            except (pre.PreflightError, entries.EntryRefused,
                    fallback.FallbackRefused, OSError, ValueError) as exc:
                raise BoundaryRefused("Protected source validation refused") from exc
            return {
                "schema": 1, "status": "validated-read-only",
                "managed_id": ident,
                "source_digest_matched": True,
                "entry_digest_matched": True,
                "route_digest_matched": True,
                "fallback_plan_generated": True,
                "multi_file_changes_required": proposal.companion is not None,
                "exclusive_client_lock_observed": True,
                "installed": False, "package_signatures_verified": False,
                "native_package_locks_verified": False,
                "native_fallback_verified": False,
                "write_eligible": False,
            }


def status() -> dict:
    if os.geteuid() != 0:
        raise BoundaryRefused("Root OS authorization required")
    return {
        "schema": 1, "status": "source-only-root-validation",
        "installed": False, "root_os_authorized": True,
        "actions": ["status", "validate"],
        "commit_available": False, "restore_available": False,
        "recover_available": False, "write_eligible": False,
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise BoundaryRefused("Invalid fixed helper arguments")


def main(argv: list[str] | None = None, *, _test_root: Path | None = None) -> int:
    parser = _Parser(prog="repocache-client-root-boundary", add_help=False)
    parser.add_argument("--json", action="store_true")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("status", add_help=False)
    validate_cmd = commands.add_parser("validate", add_help=False)
    validate_cmd.add_argument("--candidate", required=True)
    arguments = list(sys.argv[1:] if argv is None else argv)
    wants_json = "--json" in arguments
    try:
        options = parser.parse_args(arguments)
        result = (status() if options.action == "status"
                  else validate(options.candidate, _test_root=_test_root))
        success = True
    except (BoundaryRefused, OSError, ValueError) as exc:
        # Never disclose manifest/source values, URLs, local paths or full
        # exception text which might contain untrusted sensitive data.
        code = ("ROOT_REQUIRED" if os.geteuid() != 0
                else "VALIDATION_REFUSED")
        result = {"schema": 1, "status": "refused", "ok": False,
                  "write_eligible": False, "error": {"code": code}}
        success = False
    if wants_json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    elif success:
        print("Root validation complete; source writes disabled.")
    else:
        print("Source-only root helper refused the operation.", file=sys.stderr)
    return 0 if success else 3


if __name__ == "__main__":
    sys.exit(main())
