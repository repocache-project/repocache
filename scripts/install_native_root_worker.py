#!/usr/bin/env python3
"""Place the authenticated fixed worker and units before native activation.

Run from the independently reviewed checkout on an authorized host. This
operation prepares the fixed server namespace and places the authenticated
worker. It never reloads or enables a service.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

if __name__ == "__main__":
    checkout = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(checkout / "src"), str(checkout)]

from repocache import signatures, upgrade
from repocache.server_protected_namespace_bootstrap_v1 import bootstrap_protected_namespace_under_root
from repocache.server_protected_state_store_v1 import _locked
from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions
from scripts import stage_native_root_worker as stage


_MARKER = ".native-worker-placement."
_TEMP = ".repocache-worker-part-"
_UNIT_DIRECTORY = ("etc", "systemd", "system")


def _reject(reason: str) -> None:
    raise stage.WorkerStageError("WORKER_PLACEMENT_" + reason)


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _named(directory: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _attribute_check(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
        _reject("FOREIGN_FILE")


def _check_marker(info: os.stat_result) -> None:
    _attribute_check(info)
    if info.st_size or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        _reject("FOREIGN_MARKER")


def _create_marker(directory: int, name: str) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def _exact_file(
    directory: int, name: str, data: bytes, mode: int, *,
    allow_partial: bool = False, links: int = 1,
) -> os.stat_result:
    initial = _named(directory, name)
    if initial is None:
        _reject("MISSING_FILE")
    _attribute_check(initial)
    observed_mode = stat.S_IMODE(initial.st_mode)
    is_partial = allow_partial and observed_mode == 0o600
    if (initial.st_nlink != links or not 0 <= initial.st_size <= len(data)
            or (not is_partial and observed_mode != mode)):
        _reject("FILE_METADATA_MISMATCH")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(name, flags, dir_fd=directory), "rb") as stream:
        before = os.fstat(stream.fileno())
        _attribute_check(before)
        if _identity(before) != _identity(initial) or before.st_mode != initial.st_mode:
            _reject("FILE_CHANGED")
        raw = stream.read(len(data) + 1)
        after = os.fstat(stream.fileno())
    named = _named(directory, name)
    if (named is None or _identity(named) != _identity(after)
            or before.st_mode != after.st_mode or before.st_nlink != after.st_nlink
            or before.st_size != after.st_size or before.st_ctime_ns != after.st_ctime_ns
            or before.st_mtime_ns != after.st_mtime_ns):
        _reject("FILE_CHANGED")
    matches = data.startswith(raw) if is_partial else raw == data
    if not matches:
        _reject("FILE_CONTENT_MISMATCH")
    return after


def _finish_link(directory: int, target: str, part: str, data: bytes, mode: int) -> None:
    final = _exact_file(directory, target, data, mode, links=2)
    staged = _exact_file(directory, part, data, mode, links=2)
    if _identity(final) != _identity(staged):
        _reject("FOREIGN_PARTIAL_LINK")
    os.unlink(part, dir_fd=directory)
    os.fsync(directory)
    _exact_file(directory, target, data, mode)


def _place_file(directory: int, name: str, raw: bytes, mode: int) -> None:
    part = _TEMP + name
    installed = _named(directory, name)
    staged = _named(directory, part)
    if installed is not None:
        if staged is not None:
            _finish_link(directory, name, part, raw, mode)
        else:
            _exact_file(directory, name, raw, mode)
        return
    if staged is not None:
        # Only the current, signed placement's interrupted prefix may be
        # removed. A foreign file at either name blocks placement.
        _exact_file(directory, part, raw, mode, allow_partial=True)
        os.unlink(part, dir_fd=directory)
    stage._write(directory, part, raw, mode)
    os.link(part, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    os.fsync(directory)
    _finish_link(directory, name, part, raw, mode)


def _open_directory(parent: int, name: str, stack: ExitStack) -> int:
    fd = os.open(name, stage._DIRECTORY, dir_fd=parent)
    stack.callback(os.close, fd)
    stage._protected_directory(fd)
    return fd


def _worker_directory(usr: int, stack: ExitStack, *, create: bool = False) -> int | None:
    directory = usr
    for name in ("libexec", "repocache"):
        parent = directory
        try:
            directory = _open_directory(parent, name, stack)
        except FileNotFoundError:
            if not create:
                return None
            os.mkdir(name, mode=0o755, dir_fd=parent)
            directory = _open_directory(parent, name, stack)
        if create:
            # On recovery, make an earlier mkdir durable even if that
            # process was interrupted before its directory sync.
            os.fsync(directory)
            os.fsync(parent)
    return directory


def _systemd_unit_paths() -> tuple[str, ...]:
    result = subprocess.run(
        ["/usr/bin/systemctl", "--system", "--no-pager", "show", "--property=UnitPath", "--value"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        cwd="/", timeout=12, check=False,
    )
    if result.returncode or not 1 <= len(result.stdout) <= 8192:
        _reject("UNIT_PATH_UNVERIFIED")
    paths = tuple(result.stdout.decode("ascii").split())
    if ("/etc/systemd/system" not in paths or len(paths) > 64
            or any(re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)+", path) is None
                   or any(part in (".", "..") for part in path.split("/")) for path in paths)):
        _reject("UNIT_PATH_UNVERIFIED")
    return paths


def _reject_conflicting_units(root: Path, unit_paths: tuple[str, ...]) -> None:
    for path in unit_paths:
        directory = root.joinpath(*path[1:].split("/"))
        for unit in stage.UNITS:
            names = [unit + ".d", "repocache-" + Path(unit).suffix + ".d"]
            if path != "/etc/systemd/system":
                names.append(unit)
            for name in names:
                try:
                    (directory / name).lstat()
                except FileNotFoundError:
                    continue
                _reject("FOREIGN_UNIT_OR_OVERRIDE")
        try:
            entries = tuple(directory.iterdir())
        except FileNotFoundError:
            continue
        for entry in entries:
            if entry.name.endswith((".wants", ".requires", ".upholds")):
                for unit in stage.UNITS:
                    try:
                        (entry / unit).lstat()
                    except FileNotFoundError:
                        continue
                    _reject("FOREIGN_UNIT_DEPENDENCY")
            if entry.name not in stage.UNITS and entry.is_symlink():
                if Path(os.readlink(entry)).name in stage.UNITS:
                    _reject("FOREIGN_UNIT_ALIAS")


def _place_worker_files(
    root: Path, payloads: dict[str, bytes], receipt: dict, *, unit_paths: tuple[str, ...],
    prepare_namespace: bool = False,
) -> None:
    digest = hashlib.sha256(stage._json_line(receipt)).hexdigest()
    pending = _MARKER + "pending-" + digest
    complete = _MARKER + "complete-" + digest
    with ExitStack() as stack:
        fd = os.open(root, stage._DIRECTORY)
        stack.callback(os.close, fd)
        stage._protected_directory(fd)
        usr = _open_directory(fd, "usr", stack)
        units = fd
        for component in _UNIT_DIRECTORY:
            units = _open_directory(units, component, stack)
        if prepare_namespace:
            _reject_conflicting_units(root, unit_paths)
            # A fresh namespace must not be created around unowned files.
            # Existing namespaces are checked under the protected lock below.
            if not os.path.lexists(root / "var/lib/repocache"):
                worker = _worker_directory(usr, stack)
                if (any(_named(units, name) is not None
                        for unit in stage.UNITS for name in (unit, _TEMP + unit))
                        or (worker is not None and any(_named(worker, name) is not None
                            for name in (stage.WORKER, _TEMP + stage.WORKER)))
                        or os.path.lexists(root / "run/repocache/server-control.sock")):
                    _reject("FOREIGN_EXISTING_DESTINATION")
            bootstrap_protected_namespace_under_root(fd, owner_uid=0, public_catalog=True)
        with _locked(fd, 0) as state:
            markers = {name for name in os.listdir(state) if name.startswith(_MARKER)}
            if markers - {pending, complete}:
                _reject("OTHER_CANDIDATE")
            for name in markers:
                info = _named(state, name)
                if info is None:
                    _reject("MARKER_CHANGED")
                _check_marker(info)
            _reject_conflicting_units(root, unit_paths)
            worker = _worker_directory(usr, stack)
            targets = [(units, unit) for unit in stage.UNITS]
            if worker is not None:
                targets.append((worker, stage.WORKER))
            if complete in markers:
                if worker is None:
                    _reject("MISSING_WORKER_DIRECTORY")
                if any(_named(directory, _TEMP + name) is not None
                       for directory, name in targets):
                    _reject("FOREIGN_PARTIAL_FILE")
                stage._audit_worker_files(root, payloads)
            else:
                try:
                    (root / "run/repocache/server-control.sock").lstat()
                except FileNotFoundError:
                    pass
                else:
                    _reject("LIVE_CONTROL_SOCKET")
                if pending not in markers:
                    for directory, name in targets:
                        if _named(directory, name) is not None or _named(directory, _TEMP + name) is not None:
                            _reject("FOREIGN_EXISTING_DESTINATION")
                    _create_marker(state, pending)
                worker = _worker_directory(usr, stack, create=True)
                _place_file(worker, stage.WORKER, payloads[stage.WORKER], 0o755)
                for unit in stage.UNITS:
                    _place_file(units, unit, payloads[unit], 0o644)
                stage._audit_worker_files(root, payloads)
                _create_marker(state, complete)
            final_pending = _named(state, pending)
            if final_pending is not None:
                _check_marker(final_pending)
                os.unlink(pending, dir_fd=state)
                os.fsync(state)


def install_authenticated_worker(
    assets: Path, *, commit: str, archive_sha256: str,
) -> dict:
    """Authenticated placement into fixed root paths, with no activation."""
    require_native_host_preconditions()
    payloads, receipt = stage._authenticated_payloads(
        assets, commit=commit, archive_sha256=archive_sha256, system=None,
    )
    _place_worker_files(Path("/"), payloads, receipt,
                        unit_paths=_systemd_unit_paths(), prepare_namespace=True)
    return {**receipt, "status": "AUTHENTICATED_WORKER_FILES_PLACED"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--archive-sha256", required=True)
    args = parser.parse_args()
    try:
        result = install_authenticated_worker(
            args.assets, commit=args.commit, archive_sha256=args.archive_sha256,
        )
    except (OSError, ValueError, subprocess.SubprocessError,
            signatures.SignatureError, upgrade.UpgradeError):
        result = {"status": "AUTHENTICATED_WORKER_PLACEMENT_REFUSED"}
        status = 1
    else:
        status = 0
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
