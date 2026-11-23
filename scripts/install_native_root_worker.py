#!/usr/bin/env python3
"""Place the authenticated fixed worker and units before native activation.

Run from a trusted, security-assessed checkout on an authorized host. This
operation prepares the fixed server namespace and places the authenticated
worker. It never reloads or enables a service.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

if __name__ == "__main__":
    checkout = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(checkout / "src"), str(checkout)]

from repocache import signatures, upgrade
from repocache.server_install_v1 import MAX_DOCUMENT_BYTES, parse_install_bytes
from repocache.server_native_nginx_local_boundary_v1 import inspect_native_nginx_local_boundary
from repocache.server_native_nginx_ownership_v1 import inspect_fresh_nginx_footprint
from repocache.server_native_nginx_package_journal_v1 import _retain_native_package_journal_lock_under_root
from repocache.server_native_package_trust_v1 import _NATIVE, _native_install_commands, _run as _native_run, _trusted_key
from repocache.server_native_nginx_service_unit_v1 import inspect_native_nginx_unit
from repocache.server_protected_state_inspect_v1 import _FIXED_STATE_ROOT
from repocache.server_stock_nginx_package_owner_v1 import inspect_stock_nginx_package_owner, inspect_stock_nginx_package_file_integrity
from repocache.server_protected_namespace_bootstrap_v1 import bootstrap_protected_namespace_under_root
from repocache.server_locked_manifest_reconcile_v1 import (
    _validate_proposed_v2_snapshot, preview_proposed_v2_state_transition,
)
from repocache.server_repository_reconcile_v1 import plan_declarative_reconciliation
from repocache.server_native_v2_transaction_v1 import (
    _no_conflicting_pending, _write_private,
    _require_audited_native_package_for_activation,
    _native_syntax_check,
)
from repocache.server_native_nginx_effective_unit_v1 import (
    inspect_effective_native_nginx_unit, _observe_systemd_pid1,
    _safe_native_systemctl, _FIXED_ARGS as _EFFECTIVE_SYSTEMCTL_ARGS,
)
from repocache.server_root_control_full_context_v1 import _capture_default_nginx_dump_private
from repocache.server_proposed_state_v2_store import _read_v2
from repocache.server_protected_state_store_v1 import _canonical, _locked, _unlink_known
from repocache.server_root_control_fixed_candidate_v1 import (
    _MAX_ENVELOPE, _MAX_STATE, _NAME as _PROPOSAL, _canonical_json, _proposal,
)
from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions
from repocache.server_native_root_control_entrypoint_v1 import _native_distro
from repocache.server_repository_plan_v1 import _canonical_identity, propose_automatic_repository_id
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
    _native_distro()
    require_native_host_preconditions()
    payloads, receipt = stage._authenticated_payloads(
        assets, commit=commit, archive_sha256=archive_sha256, system=None,
    )
    _place_worker_files(Path("/"), payloads, receipt,
                        unit_paths=_systemd_unit_paths(), prepare_namespace=True)
    return {**receipt, "status": "AUTHENTICATED_WORKER_FILES_PLACED"}


# First-install native effects are an explicit operator action, not a
# socket, generic subprocess or implicit side effect of worker placement.
_NGINX_MASK = "/etc/systemd/system/nginx.service"
_SYSTEMCTL = ("/usr/bin/systemctl", "--system", "--no-pager")


def _nginx_systemctl(action: str) -> tuple[int, bytes]:
    """Only the five fixed service-mask / non-activating audit operations."""
    if action not in ("mask", "unmask", "disable", "is-enabled", "is-active"):
        _reject("NATIVE_SYSTEMCTL_OPERATION_REFUSED")
    result = subprocess.run(
        [*_SYSTEMCTL, action, "nginx.service"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        cwd="/", timeout=20, check=False,
    )
    if type(result.stdout) is not bytes or len(result.stdout) > 256:
        _reject("NATIVE_SYSTEMCTL_RESULT_UNVERIFIED")
    return result.returncode, result.stdout


def _owned_nginx_mask() -> bool:
    try:
        info = os.lstat(_NGINX_MASK)
        return (stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and info.st_gid == 0 and info.st_nlink == 1
                and os.readlink(_NGINX_MASK) == "/dev/null")
    except FileNotFoundError:
        return False


def _fresh_nginx_under_lock(distribution: str, document: dict, os_release: str) -> None:
    def ignore_our_state(path: str) -> os.stat_result:
        if path == _FIXED_STATE_ROOT:
            raise FileNotFoundError(path)
        return os.lstat(path)

    observed = inspect_fresh_nginx_footprint(
        os_release=os_release, python_version=sys.version_info[:2],
        document=document, lstat=ignore_our_state,
    )
    if (observed.distribution != distribution
            or observed.code != "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED"):
        _reject("NATIVE_NGINX_FOREIGN_FOOTPRINT")


def _native_package_command(command: list[str], work: Path) -> str:
    output, failure = _native_run(command, work=work, runner=subprocess.run)
    if failure:
        _reject("NATIVE_MANAGER_COMMAND_FAILED")
    return output.strip()


def _native_workspace_is_root_owned(work: Path) -> bool:
    """Reject shared or user-controlled APT/DNF override files on a real host."""
    info = work.stat()
    return (info.st_uid == 0 and info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700
            and stat.S_ISDIR(info.st_mode))


def _ensure_fixed_nginx_cache_parent_under_root(root_fd: int, *, owner_uid: int = 0) -> None:
    """Provision only the missing native systemd ReadWritePaths cache parent.

    The stock APT/DNF package may not create /var/cache/nginx. Both the signed
    control unit and the native host-preflight require that exact directory;
    enabling the socket before it exists fails with systemd 226/NAMESPACE.
    Never follow symlinks, replace an existing directory, change foreign modes,
    choose a caller-provided path, or weaken the installed systemd sandbox.
    This is a private post-package step under the durable native install lock.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or owner_uid < 0):
        _reject("NATIVE_CACHE_PARENT_UNVERIFIED")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def checked(fd: int, *, parent_dev: int | None = None) -> os.stat_result:
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid
                or info.st_gid != os.fstat(root_fd).st_gid
                or info.st_mode & 0o022
                or (parent_dev is not None and info.st_dev != parent_dev)):
            _reject("NATIVE_CACHE_PARENT_UNSAFE")
        return info

    try:
        with ExitStack() as stack:
            root = checked(root_fd)
            directory = root_fd
            for name in ("var", "cache"):
                nxt = os.open(name, flags, dir_fd=directory)
                stack.callback(os.close, nxt)
                checked(nxt, parent_dev=os.fstat(directory).st_dev)
                directory = nxt

            parent = directory
            try:
                fd = os.open("nginx", flags, dir_fd=parent)
            except FileNotFoundError:
                # A concurrent foreign inode is a conflict, not an adoption.
                os.mkdir("nginx", 0o700, dir_fd=parent)
                fd = os.open("nginx", flags, dir_fd=parent)
                stack.callback(os.close, fd)
                created = os.fstat(fd)
                if (created.st_uid != owner_uid
                        or created.st_gid != root.st_gid
                        or not stat.S_ISDIR(created.st_mode)
                        or created.st_dev != os.fstat(parent).st_dev
                        or stat.S_IMODE(created.st_mode) != 0o700):
                    _reject("NATIVE_CACHE_PARENT_UNSAFE")
                os.fchmod(fd, 0o755)
                os.fsync(fd)
                os.fsync(parent)
            else:
                stack.callback(os.close, fd)
            leaf = checked(fd, parent_dev=os.fstat(parent).st_dev)
            if stat.S_IMODE(leaf.st_mode) != 0o755:
                _reject("NATIVE_CACHE_PARENT_UNSAFE")
            again = os.stat("nginx", dir_fd=parent, follow_symlinks=False)
            if ((again.st_dev, again.st_ino, again.st_mode, again.st_uid, again.st_gid)
                    != (leaf.st_dev, leaf.st_ino, leaf.st_mode, leaf.st_uid, leaf.st_gid)):
                _reject("NATIVE_CACHE_PARENT_CHANGED")
            # Verify fixed ancestry once more after any mkdir/fchmod/fsync.
            checked(root_fd)
            checked(parent, parent_dev=root.st_dev)
    except stage.WorkerStageError:
        raise
    except (OSError, ValueError, TypeError):
        _reject("NATIVE_CACHE_PARENT_UNVERIFIED")



def _require_private_nginx_listeners() -> None:
    """Fail closed on implicit, wildcard or non-loopback packaged listeners.

    Actual nginx -T expands every include. This restrictive bootstrap policy
    only accepts explicitly bound loopback sockets, one per server block at
    minimum. It is deliberately NOT a general nginx configuration parser:
    unfamiliar compressed/ambiguous forms are refused before systemctl start.
    """
    _native_syntax_check()
    try:
        dump = _capture_default_nginx_dump_private()
        if type(dump) is not bytes or not 1 <= len(dump) <= 1024 * 1024:
            _reject("NATIVE_LISTENERS_UNVERIFIED")
        lines = dump.decode("utf-8", "strict").splitlines()
        depth = 0
        servers: list[list[int | bool]] = []
        count = 0
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            # NGINX permits multiple statements per line. Such syntax is
            # valid but not safely assessable by this intentionally narrow
            # pre-start gate; refuse instead of guessing at socket exposure.
            if line.count(";") > 1 or line.count("{") > 1 or line.count("}") > 1:
                _reject("NATIVE_LISTENERS_UNVERIFIED")
            if re.search(r"\bserver\s*\{", line):
                if line != "server {":
                    _reject("NATIVE_LISTENERS_UNVERIFIED")
                servers.append([depth + 1, False])
            elif re.search(r"\bserver\b", line):
                # A server block with no explicit listen would default to
                # wildcard port 80. Reject unusual split/inline constructs.
                _reject("NATIVE_LISTENERS_UNVERIFIED")
            if re.search(r"\blisten\b", line):
                match = re.fullmatch(
                    r"listen\s+(?:127\.0\.0\.1:(\d{1,5})|\[::1\]:(\d{1,5}))"
                    r"(?:\s+ssl)?\s*;", line,
                )
                if match is None or not servers:
                    _reject("NATIVE_LISTENERS_UNVERIFIED")
                port = int(match.group(1) or match.group(2))
                if not 1 <= port <= 65535:
                    _reject("NATIVE_LISTENERS_UNVERIFIED")
                servers[-1][1] = True
                count += 1
            depth += line.count("{") - line.count("}")
            if depth < 0:
                _reject("NATIVE_LISTENERS_UNVERIFIED")
            while servers and depth < servers[-1][0]:
                if servers[-1][1] is not True:
                    _reject("NATIVE_LISTENERS_UNVERIFIED")
                servers.pop()
        if depth != 0 or servers or count == 0:
            _reject("NATIVE_LISTENERS_UNVERIFIED")
    except stage.WorkerStageError:
        raise
    except (OSError, ValueError, UnicodeError, TypeError):
        _reject("NATIVE_LISTENERS_UNVERIFIED")


def _nginx_inactive_vendor_service(distribution: str) -> None:
    """Verify the effective PID1 unit while inactive, before starting it."""
    try:
        _observe_systemd_pid1()
        _safe_native_systemctl()
        vendor = inspect_native_nginx_unit(distribution).to_dict()
        if (vendor.get("code") != "VENDOR_NGINX_UNIT_OBSERVED"
                or vendor.get("vendor_unit_bounded_and_owned") is not True
                or not re.fullmatch(r"[0-9a-f]{64}", vendor.get("vendor_unit_sha256", ""))):
            _reject("NATIVE_INACTIVE_UNIT_UNVERIFIED")
        result = subprocess.run(
            _EFFECTIVE_SYSTEMCTL_ARGS, shell=False, check=False, capture_output=True,
            text=True, timeout=5, cwd="/", stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, start_new_session=True,
        )
        if (result.returncode != 0 or type(result.stdout) is not str
                or not 1 <= len(result.stdout) <= 8192
                or type(result.stderr) is not str or len(result.stderr) > 4096):
            _reject("NATIVE_INACTIVE_UNIT_UNVERIFIED")
        fields = {}
        for line in result.stdout.splitlines():
            if "=" not in line:
                _reject("NATIVE_INACTIVE_UNIT_UNVERIFIED")
            k, v = line.split("=", 1)
            if k in fields:
                _reject("NATIVE_INACTIVE_UNIT_UNVERIFIED")
            fields[k] = v
        expected = {
            "Id": "nginx.service", "Names": "nginx.service",
            "FragmentPath": "/usr/lib/systemd/system/nginx.service",
            "DropInPaths": "", "LoadState": "loaded",
            "ActiveState": "inactive", "SubState": "dead",
            "MainPID": "0", "CanReload": "yes", "NeedDaemonReload": "no",
        }
        if fields != expected:
            _reject("NATIVE_INACTIVE_UNIT_UNVERIFIED")
    except stage.WorkerStageError:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        _reject("NATIVE_INACTIVE_UNIT_UNVERIFIED")


def _nginx_activation_command(action: str) -> None:
    if action not in ("start", "enable", "stop", "disable"):
        _reject("NATIVE_ACTIVATION_COMMAND_REFUSED")
    _safe_native_systemctl()
    try:
        proc = subprocess.run(
            [*_SYSTEMCTL, action, "nginx.service"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, cwd="/", timeout=30, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
            start_new_session=True,
        )
        if type(proc.returncode) is not int or proc.returncode != 0:
            _reject("NATIVE_ACTIVATION_COMMAND_FAILED")
    except stage.WorkerStageError:
        raise
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        _reject("NATIVE_ACTIVATION_COMMAND_FAILED")


def _activate_audited_native_nginx_under_lock(state_fd: int, distribution: str) -> dict:
    """Explicit fixed activation after signed install; never adopt foreign NGINX.

    No socket request can call this operation. The authenticated install tool
    owns the external operator action and the exclusive protected state lock.
    """
    _require_audited_native_package_for_activation(state_fd, distribution=distribution)
    _no_conflicting_pending(state_fd)
    if _read_v2(state_fd, 0)[0] is not None:
        _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")
    enabled = _nginx_systemctl("is-enabled")
    active = _nginx_systemctl("is-active")
    if enabled == (0, b"enabled\n") and active == (0, b"active\n"):
        # An operator may have started stock wildcard HTTP outside this
        # helper. Never certify that existing exposure merely because the
        # package receipt and vendor executable are authentic.
        _require_private_nginx_listeners()
        verified = inspect_effective_native_nginx_unit(distribution)
        if (verified.get("status") != "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION"
                or verified.get("authorizes_systemctl") is not False):
            _reject("NATIVE_ACTIVATION_UNIT_UNVERIFIED")
        return {"status": "AUTHENTICATED_NATIVE_NGINX_ALREADY_ACTIVE",
                "nginx_active_verified": True, "nginx_enabled_verified": True}
    if enabled != (1, b"disabled\n") or active != (3, b"inactive\n"):
        _reject("NATIVE_ACTIVATION_FOREIGN_SERVICE_STATE")
    _nginx_inactive_vendor_service(distribution)
    _require_private_nginx_listeners()
    try:
        _nginx_activation_command("start")
        observed = inspect_effective_native_nginx_unit(distribution)
        if (observed.get("status") != "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION"
                or type(observed.get("main_pid_observed")) is not int
                or observed["main_pid_observed"] <= 1):
            _reject("NATIVE_ACTIVATION_UNIT_UNVERIFIED")
        _nginx_activation_command("enable")
        after = inspect_effective_native_nginx_unit(distribution)
        if (after.get("vendor_unit_sha256") != observed.get("vendor_unit_sha256")
                or after.get("main_pid_observed") != observed["main_pid_observed"]
                or _nginx_systemctl("is-enabled") != (0, b"enabled\n")
                or _nginx_systemctl("is-active") != (0, b"active\n")):
            _reject("NATIVE_ACTIVATION_POSTCHECK_FAILED")
        _require_audited_native_package_for_activation(state_fd, distribution=distribution)
        return {"status": "AUTHENTICATED_NATIVE_NGINX_ACTIVE",
                "nginx_active_verified": True, "nginx_enabled_verified": True}
    except Exception:
        # The start command can report a timeout/failure AFTER systemd has
        # already launched the vendor master. Inspect the real active state
        # even when start raised; never leave a partially started listener.
        # Stop only a verified vendor unit, never an unknown/foreign process.
        try:
            current = _nginx_systemctl("is-active")
            if current == (0, b"active\n"):
                observed = inspect_effective_native_nginx_unit(distribution)
                if (observed.get("status") != "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION"
                        or observed.get("authorizes_systemctl") is not False):
                    _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                _nginx_activation_command("stop")
            elif current != (3, b"inactive\n"):
                _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
            _nginx_activation_command("disable")
            _nginx_inactive_vendor_service(distribution)
            if (_nginx_systemctl("is-enabled") != (1, b"disabled\n")
                    or _nginx_systemctl("is-active") != (3, b"inactive\n")):
                _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
        except Exception:
            _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
        _reject("NATIVE_ACTIVATION_FAILED_ROLLED_BACK")


def activate_authenticated_native_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
) -> dict:
    """Opt-in activation, with repeatable signed worker and OS checks."""
    distribution = _native_distro()
    require_native_host_preconditions()
    attested = stage.verify_installed_worker(
        assets, commit=commit, archive_sha256=archive_sha256,
    )
    if (type(attested) is not dict
            or attested.get("status") != "AUTHENTICATED_WORKER_FILES_MATCH"
            or attested.get("source_sha") != commit
            or attested.get("archive_sha256") != archive_sha256
            or attested.get("authorizes_host_installation") is not False
            or attested.get("authorizes_service_activation") is not False):
        _reject("NATIVE_SIGNED_WORKER_AUDIT_UNVERIFIED")
    root = os.open("/", stage._DIRECTORY)
    try:
        with _locked(root, 0) as state:
            return _activate_audited_native_nginx_under_lock(state, distribution)
    finally:
        os.close(root)


def _execute_native_nginx_install_locked(
    root_fd: int, *, distribution: str, document: dict, os_release: str,
    owner_uid: int = 0,
) -> dict:
    """Host APT/DNF; one durable marker and lock across signed-source install.

    A failure retains the blocking journal. The persistent systemd mask
    survives power loss while native package effects may be incomplete.
    """
    def refuse_stable_foreign_host_before_journal() -> None:
        # Same exclusive lock as the journal. A stable foreign host must not
        # receive a misleading pending marker when no package effect began.
        _fresh_nginx_under_lock(distribution, document, os_release)
        if not _trusted_key(_NATIVE[distribution][2]):
            _reject("NATIVE_TRUST_ANCHOR_UNVERIFIED")
        if os.path.lexists(_NGINX_MASK):
            _reject("NATIVE_FOREIGN_SERVICE_MASK")

    with _retain_native_package_journal_lock_under_root(
        root_fd, owner_uid=owner_uid, distribution=distribution,
        allow_native_package_parent_changes=True, expose_audited_completion=True,
        preflight_before_journal=refuse_stable_foreign_host_before_journal,
    ) as transaction:
        if (transaction.get("status") != "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
                or transaction.get("authorizes_package_installation") is not False
                or "_complete_under_lock" not in transaction):
            _reject("NATIVE_JOURNAL_UNVERIFIED")
        _fresh_nginx_under_lock(distribution, document, os_release)
        if not _trusted_key(_NATIVE[distribution][2]):
            _reject("NATIVE_TRUST_ANCHOR_UNVERIFIED")
        if os.path.lexists(_NGINX_MASK):
            _reject("NATIVE_FOREIGN_SERVICE_MASK")
        if _nginx_systemctl("mask")[0] != 0 or not _owned_nginx_mask():
            _reject("NATIVE_SERVICE_MASK_FAILED")
        try:
            with tempfile.TemporaryDirectory(prefix="repocache-native-nginx-", dir="/var/tmp") as temp:
                work = Path(temp)
                if not _native_workspace_is_root_owned(work):
                    _reject("NATIVE_WORKSPACE_UNSAFE")
                refresh, install = _native_install_commands(distribution, work)
                _native_package_command(refresh, work)
                _native_package_command(install, work)
                if distribution == "debian":
                    status = _native_package_command(
                        ["/usr/bin/dpkg-query", "-W", "-f=${Status}", "nginx"], work,
                    )
                    if status != "install ok installed":
                        _reject("NATIVE_PACKAGE_STATUS_UNVERIFIED")
                else:
                    status = _native_package_command(
                        ["/usr/bin/rpm", "-q", "--queryformat=%{NAME}", "nginx"], work,
                    )
                    if status != "nginx":
                        _reject("NATIVE_PACKAGE_STATUS_UNVERIFIED")
                _native_package_command(["/usr/sbin/nginx", "-t", "-q"], work)
            if (inspect_stock_nginx_package_owner().get("native_package_db_owner_observed") is not True
                    or inspect_stock_nginx_package_file_integrity().get(
                        "native_package_file_integrity_verified") is not True):
                _reject("NATIVE_PACKAGE_INTEGRITY_UNVERIFIED")
            # Package scripts may enable nginx automatically. Disable it
            # while masked, BEFORE allowing any later service activation.
            if _nginx_systemctl("disable")[0] != 0 or not _owned_nginx_mask():
                _reject("NATIVE_SERVICE_DISABLE_FAILED")
            if _nginx_systemctl("unmask")[0] != 0 or os.path.lexists(_NGINX_MASK):
                _reject("NATIVE_SERVICE_UNMASK_FAILED")
            if (_nginx_systemctl("is-enabled") != (1, b"disabled\n")
                    or _nginx_systemctl("is-active") != (3, b"inactive\n")):
                _reject("NATIVE_SERVICE_EXPOSURE_UNVERIFIED")
            unit = inspect_native_nginx_unit(distribution).to_dict()
            if unit.get("code") != "VENDOR_NGINX_UNIT_OBSERVED":
                _reject("NATIVE_VENDOR_UNIT_UNVERIFIED")
            # The signed control unit requires this fixed ReadWritePaths
            # directory. Some native nginx packages do not provision it.
            # Complete the package receipt only after its owned parent is safe.
            _ensure_fixed_nginx_cache_parent_under_root(root_fd, owner_uid=owner_uid)
            # The atomic completion primitive independently repeats the
            # protected-state, package, file and vendor-unit checks.
            result = transaction["_complete_under_lock"]()
            if (result.get("native_package_effects_reconciled") is not True
                    or result.get("authorizes_service_activation") is not False):
                _reject("NATIVE_COMPLETION_UNVERIFIED")
            return {
                "status": "AUTHENTICATED_NATIVE_NGINX_PACKAGE_INSTALLED",
                "native_package_effects_reconciled": True,
                "authorizes_service_activation": False,
                "booted_service_verified": False,
            }
        except Exception:
            # Retain/recreate a fixed fail-closed mask on ambiguous failure.
            # Never clear the durable pending marker or retry native effects.
            if not os.path.lexists(_NGINX_MASK):
                try:
                    _nginx_systemctl("mask")
                except (OSError, ValueError, subprocess.SubprocessError):
                    pass
            raise


def install_authenticated_native_nginx(
    assets: Path, document: Path, document_sha256: str, *,
    commit: str, archive_sha256: str,
) -> dict:
    """Opt-in first-install from owner-authenticated release; no NGINX start."""
    distribution = _native_distro()
    require_native_host_preconditions()
    attested = stage.verify_installed_worker(
        assets, commit=commit, archive_sha256=archive_sha256,
    )
    if (type(attested) is not dict
            or attested.get("status") != "AUTHENTICATED_WORKER_FILES_MATCH"
            or attested.get("source_sha") != commit
            or attested.get("archive_sha256") != archive_sha256
            or attested.get("authorizes_host_installation") is not False
            or attested.get("authorizes_service_activation") is not False):
        _reject("NATIVE_SIGNED_WORKER_AUDIT_UNVERIFIED")
    if (type(document_sha256) is not str
            or signatures.HEX64.fullmatch(document_sha256) is None):
        _reject("NATIVE_DOCUMENT_PIN_INVALID")
    with ExitStack() as stack:
        source = os.open(document.parent, stage._DIRECTORY)
        stack.callback(os.close, source)
        raw = stage._asset_bytes(source, document.name, MAX_DOCUMENT_BYTES)
        if hashlib.sha256(raw).hexdigest() != document_sha256:
            _reject("NATIVE_DOCUMENT_PIN_MISMATCH")
        parsed = parse_install_bytes(raw)
        if parsed["expected_state_generation"] != 0:
            _reject("NATIVE_INITIAL_GENERATION_REQUIRED")
        os_release = Path("/usr/lib/os-release").read_text(encoding="ascii")
        boundary = inspect_native_nginx_local_boundary(
            os_release=os_release, python_version=sys.version_info[:2],
            document=parsed,
        )
        if (boundary.distribution != distribution
                or boundary.code != "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED"
                or not _trusted_key(_NATIVE[distribution][2])):
            _reject("NATIVE_PREPACKAGE_BOUNDARY_UNVERIFIED")
        root = os.open("/", stage._DIRECTORY)
        stack.callback(os.close, root)
        return _execute_native_nginx_install_locked(
            root, distribution=distribution, document=parsed, os_release=os_release,
        )


_PROPOSAL_STAGE = ".admin-candidate-v2.stage"


def _initial_proposal(raw: bytes, decision_sha256: str) -> bytes:
    """Prepare generation one as data for separate review and locked intake."""
    if type(decision_sha256) is not str or not signatures.HEX64.fullmatch(decision_sha256):
        _reject("DECISION_DIGEST_INVALID")
    document = parse_install_bytes(raw, for_apply=True)
    if document["expected_state_generation"] != 0:
        _reject("INITIAL_GENERATION_REQUIRED")
    identified = [row for row in document["repositories"] if "id" in row]
    base = {**document, "repositories": identified}
    reserved = {row["id"] for row in identified}
    for row in document["repositories"]:
        if "id" not in row:
            suggestion = propose_automatic_repository_id(
                base, row, current_generation=0, reserved_ids=reserved,
            )
            row["id"] = suggestion["repository_id"]
            reserved.add(row["id"])
            identified.append(row)
    return _encode_proposal(document, decision_sha256)


def _encode_proposal(document: dict, decision_sha256: str, previous: dict | None = None) -> bytes:
    generation = document["expected_state_generation"]
    document["expected_state_generation"] = generation + 1
    configuration = _canonical(document, limit=MAX_DOCUMENT_BYTES)
    records = [{
        "id": row["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(row).encode("utf-8")
        ).hexdigest(),
        "desired_state": row["desired_state"],
        "observed_state": "not-activated",
    } for row in document["repositories"]]
    digest = hashlib.sha256(configuration).hexdigest()
    reservations = [{
        "id": row["id"],
        "canonical_identity_sha256": row["canonical_identity_sha256"],
        "status": "allocated",
    } for row in records]
    if previous is not None:
        present = {row["id"] for row in records}
        reservations.extend({
            **row, "status": "retired",
        } for row in previous["id_reservations"] if row["id"] not in present)
    snapshot = {
        "state_schema_version": 2,
        "state_generation": generation + 1,
        "configuration_base64": base64.b64encode(configuration).decode("ascii"),
        "configuration_sha256": digest,
        "repository_records": records,
        "id_reservations": reservations,
        "approval_reference": {
            "source": "operator",
            "decision_sha256": decision_sha256,
            "configuration_sha256": digest,
            "expected_generation": generation,
        },
    }
    preview_proposed_v2_state_transition(
        snapshot, expected_generation=generation, previous_snapshot=previous,
    )
    return _canonical(snapshot, limit=_MAX_STATE)


def _repair_proposal(raw: bytes, prior_raw: bytes, prior_sha256: str, decision_sha256: str) -> bytes:
    """Plan a partial same-version repair, preserving all omitted repositories."""
    if (type(prior_sha256) is not str or not signatures.HEX64.fullmatch(prior_sha256)
            or hashlib.sha256(prior_raw).hexdigest() != prior_sha256):
        _reject("PREVIOUS_STATE_PIN_MISMATCH")
    if type(decision_sha256) is not str or not signatures.HEX64.fullmatch(decision_sha256):
        _reject("DECISION_DIGEST_INVALID")
    previous = _canonical_json(prior_raw, _MAX_STATE)
    generation = _validate_proposed_v2_snapshot(previous)["generation"]
    current = parse_install_bytes(base64.b64decode(previous["configuration_base64"]), for_apply=True)
    proposed = parse_install_bytes(raw, for_apply=True)
    plan = plan_declarative_reconciliation(
        current, proposed, current_generation=generation,
    )
    if not plan["changed"]:
        return prior_raw
    return _encode_proposal(plan["candidate_document"], decision_sha256, previous)


def prepare_authenticated_proposal(
    assets: Path, document: Path, output: Path, *,
    commit: str, archive_sha256: str, decision_sha256: str,
    previous: Path | None = None, previous_sha256: str | None = None,
) -> dict:
    """Authenticate the candidate, then create a private proposal for review."""
    stage._authenticated_payloads(
        assets, commit=commit, archive_sha256=archive_sha256, system=None,
    )
    with ExitStack() as stack:
        source = os.open(document.parent, stage._DIRECTORY)
        stack.callback(os.close, source)
        raw = stage._asset_bytes(source, document.name, MAX_DOCUMENT_BYTES)
        if previous is None:
            if previous_sha256 is not None:
                _reject("PREVIOUS_STATE_REQUIRED")
            proposal = _initial_proposal(raw, decision_sha256)
        else:
            prior_source = os.open(previous.parent, stage._DIRECTORY)
            stack.callback(os.close, prior_source)
            prior_raw = stage._asset_bytes(prior_source, previous.name, _MAX_STATE)
            proposal = _repair_proposal(raw, prior_raw, previous_sha256, decision_sha256)
        destination = os.open(output.parent, stage._DIRECTORY)
        stack.callback(os.close, destination)
        parent = os.fstat(destination)
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            _reject("PROPOSAL_OUTPUT_UNSAFE")
        stage._write(destination, output.name, proposal, 0o600)
        os.fsync(destination)
    return {
        "status": "AUTHENTICATED_V2_PROPOSAL_PREPARED",
        "proposed_state_sha256": hashlib.sha256(proposal).hexdigest(),
        "state_generation": _canonical_json(proposal, _MAX_STATE)["state_generation"],
        "expected_state_sha256": previous_sha256,
        "requires_operator_review": True,
        "authorizes_service_activation": False,
    }


def _read_proposal_at(state: int, name: str) -> bytes | None:
    if _named(state, name) is None:
        return None
    return stage._asset_bytes(state, name, _MAX_ENVELOPE, installed_mode=0o600)


def _stage_proposal_under_root(
    root_fd: int, raw: bytes, reviewed_sha: str, *, expected_state_sha256: str | None = None,
) -> dict:
    if not signatures.HEX64.fullmatch(reviewed_sha) or hashlib.sha256(raw).hexdigest() != reviewed_sha:
        _reject("PROPOSAL_PIN_MISMATCH")
    snapshot = _canonical_json(raw, _MAX_STATE)
    if expected_state_sha256 is not None and (
        type(expected_state_sha256) is not str or not signatures.HEX64.fullmatch(expected_state_sha256)
    ):
        _reject("PREVIOUS_STATE_PIN_MISMATCH")
    with _locked(root_fd, 0) as state:
        # Native package-effects markers and all unresolved WALs must stay
        # in place. Proposal staging grants no recovery or activation authority.
        _no_conflicting_pending(state)
        previous, previous_raw = _read_v2(state, 0)
        generation = 0 if previous is None else previous["state_generation"]
        prior = _read_proposal_at(state, _PROPOSAL)
        interrupted = _read_proposal_at(state, _PROPOSAL_STAGE)
        if raw == previous_raw:
            if prior is None:
                _reject("COMMITTED_PROPOSAL_MISSING")
            prior_report, prior_state = _proposal(prior)
            if prior_state != raw or prior_report["expected_generation"] != generation - 1:
                _reject("COMMITTED_PROPOSAL_MISSING")
            if expected_state_sha256 is not None and expected_state_sha256 not in (
                reviewed_sha, prior_report["expected_state_sha256"],
            ):
                _reject("PREVIOUS_STATE_PIN_MISMATCH")
            if interrupted is not None:
                _reject("PROPOSAL_STAGE_PENDING")
            return {
                "status": "AUTHENTICATED_V2_PROPOSAL_ALREADY_COMMITTED",
                "proposed_state_sha256": reviewed_sha,
                "committed_generation": generation,
                "authorizes_service_activation": False,
            }
        if expected_state_sha256 is not None and (
            previous_raw is None or hashlib.sha256(previous_raw).hexdigest() != expected_state_sha256
        ):
            _reject("PREVIOUS_STATE_PIN_MISMATCH")
        preview_proposed_v2_state_transition(
            snapshot, expected_generation=generation, previous_snapshot=previous,
        )
        envelope = _canonical({
            "request_schema_version": 1,
            "expected_generation": generation,
            "expected_state_sha256": (
                None if previous_raw is None else hashlib.sha256(previous_raw).hexdigest()
            ),
            "next_state_base64": base64.b64encode(raw).decode("ascii"),
            "next_state_sha256": reviewed_sha,
        }, limit=_MAX_ENVELOPE)
        _proposal(envelope)
        if interrupted is not None and interrupted != envelope:
            _reject("FOREIGN_PROPOSAL_STAGE")
        if prior is not None and prior != envelope:
            # Replace only a proposal whose exact state is now committed.
            # A different, still-pending operator decision remains untouched.
            _, prior_state = _proposal(prior)
            if prior_state != previous_raw:
                _reject("UNCOMMITTED_PRIOR_PROPOSAL")
        if interrupted is not None:
            _unlink_known(state, _PROPOSAL_STAGE, envelope, 0, _MAX_ENVELOPE)
        if prior != envelope:
            _write_private(state, _PROPOSAL, _PROPOSAL_STAGE, prior, envelope, _MAX_ENVELOPE)
    return {
        "status": "AUTHENTICATED_V2_PROPOSAL_STAGED",
        "proposed_state_sha256": reviewed_sha,
        "expected_generation": generation,
        "authorizes_service_activation": False,
    }


def stage_authenticated_proposal(
    assets: Path, snapshot: Path, *, commit: str, archive_sha256: str, proposal_sha256: str,
    expected_state_sha256: str | None = None,
) -> dict:
    """Verify the installed worker against the authenticated release before staging."""
    _native_distro()
    require_native_host_preconditions()
    stage.verify_installed_worker(assets, commit=commit, archive_sha256=archive_sha256)
    with ExitStack() as stack:
        source = os.open(snapshot.parent, stage._DIRECTORY)
        stack.callback(os.close, source)
        raw = stage._asset_bytes(source, snapshot.name, _MAX_STATE)
        root = os.open("/", stage._DIRECTORY)
        stack.callback(os.close, root)
        return _stage_proposal_under_root(
            root, raw, proposal_sha256, expected_state_sha256=expected_state_sha256,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--archive-sha256", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--stage-v2-proposal", type=Path)
    mode.add_argument("--install-native-nginx", type=Path)
    mode.add_argument("--activate-native-nginx", action="store_true")
    mode.add_argument("--prepare-initial-v2-proposal", type=Path)
    mode.add_argument("--prepare-v2-repair", type=Path)
    parser.add_argument("--proposal-sha256")
    parser.add_argument("--document-sha256")
    parser.add_argument("--proposal-output", type=Path)
    parser.add_argument("--decision-sha256")
    parser.add_argument("--previous-v2-state", type=Path)
    parser.add_argument("--previous-state-sha256")
    parser.add_argument("--expected-state-sha256")
    args = parser.parse_args()
    if (args.install_native_nginx is None) != (args.document_sha256 is None):
        parser.error("--install-native-nginx requires --document-sha256")
    if (args.stage_v2_proposal is None) != (args.proposal_sha256 is None):
        parser.error("--stage-v2-proposal and --proposal-sha256 must be supplied together")
    repairing = args.prepare_v2_repair is not None
    preparing = args.prepare_initial_v2_proposal is not None or repairing
    if preparing != (args.proposal_output is not None) or preparing != (args.decision_sha256 is not None):
        parser.error("proposal preparation requires --proposal-output and --decision-sha256")
    if repairing != (args.previous_v2_state is not None) or repairing != (args.previous_state_sha256 is not None):
        parser.error("--prepare-v2-repair requires --previous-v2-state and --previous-state-sha256")
    if args.expected_state_sha256 is not None and args.stage_v2_proposal is None:
        parser.error("--expected-state-sha256 requires --stage-v2-proposal")
    pins = {"commit": args.commit, "archive_sha256": args.archive_sha256}
    try:
        if preparing:
            result = prepare_authenticated_proposal(
                args.assets, args.prepare_v2_repair or args.prepare_initial_v2_proposal,
                args.proposal_output, decision_sha256=args.decision_sha256,
                previous=args.previous_v2_state, previous_sha256=args.previous_state_sha256, **pins,
            )
        elif args.activate_native_nginx:
            result = activate_authenticated_native_nginx(args.assets, **pins)
        elif args.install_native_nginx is not None:
            result = install_authenticated_native_nginx(
                args.assets, args.install_native_nginx, args.document_sha256, **pins,
            )
        elif args.stage_v2_proposal is None:
            result = install_authenticated_worker(args.assets, **pins)
        else:
            result = stage_authenticated_proposal(
                args.assets, args.stage_v2_proposal, proposal_sha256=args.proposal_sha256,
                expected_state_sha256=args.expected_state_sha256, **pins,
            )
    except (OSError, ValueError, subprocess.SubprocessError,
            signatures.SignatureError, upgrade.UpgradeError):
        refused = "AUTHENTICATED_WORKER_PLACEMENT_REFUSED"
        if preparing or args.stage_v2_proposal is not None:
            refused = "AUTHENTICATED_V2_PROPOSAL_REFUSED"
        elif args.install_native_nginx is not None:
            refused = "AUTHENTICATED_NATIVE_NGINX_INSTALL_REFUSED"
        elif args.activate_native_nginx:
            refused = "AUTHENTICATED_NATIVE_NGINX_ACTIVATION_REFUSED"
        result = {"status": refused}
        status = 1
    else:
        status = 0
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
