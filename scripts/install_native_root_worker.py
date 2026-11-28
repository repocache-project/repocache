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
from repocache.server_native_installed_storage_v1 import (
    _Labels, prepare_installed_storage, verify_service_storage_mounts,
)
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
    _native_syntax_check, _OWNED_BOOTSTRAP_CONFIG,
    _owned_layout_locked, _read_owned_resources, _validate_owned_resources,
    _owned_live_observe, _owned_live_validate, _owned_live_health_bound,
    _owned_socket_require_inactive_routes, _no_conflicting_owned_wal_pending,
    _owned_debian_runtime_temps, _owned_alma_runtime_temps, _OWNED_WAL, _MAX_WAL, _CATALOG,
    _decode_owned_wal, _owned_live_guard,
    _prepare_owned_inactive_wal_rollback_locked,
    _finish_owned_inactive_wal_rollback_locked,
    NativeV2TransactionError,
)
from repocache.server_native_nginx_effective_unit_v1 import (
    inspect_effective_native_nginx_unit, _observe_systemd_pid1,
    _safe_native_systemctl, _FIXED_ARGS as _EFFECTIVE_SYSTEMCTL_ARGS,
    EffectiveNginxUnitError, inspect_effective_owned_nginx_unit,
    OWNED_NGINX_CONFIG_MARKER_PREFIX, _read_exact_owned_unit_at,
)
from repocache.server_root_control_full_context_v1 import _capture_default_nginx_dump_private
from repocache.server_proposed_state_v2_store import _read_v2
from repocache.server_protected_state_store_v1 import (
    _canonical, _locked, _unlink_known, _read_file,
)
from repocache.server_root_control_fixed_candidate_v1 import (
    _MAX_ENVELOPE, _MAX_STATE, _NAME as _PROPOSAL, _canonical_json, _proposal,
)
from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions
from repocache.server_native_root_control_entrypoint_v1 import _native_distro
from repocache.server_repository_plan_v1 import _canonical_identity, propose_automatic_repository_id
from scripts import stage_native_root_worker as stage


_MARKER = ".native-worker-placement."
_RUNTIME_RECEIPT = ".native-worker-receipt-v1.json"
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
                        link = (entry / unit).lstat()
                    except FileNotFoundError:
                        continue
                    if (unit == "repocache-nginx.service"
                            and path == "/etc/systemd/system"
                            and entry.name == "multi-user.target.wants"
                            and stat.S_ISLNK(link.st_mode)
                            and link.st_uid == 0 and link.st_gid == 0
                            and stat.S_ISDIR(entry.lstat().st_mode)
                            and entry.lstat().st_uid == 0
                            and entry.lstat().st_gid == 0
                            and not (stat.S_IMODE(entry.lstat().st_mode) & 0o022)
                            and os.readlink(entry / unit) == "../repocache-nginx.service"
                            and (directory / unit).is_file()
                            and (not (directory / unit).is_symlink())):
                        # Our signed service's normal enablement is not a
                        # foreign dependency. The installed unit bytes are
                        # separately reauthenticated under the placement lock.
                        continue
                    _reject("FOREIGN_UNIT_DEPENDENCY")
            if entry.name not in stage.UNITS and entry.is_symlink():
                if Path(os.readlink(entry)).name in stage.UNITS:
                    _reject("FOREIGN_UNIT_ALIAS")


def _place_worker_files(
    root: Path, payloads: dict[str, bytes], receipt: dict, *, unit_paths: tuple[str, ...],
    prepare_namespace: bool = False,
) -> None:
    receipt_raw = stage._json_line(receipt)
    digest = hashlib.sha256(receipt_raw).hexdigest()
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
                # Only an independently authenticated identical installation
                # can fill the local receipt on an older completed placement.
                _place_file(state, _RUNTIME_RECEIPT, receipt_raw, 0o600)
            else:
                try:
                    (root / "run/repocache/server-control.sock").lstat()
                except FileNotFoundError:
                    pass
                else:
                    _reject("LIVE_CONTROL_SOCKET")
                if pending not in markers:
                    if any(_named(state, name) is not None for name in (
                            _RUNTIME_RECEIPT, _TEMP + _RUNTIME_RECEIPT)):
                        _reject("FOREIGN_RUNTIME_RECEIPT")
                    for directory, name in targets:
                        if _named(directory, name) is not None or _named(directory, _TEMP + name) is not None:
                            _reject("FOREIGN_EXISTING_DESTINATION")
                    _create_marker(state, pending)
                worker = _worker_directory(usr, stack, create=True)
                _place_file(worker, stage.WORKER, payloads[stage.WORKER], 0o755)
                for unit in stage.UNITS:
                    _place_file(units, unit, payloads[unit], 0o644)
                stage._audit_worker_files(root, payloads)
                _place_file(state, _RUNTIME_RECEIPT, receipt_raw, 0o600)
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


def _candidate_payload_sha256(path: Path) -> str:
    """Bounded fixed-workspace payload read; no archive extraction."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_gid != 0 or before.st_nlink != 1
                or before.st_mode & 0o022 or not 0 < before.st_size <= 32 * 1024 * 1024):
            _reject("NATIVE_EXECUTABLE_PAYLOAD_UNSAFE")
        raw = stream.read(32 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
        named = path.lstat()
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(raw) != before.st_size or
                any(getattr(before, k) != getattr(after, k) or
                    getattr(after, k) != getattr(named, k) for k in fields)):
            _reject("NATIVE_EXECUTABLE_PAYLOAD_CHANGED")
        return hashlib.sha256(raw).hexdigest()


def _candidate_native_identity(distribution: str, work: Path) -> str:
    if distribution == "debian":
        version = _native_package_command(
            ["/usr/bin/dpkg-query", "-W", "-f=${Version}\\t${Status}\\t${Architecture}",
             "nginx:amd64"], work)
        fields = version.split("\t")
        if (len(fields) != 3 or fields[1:] != ["install ok installed", "amd64"]
                or re.fullmatch(r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+~:-]{0,127}", fields[0]) is None):
            _reject("NATIVE_EXECUTABLE_PACKAGE_IDENTITY_REFUSED")
        return "nginx:amd64=" + fields[0]
    if distribution == "almalinux":
        identity = _native_package_command(
            ["/usr/bin/rpm", "-q", "--queryformat=%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}",
             "nginx-core"], work)
        if re.fullmatch(r"nginx-core-[0-9]+:[A-Za-z0-9._+~-]+-[A-Za-z0-9._+~-]+\.x86_64", identity) is None:
            _reject("NATIVE_EXECUTABLE_PACKAGE_IDENTITY_REFUSED")
        return identity
    _reject("NATIVE_EXECUTABLE_DISTRIBUTION_REFUSED")


def _authenticate_candidate_deb(work: Path, identity: str) -> tuple[str, str]:
    from repocache.server_native_package_trust_v1 import _apt_commands
    from repocache.server_native_nginx_executable_v1 import (
        debian_nginx_metadata_digest, debian_nginx_tar_digest,
    )
    refresh, query = _apt_commands(work)
    if refresh[-1] != "update" or query[-2:] != ["policy", "nginx"]:
        _reject("NATIVE_EXECUTABLE_APT_PROFILE_CHANGED")
    _native_package_command(refresh, work)
    version = identity.removeprefix("nginx:amd64=")
    metadata = _native_package_command([*query[:-2], "show", identity], work)
    expected = debian_nginx_metadata_digest(metadata, version)
    _native_package_command([*refresh[:-1], "download", identity], work)
    packages = list(work.glob("*.deb"))
    if len(packages) != 1 or _candidate_payload_sha256(packages[0]) != expected:
        _reject("NATIVE_EXECUTABLE_DEB_DIGEST_REFUSED")
    payload = packages[0]
    for field, value in (("Package", "nginx"), ("Version", version), ("Architecture", "amd64")):
        if _native_package_command(["/usr/bin/dpkg-deb", "--field", str(payload), field], work) != value:
            _reject("NATIVE_EXECUTABLE_DEB_IDENTITY_REFUSED")
    data = work / "payload.tar"
    with data.open("xb") as out:
        os.fchmod(out.fileno(), 0o600)
        subprocess.run(
            ["/usr/bin/prlimit", "--fsize=67108864:67108864", "--",
             "/usr/bin/dpkg-deb", "--fsys-tarfile", str(payload)],
            stdout=out, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True, timeout=60, cwd=str(work),
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
        out.flush()
        os.fsync(out.fileno())
    if (not 0 < data.stat().st_size <= 64 * 1024 * 1024
            or _candidate_payload_sha256(payload) != expected):
        _reject("NATIVE_EXECUTABLE_DEB_DIGEST_REFUSED")
    return expected, debian_nginx_tar_digest(data.read_bytes())


def _authenticate_candidate_rpm(work: Path, identity: str) -> tuple[str, str]:
    from repocache.server_native_package_trust_v1 import _dnf_commands
    update, query = _dnf_commands(work)
    if query[-4:] != ["repoquery", "--available", "--queryformat=%{name}", "nginx"]:
        _reject("NATIVE_EXECUTABLE_DNF_PROFILE_CHANGED")
    _native_package_command(update, work)
    urls = set(_native_package_command(
        [*query[:-4], "-q", "repoquery", "--available", "--location", identity], work).splitlines())
    if len(urls) != 1:
        _reject("NATIVE_EXECUTABLE_RPM_LOCATION_REFUSED")
    url = urls.pop()
    if re.fullmatch(
        r"https://repo\.almalinux\.org/almalinux/10/(?:AppStream|BaseOS)/"
        r"x86_64/os/Packages/(?:[A-Za-z0-9._+~-]+/)*nginx-core-[A-Za-z0-9._+~-]+\.rpm",
        url,
    ) is None:
        _reject("NATIVE_EXECUTABLE_RPM_LOCATION_REFUSED")
    payload = work / "nginx-core.rpm"
    _native_package_command(["/usr/bin/curl", "--fail", "--silent", "--show-error",
                             "--proto", "=https", "--tlsv1.2", "--max-filesize", "33554432",
                             "--max-time", "90", "--output", str(payload), url], work)
    archive_digest = _candidate_payload_sha256(payload)
    key = _NATIVE["almalinux"][2]
    if not _trusted_key(key):
        _reject("NATIVE_EXECUTABLE_TRUST_ANCHOR_REFUSED")
    # The private verification database is a new root-owned scratch inode,
    # not the native system database or a new system trust anchor. Match
    # its existing distro RPMDB label, never change a policy or host path.
    with tempfile.TemporaryDirectory(prefix="repocache-native-executable-rpmdb-", dir="/var/lib") as tmp:
        db = Path(tmp)
        if not _native_workspace_is_root_owned(db) or any(db.iterdir()):
            _reject("NATIVE_EXECUTABLE_RPMDB_REFUSED")
        with ExitStack() as stack:
            reference = os.open("/usr/lib/sysimage/rpm", stage._DIRECTORY)
            stack.callback(os.close, reference)
            stage._protected_directory(reference)
            directory = os.open(db, stage._DIRECTORY)
            stack.callback(os.close, directory)
            stage._protected_directory(directory)
            label = os.getxattr(reference, "security.selinux")
            if label.split(b":")[2:3] != [b"rpm_var_lib_t"]:
                _reject("NATIVE_EXECUTABLE_RPMDB_LABEL_REFUSED")
            os.setxattr(directory, "security.selinux", label)
            if os.getxattr(directory, "security.selinux") != label:
                _reject("NATIVE_EXECUTABLE_RPMDB_LABEL_REFUSED")
        for action in (["--initdb"], ["--import", key]):
            _native_package_command(["/usr/bin/rpm", "--dbpath", str(db), *action], work)
        verified = _native_package_command(
            ["/usr/bin/rpmkeys", "--dbpath", str(db), "--checksig", str(payload)], work)
        if verified != str(payload) + ": digests signatures OK":
            _reject("NATIVE_EXECUTABLE_RPM_SIGNATURE_REFUSED")
        if _candidate_payload_sha256(payload) != archive_digest:
            _reject("NATIVE_EXECUTABLE_PAYLOAD_CHANGED")
        def query_rpm(fmt):
            return _native_package_command(
                ["/usr/bin/rpm", "--dbpath", str(db), "-qp", "--queryformat=" + fmt,
                 str(payload)], work)
        if (query_rpm("%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}") != identity
                or query_rpm("%{FILEDIGESTALGO}") != "8"):
            _reject("NATIVE_EXECUTABLE_RPM_IDENTITY_REFUSED")
        rows = query_rpm("[%{FILENAMES}\\t%{FILEDIGESTS}\\n]").splitlines()
        matching = [row.split("\t", 1)[1] for row in rows
                    if row.startswith("/usr/sbin/nginx\t")]
        if len(matching) != 1 or re.fullmatch(r"[0-9a-f]{64}", matching[0]) is None:
            _reject("NATIVE_EXECUTABLE_RPM_MEMBER_REFUSED")
        if _candidate_payload_sha256(payload) != archive_digest:
            _reject("NATIVE_EXECUTABLE_PAYLOAD_CHANGED")
        return archive_digest, matching[0]


def _stage_authenticated_native_executable_candidate(
    assets: Path, *, commit: str, archive_sha256: str,
    dedicated_selinux: bool = False,
) -> dict:
    """Internal candidate placement only; not a CLI or activation path.

    The caller is the authorized isolated installer harness. Re-authenticate
    source and native package, retain the existing server-state lock, stage
    only the fixed executable in the existing authenticated worker directory.
    No systemd unit, SELinux policy, vendor label or firewall is modified.
    The optional dedicated mode requires an already loaded, independently
    verified policy and assigns its fixed label only to the unpublished
    new inode. Refuse uncertain receipt/placement; never adopt or execute.
    """
    from repocache.server_native_nginx_executable_v1 import (
        NativeExecutableCandidateError, stage_nginx_candidate_with_receipt,
        _identity as executable_identity, _verify_leaf, _read_executable_receipt,
        _policy_candidate, _POLICY_MEMBER,
    )
    from repocache.server_protected_state_store_v1 import _read_file
    distribution = _native_distro()
    if type(dedicated_selinux) is not bool or (dedicated_selinux and distribution != "almalinux"):
        _reject("NATIVE_EXECUTABLE_DEDICATED_POLICY_TARGET_REFUSED")
    require_native_host_preconditions()
    payloads, receipt = stage._authenticated_payloads(
        assets, commit=commit, archive_sha256=archive_sha256, system=None)
    policy_digest = None
    labels = None
    if dedicated_selinux:
        import io
        import zipfile
        labels = _Labels(distribution)
        # No caller-provided policy bytes or digest. The verified release
        # archive determines the exact policy embedded in the worker.
        try:
            with zipfile.ZipFile(io.BytesIO(payloads[stage.WORKER])) as archive:
                if (archive.namelist().count(_POLICY_MEMBER) != 1
                        or not 0 < archive.getinfo(_POLICY_MEMBER).file_size <= 16384):
                    _reject("NATIVE_EXECUTABLE_DEDICATED_POLICY_REFUSED")
                policy_digest = _policy_candidate(archive.read(_POLICY_MEMBER))["policy_sha256"]
        except (KeyError, zipfile.BadZipFile, NativeExecutableCandidateError):
            _reject("NATIVE_EXECUTABLE_DEDICATED_POLICY_REFUSED")
    expected = stage._json_line(receipt)
    completed = _MARKER + "complete-" + hashlib.sha256(expected).hexdigest()
    with ExitStack() as stack:
        root = os.open("/", stage._DIRECTORY)
        stack.callback(os.close, root)
        # The private APT workspace and isolated RPM database are created
        # and removed under /var/lib. Reuse the audited native-effects lock
        # contract for shared-parent metadata only; the private REPOCACHE
        # ancestor, state directory, lock and mount checks remain enforced.
        state = stack.enter_context(_locked(
            root, 0, allow_native_package_parent_changes=True))
        def require_boundary():
            if labels is not None:
                labels.finish()
            stage._audit_worker_files(Path("/"), payloads)
            if (_read_file(state, _RUNTIME_RECEIPT, 0, 8192) != expected
                    or {name for name in os.listdir(state) if name.startswith(_MARKER)} != {completed}
                    or _read_file(state, completed, 0, 0) != b""):
                _reject("NATIVE_EXECUTABLE_WORKER_RECEIPT_REFUSED")
            _no_conflicting_owned_wal_pending(state)
            _require_audited_native_package_for_activation(state, distribution=distribution)
            if (_read_v2(state, 0)[0] is not None or
                    _nginx_systemctl("is-enabled") != (1, b"disabled\n")
                    or _nginx_systemctl("is-active") != (3, b"inactive\n")
                    or _own_systemctl("is-enabled") != (1, b"disabled\n")
                    or _own_systemctl("is-active") != (3, b"inactive\n")):
                _reject("NATIVE_EXECUTABLE_INACTIVE_BOUNDARY_REFUSED")
        require_boundary()
        usr = _open_directory(root, "usr", stack)
        sbin = _open_directory(usr, "sbin", stack)
        libexec = _open_directory(usr, "libexec", stack)
        destination = _open_directory(libexec, "repocache", stack)
        vendor = os.open("nginx", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                         os.O_CLOEXEC, dir_fd=sbin)
        stack.callback(os.close, vendor)
        vendor_before = executable_identity(os.fstat(vendor))
        def recheck_paths():
            for parent, name, fd in ((root, "usr", usr), (usr, "sbin", sbin),
                                     (usr, "libexec", libexec),
                                     (libexec, "repocache", destination)):
                stage._protected_directory(fd)
                if _identity(os.fstat(fd)) != _identity(os.stat(
                        name, dir_fd=parent, follow_symlinks=False)):
                    _reject("NATIVE_EXECUTABLE_PARENT_CHANGED")
            if (executable_identity(os.fstat(vendor)) != vendor_before or
                    executable_identity(os.stat("nginx", dir_fd=sbin,
                                                follow_symlinks=False)) != vendor_before):
                _reject("NATIVE_EXECUTABLE_VENDOR_CHANGED")
        recheck_paths()
        if not _trusted_key(_NATIVE[distribution][2]):
            _reject("NATIVE_EXECUTABLE_TRUST_ANCHOR_REFUSED")
        # Refuse an unowned preexisting leaf or pending evidence before any
        # package download. Only the exact known receipt may enable repeat.
        if (_named(destination, ".repocache-nginx-executable.pending") is not None
                or (_named(destination, "nginx") is not None and
                    _read_executable_receipt(destination) is None)):
            _reject("NATIVE_EXECUTABLE_FOREIGN_OR_PENDING")
        with tempfile.TemporaryDirectory(prefix="repocache-native-executable-", dir="/var/lib") as tmp:
            work = Path(tmp)
            if not _native_workspace_is_root_owned(work):
                _reject("NATIVE_EXECUTABLE_WORKSPACE_REFUSED")
            identity = _candidate_native_identity(distribution, work)
            package_digest, binary_digest = (
                _authenticate_candidate_deb(work, identity) if distribution == "debian"
                else _authenticate_candidate_rpm(work, identity))
            require_boundary()
            recheck_paths()
            if (_candidate_native_identity(distribution, work) != identity
                    or not _trusted_key(_NATIVE[distribution][2])):
                _reject("NATIVE_EXECUTABLE_PACKAGE_CHANGED")
            options = dict(distribution=distribution, package_identity=identity,
                           native_payload_sha256=package_digest, authenticated_sha256=binary_digest,
                           release_source_sha=commit, release_archive_sha256=archive_sha256,
                           dedicated_policy_sha256=policy_digest)
            try:
                result = stage_nginx_candidate_with_receipt(destination, vendor, **options)
                again = stage_nginx_candidate_with_receipt(destination, vendor, **options)
                if (again["status"] != "NGINX_EXECUTABLE_CANDIDATE_UNCHANGED"
                        or again["receipt_sha256"] != result["receipt_sha256"]
                        or _verify_leaf(destination, binary_digest,
                                        dedicated_selinux=dedicated_selinux)[:2] !=
                           (result["device"], result["inode"])):
                    _reject("NATIVE_EXECUTABLE_READBACK_REFUSED")
            except NativeExecutableCandidateError:
                _reject("NATIVE_EXECUTABLE_PLACEMENT_REFUSED")
            require_boundary()
            recheck_paths()
            if _candidate_native_identity(distribution, work) != identity:
                _reject("NATIVE_EXECUTABLE_PACKAGE_CHANGED")
        return {**result, "native_payload_authenticated_by_installer": True,
                "package_identity": identity, "native_payload_sha256": package_digest,
                "release_source_sha": commit, "release_archive_sha256": archive_sha256,
                "service_enabled": False, "service_active": False}


def _ensure_fixed_nginx_cache_parent_under_root(
    root_fd: int, *, owner_uid: int = 0, distribution: str | None = None,
) -> None:
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
            real_root = os.stat("/", follow_symlinks=False)
            labels = (_Labels(distribution) if distribution == "almalinux"
                      and (root.st_dev, root.st_ino) == (real_root.st_dev, real_root.st_ino)
                      else None)
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
                if labels is not None:
                    labels.check(fd, "/var/cache/nginx", b"httpd_cache_t", fresh=True)
                os.fchmod(fd, 0o755)
                os.fsync(fd)
                os.fsync(parent)
            else:
                stack.callback(os.close, fd)
            if labels is not None:
                labels.check(fd, "/var/cache/nginx", b"httpd_cache_t")
                labels.finish()
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



_OWN_UNIT = "repocache-nginx.service"
_OWN_CONFIG = "/etc/nginx/repocache.d/repocache.conf"
# Activation ownership marker is intentionally separate from the signed worker
# receipt: no unrelated root-owned file is implicitly adopted on first use.
_CONFIG_MARKER_PREFIX = OWNED_NGINX_CONFIG_MARKER_PREFIX
# A fixed, reviewed immutable bootstrap; the source archive must contain
# precisely these signed bytes. Managed TLS deployment is a different step.
_BOOTSTRAP_CONFIG = _OWNED_BOOTSTRAP_CONFIG
_CONFIG_MARKER = _CONFIG_MARKER_PREFIX + hashlib.sha256(
    b"/etc/nginx/repocache.d/\0" + _BOOTSTRAP_CONFIG).hexdigest()



def _private_config_present() -> None:
    """Check installed signed bootstrap exactly, without altering vendor files."""
    try:
        with ExitStack() as stack:
            root = os.open("/", stage._DIRECTORY)
            stack.callback(os.close, root)
            etc = _open_directory(root, "etc", stack)
            nginx = _open_directory(etc, "nginx", stack)
            dedicated = _open_directory(nginx, "repocache.d", stack)
            if stat.S_IMODE(os.fstat(dedicated).st_mode) != 0o755:
                _reject("NATIVE_PRIVATE_DIRECTORY_UNSAFE")
            _exact_file(dedicated, stage.CONFIG, _BOOTSTRAP_CONFIG, 0o644)
    except stage.WorkerStageError:
        raise
    except (OSError, ValueError, TypeError):
        _reject("NATIVE_PRIVATE_CONFIG_UNVERIFIED")


def _require_owned_private_config_intent(state_fd: int, nginx_fd: int) -> None:
    """Persist first-use intent; refuse even byte-identical foreign config.

    A marker written and fsynced before file placement permits recovery after
    a process interruption. Under the same protected lock, subsequent attempts
    can only recheck our originally claimed exact signed configuration.
    This marker does not grant arbitrary overwrite, service or TLS authority.
    """
    try:
        markers = [
            name for name in os.listdir(state_fd)
            if name.startswith(_CONFIG_MARKER_PREFIX)
        ]
        if any(name != _CONFIG_MARKER for name in markers):
            _reject("NATIVE_PRIVATE_CONFIG_MARKER_CONFLICT")
        existing_marker = _named(state_fd, _CONFIG_MARKER)
        if existing_marker is None:
            if _named(nginx_fd, stage.CONFIG) is not None:
                _reject("NATIVE_PRIVATE_CONFIG_FOREIGN_COLLISION")
            _create_marker(state_fd, _CONFIG_MARKER)
        else:
            _check_marker(existing_marker)
    except stage.WorkerStageError:
        raise
    except (OSError, ValueError, TypeError):
        _reject("NATIVE_PRIVATE_CONFIG_INTENT_UNVERIFIED")


def _place_signed_private_config(raw: bytes, state_fd: int) -> None:
    """Stage only an owned signed bootstrap; never adopt third-party files."""
    if type(raw) is not bytes or raw != _BOOTSTRAP_CONFIG:
        _reject("NATIVE_SIGNED_CONFIG_UNEXPECTED")
    try:
        with ExitStack() as stack:
            root = os.open("/", stage._DIRECTORY)
            stack.callback(os.close, root)
            etc = _open_directory(root, "etc", stack)
            nginx = _open_directory(etc, "nginx", stack)
            # Refuse the previous layout, including dangling entries. No
            # implicit migration/adoption or removal of any foreign file.
            for name in (stage.CONFIG, "repocache-managed.conf",
                         _TEMP + stage.CONFIG, ".repocache-owned-main.stage",
                         ".repocache-owned-include.stage"):
                if _named(nginx, name) is not None:
                    _reject("NATIVE_PRIVATE_CONFIG_LEGACY_LAYOUT_REFUSED")
            existing = _named(nginx, "repocache.d")
            if _named(state_fd, _CONFIG_MARKER) is None and existing is not None:
                _reject("NATIVE_PRIVATE_CONFIG_FOREIGN_COLLISION")
            _require_owned_private_config_intent(state_fd, nginx)
            if existing is None:
                # The signed intent is durable before mkdir. Explicitly
                # set the new directory mode, independent of caller umask.
                os.mkdir("repocache.d", mode=0o755, dir_fd=nginx)
                new_fd = _open_directory(nginx, "repocache.d", stack)
                os.fchmod(new_fd, 0o755)
                os.fsync(new_fd)
                os.fsync(nginx)
            dedicated = _open_directory(nginx, "repocache.d", stack)
            if (stat.S_IMODE(os.fstat(dedicated).st_mode) != 0o755
                    or os.fstat(dedicated).st_dev != os.fstat(nginx).st_dev
                    or set(os.listxattr(nginx)) - {"security.selinux"}
                    or set(os.listxattr(dedicated)) - {"security.selinux"}
                    or set(os.listdir(dedicated)) - {stage.CONFIG, _TEMP + stage.CONFIG}):
                _reject("NATIVE_PRIVATE_DIRECTORY_UNSAFE")
            os.fsync(dedicated)
            os.fsync(nginx)
            _place_file(dedicated, stage.CONFIG, raw, 0o644)
        _private_config_present()
    except stage.WorkerStageError:
        raise
    except (OSError, ValueError, TypeError):
        _reject("NATIVE_PRIVATE_CONFIG_PLACEMENT_REFUSED")


def _unlink_inert_nginx_syntax_pid(directory: int) -> None:
    """Remove only the empty file created by nginx -t before activation.

    Never use this helper for a running service. A nonempty/foreign PID
    remains untouched and blocks the pre-start operation.
    """
    info = _named(directory, "nginx.pid")
    if info is None:
        return
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_gid != 0 or info.st_nlink != 1 or info.st_size != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        _reject("NATIVE_RUNTIME_PID_FOREIGN")
    again = os.stat("nginx.pid", dir_fd=directory, follow_symlinks=False)
    if _identity(again) != _identity(info) or again.st_ctime_ns != info.st_ctime_ns:
        _reject("NATIVE_RUNTIME_PID_CHANGED")
    os.unlink("nginx.pid", dir_fd=directory)
    os.fsync(directory)


def _cleanup_own_nginx_syntax_pid() -> None:
    try:
        with ExitStack() as stack:
            root = os.open("/", stage._DIRECTORY)
            stack.callback(os.close, root)
            run = _open_directory(root, "run", stack)
            own = _open_directory(run, "repocache-nginx", stack)
            _unlink_inert_nginx_syntax_pid(own)
    except stage.WorkerStageError:
        raise
    except (OSError, ValueError, TypeError):
        _reject("NATIVE_RUNTIME_PID_UNVERIFIED")


def _prepare_own_runtime_directory(*, managed_debian: bool = False,
                                   managed_almalinux: bool = False) -> None:
    """Make a bounded /run directory before pre-start nginx -t.

    PID1 will independently own and clean RuntimeDirectory at service startup.
    Never adopt a foreign/linked directory or a leftover master PID file.
    """
    try:
        with ExitStack() as stack:
            root = os.open("/", stage._DIRECTORY)
            stack.callback(os.close, root)
            run = _open_directory(root, "run", stack)
            try:
                os.mkdir("repocache-nginx", mode=0o700, dir_fd=run)
            except FileExistsError:
                pass
            own = _open_directory(run, "repocache-nginx", stack)
            if (os.fstat(own).st_dev != os.fstat(run).st_dev
                    or os.fstat(own).st_uid != 0
                    or os.fstat(own).st_gid != 0
                    or stat.S_IMODE(os.fstat(own).st_mode) not in (0o700, 0o755)):
                _reject("NATIVE_RUNTIME_DIRECTORY_UNSAFE")
            _unlink_inert_nginx_syntax_pid(own)
            if os.listdir(own):
                # Retry an interrupted inactive syntax check only with the
                # exact empty scratch names and safe metadata. Never delete
                # or adopt foreign content; systemd owns runtime cleanup.
                if managed_debian and not managed_almalinux:
                    _owned_debian_runtime_temps(root, require_all=False, inactive=True)
                elif managed_almalinux and not managed_debian:
                    _owned_alma_runtime_temps(root, dedicated=False,
                                              require_all=False, inactive=True)
                else:
                    _reject("NATIVE_RUNTIME_DIRECTORY_UNSAFE")
            if stat.S_IMODE(os.fstat(own).st_mode) == 0o700:
                os.fchmod(own, 0o755)
            os.fsync(run)
    except stage.WorkerStageError:
        raise
    except (OSError, ValueError, TypeError):
        _reject("NATIVE_RUNTIME_DIRECTORY_UNVERIFIED")


def _require_private_nginx_listeners() -> None:
    """Fixed known-good loopback config, real native syntax check, no -T leaks."""
    _private_config_present()
    try:
        proc = subprocess.run(
            ("/usr/sbin/nginx", "-t", "-q", "-c", _OWN_CONFIG),
            shell=False, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd="/", env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
            timeout=15, close_fds=True, start_new_session=True,
        )
        if type(proc.returncode) is not int or proc.returncode != 0:
            _reject("NATIVE_LISTENERS_UNVERIFIED")
        # NGINX -t creates an empty PID file even in syntax-only mode.
        # Clean exactly that inert inode; do not truncate a live master PID.
        _cleanup_own_nginx_syntax_pid()
        _private_config_present()
    except stage.WorkerStageError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _reject("NATIVE_LISTENERS_UNVERIFIED")


def _own_systemctl(action: str) -> tuple[int, bytes]:
    if action not in ("is-enabled", "is-active"):
        _reject("NATIVE_OWN_SYSTEMCTL_REFUSED")
    _safe_native_systemctl()
    try:
        result = subprocess.run(
            [*_SYSTEMCTL, action, _OWN_UNIT], shell=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd="/", timeout=10, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            close_fds=True, start_new_session=True,
        )
        if type(result.returncode) is not int or type(result.stdout) is not bytes or len(result.stdout) > 128:
            _reject("NATIVE_OWN_SYSTEMCTL_UNVERIFIED")
        return result.returncode, result.stdout
    except stage.WorkerStageError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _reject("NATIVE_OWN_SYSTEMCTL_UNVERIFIED")


def _own_service_observation(*, active: bool) -> dict:
    """Retain installer diagnostics while sharing the fixed observer."""
    try:
        return inspect_effective_owned_nginx_unit(active=active)
    except EffectiveNginxUnitError as exc:
        if str(exc) == "NATIVE_NGINX_EFFECTIVE_OWN_UNIT_CHANGED":
            _reject("NATIVE_OWN_UNIT_CHANGED")
        _reject("NATIVE_OWN_UNIT_UNVERIFIED")


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
    if action not in ("start", "enable", "stop", "disable", "daemon-reload"):
        _reject("NATIVE_ACTIVATION_COMMAND_REFUSED")
    _safe_native_systemctl()
    try:
        proc = subprocess.run(
            [*_SYSTEMCTL, action, _OWN_UNIT] if action != "daemon-reload" else [*_SYSTEMCTL, action],
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


def _verify_active_managed_nginx_under_lock(
    root_fd: int, state_fd: int, distribution: str, unit_bytes: bytes,
) -> dict:
    """Same-version active managed no-op; never rewrite or reload resources.

    Called only after the signed installer independently authenticated and
    audited the exact worker and unit. Retain the existing state lock.
    Pending, legacy and active-route cases remain fail closed here.
    """
    if (_own_systemctl("is-enabled") != (0, b"enabled\n")
            or _own_systemctl("is-active") != (0, b"active\n")):
        _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")
    try:
        with _owned_layout_locked(root_fd, state_fd, recovering=False) as layout:
            _, nginx_fd, public_fd, check = layout
            old = _read_owned_resources(state_fd, nginx_fd, public_fd)
            snapshot = _validate_owned_resources(old, distribution=distribution)
            if snapshot is None:
                _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")
            _owned_socket_require_inactive_routes(snapshot)
            storage = prepare_installed_storage(distribution, allow_create=False)
            identity = _owned_live_observe(root_fd, expected_unit=unit_bytes)
            verify_service_storage_mounts(identity[0])
            context = _owned_live_validate(root_fd, state_fd, old)
            _owned_live_health_bound(root_fd, identity, context, old["catalog.json"],
                                     publish=True, expected_unit=unit_bytes)
            check()
            _no_conflicting_owned_wal_pending(state_fd)
            _require_audited_native_package_for_activation(state_fd, distribution=distribution)
            _nginx_inactive_vendor_service(distribution)
            if (prepare_installed_storage(distribution, allow_create=False) != storage
                    or _owned_live_observe(root_fd, expected_unit=unit_bytes) != identity
                    or _read_owned_resources(state_fd, nginx_fd, public_fd) != old
                    or _owned_live_validate(root_fd, state_fd, old) != context
                    or _own_systemctl("is-enabled") != (0, b"enabled\n")
                    or _own_systemctl("is-active") != (0, b"active\n")):
                _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")
            verify_service_storage_mounts(identity[0])
            _owned_live_health_bound(root_fd, identity, context, old["catalog.json"],
                                     publish=True, expected_unit=unit_bytes)
            check()
            _no_conflicting_owned_wal_pending(state_fd)
            if _read_owned_resources(state_fd, nginx_fd, public_fd) != old:
                _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")
            return {"status": "AUTHENTICATED_REPOCACHE_NGINX_ALREADY_ACTIVE",
                    "nginx_active_verified": True, "nginx_enabled_verified": True,
                    "storage": storage, "service_storage_mounts_verified": True,
                    "state_generation": snapshot["state_generation"]}
    except stage.WorkerStageError:
        raise
    except (NativeV2TransactionError, EffectiveNginxUnitError, OSError, ValueError, TypeError):
        _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")


def _repair_inactive_managed_nginx_under_lock(
    root_fd: int, state_fd: int, distribution: str, unit_bytes: bytes,
) -> dict:
    """Restart only the exact enabled, inactive, clean managed generation.

    No configuration, catalog, storage or enablement changes are authorized.
    The explicit signed installer invocation and original lock are required.
    A disabled service is not implicitly enabled; pending WAL, foreign
    state and active repositories remain refused.
    """
    def inactive_identity():
        before = _read_exact_owned_unit_at(root_fd, unit_bytes, owner_uid=0, owner_gid=0)
        if (_own_systemctl("is-enabled") != (0, b"enabled\n")
                or _own_systemctl("is-active") != (3, b"inactive\n")
                or _own_service_observation(active=False)["main_pid_observed"] != 0
                or _read_exact_owned_unit_at(root_fd, unit_bytes, owner_uid=0, owner_gid=0) != before):
            _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")
        return before

    try:
        with _owned_layout_locked(root_fd, state_fd, recovering=False) as layout:
            _, nginx_fd, public_fd, check = layout
            old = _read_owned_resources(state_fd, nginx_fd, public_fd)
            snapshot = _validate_owned_resources(old, distribution=distribution)
            if snapshot is None:
                _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")
            _owned_socket_require_inactive_routes(snapshot)
            unit_identity = inactive_identity()
            storage = prepare_installed_storage(distribution, allow_create=False)

            def clean():
                check()
                _no_conflicting_owned_wal_pending(state_fd)
                if (_read_owned_resources(state_fd, nginx_fd, public_fd) != old
                        or prepare_installed_storage(distribution, allow_create=False) != storage
                        or _read_exact_owned_unit_at(root_fd, unit_bytes, owner_uid=0,
                                                     owner_gid=0) != unit_identity):
                    _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")

            clean()
            _prepare_own_runtime_directory(managed_debian=distribution == "debian",
                                           managed_almalinux=distribution == "almalinux")
            # nginx -T may create an inert PID file while inactive.
            # Never remove it unless the exact unit is still inactive.
            try:
                context = _owned_live_validate(root_fd, state_fd, old)
            finally:
                if inactive_identity() != unit_identity:
                    _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")
                _cleanup_own_nginx_syntax_pid()
            _require_audited_native_package_for_activation(state_fd, distribution=distribution)
            _nginx_inactive_vendor_service(distribution)
            clean()
            if inactive_identity() != unit_identity:
                _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")
            identity = None
            try:
                _nginx_activation_command("start")
                identity = _owned_live_observe(root_fd, expected_unit=unit_bytes)
                if identity[1] != unit_identity:
                    _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")
                verify_service_storage_mounts(identity[0])
                _owned_live_health_bound(root_fd, identity, context, old["catalog.json"],
                                         publish=True, expected_unit=unit_bytes)
                # Reuse the complete active repeat assessment, retaining
                # the original lock and exact pre-start resource snapshot.
                result = _verify_active_managed_nginx_under_lock(
                    root_fd, state_fd, distribution, unit_bytes,
                )
                clean()
                if (_owned_live_observe(root_fd, expected_unit=unit_bytes) != identity
                        or result["state_generation"] != snapshot["state_generation"]):
                    _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")
                return {**result, "status": "AUTHENTICATED_REPOCACHE_NGINX_ACTIVE"}
            except Exception:
                # Restore the original inactive/enabled state only when
                # the exact unit and unchanged resources still establish
                # our authority. Never stop an unverified process.
                try:
                    clean()
                    current = _own_systemctl("is-active")
                    if current == (0, b"active\n"):
                        current_identity = _owned_live_observe(root_fd, expected_unit=unit_bytes)
                        if (current_identity[1] != unit_identity
                                or (identity is not None and current_identity != identity)):
                            _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                        _nginx_activation_command("stop")
                    elif current != (3, b"inactive\n"):
                        _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                    if inactive_identity() != unit_identity:
                        _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                    clean()
                except Exception:
                    _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                _reject("NATIVE_ACTIVATION_FAILED_ROLLED_BACK")
    except stage.WorkerStageError:
        raise
    except (NativeV2TransactionError, EffectiveNginxUnitError, OSError, ValueError, TypeError):
        _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")


def _recover_enabled_inactive_owned_wal_under_lock(
    root_fd: int, state_fd: int, distribution: str, unit_bytes: bytes,
    expected_wal: bytes, recheck_signed_worker,
) -> dict:
    """Explicit signed installer recovery of an already enabled stopped unit.

    Preserve the original WAL through prior-byte preparation and exact
    runtime verification; keep the catalog withdrawn until the old service
    is proven. No enablement, foreign unit, active route or dedicated
    namespace transition is authorized here. The existing signed caller
    retains the original state lock and exact release payload.
    """
    if not callable(recheck_signed_worker):
        _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")
    try:
        with _owned_layout_locked(root_fd, state_fd, recovering=True) as layout:
            _, nginx_fd, public_fd, check = layout
            old, _ = _decode_owned_wal(expected_wal, distribution=distribution)
            snapshot = _validate_owned_resources(old, distribution=distribution)
            _owned_socket_require_inactive_routes(snapshot)
            withdrawn = {**old, _CATALOG: None}
            unit_identity = _read_exact_owned_unit_at(
                root_fd, unit_bytes, owner_uid=0, owner_gid=0)
            storage = prepare_installed_storage(distribution, allow_create=False)

            def fixed_owner():
                recheck_signed_worker()
                _nginx_inactive_vendor_service(distribution)
                if (_nginx_systemctl("is-enabled") != (1, b"disabled\n")
                        or _nginx_systemctl("is-active") != (3, b"inactive\n")
                        or _read_exact_owned_unit_at(root_fd, unit_bytes, owner_uid=0,
                                                    owner_gid=0) != unit_identity
                        or _own_systemctl("is-enabled") != (0, b"enabled\n")
                        or prepare_installed_storage(distribution, allow_create=False) != storage):
                    _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")

            def stopped():
                fixed_owner()
                if (_own_systemctl("is-active") != (3, b"inactive\n")
                        or _own_service_observation(active=False)["main_pid_observed"] != 0):
                    _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")

            def retained(owner):
                _owned_live_guard(state_fd, nginx_fd, public_fd, check,
                                  expected_wal, withdrawn)
                owner()
                _owned_live_guard(state_fd, nginx_fd, public_fd, check,
                                  expected_wal, withdrawn)

            stopped()
            _prepare_owned_inactive_wal_rollback_locked(
                *layout, distribution=distribution, expected_wal=expected_wal,
                recheck_stopped_owner=stopped)
            retained(stopped)
            _prepare_own_runtime_directory(
                managed_debian=distribution == "debian" and snapshot is not None,
                managed_almalinux=distribution == "almalinux" and snapshot is not None)
            try:
                _owned_live_validate(root_fd, state_fd, old)
            finally:
                retained(stopped)
                _cleanup_own_nginx_syntax_pid()
            _require_audited_native_package_for_activation(state_fd, distribution=distribution)
            retained(stopped)
            identity = None
            try:
                _nginx_activation_command("start")
                identity = _owned_live_observe(root_fd, expected_unit=unit_bytes)
                if identity[1] != unit_identity:
                    _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")

                def active():
                    fixed_owner()
                    if (_own_systemctl("is-active") != (0, b"active\n")
                            or _owned_live_observe(root_fd, expected_unit=unit_bytes) != identity):
                        _reject("NATIVE_ACTIVATION_MANAGED_STATE_CHANGED")
                    verify_service_storage_mounts(identity[0])

                retained(active)
                _require_audited_native_package_for_activation(state_fd, distribution=distribution)
                retained(active)
                result = _finish_owned_inactive_wal_rollback_locked(
                    root_fd, *layout, distribution=distribution,
                    expected_wal=expected_wal, expected_unit=unit_bytes,
                    recheck_active_owner=active)
                generation = None if snapshot is None else snapshot["state_generation"]
                if result != {"status": "OWNED_INACTIVE_WAL_ROLLBACK_OBSERVED",
                              "prior_generation": generation, "recovery_required": False}:
                    _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                report = {"status": "AUTHENTICATED_REPOCACHE_NGINX_ACTIVE",
                          "nginx_active_verified": True, "nginx_enabled_verified": True,
                          "storage": storage, "service_storage_mounts_verified": True}
                if generation is not None:
                    report["state_generation"] = generation
                return report
            except Exception:
                # Compensate only while the exact pending WAL and withdrawn
                # prior bytes still authorize a stop. Never stop after an
                # uncertain unlink, changed unit, unknown master or catalog.
                try:
                    retained(fixed_owner)
                    current = _own_systemctl("is-active")
                    if current == (0, b"active\n"):
                        observed = _owned_live_observe(root_fd, expected_unit=unit_bytes)
                        if (observed[1] != unit_identity
                                or (identity is not None and observed != identity)):
                            _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                        retained(fixed_owner)
                        if _owned_live_observe(root_fd, expected_unit=unit_bytes) != observed:
                            _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                        _nginx_activation_command("stop")
                    elif current != (3, b"inactive\n"):
                        _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                    retained(stopped)
                except Exception:
                    _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
                # Prior bytes are prepared, but runtime recovery is pending.
                _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
    except stage.WorkerStageError:
        raise
    except (NativeV2TransactionError, EffectiveNginxUnitError, OSError, ValueError, TypeError):
        _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")


def _activate_audited_native_nginx_under_lock(
    state_fd: int, distribution: str, config: bytes, *,
    root_fd: int | None = None, unit_bytes: bytes | None = None,
    recheck_signed_worker=None,
) -> dict:
    """Start only signed REPOCACHE unit; never start or override vendor NGINX."""
    _require_audited_native_package_for_activation(state_fd, distribution=distribution)
    if recheck_signed_worker is not None:
        if (not callable(recheck_signed_worker) or root_fd is None
                or type(unit_bytes) is not bytes or not unit_bytes):
            _reject("NATIVE_SIGNED_WORKER_AUDIT_UNVERIFIED")
        recheck_signed_worker()
        pending = _read_file(state_fd, _OWNED_WAL, 0, _MAX_WAL)
        if pending is not None:
            return _recover_enabled_inactive_owned_wal_under_lock(
                root_fd, state_fd, distribution, unit_bytes, pending,
                recheck_signed_worker)
    managed = _read_v2(state_fd, 0)[0] is not None
    if managed and (root_fd is None or unit_bytes is None):
        _reject("NATIVE_ACTIVATION_MANAGED_STATE_REFUSED")
    if not managed:
        _no_conflicting_pending(state_fd)
    # The native distro service is separately verified but MUST stay disabled.
    # An active or enabled foreign daemon is never adopted or stopped.
    _nginx_inactive_vendor_service(distribution)
    if (_nginx_systemctl("is-enabled") != (1, b"disabled\n")
            or _nginx_systemctl("is-active") != (3, b"inactive\n")):
        _reject("NATIVE_ACTIVATION_VENDOR_SERVICE_STATE")
    if managed:
        if (_own_systemctl("is-enabled") == (0, b"enabled\n")
                and _own_systemctl("is-active") == (3, b"inactive\n")):
            return _repair_inactive_managed_nginx_under_lock(
                root_fd, state_fd, distribution, unit_bytes,
            )
        return _verify_active_managed_nginx_under_lock(
            root_fd, state_fd, distribution, unit_bytes,
        )
    _place_signed_private_config(config, state_fd)
    current_enabled = _own_systemctl("is-enabled")
    current_active = _own_systemctl("is-active")
    if current_enabled == (0, b"enabled\n") and current_active == (0, b"active\n"):
        _private_config_present()
        storage = prepare_installed_storage(distribution, allow_create=False)
        observed = _own_service_observation(active=True)
        verify_service_storage_mounts(observed["main_pid_observed"])
        if _own_service_observation(active=True) != observed:
            _reject("NATIVE_ACTIVATION_SERVICE_CHANGED")
        return {"status": "AUTHENTICATED_REPOCACHE_NGINX_ALREADY_ACTIVE",
                "nginx_active_verified": True, "nginx_enabled_verified": True,
                "storage": storage, "service_storage_mounts_verified": True}
    if current_enabled != (1, b"disabled\n") or current_active != (3, b"inactive\n"):
        _reject("NATIVE_ACTIVATION_FOREIGN_SERVICE_STATE")
    storage = prepare_installed_storage(distribution, allow_create=True)
    _prepare_own_runtime_directory()
    _require_private_nginx_listeners()
    # The signed unit may have been placed before the distro NGINX package;
    # never start until systemd has loaded exactly our file, without drop-ins.
    _nginx_activation_command("daemon-reload")
    _own_service_observation(active=False)
    try:
        _nginx_activation_command("start")
        before = _own_service_observation(active=True)
        verify_service_storage_mounts(before["main_pid_observed"])
        _private_config_present()
        _nginx_activation_command("enable")
        after = _own_service_observation(active=True)
        if (after["main_pid_observed"] != before["main_pid_observed"]
                or _own_systemctl("is-enabled") != (0, b"enabled\n")
                or _own_systemctl("is-active") != (0, b"active\n")):
            _reject("NATIVE_ACTIVATION_POSTCHECK_FAILED")
        _private_config_present()
        _require_audited_native_package_for_activation(state_fd, distribution=distribution)
        _nginx_inactive_vendor_service(distribution)
        storage = prepare_installed_storage(distribution, allow_create=False)
        verify_service_storage_mounts(after["main_pid_observed"])
        if _own_service_observation(active=True) != after:
            _reject("NATIVE_ACTIVATION_SERVICE_CHANGED")
        return {"status": "AUTHENTICATED_REPOCACHE_NGINX_ACTIVE",
                "nginx_active_verified": True, "nginx_enabled_verified": True,
                "storage": storage, "service_storage_mounts_verified": True}
    except Exception:
        # systemctl start may time out after spawning a process. Never kill
        # an unknown master; only stop our exactly authenticated active unit.
        try:
            current = _own_systemctl("is-active")
            if current == (0, b"active\n"):
                _own_service_observation(active=True)
                _nginx_activation_command("stop")
            elif current != (3, b"inactive\n"):
                _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
            _nginx_activation_command("disable")
            _own_service_observation(active=False)
            if (_own_systemctl("is-enabled") != (1, b"disabled\n")
                    or _own_systemctl("is-active") != (3, b"inactive\n")):
                _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
        except Exception:
            _reject("NATIVE_ACTIVATION_RECOVERY_REQUIRED")
        _reject("NATIVE_ACTIVATION_FAILED_ROLLED_BACK")


# Fixed installer-only bootstrap, not a new socket or CLI operation.
_DEDICATED_RECOVERY_CHILD = r"""
import hashlib,json,os,re,stat,sys
from contextlib import ExitStack
if os.getresuid()!=(0,0,0) or os.getresgid()!=(0,0,0) or not sys.flags.isolated:
    raise SystemExit(2)
raw=sys.stdin.buffer.read(8193)
if not 0<len(raw)<=8192:
    raise SystemExit(2)
pins=json.loads(raw)
if (type(pins) is not dict or type(pins.get("worker_sha256")) is not str
        or re.fullmatch(r"[0-9a-f]{64}",pins["worker_sha256"]) is None):
    raise SystemExit(2)
worker="/usr/libexec/repocache/server-control-worker"
flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC
with ExitStack() as stack:
    fd=os.open("/",flags|os.O_DIRECTORY)
    stack.callback(os.close,fd)
    chain=[]
    def protected_directory(directory):
        info=os.fstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0
                or info.st_mode&0o022 or set(os.listxattr(directory))-{"security.selinux"}):
            raise SystemExit(2)
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    for name in ("usr","libexec","repocache"):
        protected_directory(fd)
        parent=fd
        fd=os.open(name,flags|os.O_DIRECTORY,dir_fd=parent)
        stack.callback(os.close,fd)
        chain.append((parent,name,fd,protected_directory(fd)))
    def recheck():
        for parent,name,directory,expected in chain:
            seen=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if (protected_directory(directory)!=expected or
                    (seen.st_dev,seen.st_ino,seen.st_mode,seen.st_uid,seen.st_gid)!=expected):
                raise SystemExit(2)
    recheck()
    leaf=os.open("server-control-worker",flags|os.O_NONBLOCK,dir_fd=fd)
    stack.callback(os.close,leaf)
    info=os.fstat(leaf)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0
            or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o755
            or not 0<info.st_size<=16*1024*1024
            or set(os.listxattr(leaf))-{"security.selinux"}):
        raise SystemExit(2)
    with os.fdopen(os.dup(leaf),"rb") as stream:
        data=stream.read(16*1024*1024+1)
    def identity(value):
        return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
                value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    if (len(data)!=info.st_size or hashlib.sha256(data).hexdigest()!=pins["worker_sha256"]
            or identity(os.fstat(leaf))!=identity(info)
            or identity(os.stat(worker,follow_symlinks=False))!=identity(info)):
        raise SystemExit(2)
    recheck()
    sys.path.insert(0,worker)
    from repocache import server_native_v2_transaction_v1 as transaction
    recheck()
    try:
        report=transaction._recover_installed_prepared_dedicated(pins)
    except Exception as exc:
        transaction._audit_native_failure(exc)
        raise SystemExit(2) from None
    sys.stdout.write(json.dumps(report,sort_keys=True,separators=(",",":"))+"\n")
"""


def _recover_authenticated_prepared_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    boot_receipt_sha256: str, wal_sha256: str,
) -> dict:
    """Private authenticated installer bridge for an already prepared profile.

    Receipt pins come from the trusted lifecycle caller, not from the
    files being verified. No public CLI selector or transferred lock fd.
    Authenticate in a read-only phase (private package scratch only);
    the installed child acquires its own lock and rechecks every pin.
    """
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           boot_receipt_sha256=boot_receipt_sha256, wal_sha256=wal_sha256))


def _recover_authenticated_rolled_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    expected_pins: dict | None = None,
) -> dict:
    """Select already prepared recovery from protected prior-boot intent."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256, recovery_pins=None,
        expected_rolled_pins=expected_pins)


_DEDICATED_PREPARE_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._prepare_installed_committed_dedicated(pins)")


_DEDICATED_PROFILE_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._stage_installed_committed_dedicated_profile(pins)")


def _stage_authenticated_committed_dedicated_profile(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, generation_manifest_sha256: str,
) -> dict:
    """Place only a fresh fixed profile for an authenticated stopped generation."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256,
        prepare=True, stage_profile=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256))


_DEDICATED_PROFILE_LOAD_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._load_installed_committed_dedicated_profile(pins)")


def _load_authenticated_committed_dedicated_profile(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    generation_manifest_sha256: str,
) -> dict:
    """Load only the exact previously placed stopped profile; repeat is read-only."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256,
        prepare=True, load_profile=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256))


def _prepare_authenticated_committed_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    generation_manifest_sha256: str,
) -> dict:
    """Prepare only an absent first-boot namespace for an exact managed profile."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256, prepare=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256))


_DEDICATED_ROLLOVER_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._rollover_installed_committed_dedicated(pins)")


def _rollover_authenticated_committed_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    generation_manifest_sha256: str, previous_boot_receipt_sha256: str,
) -> dict:
    """Private explicit recreation after a different boot; never adopt a namespace."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256, prepare=True, rollover=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256,
                           previous_boot_receipt_sha256=previous_boot_receipt_sha256))


_DEDICATED_PENDING_PREPARE_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._prepare_installed_prepared_wal_dedicated(pins)")


def _prepare_authenticated_prepared_wal_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    generation_manifest_sha256: str, wal_sha256: str,
) -> dict:
    """Prepare an absent first-boot namespace for the exact withdrawn prior WAL."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256,
        prepare=True, pending_prepare=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256,
                           wal_sha256=wal_sha256))


_DEDICATED_COMMITTED_RESUME_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._resume_installed_committed_dedicated(pins)")


def _resume_authenticated_committed_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    generation_manifest_sha256: str, boot_receipt_sha256: str,
) -> dict:
    """Resume only an exact retained same-boot committed namespace intent."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256,
        prepare=True, resume_boot=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256,
                           boot_receipt_sha256=boot_receipt_sha256))


_DEDICATED_PENDING_RESUME_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._resume_installed_prepared_wal_dedicated(pins)")


def _resume_authenticated_prepared_wal_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    generation_manifest_sha256: str, wal_sha256: str, boot_receipt_sha256: str,
) -> dict:
    """Resume only the exact same-boot pending WAL namespace intent."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256,
        prepare=True, pending_prepare=True, resume_boot=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256,
                           wal_sha256=wal_sha256, boot_receipt_sha256=boot_receipt_sha256))


_DEDICATED_PENDING_ROLLOVER_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._rollover_installed_prepared_wal_dedicated(pins)")


def _rollover_authenticated_prepared_wal_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    generation_manifest_sha256: str, previous_boot_receipt_sha256: str,
    wal_sha256: str,
) -> dict:
    """Recreate only the exact withdrawn prior generation under a retained WAL."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256,
        prepare=True, rollover=True, pending_prepare=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256,
                           previous_boot_receipt_sha256=previous_boot_receipt_sha256,
                           wal_sha256=wal_sha256))


_DEDICATED_START_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._start_installed_committed_dedicated(pins)")


def _start_authenticated_committed_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    generation_manifest_sha256: str, boot_receipt_sha256: str,
) -> dict:
    """Private explicit start of an already prepared, disabled loopback service."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256, start=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256,
                           boot_receipt_sha256=boot_receipt_sha256))


_DEDICATED_ROLLED_START_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._start_or_verify_installed_committed_dedicated(pins)")


_DEDICATED_PENDING_START_CHILD = _DEDICATED_RECOVERY_CHILD.replace(
    "transaction._recover_installed_prepared_dedicated(pins)",
    "transaction._start_installed_prepared_wal_dedicated(pins)")


def _start_authenticated_prepared_wal_dedicated_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
    executable_receipt_sha256: str, profile_receipt_sha256: str,
    generation_manifest_sha256: str, boot_receipt_sha256: str, wal_sha256: str,
) -> dict:
    """Start only the prepared prior loopback generation; keep WAL and withdrawal."""
    return _authenticated_prepared_dedicated_bridge(
        assets, commit=commit, archive_sha256=archive_sha256, start=True,
        pending_start=True,
        recovery_pins=dict(executable_receipt_sha256=executable_receipt_sha256,
                           profile_receipt_sha256=profile_receipt_sha256,
                           generation_manifest_sha256=generation_manifest_sha256,
                           boot_receipt_sha256=boot_receipt_sha256, wal_sha256=wal_sha256))


def _authenticated_prepared_dedicated_bridge(
    assets: Path, *, commit: str, archive_sha256: str, recovery_pins: dict | None,
    prepare: bool = False, start: bool = False, rollover: bool = False,
    pending_prepare: bool = False, resume_boot: bool = False,
    pending_start: bool = False, expected_rolled_pins: dict | None = None,
    stage_profile: bool = False, load_profile: bool = False,
) -> dict:
    if (expected_rolled_pins is not None and recovery_pins is not None
            or type(prepare) is not bool or type(start) is not bool or type(rollover) is not bool
            or type(pending_prepare) is not bool or (pending_prepare and not prepare)
            or type(resume_boot) is not bool or (resume_boot and (not prepare or rollover))
            or type(pending_start) is not bool or (pending_start and not start)
            or type(stage_profile) is not bool or (stage_profile and (
                not prepare or rollover or pending_prepare or resume_boot))
            or type(load_profile) is not bool or (load_profile and (
                not prepare or rollover or pending_prepare or resume_boot or stage_profile))
            or (prepare and start) or (rollover and not prepare)
            or (prepare and recovery_pins is None)
            or (start and recovery_pins is None and
                (pending_start or expected_rolled_pins is None))):
        _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
    rolled_start = start and recovery_pins is None
    fields = {"executable_receipt_sha256", "profile_receipt_sha256"} | (
        {"generation_manifest_sha256"} if prepare else
        {"generation_manifest_sha256", "boot_receipt_sha256"} if start else
        {"boot_receipt_sha256", "wal_sha256"})
    if stage_profile:
        fields.remove("profile_receipt_sha256")
    if rollover:
        fields.add("previous_boot_receipt_sha256")
    if pending_prepare or pending_start:
        fields.add("wal_sha256")
    if resume_boot:
        fields.add("boot_receipt_sha256")

    def validate_pins(pins):
        if (type(pins) is not dict or set(pins) != fields
                or any(type(value) is not str or signatures.HEX64.fullmatch(value) is None
                       for value in pins.values())):
            _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")

    if recovery_pins is not None:
        validate_pins(recovery_pins)
    if expected_rolled_pins is not None:
        validate_pins(expected_rolled_pins)
    if (type(archive_sha256) is not str or signatures.HEX64.fullmatch(archive_sha256) is None
            or type(commit) is not str or signatures.HEX40.fullmatch(commit) is None
            or _native_distro() != "almalinux"):
        _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
    require_native_host_preconditions()
    payloads, receipt = stage._authenticated_payloads(
        assets, commit=commit, archive_sha256=archive_sha256, system=None)
    if payloads.get(stage.CONFIG) != _BOOTSTRAP_CONFIG:
        _reject("NATIVE_SIGNED_CONFIG_UNEXPECTED")
    expected = stage._json_line(receipt)
    placement_sha = hashlib.sha256(expected).hexdigest()
    root = os.open("/", stage._DIRECTORY)
    try:
        with _locked(root, 0, allow_native_package_parent_changes=True) as state:
            stage._audit_worker_files(Path("/"), payloads)
            if (_read_file(state, _RUNTIME_RECEIPT, 0, 8192) != expected
                    or {name for name in os.listdir(state) if name.startswith(_MARKER)}
                       != {_MARKER + "complete-" + placement_sha}
                    or _read_file(state, _MARKER + "complete-" + placement_sha, 0, 0) != b""):
                _reject("NATIVE_DEDICATED_RECOVERY_PLACEMENT_REFUSED")
            if recovery_pins is None:
                from repocache.server_native_v2_transaction_v1 import (
                    _retained_rolled_dedicated_recovery_pins_locked,
                    _retained_rolled_committed_dedicated_pins_locked,
                )
                select = (_retained_rolled_committed_dedicated_pins_locked if start else
                          _retained_rolled_dedicated_recovery_pins_locked)
                recovery_pins = select(root, state)
                if expected_rolled_pins is not None and recovery_pins != expected_rolled_pins:
                    _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
            validate_pins(recovery_pins)
            if prepare or start:
                from repocache.server_native_v2_transaction_v1 import (
                    _OWNED_MANIFEST, _OWNED_LIMIT, _OWNED_WAL_TMP,
                )
                from repocache.server_native_egress_candidate_v1 import (
                    _read_boot_egress_receipt, _BOOT_EGRESS_HISTORY_PREFIX, _BOOT_EGRESS_ROLLOVER,
                )
                manifest = _read_file(state, _OWNED_MANIFEST, 0, _OWNED_LIMIT[_OWNED_MANIFEST])
                wal = _read_file(state, _OWNED_WAL, 0, _MAX_WAL)
                if pending_prepare or pending_start:
                    if wal is None or hashlib.sha256(wal).hexdigest() != recovery_pins["wal_sha256"]:
                        _reject("NATIVE_DEDICATED_RECOVERY_WAL_REFUSED")
                elif wal is not None:
                    _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
                if (manifest is None or hashlib.sha256(manifest).hexdigest() !=
                        recovery_pins["generation_manifest_sha256"]
                        or _read_file(state, _OWNED_WAL_TMP, 0, _MAX_WAL) is not None
                        or _BOOT_EGRESS_ROLLOVER in os.listdir(state)):
                    _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
                boot = _read_boot_egress_receipt(state, 0, 0)
                if stage_profile:
                    from repocache.server_native_nginx_effective_unit_v1 import (
                        _NAMESPACE_PROFILE_RECEIPT,
                    )
                    if any(name.startswith(_NAMESPACE_PROFILE_RECEIPT.removesuffix(".json"))
                           for name in os.listdir(state)):
                        _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
                if rollover:
                    if (boot is None or hashlib.sha256(boot).hexdigest() !=
                            recovery_pins["previous_boot_receipt_sha256"]):
                        _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
                elif resume_boot:
                    if boot is None or hashlib.sha256(boot).hexdigest() != recovery_pins["boot_receipt_sha256"]:
                        _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
                elif prepare:
                    if boot is not None or any(name.startswith(_BOOT_EGRESS_HISTORY_PREFIX)
                                               for name in os.listdir(state)):
                        _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
                elif boot is None or hashlib.sha256(boot).hexdigest() != recovery_pins["boot_receipt_sha256"]:
                    _reject("NATIVE_DEDICATED_RECOVERY_PIN_REFUSED")
            else:
                wal_sha256 = recovery_pins["wal_sha256"]
                wal = _read_file(state, _OWNED_WAL, 0, _MAX_WAL)
                if wal is None or hashlib.sha256(wal).hexdigest() != wal_sha256:
                    _reject("NATIVE_DEDICATED_RECOVERY_WAL_REFUSED")
            _require_audited_native_package_for_activation(state, distribution="almalinux")
            with tempfile.TemporaryDirectory(prefix="repocache-native-recovery-", dir="/var/lib") as tmp:
                work = Path(tmp)
                if not _native_workspace_is_root_owned(work):
                    _reject("NATIVE_EXECUTABLE_WORKSPACE_REFUSED")
                package = _candidate_native_identity("almalinux", work)
                native_digest, binary_digest = _authenticate_candidate_rpm(work, package)
                if _candidate_native_identity("almalinux", work) != package:
                    _reject("NATIVE_EXECUTABLE_PACKAGE_CHANGED")
            stage._audit_worker_files(Path("/"), payloads)
    finally:
        os.close(root)
    # No protected resource changed before releasing the first lock.
    # A concurrent change must be refused by the child's fresh pin checks.
    pins = dict(source_sha=commit, archive_sha256=archive_sha256,
                worker_sha256=hashlib.sha256(payloads[stage.WORKER]).hexdigest(),
                placement_sha256=placement_sha, package_identity=package,
                native_payload_sha256=native_digest, binary_sha256=binary_digest,
                **recovery_pins)
    try:
        result = subprocess.run(
            ("/usr/bin/python3", "-IS", "-B", "-c",
             _DEDICATED_PROFILE_CHILD if stage_profile else
             _DEDICATED_PROFILE_LOAD_CHILD if load_profile else
             _DEDICATED_PENDING_RESUME_CHILD if resume_boot and pending_prepare else
             _DEDICATED_COMMITTED_RESUME_CHILD if resume_boot else
             _DEDICATED_PENDING_ROLLOVER_CHILD if pending_prepare and rollover else
             _DEDICATED_PENDING_PREPARE_CHILD if pending_prepare else
             _DEDICATED_ROLLOVER_CHILD if rollover else
             _DEDICATED_PREPARE_CHILD if prepare else
             _DEDICATED_PENDING_START_CHILD if pending_start else
             _DEDICATED_ROLLED_START_CHILD if rolled_start else
             _DEDICATED_START_CHILD if start else _DEDICATED_RECOVERY_CHILD),
            input=json.dumps(pins, sort_keys=True).encode("ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/",
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
            shell=False, close_fds=True, timeout=420, check=False)
        if result.returncode != 0 or not 0 < len(result.stdout) <= 65536:
            # Preserve only the worker's closed, non-sensitive audit codes.
            from repocache.server_native_v2_transaction_v1 import _AUDIT_FAILURE_CODES
            for line in result.stderr.splitlines():
                prefix = b"REPOCACHE_FIXED_TRANSACTION_REFUSAL: "
                if line.startswith(prefix) and line[len(prefix):].isascii():
                    code = line[len(prefix):].decode("ascii")
                    if code in _AUDIT_FAILURE_CODES:
                        print(prefix.decode("ascii") + code, file=sys.stderr)
            _reject("NATIVE_DEDICATED_RECOVERY_CHILD_REFUSED")
        report = json.loads(result.stdout)
        if type(report) is not dict:
            _reject("NATIVE_DEDICATED_RECOVERY_CHILD_REFUSED")
        if stage_profile:
            if (report.get("status") != "OWNED_DEDICATED_PROFILE_STAGED"
                    or report.get("generation_manifest_sha256") !=
                       recovery_pins["generation_manifest_sha256"]
                    or report.get("executable_receipt_sha256") !=
                       recovery_pins["executable_receipt_sha256"]
                    or type(report.get("receipt_sha256")) is not str
                    or signatures.HEX64.fullmatch(report["receipt_sha256"]) is None
                    or report.get("receipt_matches_owned_dropin") is not True
                    or report.get("authorizes_systemctl") is not False
                    or report.get("authorizes_nginx_activation") is not False
                    or report.get("authorizes_catalog_publication") is not False):
                _reject("NATIVE_DEDICATED_RECOVERY_CHILD_REFUSED")
        elif load_profile:
            if (report.get("status") != "OWNED_DEDICATED_PROFILE_LOADED"
                    or report.get("generation_manifest_sha256") !=
                       recovery_pins["generation_manifest_sha256"]
                    or report.get("executable_receipt_sha256") !=
                       recovery_pins["executable_receipt_sha256"]
                    or report.get("receipt_sha256") != recovery_pins["profile_receipt_sha256"]
                    or report.get("profile_loaded") is not True
                    or type(report.get("daemon_reloaded")) is not bool
                    or report.get("receipt_matches_owned_dropin") is not True
                    or report.get("authorizes_systemctl") is not False
                    or report.get("authorizes_nginx_activation") is not False
                    or report.get("authorizes_catalog_publication") is not False):
                _reject("NATIVE_DEDICATED_RECOVERY_CHILD_REFUSED")
        elif prepare:
            if (report.get("status") != "NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED"
                    or report.get("generation_manifest_sha256") !=
                    recovery_pins["generation_manifest_sha256"]
                    or (not pending_prepare and report.get("committed_resources_verified") is not True)
                    or (pending_prepare and (
                        report.get("prior_resources_verified") is not True
                        or report.get("recovery_required") is not True
                        or report.get("catalog_withdrawn") is not True
                        or report.get("wal_sha256") != recovery_pins["wal_sha256"]
                        or "committed_resources_verified" in report))
                    or report.get("authorizes_nginx_activation") is not False
                    or report.get("authorizes_catalog_publication") is not False
                    or type(report.get("receipt_sha256")) is not str
                    or signatures.HEX64.fullmatch(report["receipt_sha256"]) is None
                    or (rollover and report["receipt_sha256"] ==
                        recovery_pins["previous_boot_receipt_sha256"])
                    or (resume_boot and report["receipt_sha256"] != recovery_pins["boot_receipt_sha256"])):
                _reject("NATIVE_DEDICATED_RECOVERY_CHILD_REFUSED")
        elif start:
            accepted_status = ({"OWNED_DEDICATED_PREPARED_WAL_START_OBSERVED"} if pending_start
                               else {"OWNED_DEDICATED_COMMITTED_START_OBSERVED"})
            if rolled_start:
                accepted_status.add("OWNED_DEDICATED_COMMITTED_ACTIVE_VERIFIED")
            if (report.get("status") not in accepted_status
                    or report.get("generation_manifest_sha256") != recovery_pins["generation_manifest_sha256"]
                    or report.get("boot_receipt_sha256") != recovery_pins["boot_receipt_sha256"]
                    or report.get("catalog_observed") is not (not pending_start)
                    or (pending_start and (report.get("wal_sha256") != recovery_pins["wal_sha256"]
                                           or report.get("catalog_withdrawn") is not True
                                           or report.get("recovery_required") is not True))
                    or report.get("service_storage_mounts_verified") is not True
                    or report.get("service_scratch_mounts_verified") is not True
                    or report.get("enablement_changed") is not False
                    or any(type(report.get(key)) is not int or report[key] <= 0
                           for key in ("main_pid", "listener_inode"))):
                _reject("NATIVE_DEDICATED_RECOVERY_CHILD_REFUSED")
        elif (report.get("status") != "OWNED_DEDICATED_WAL_ROLLBACK_OBSERVED"
                or report.get("wal_sha256") != wal_sha256
                or report.get("recovery_required") is not False
                or report.get("catalog_observed") is not True):
            _reject("NATIVE_DEDICATED_RECOVERY_CHILD_REFUSED")
        return report
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _reject("NATIVE_DEDICATED_RECOVERY_CHILD_REFUSED")


def _select_rolled_activation_recovery_locked(root: int, state: int, distribution: str) -> dict | None:
    """Recognize dedicated intent without adopting or repairing any resource.

    The signed caller retains the lock. Presence of incomplete dedicated
    evidence is a refusal, not permission to try legacy activation.
    """
    from repocache.server_native_nginx_effective_unit_v1 import _NAMESPACE_PROFILE_RECEIPT
    from repocache.server_native_egress_candidate_v1 import (
        _BOOT_EGRESS_RECEIPT, _BOOT_EGRESS_HISTORY_PREFIX, _BOOT_EGRESS_ROLLOVER,
    )
    from repocache.server_native_v2_transaction_v1 import (
        _retained_rolled_dedicated_recovery_pins_locked,
        _retained_rolled_committed_dedicated_pins_locked,
    )

    names = set(os.listdir(state))
    prefixes = (_NAMESPACE_PROFILE_RECEIPT.removesuffix(".json"),
                _BOOT_EGRESS_RECEIPT.removesuffix(".json"))
    if not any(name.startswith(prefixes) for name in names):
        return None
    if (distribution != "almalinux"
            or not {_NAMESPACE_PROFILE_RECEIPT, _BOOT_EGRESS_RECEIPT} <= names
            or _BOOT_EGRESS_ROLLOVER in names
            or not any(name.startswith(_BOOT_EGRESS_HISTORY_PREFIX) for name in names)
            or any(name.startswith(prefixes) and name not in
                   (_NAMESPACE_PROFILE_RECEIPT, _BOOT_EGRESS_RECEIPT)
                   and not name.startswith(_BOOT_EGRESS_HISTORY_PREFIX) for name in names)):
        _reject("NATIVE_DEDICATED_ACTIVATION_RECOVERY_REFUSED")
    # No following symlinks, including dangling dedicated markers. Full
    # ownership, byte and label verification is still required downstream.
    pending = _OWNED_WAL in names
    for name in (_NAMESPACE_PROFILE_RECEIPT, _BOOT_EGRESS_RECEIPT,
                 *([_OWNED_WAL] if pending else [])):
        info = _named(state, name)
        if info is None or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            _reject("NATIVE_DEDICATED_ACTIVATION_RECOVERY_REFUSED")
    _require_audited_native_package_for_activation(state, distribution=distribution)
    select = (_retained_rolled_dedicated_recovery_pins_locked if pending else
              _retained_rolled_committed_dedicated_pins_locked)
    selected = select(root, state)
    fields = {"executable_receipt_sha256", "profile_receipt_sha256",
              "boot_receipt_sha256", "wal_sha256" if pending else "generation_manifest_sha256"}
    if (type(selected) is not dict
            or set(selected) != fields
            or any(type(value) is not str or signatures.HEX64.fullmatch(value) is None
                   for value in selected.values())):
        _reject("NATIVE_DEDICATED_ACTIVATION_RECOVERY_REFUSED")
    return selected


def activate_authenticated_native_nginx(
    assets: Path, *, commit: str, archive_sha256: str,
) -> dict:
    """Explicit signed activation; dedicated recovery never enables a unit."""
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
    payloads, _receipt = stage._authenticated_payloads(
        assets, commit=commit, archive_sha256=archive_sha256, system=None,
    )
    if payloads.get(stage.CONFIG) != _BOOTSTRAP_CONFIG:
        _reject("NATIVE_SIGNED_CONFIG_UNEXPECTED")
    root = os.open("/", stage._DIRECTORY)
    try:
        with _locked(root, 0) as state:
            # Recheck installed source identity after acquiring shared lock.
            def recheck_signed_worker():
                stage._audit_worker_files(Path("/"), payloads)
            recheck_signed_worker()
            selected = _select_rolled_activation_recovery_locked(root, state, distribution)
            if selected is None:
                result = _activate_audited_native_nginx_under_lock(
                    state, distribution, payloads[stage.CONFIG], root_fd=root,
                    unit_bytes=payloads[_OWN_UNIT],
                    recheck_signed_worker=recheck_signed_worker,
                )
                if "state_generation" in result:
                    stage._audit_worker_files(Path("/"), payloads)
                return result
            recheck_signed_worker()
    finally:
        os.close(root)
    # The signed bridge reconstructs the selection again under its own
    # lock and the installed child independently rechecks the exact pins.
    # A changed or failed selection never falls through to legacy start.
    if "wal_sha256" in selected:
        report = _recover_authenticated_rolled_dedicated_nginx(
            assets, commit=commit, archive_sha256=archive_sha256, expected_pins=selected)
    else:
        report = _authenticated_prepared_dedicated_bridge(
            assets, commit=commit, archive_sha256=archive_sha256,
            recovery_pins=None, start=True, expected_rolled_pins=selected)
    return {**report, "nginx_active_verified": True,
            "nginx_enabled_verified": False, "enablement_changed": False}


def _execute_native_nginx_install_locked(
    root_fd: int, *, distribution: str, document: dict, os_release: str,
    owner_uid: int = 0, expected_worker_receipt: bytes | None = None,
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
        expected_worker_receipt=expected_worker_receipt,
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
            _ensure_fixed_nginx_cache_parent_under_root(
                root_fd, owner_uid=owner_uid, distribution=distribution,
            )
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
            expected_worker_receipt=stage._json_line({
                **attested, "status": "AUTHENTICATED_WORKER_STAGED",
            }),
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
    with ExitStack() as stack:
        state = stack.enter_context(_locked(root_fd, 0))
        # Staging never adopts foreign files or consumes a pending WAL.
        # A dedicated ownership claim must select the dedicated manifest
        # domain, even when no managed generation has yet been committed.
        claimed = any(name.startswith(OWNED_NGINX_CONFIG_MARKER_PREFIX)
                      for name in os.listdir(state))
        if claimed:
            _, nginx, public, check_layout = stack.enter_context(
                _owned_layout_locked(root_fd, state, recovering=False),
            )
            owned = _read_owned_resources(state, nginx, public)
            _validate_owned_resources(owned)
        else:
            _no_conflicting_pending(state)
        previous, previous_raw = _read_v2(state, 0)
        if claimed and previous_raw != owned["state-v2.json"]:
            _reject("PROPOSAL_OWNED_STATE_CHANGED")
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
        if claimed:
            check_layout()
            if _read_owned_resources(state, nginx, public) != owned:
                _reject("PROPOSAL_OWNED_STATE_CHANGED")
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
