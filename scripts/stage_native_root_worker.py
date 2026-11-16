#!/usr/bin/env python3
"""Authenticate an offline v0.6 candidate and stage its fixed worker and units.

Run from the independently trusted checkout. The candidate supplies data to
verify and package. This step does not install files into the OS or activate
any service.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

if __name__ == "__main__":
    checkout = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(checkout / "src"), str(checkout)]

from repocache import signatures, upgrade
from scripts import build_native_root_worker


VERSION = "0.6.0"
ARCHIVE = f"repocache-v{VERSION}.tar.gz"
EXPECTED_REPOSITORY = "repocache-project/repocache"
UNIT_DIR = Path("docs/examples/systemd")
UNITS = ("repocache-control.service", "repocache-control.socket")
WORKER = "server-control-worker"
RECEIPT = "worker-receipt.json"
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class WorkerStageError(ValueError):
    """Refuse staging with a static, redacted error."""


def _asset_bytes(
    directory: int, name: str, maximum: int, *, installed_mode: int | None = None,
) -> bytes:
    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(name, flags, dir_fd=directory), "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum):
            raise WorkerStageError("WORKER_STAGE_INVALID_ASSET")
        if installed_mode is not None and (
            before.st_uid != 0 or before.st_gid != 0 or stat.S_IMODE(before.st_mode) != installed_mode
        ):
            raise WorkerStageError("WORKER_INSTALL_METADATA_MISMATCH")
        payload = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (len(payload) != before.st_size or identity(before) != identity(after)
                or identity(after) != identity(named)):
            raise WorkerStageError("WORKER_STAGE_CHANGED_ASSET")
        return payload


def _write(directory: int, name: str, raw: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(name, flags, 0o600, dir_fd=directory), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def _json_line(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _authenticated_payloads(
    asset_directory: Path, *, commit: str, archive_sha256: str,
    system: dict[str, str] | None,
) -> tuple[dict[str, bytes], dict]:
    """Verify with the existing host trust anchor before extracting any member."""
    if (type(commit) is not str or signatures.HEX40.fullmatch(commit) is None
            or type(archive_sha256) is not str or signatures.HEX64.fullmatch(archive_sha256) is None):
        raise WorkerStageError("WORKER_STAGE_INVALID_EXPECTED_IDENTITY")
    with ExitStack() as stack:
        asset_fd = os.open(asset_directory, _DIRECTORY)
        stack.callback(os.close, asset_fd)
        archive = _asset_bytes(asset_fd, ARCHIVE, upgrade.MAX_ARCHIVE)
        manifest = _asset_bytes(asset_fd, ARCHIVE + ".manifest.json", signatures.MAX_MANIFEST)
        detached = _asset_bytes(asset_fd, ARCHIVE + ".manifest.json.sig", signatures.MAX_SIGNATURE)
    identity = signatures.verify(archive, manifest, detached, VERSION)
    if (identity["repository"] != EXPECTED_REPOSITORY or identity["schema"] != 1
            or identity["commit"] != commit or identity["archive_sha256"] != archive_sha256):
        raise WorkerStageError("WORKER_STAGE_SIGNED_IDENTITY_MISMATCH")
    with tempfile.TemporaryDirectory(prefix="repocache-worker-verified-") as temp:
        source, policy = upgrade._extract_verified(
            archive, VERSION, Path(temp), {"version": "0.0.0"},
            system=system, signed_policy_sha256=identity["policy_sha256"],
        )
        upgrade._verified_dependency_profile(identity, policy, VERSION)
        payloads = {WORKER: build_native_root_worker.build(source)}
        payloads.update({name: (source / UNIT_DIR / name).read_bytes() for name in UNITS})

    receipt = {
        "schema_version": 1,
        "status": "AUTHENTICATED_WORKER_STAGED",
        "version": VERSION,
        "source_sha": commit,
        "archive_sha256": archive_sha256,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "publisher_key_id": identity["key_id"],
        "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()},
        "authorizes_host_installation": False,
        "authorizes_service_activation": False,
    }
    return payloads, receipt


def stage_authenticated_worker(
    asset_directory: Path, output: Path, *, commit: str, archive_sha256: str,
    system: dict[str, str] | None = None,
) -> dict:
    payloads, receipt = _authenticated_payloads(
        asset_directory, commit=commit, archive_sha256=archive_sha256, system=system,
    )
    if output.name in ("", ".", ".."):
        raise WorkerStageError("WORKER_STAGE_UNSAFE_OUTPUT")
    with ExitStack() as stack:
        parent_fd = os.open(output.parent, _DIRECTORY)
        stack.callback(os.close, parent_fd)
        parent = os.fstat(parent_fd)
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise WorkerStageError("WORKER_STAGE_UNSAFE_OUTPUT")
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        destination = os.open(output.name, _DIRECTORY, dir_fd=parent_fd)
        stack.callback(os.close, destination)
        for name, raw in payloads.items():
            _write(destination, name, raw, 0o700 if name == WORKER else 0o600)
        # The receipt is the last file. On an interrupted attempt without a
        # receipt, start fresh and retain the partial output for inspection.
        os.fsync(destination)
        _write(destination, RECEIPT, _json_line(receipt), 0o600)
        os.fsync(destination)
        os.fsync(parent_fd)
    return receipt


def _protected_directory(fd: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_mode & 0o022):
        raise WorkerStageError("WORKER_INSTALL_PARENT_UNSAFE")


def _audit_worker_files(root: Path, payloads: dict[str, bytes]) -> None:
    """Check only the fixed operator installation paths using pinned descriptors."""
    paths = (
        (("usr", "libexec", "repocache"), (WORKER,), 0o755),
        (("etc", "systemd", "system"), UNITS, 0o644),
    )
    with ExitStack() as stack:
        root_fd = os.open(root, _DIRECTORY)
        stack.callback(os.close, root_fd)
        _protected_directory(root_fd)
        opened = []
        for components, names, mode in paths:
            directory = root_fd
            for component in components:
                parent = directory
                directory = os.open(component, _DIRECTORY, dir_fd=parent)
                stack.callback(os.close, directory)
                opened.append((parent, component, directory))
                _protected_directory(directory)
            for name in names:
                expected = payloads[name]
                if _asset_bytes(directory, name, len(expected), installed_mode=mode) != expected:
                    raise WorkerStageError("WORKER_INSTALL_CONTENT_MISMATCH")
        for parent, name, fd in opened:
            _protected_directory(fd)
            seen = os.stat(name, dir_fd=parent, follow_symlinks=False)
            actual = os.fstat(fd)
            if (seen.st_dev, seen.st_ino) != (actual.st_dev, actual.st_ino):
                raise WorkerStageError("WORKER_INSTALL_PARENT_CHANGED")


def verify_installed_worker(
    asset_directory: Path, *, commit: str, archive_sha256: str,
) -> dict:
    """Re-authenticate the candidate and compare the current installation bytes."""
    if os.geteuid() != 0:
        raise WorkerStageError("WORKER_INSTALL_AUDIT_REQUIRES_ROOT")
    payloads, receipt = _authenticated_payloads(
        asset_directory, commit=commit, archive_sha256=archive_sha256, system=None,
    )
    _audit_worker_files(Path("/"), payloads)
    return {**receipt, "status": "AUTHENTICATED_WORKER_FILES_MATCH"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--verify-installed", action="store_true")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--archive-sha256", required=True)
    args = parser.parse_args()
    try:
        pins = {"commit": args.commit, "archive_sha256": args.archive_sha256}
        if args.verify_installed:
            result = verify_installed_worker(args.assets, **pins)
        else:
            result = stage_authenticated_worker(args.assets, args.output, **pins)
    except (OSError, ValueError, signatures.SignatureError, upgrade.UpgradeError):
        status = ("AUTHENTICATED_WORKER_AUDIT_REFUSED" if args.verify_installed
                  else "AUTHENTICATED_WORKER_STAGE_REFUSED")
        print(_json_line({"status": status}).decode("ascii"), end="")
        return 1
    print(_json_line(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
