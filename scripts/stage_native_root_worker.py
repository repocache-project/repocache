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


def _asset_bytes(directory: int, name: str, maximum: int) -> bytes:
    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(name, flags, dir_fd=directory), "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum):
            raise WorkerStageError("WORKER_STAGE_INVALID_ASSET")
        payload = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
        if len(payload) != before.st_size or identity(before) != identity(after):
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


def stage_authenticated_worker(
    asset_directory: Path, output: Path, *, commit: str, archive_sha256: str,
    system: dict[str, str] | None = None,
) -> dict:
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--archive-sha256", required=True)
    args = parser.parse_args()
    try:
        result = stage_authenticated_worker(
            args.assets, args.output, commit=args.commit, archive_sha256=args.archive_sha256,
        )
    except (OSError, ValueError, signatures.SignatureError, upgrade.UpgradeError):
        print('{"status":"AUTHENTICATED_WORKER_STAGE_REFUSED"}')
        return 1
    print(_json_line(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
