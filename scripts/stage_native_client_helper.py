#!/usr/bin/env python3
"""Build the non-activating client helper from authenticated v0.6 release bytes.

Run only from an independently trusted checkout. The same Ed25519 verifier
and closed release extractor used by normal installation authenticate the
candidate. No server worker authority, unsigned recipe or candidate code is
executed. Staging does not authorize installation or package source changes.
"""
from __future__ import annotations

import argparse
import ctypes
import secrets
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import zipfile

if __name__ == "__main__":
    checkout = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(checkout / "src"), str(checkout)]

from repocache import signatures, upgrade
from scripts.stage_native_root_worker import _asset_bytes

VERSION = "0.6.0"
ARCHIVE = "repocache-v0.6.0.tar.gz"
HELPER = "client-source-helper"
RECEIPT = "client-helper-receipt.json"
INTERPRETER = b"#!/usr/bin/python3 -IS\n"
MODULES = (
    "root_source_boundary", "repocache_client", "native_fallback_plan",
    "source_preflight", "source_entry_boundaries", "source_structure_subset",
    "native_package_lock_observation", "source_metadata_lab", "recovery_journal_v1",
)
ENTRYPOINT = b"from root_source_boundary import main\nraise SystemExit(main())\n"
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class ClientHelperStageError(ValueError):
    """Static refusal of an unauthenticated or unsafe stage."""


def build(source: Path) -> bytes:
    """Deterministic isolated OS-Python executable; no ambient imports."""
    client = source / "client"
    if source.is_symlink() or client.is_symlink() or not client.is_dir():
        raise ClientHelperStageError("CLIENT_HELPER_SOURCE_UNSAFE")
    stream = io.BytesIO(INTERPRETER)
    stream.seek(0, io.SEEK_END)
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(zipfile.ZipInfo("__main__.py"), ENTRYPOINT)
        for module in MODULES:
            file = client / (module + ".py")
            if file.is_symlink() or not file.is_file():
                raise ClientHelperStageError("CLIENT_HELPER_SOURCE_MISSING")
            raw = file.read_bytes()
            if not 1 <= len(raw) <= 256 * 1024:
                raise ClientHelperStageError("CLIENT_HELPER_SOURCE_SIZE")
            archive.writestr(zipfile.ZipInfo(file.name), raw)
    return stream.getvalue()


def authenticated_payload(asset_directory: Path, *, commit: str,
                          archive_sha256: str, system: dict | None = None):
    if (type(commit) is not str or not signatures.HEX40.fullmatch(commit)
            or type(archive_sha256) is not str
            or not signatures.HEX64.fullmatch(archive_sha256)):
        raise ClientHelperStageError("CLIENT_HELPER_EXPECTED_IDENTITY")
    with ExitStack() as stack:
        directory = os.open(asset_directory, DIRECTORY)
        stack.callback(os.close, directory)
        archive = _asset_bytes(directory, ARCHIVE, upgrade.MAX_ARCHIVE)
        manifest = _asset_bytes(directory, ARCHIVE + ".manifest.json", signatures.MAX_MANIFEST)
        detached = _asset_bytes(directory, ARCHIVE + ".manifest.json.sig", signatures.MAX_SIGNATURE)
    identity = signatures.verify(archive, manifest, detached, VERSION)
    if (identity["schema"] != 1 or identity["repository"] != "repocache-project/repocache"
            or identity["commit"] != commit or identity["archive_sha256"] != archive_sha256):
        raise ClientHelperStageError("CLIENT_HELPER_SIGNED_IDENTITY_MISMATCH")
    with tempfile.TemporaryDirectory(prefix="repocache-client-helper-verified-") as tmp:
        source, policy = upgrade._extract_verified(
            archive, VERSION, Path(tmp), {"version": "0.0.0"},
            system=system, signed_policy_sha256=identity["policy_sha256"])
        upgrade._verified_dependency_profile(identity, policy, VERSION)
        payload = build(source)
    receipt = {
        "schema_version": 1, "status": "AUTHENTICATED_CLIENT_HELPER_STAGED",
        "version": VERSION, "source_sha": commit, "archive_sha256": archive_sha256,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "publisher_key_id": identity["key_id"],
        "helper_sha256": hashlib.sha256(payload).hexdigest(),
        "authorizes_host_installation": False, "authorizes_source_mutation": False,
    }
    return payload, receipt


def _private_write(directory: int, name: str, payload: bytes, mode: int) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def stage_authenticated_client_helper(asset_directory: Path, output: Path, *,
                                      commit: str, archive_sha256: str,
                                      system: dict | None = None) -> dict:
    payload, receipt = authenticated_payload(
        asset_directory, commit=commit, archive_sha256=archive_sha256, system=system)
    if output.name in ("", ".", ".."):
        raise ClientHelperStageError("CLIENT_HELPER_OUTPUT_UNSAFE")
    with ExitStack() as stack:
        parent = os.open(output.parent, DIRECTORY)
        stack.callback(os.close, parent)
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ClientHelperStageError("CLIENT_HELPER_OUTPUT_UNSAFE")
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        directory = os.open(output.name, DIRECTORY, dir_fd=parent)
        stack.callback(os.close, directory)
        _private_write(directory, HELPER, payload, 0o700)
        os.fsync(directory)
        encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        _private_write(directory, RECEIPT, encoded, 0o600)
        os.fsync(directory)
        os.fsync(parent)
    return receipt


def install_authenticated_fixture(asset_directory: Path, *, platform: str,
                                  commit: str, archive_sha256: str) -> dict:
    """Fixed real placement in the explicitly disposable native VM only.

    This operation is deliberately absent from the production installer and
    stage CLI. The caller cannot supply an alternate destination or trust key.
    No setuid, socket, service, source writer or root escalation is installed.
    """
    from scripts.ci_v06_vm_signed_client_guest import guarded_native_guest

    guarded_native_guest(platform)
    if os.getresuid() != (0, 0, 0):
        raise ClientHelperStageError("CLIENT_HELPER_INSTALL_ROOT_REQUIRED")
    payload, receipt = authenticated_payload(
        asset_directory, commit=commit, archive_sha256=archive_sha256)
    with ExitStack() as stack:
        parent = os.open("/", DIRECTORY)
        stack.callback(os.close, parent)
        witnesses = []
        for name in ("usr", "libexec", "repocache-client"):
            if name != "usr":
                try:
                    os.mkdir(name, mode=0o755, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
            child = os.open(name, DIRECTORY, dir_fd=parent)
            stack.callback(os.close, child)
            info = os.fstat(child)
            if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
                raise ClientHelperStageError("CLIENT_HELPER_INSTALL_PARENT_UNSAFE")
            witnesses.append((parent, name, child))
            parent = child

        def recheck():
            for p, name, fd in witnesses:
                actual = os.fstat(fd)
                named = os.stat(name, dir_fd=p, follow_symlinks=False)
                if (actual.st_uid != 0 or actual.st_gid != 0 or actual.st_mode & 0o022
                        or (actual.st_dev, actual.st_ino) != (named.st_dev, named.st_ino)):
                    raise ClientHelperStageError("CLIENT_HELPER_INSTALL_PARENT_CHANGED")

        recheck()
        try:
            os.stat(HELPER, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            temporary = ".client-helper-" + secrets.token_hex(16)
            _private_write(parent, temporary, payload, 0o700)
            if _asset_bytes(parent, temporary, len(payload), installed_mode=0o700) != payload:
                raise ClientHelperStageError("CLIENT_HELPER_INSTALL_STAGE_MISMATCH")
            recheck()
            libc = ctypes.CDLL(None, use_errno=True)
            rename = libc.renameat2
            rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                               ctypes.c_char_p, ctypes.c_uint)
            rename.restype = ctypes.c_int
            if rename(parent, os.fsencode(temporary), parent, os.fsencode(HELPER), 1):
                # Preserve the private staged inode for investigation. Never
                # overwrite a destination that appeared concurrently.
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            os.fsync(parent)
            placement = "placed"
        else:
            placement = "unchanged"
        recheck()
        if _asset_bytes(parent, HELPER, len(payload), installed_mode=0o700) != payload:
            raise ClientHelperStageError("CLIENT_HELPER_INSTALL_CONTENT_MISMATCH")
        os.fsync(parent)
    # The independently trusted fixture checkout supplies this internal
    # bootstrap. Only after authenticated executable placement may it
    # create the fixed root-private registry; no source writes are enabled.
    import root_source_boundary as boundary

    registry = boundary.bootstrap_protected_state()
    return {**receipt, "status": "AUTHENTICATED_CLIENT_HELPER_FIXTURE_PLACED",
            "placement": placement, "registry": registry["status"],
            "protected_state_ready": registry["protected_state_ready"],
            "source_writer_installed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--archive-sha256", required=True)
    args = parser.parse_args()
    try:
        result = stage_authenticated_client_helper(
            args.assets, args.output, commit=args.commit,
            archive_sha256=args.archive_sha256)
    except (OSError, ValueError, RuntimeError):
        print("Authenticated client helper staging refused.", file=sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
