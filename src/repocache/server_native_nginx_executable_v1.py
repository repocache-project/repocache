"""Descriptor-bound staging of a separately authenticated native NGINX binary.

Internal candidate primitive only. No path from an operator, package download,
policy installation, relabel, execution, service activation or host permission.
The caller must independently authenticate the exact distribution payload and
hold the owned placement transaction. The digest alone is not a trust token.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import tarfile
from pathlib import PurePosixPath

_MAX = 32 * 1024 * 1024
_LEAF = "nginx"
_PENDING = ".repocache-nginx-executable.pending"
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class NativeExecutableCandidateError(ValueError):
    """Redacted placement refusal."""


def _deny(code: str) -> None:
    raise NativeExecutableCandidateError("NGINX_EXECUTABLE_" + code)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _named(directory, name):
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _safe_file(info, *, mode=0o755):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode
            or not 0 < info.st_size <= _MAX):
        _deny("METADATA_REFUSED")


def _read_verified(fd, digest, *, mode=0o755):
    before = os.fstat(fd)
    _safe_file(before, mode=mode)
    # Copy bytes, never package file capabilities, ACLs or other xattrs.
    # A native SELinux label may already exist; never change it here.
    attrs = tuple(sorted(os.listxattr(fd)))
    if any(name != "security.selinux" for name in attrs):
        _deny("ATTRIBUTE_REFUSED")
    data = bytearray()
    while len(data) < before.st_size:
        block = os.pread(fd, min(65536, before.st_size - len(data)), len(data))
        if not block:
            _deny("READ_CHANGED")
        data.extend(block)
    if (os.pread(fd, 1, len(data)) or _identity(os.fstat(fd)) != _identity(before)
            or tuple(sorted(os.listxattr(fd))) != attrs
            or hashlib.sha256(data).hexdigest() != digest):
        _deny("DIGEST_OR_IDENTITY_REFUSED")
    return bytes(data), _identity(before)


def _directory(directory):
    info = os.fstat(directory)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) not in (0o700, 0o755)):
        _deny("DIRECTORY_REFUSED")
    if any(name != "security.selinux" for name in os.listxattr(directory)):
        _deny("DIRECTORY_ATTRIBUTE_REFUSED")
    return info.st_dev, info.st_ino


def _verify_leaf(directory, digest):
    fd = os.open(_LEAF, _READ, dir_fd=directory)
    try:
        _, identity = _read_verified(fd, digest)
        named = _named(directory, _LEAF)
        if named is None or _identity(named) != identity:
            _deny("DESTINATION_CHANGED")
        if identity[0] != os.fstat(directory).st_dev:
            _deny("DESTINATION_DEVICE_REFUSED")
        return identity
    finally:
        os.close(fd)


def stage_verified_nginx_candidate(
    directory: int, vendor_fd: int, *, authenticated_sha256: str,
    previous_inode: tuple[int, int] | None = None,
) -> dict:
    """Place fixed leaf in a retained owned directory without overwrite.

    Root-only; input fd and hash must come from the independently verified
    package identity, not a request. The caller retains namespace and
    placement lock authority, independently verifies the directory path,
    and must never execute before checking the service policy and receipt.
    Repeat staging requires the caller's previously owned device/inode;
    equal bytes alone cannot establish ownership. Unexpected pending
    evidence is preserved for manual reconciliation.
    """
    if (os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
            or type(directory) is not int or type(vendor_fd) is not int
            or directory == vendor_fd or type(authenticated_sha256) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", authenticated_sha256)
            or (previous_inode is not None and (
                type(previous_inode) is not tuple or len(previous_inode) != 2
                or any(type(x) is not int or x < 0 for x in previous_inode)))):
        _deny("INPUT_REFUSED")
    try:
        dir_id = _directory(directory)
        if _named(directory, _PENDING) is not None:
            _deny("PENDING_REFUSED")
        raw, source_id = _read_verified(vendor_fd, authenticated_sha256)
        existed = _named(directory, _LEAF) is not None
        if existed:
            if previous_inode is None or _verify_leaf(directory, authenticated_sha256)[:2] != previous_inode:
                _deny("FOREIGN_DESTINATION")
        elif previous_inode is not None:
            _deny("OWNED_DESTINATION_MISSING")
        published_inode = previous_inode
        if not existed:
            fd = os.open(_PENDING, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            try:
                with os.fdopen(os.dup(fd), "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                os.fchmod(fd, 0o755)
                os.fsync(fd)
                _, staged = _read_verified(fd, authenticated_sha256)
                named = _named(directory, _PENDING)
                if (named is None or _identity(named) != staged
                        or staged[0] != dir_id[0]
                        or _directory(directory) != dir_id
                        or _identity(os.fstat(vendor_fd)) != source_id):
                    _deny("STAGING_CHANGED")
                # Atomic no-replace publication. If interrupted between
                # link/unlink, preserve the pending name and refuse replay.
                os.link(_PENDING, _LEAF, src_dir_fd=directory,
                        dst_dir_fd=directory, follow_symlinks=False)
                linked = os.fstat(fd)
                target = _named(directory, _LEAF)
                pending = _named(directory, _PENDING)
                if (linked.st_nlink != 2 or target is None or pending is None
                        or _identity(target) != _identity(linked)
                        or _identity(pending) != _identity(linked)):
                    _deny("PUBLICATION_CHANGED")
                published_inode = (linked.st_dev, linked.st_ino)
                os.unlink(_PENDING, dir_fd=directory)
                os.fsync(directory)
            finally:
                os.close(fd)
        copy_id = _verify_leaf(directory, authenticated_sha256)
        if (_directory(directory) != dir_id
                or _identity(os.fstat(vendor_fd)) != source_id
                or copy_id[:2] == source_id[:2]
                or copy_id[:2] != published_inode
                or _named(directory, _PENDING) is not None):
            _deny("PLACEMENT_CHANGED")
        return {
            "status": "NGINX_EXECUTABLE_CANDIDATE_UNCHANGED" if existed else
                      "NGINX_EXECUTABLE_CANDIDATE_STAGED",
            "sha256": authenticated_sha256,
            "device": copy_id[0], "inode": copy_id[1],
            "authorizes_nginx_activation": False,
            "native_payload_authenticity_verified_by_primitive": False,
            "selinux_domain_verified": False,
        }
    except NativeExecutableCandidateError:
        raise
    except (OSError, OverflowError, ValueError, TypeError):
        _deny("PLACEMENT_REFUSED")


# These helpers neither authenticate a package manager nor execute a binary.
# The trusted native installer must obtain the exact payload under its
# existing signed-source profile and independently retain the package lock.
_DEB_TAR_MAX = 64 * 1024 * 1024
_RECEIPT = ".native-nginx-executable-v1.json"
_RECEIPT_MAX = 4096
_DEB_VERSION = re.compile(r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+~:-]{0,127}", re.ASCII)
_RPM_ID = re.compile(r"nginx-core-[0-9]+:[A-Za-z0-9._+~-]+-[A-Za-z0-9._+~-]+\.x86_64", re.ASCII)


def debian_nginx_metadata_digest(metadata: str, version: str) -> str:
    """Exact nginx:amd64 archive SHA256 from authenticated APT metadata.

    The caller must use fresh apt-secure lists under the fixed OS profile.
    Equal package/version strings from unauthenticated input are not proof.
    """
    if (type(metadata) is not str or len(metadata) > 65536 or not metadata.isascii()
            or type(version) is not str or _DEB_VERSION.fullmatch(version) is None):
        _deny("DEB_METADATA_REFUSED")
    found = set()
    for stanza in re.split(r"\n[ \t]*\n", metadata.strip()):
        fields = {}
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")):
                continue
            key, sep, value = line.partition(":")
            if not sep or key in fields:
                _deny("DEB_METADATA_REFUSED")
            fields[key] = value.strip()
        if (fields.get("Package") != "nginx" or fields.get("Architecture") != "amd64"
                or fields.get("Version") != version
                or re.fullmatch(r"[0-9a-f]{64}", fields.get("SHA256", "")) is None):
            _deny("DEB_METADATA_REFUSED")
        found.add(fields["SHA256"])
    if len(found) != 1:
        _deny("DEB_METADATA_REFUSED")
    return found.pop()


def debian_nginx_tar_digest(raw: bytes) -> str:
    """Read only the exact regular root-owned NGINX member; never extract.

    Input must be the bounded uncompressed data archive of the separately
    authenticated exact Debian package. No maintainer script is executed.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= _DEB_TAR_MAX:
        _deny("DEB_TAR_REFUSED")
    try:
        found = None
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or "\x00" in member.name:
                    _deny("DEB_TAR_REFUSED")
                if path != PurePosixPath("usr/sbin/nginx"):
                    continue
                if (found is not None or member.name not in ("usr/sbin/nginx", "./usr/sbin/nginx")
                        or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                        or member.sparse is not None or member.uid != 0 or member.gid != 0
                        or member.mode != 0o755 or not 0 < member.size <= _MAX):
                    _deny("DEB_TAR_MEMBER_REFUSED")
                content = archive.extractfile(member)
                if content is None:
                    _deny("DEB_TAR_MEMBER_REFUSED")
                with content:
                    payload = content.read(_MAX + 1)
                if len(payload) != member.size:
                    _deny("DEB_TAR_MEMBER_REFUSED")
                found = hashlib.sha256(payload).hexdigest()
        if found is None:
            _deny("DEB_TAR_MEMBER_REFUSED")
        return found
    except NativeExecutableCandidateError:
        raise
    except (OSError, ValueError, TypeError, EOFError, tarfile.TarError):
        _deny("DEB_TAR_REFUSED")


def _read_executable_receipt(directory: int) -> bytes | None:
    named = _named(directory, _RECEIPT)
    if named is None:
        return None
    fd = os.open(_RECEIPT, _READ, dir_fd=directory)
    try:
        info = os.fstat(fd)
        _safe_file(info, mode=0o600)
        if (info.st_size > _RECEIPT_MAX or info.st_dev != os.fstat(directory).st_dev
                or _identity(info) != _identity(named)
                or any(name != "security.selinux" for name in os.listxattr(fd))):
            _deny("RECEIPT_REFUSED")
        raw = os.read(fd, _RECEIPT_MAX + 1)
        current = _named(directory, _RECEIPT)
        if (len(raw) != info.st_size or current is None
                or _identity(info) != _identity(os.fstat(fd))
                or _identity(info) != _identity(current)):
            _deny("RECEIPT_CHANGED")
        return raw
    finally:
        os.close(fd)


def stage_nginx_candidate_with_receipt(
    directory: int, vendor_fd: int, *, distribution: str, package_identity: str,
    native_payload_sha256: str, authenticated_sha256: str,
    release_source_sha: str, release_archive_sha256: str,
) -> dict:
    """Bind candidate inode to independently authenticated package/release.

    Internal root-only operation under the caller's retained owned
    placement transaction. Neither inputs nor receipt independently grant
    trust; caller verifies the package and release on each invocation.
    A crash before complete receipt publication leaves a refused unowned
    or incomplete state, never an automatically adopted executable.
    """
    from repocache.server_protected_state_store_v1 import (
        ProtectedStateStoreError, _canonical, _json, _write_exclusive,
    )
    if (os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
            or type(directory) is not int or type(vendor_fd) is not int
            or directory == vendor_fd or type(package_identity) is not str
            or type(distribution) is not str or distribution not in ("debian", "almalinux")
            or (distribution == "debian" and
                (not package_identity.startswith("nginx:amd64=")
                 or _DEB_VERSION.fullmatch(package_identity.removeprefix("nginx:amd64=")) is None))
            or (distribution == "almalinux" and _RPM_ID.fullmatch(package_identity) is None)
            or type(release_source_sha) is not str
            or re.fullmatch(r"[0-9a-f]{40}", release_source_sha) is None
            or any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
                   for value in (native_payload_sha256, authenticated_sha256, release_archive_sha256))):
        _deny("RECEIPT_INPUT_REFUSED")
    expected = {
        "schema_version": 1,
        "distribution": distribution,
        "package_identity": package_identity,
        "native_payload_sha256": native_payload_sha256,
        "executable_sha256": authenticated_sha256,
        "release_source_sha": release_source_sha,
        "release_archive_sha256": release_archive_sha256,
        "authorizes_nginx_activation": False,
    }
    try:
        identity = _directory(directory)
        raw = _read_executable_receipt(directory)
        previous = None
        if raw is not None:
            saved = _json(raw, limit=_RECEIPT_MAX)
            if (type(saved) is not dict or set(saved) != set(expected) | {"device", "inode"}
                    or _canonical(saved, limit=_RECEIPT_MAX) != raw
                    or any(type(saved[key]) is not type(value) or saved[key] != value
                           for key, value in expected.items())
                    or type(saved["device"]) is not int or saved["device"] != identity[0]
                    or type(saved["inode"]) is not int or saved["inode"] <= 0):
                _deny("RECEIPT_REFUSED")
            previous = (saved["device"], saved["inode"])
        result = stage_verified_nginx_candidate(
            directory, vendor_fd, authenticated_sha256=authenticated_sha256,
            previous_inode=previous,
        )
        record = {**expected, "device": result["device"], "inode": result["inode"]}
        encoded = _canonical(record, limit=_RECEIPT_MAX)
        if raw is None:
            _write_exclusive(directory, _RECEIPT, encoded, 0, _RECEIPT_MAX)
        if (_read_executable_receipt(directory) != encoded
                or _directory(directory) != identity
                or _verify_leaf(directory, authenticated_sha256)[:2] !=
                    (record["device"], record["inode"])):
            _deny("RECEIPT_CHANGED")
        return {**result, "receipt_sha256": hashlib.sha256(encoded).hexdigest(),
                "receipt_matches_owned_inode": True}
    except NativeExecutableCandidateError:
        raise
    except (ProtectedStateStoreError, OSError, ValueError, TypeError, RecursionError):
        _deny("RECEIPT_REFUSED")
