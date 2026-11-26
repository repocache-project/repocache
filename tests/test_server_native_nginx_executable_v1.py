"""Private-root tests; never read or replace a host package executable."""
import hashlib
import os

import pytest

from repocache.server_native_nginx_executable_v1 import (
    NativeExecutableCandidateError, stage_verified_nginx_candidate,
)


def test_rejects_nonroot_or_invalid_identity(monkeypatch):
    monkeypatch.setattr(os, "getresuid", lambda: (0, 0, 1))
    with pytest.raises(NativeExecutableCandidateError, match="INPUT_REFUSED"):
        stage_verified_nginx_candidate(5, 6, authenticated_sha256="a" * 64)


@pytest.mark.skipif(os.geteuid() != 0 or os.getegid() != 0, reason="private root fixture")
def test_stage_idempotence_foreign_and_pending_refusal(tmp_path):
    source = tmp_path / "vendor"
    source.write_bytes(b"private synthetic executable")
    source.chmod(0o755)
    owned = tmp_path / "owned"
    owned.mkdir(mode=0o700)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    parent = os.open(owned, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with pytest.raises(NativeExecutableCandidateError):
            stage_verified_nginx_candidate(parent, fd, authenticated_sha256="a" * 64)
        assert not list(owned.iterdir())
        first = stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest)
        target = owned / "nginx"
        info = target.stat()
        assert first["status"].endswith("STAGED")
        assert not first["authorizes_nginx_activation"]
        assert not first["native_payload_authenticity_verified_by_primitive"]
        assert target.read_bytes() == source.read_bytes()
        assert target.stat().st_ino != source.stat().st_ino
        with pytest.raises(NativeExecutableCandidateError, match="FOREIGN_DESTINATION"):
            stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest)
        again = stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest,
                                              previous_inode=(info.st_dev, info.st_ino))
        assert again["status"].endswith("UNCHANGED")
        assert target.stat().st_ino == info.st_ino
        assert target.stat().st_mtime_ns == info.st_mtime_ns
        pending = owned / ".repocache-nginx-executable.pending"
        pending.symlink_to("absent")
        with pytest.raises(NativeExecutableCandidateError, match="PENDING_REFUSED"):
            stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest)
        assert pending.is_symlink()
        pending.unlink()
        target.write_bytes(b"foreign")
        with pytest.raises(NativeExecutableCandidateError):
            stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest,
                                           previous_inode=(info.st_dev, info.st_ino))
        assert target.read_bytes() == b"foreign"
        assert source.read_bytes() == b"private synthetic executable"
    finally:
        os.close(fd)
        os.close(parent)


def test_debian_metadata_digest_exact_version_and_conflicting_hash():
    from repocache.server_native_nginx_executable_v1 import debian_nginx_metadata_digest
    stanza = "Package: nginx\nVersion: 1.2-3+deb13u1\nArchitecture: amd64\nSHA256: " + "a" * 64
    assert debian_nginx_metadata_digest(stanza, "1.2-3+deb13u1") == "a" * 64
    for bad in (stanza.replace("amd64", "arm64"), stanza + "\nSHA256: " + "a" * 64,
                stanza + "\n\n" + stanza.replace("a" * 64, "b" * 64)):
        with pytest.raises(NativeExecutableCandidateError):
            debian_nginx_metadata_digest(bad, "1.2-3+deb13u1")


@pytest.mark.parametrize("fault", [None, "duplicate", "symlink", "owner", "mode", "traversal", "missing"])
def test_debian_data_tar_exact_regular_executable(fault):
    import io
    import tarfile
    from repocache.server_native_nginx_executable_v1 import debian_nginx_tar_digest
    raw = io.BytesIO()
    payload = b"synthetic fixture bytes"
    with tarfile.open(fileobj=raw, mode="w") as archive:
        entry = tarfile.TarInfo("./usr/sbin/nginx" if fault != "missing" else "other")
        entry.mode = 0o755 if fault != "mode" else 0o4755
        entry.uid = 1 if fault == "owner" else 0
        entry.size = len(payload)
        if fault == "symlink":
            entry.type, entry.linkname, entry.size = tarfile.SYMTYPE, "other", 0
        if fault == "traversal":
            entry.name = "./usr/../usr/sbin/nginx"
        archive.addfile(entry, io.BytesIO(payload))
        if fault == "duplicate":
            archive.addfile(entry, io.BytesIO(payload))
    if fault is None:
        assert debian_nginx_tar_digest(raw.getvalue()) == hashlib.sha256(payload).hexdigest()
    else:
        with pytest.raises(NativeExecutableCandidateError):
            debian_nginx_tar_digest(raw.getvalue())


@pytest.mark.skipif(os.geteuid() != 0 or os.getegid() != 0, reason="private root fixture")
def test_receipt_requires_exact_owned_inode_and_native_release_identity(tmp_path):
    from repocache.server_native_nginx_executable_v1 import stage_nginx_candidate_with_receipt
    source = tmp_path / "vendor"
    source.write_bytes(b"synthetic native executable")
    source.chmod(0o755)
    owned = tmp_path / "owned"
    owned.mkdir(mode=0o700)
    opts = dict(distribution="debian", package_identity="nginx:amd64=1.2-3",
                native_payload_sha256="a" * 64, release_source_sha="b" * 40,
                release_archive_sha256="c" * 64,
                authenticated_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    parent = os.open(owned, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = stage_nginx_candidate_with_receipt(parent, fd, **opts)
        receipt = owned / ".native-nginx-executable-v1.json"
        before = receipt.read_bytes()
        assert first["receipt_sha256"] == hashlib.sha256(before).hexdigest()
        second = stage_nginx_candidate_with_receipt(parent, fd, **opts)
        assert second["status"].endswith("UNCHANGED") and second["inode"] == first["inode"]
        for key, value in (("native_payload_sha256", "d" * 64), ("release_archive_sha256", "e" * 64)):
            with pytest.raises(NativeExecutableCandidateError):
                stage_nginx_candidate_with_receipt(parent, fd, **{**opts, key: value})
            assert receipt.read_bytes() == before
        # An independently created equal-byte inode cannot be adopted.
        replacement = owned / "foreign"
        replacement.write_bytes(source.read_bytes())
        replacement.chmod(0o755)
        os.replace(replacement, owned / "nginx")
        with pytest.raises(NativeExecutableCandidateError):
            stage_nginx_candidate_with_receipt(parent, fd, **opts)
        assert receipt.read_bytes() == before
    finally:
        os.close(fd)
        os.close(parent)
