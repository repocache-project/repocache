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
