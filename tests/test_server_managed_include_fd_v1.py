"""Descriptor-relative, read-only observation tests (not native installation)."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path

import pytest

from repocache import server_managed_include_fd_v1 as observer


@contextmanager
def opened_directory(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd
    finally:
        os.close(fd)


def observe(path: Path):
    with opened_directory(path) as fd:
        return observer.observe_managed_include_at(fd)


def test_regular_file_real_fd_byte_hash_no_write(tmp_path):
    value = b"# sample inert nginx include\n"
    path = tmp_path / observer.MANAGED_INCLUDE_NAME
    path.write_bytes(value)
    path.chmod(0o640)
    before = path.stat()
    seen = observe(tmp_path)
    assert seen == {
        "schema_version": 1, "status": "FD_SNAPSHOT_ONLY",
        "file_present": True,
        "observation": {
            "kind": "regular", "sha256": hashlib.sha256(value).hexdigest(),
            "uid": before.st_uid, "gid": before.st_gid,
            "mode": 0o640, "dev": before.st_dev, "ino": before.st_ino,
            "nlink": 1,
        },
        "trusted_parent_ancestry_verified": False,
        "protected_manifest_provenance_verified": False,
        "authorizes_write": False, "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }
    assert path.read_bytes() == value
    assert (path.stat().st_dev, path.stat().st_ino) == (before.st_dev, before.st_ino)
    assert sorted(x.name for x in tmp_path.iterdir()) == [observer.MANAGED_INCLUDE_NAME]


def test_missing_include_still_not_authorized(tmp_path):
    result = observe(tmp_path)
    assert result["file_present"] is False
    assert result["observation"] is None
    assert result["authorizes_write"] is False
    assert not list(tmp_path.iterdir())


def test_symlink_to_file_refused_without_reading_target(tmp_path):
    secret = tmp_path / "operator-private.key"
    secret.write_bytes(b"SECRET-TEST-BYTES")
    (tmp_path / observer.MANAGED_INCLUDE_NAME).symlink_to(secret)
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_OPEN_UNSAFE") as exc:
        observe(tmp_path)
    assert "operator-private" not in str(exc.value)
    assert secret.read_bytes() == b"SECRET-TEST-BYTES"


def test_hardlink_to_file_refused(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"data")
    original.chmod(0o640)
    os.link(original, tmp_path / observer.MANAGED_INCLUDE_NAME)
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_HARDLINK"):
        observe(tmp_path)
    assert original.read_bytes() == b"data"


def test_fifo_refused_without_blocking(tmp_path):
    os.mkfifo(tmp_path / observer.MANAGED_INCLUDE_NAME)
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_NOT_REGULAR"):
        observe(tmp_path)


@pytest.mark.parametrize("mode", [0o666, 0o777, 0o000, 0o444, 0o400, 0o664, 0o4755])
def test_nonallowlisted_file_modes_refused(tmp_path, mode):
    path = tmp_path / observer.MANAGED_INCLUDE_NAME
    path.write_bytes(b"data")
    path.chmod(mode)
    with pytest.raises(observer.ManagedIncludeObservationError) as exc:
        observe(tmp_path)
    # Unprivileged runners cannot open 000-mode files, while root reaches
    # metadata validation. Both are the intended fail-closed outcomes.
    allowed = ({"INCLUDE_OPEN_UNSAFE_OR_UNAVAILABLE", "INCLUDE_METADATA_UNSAFE"}
               if mode == 0 else {"INCLUDE_METADATA_UNSAFE"})
    assert str(exc.value) in allowed


def test_group_writable_parent_refused(tmp_path):
    path = tmp_path / observer.MANAGED_INCLUDE_NAME
    path.write_bytes(b"data")
    tmp_path.chmod(0o770)
    try:
        with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_PARENT_UNSAFE"):
            observe(tmp_path)
    finally:
        tmp_path.chmod(0o700)


def test_parent_fd_must_be_open_directory(tmp_path):
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_PARENT_INVALID"):
        observer.observe_managed_include_at(True)
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_PARENT_INVALID"):
        observer.observe_managed_include_at(-1)
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_PARENT_UNAVAILABLE"):
        observer.observe_managed_include_at(2**30)
    path = tmp_path / "regular"
    path.write_bytes(b"data")
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_PARENT_UNSAFE"):
            observer.observe_managed_include_at(fd)
    finally:
        os.close(fd)


def test_exact_size_allowed_and_oversized_refused(tmp_path):
    path = tmp_path / observer.MANAGED_INCLUDE_NAME
    path.write_bytes(b"x" * observer.MAX_INCLUDE_BYTES)
    assert observe(tmp_path)["observation"]["sha256"] == hashlib.sha256(b"x" * observer.MAX_INCLUDE_BYTES).hexdigest()
    path.write_bytes(b"x" * (observer.MAX_INCLUDE_BYTES + 1))
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_TOO_LARGE"):
        observe(tmp_path)


def test_empty_file_refused(tmp_path):
    (tmp_path / observer.MANAGED_INCLUDE_NAME).touch()
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_METADATA_UNSAFE"):
        observe(tmp_path)


def test_in_place_mutation_detected(tmp_path, monkeypatch):
    path = tmp_path / observer.MANAGED_INCLUDE_NAME
    path.write_bytes(b"unchanged data")
    original = observer.os.read
    def mutate_read(fd, count):
        chunk = original(fd, count)
        if chunk:
            path.write_bytes(b"changed bytes!")
        return chunk
    monkeypatch.setattr(observer.os, "read", mutate_read)
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_CHANGED_DURING_READ"):
        observe(tmp_path)


def test_name_replacement_detected(tmp_path, monkeypatch):
    path = tmp_path / observer.MANAGED_INCLUDE_NAME
    path.write_bytes(b"first file")
    path.chmod(0o640)
    original = observer.os.read
    changed = False
    def replace_read(fd, count):
        nonlocal changed
        chunk = original(fd, count)
        if chunk and not changed:
            changed = True
            path.unlink()
            path.write_bytes(b"second file")
            path.chmod(0o640)
        return chunk
    monkeypatch.setattr(observer.os, "read", replace_read)
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_CHANGED_DURING_READ"):
        observe(tmp_path)


def test_parent_permission_change_detected(tmp_path, monkeypatch):
    (tmp_path / observer.MANAGED_INCLUDE_NAME).write_bytes(b"constant")
    original = observer.os.read
    def relax_read(fd, count):
        chunk = original(fd, count)
        if chunk:
            tmp_path.chmod(0o770)
        return chunk
    monkeypatch.setattr(observer.os, "read", relax_read)
    try:
        with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_PARENT_UNSAFE"):
            observe(tmp_path)
    finally:
        tmp_path.chmod(0o700)


def test_no_external_subprocess_or_network(tmp_path, monkeypatch):
    import socket
    import subprocess
    path = tmp_path / observer.MANAGED_INCLUDE_NAME
    path.write_bytes(b"demo")
    def deny(*args, **kwargs):
        raise AssertionError("Forbidden process/network operation")
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(subprocess, "run", deny)
    assert observe(tmp_path)["observation"]["sha256"] == hashlib.sha256(b"demo").hexdigest()


def test_never_reads_arbitrary_name_even_with_open_parent_fd(tmp_path):
    target = tmp_path / "root-private.key"
    target.write_bytes(b"private-synthetic-data")
    observed = observe(tmp_path)
    assert observed["file_present"] is False
    assert target.read_bytes() == b"private-synthetic-data"
    assert observed["authorizes_write"] is False


def test_dangling_symlink_is_not_absence(tmp_path):
    (tmp_path / observer.MANAGED_INCLUDE_NAME).symlink_to("missing")
    with pytest.raises(observer.ManagedIncludeObservationError, match="INCLUDE_OPEN_UNSAFE"):
        observe(tmp_path)
