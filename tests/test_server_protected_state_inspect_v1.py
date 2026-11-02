"""Fixed-path, bounded, read-only protected-state observation regression (#31)."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from repocache import server_protected_state_inspect_v1 as subject
from repocache.server_managed_include_fd_v1 import MANAGED_INCLUDE_NAME


@pytest.fixture
def layout(tmp_path):
    state_root = tmp_path / "var/lib/repocache/server"
    nginx_root = tmp_path / "etc/nginx/conf.d"
    state_root.mkdir(parents=True)
    nginx_root.mkdir(parents=True)
    # Real CI uses an unprivileged user; roots of temporary trees must be
    # owned by the invoking user. Production's public entry requires UID 0.
    for path in (tmp_path, *state_root.parents, state_root, *nginx_root.parents, nginx_root):
        if path == tmp_path or tmp_path in path.parents:
            path.chmod(0o700)
    return tmp_path, state_root, nginx_root


def inspect(root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return subject._inspect_under_root(fd, owner_uid=os.getuid())
    finally:
        os.close(fd)


def make_state(directory, data=b'{"state_schema_version":1,"generation":1}'):
    path = directory / subject.STATE_FILE_NAME
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def make_include(directory, data=b"# inert NGINX candidate\n"):
    path = directory / MANAGED_INCLUDE_NAME
    path.write_bytes(data)
    path.chmod(0o640)
    return path


def test_absence_does_not_establish_any_authority(layout):
    root, state, nginx = layout
    result = inspect(root)
    assert result == {
        "schema_version": 1, "status": "READ_ONLY_INSPECTION",
        "state_file": {"present": False, "sha256": None, "size": None},
        "include_file": {"present": False, "sha256": None},
        "verified_static_segments": True,
        "protected_state_schema_verified": False,
        "protected_manifest_provenance_verified": False,
        "mount_namespace_and_acl_verified": False,
        "transaction_lock_held": False,
        "authorizes_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }
    assert not list(state.iterdir()) and not list(nginx.iterdir())


def test_real_content_digests_and_unchanged_files(layout):
    root, state, nginx = layout
    state_bytes = b'{"opaque":"not parsed","secret":"not exposed"}'
    include_bytes = b"# read-only include\n"
    state_path = make_state(state, state_bytes)
    include_path = make_include(nginx, include_bytes)
    before_state = state_path.stat()
    before_inc = include_path.stat()
    report = inspect(root)
    assert report["state_file"] == {
        "present": True, "sha256": hashlib.sha256(state_bytes).hexdigest(),
        "size": len(state_bytes),
    }
    assert report["include_file"] == {
        "present": True, "sha256": hashlib.sha256(include_bytes).hexdigest(),
    }
    assert "secret" not in str(report)
    assert report["protected_state_schema_verified"] is False
    assert not any(report[k] for k in ("authorizes_write", "authorizes_nginx_reload",
                                        "authorizes_catalog_publication"))
    assert state_path.read_bytes() == state_bytes
    assert include_path.read_bytes() == include_bytes
    assert state_path.stat().st_ino == before_state.st_ino
    assert include_path.stat().st_ino == before_inc.st_ino


@pytest.mark.parametrize("segment", ["var", "lib", "repocache", "server", "etc", "nginx", "conf.d"])
def test_missing_component_fail_closed(layout, segment):
    root, state, nginx = layout
    if segment in subject._STATE_SEGMENTS:
        chain = root.joinpath(*subject._STATE_SEGMENTS)
        idx = subject._STATE_SEGMENTS.index(segment)
        path = root.joinpath(*subject._STATE_SEGMENTS[:idx + 1])
    else:
        idx = subject._INCLUDE_SEGMENTS.index(segment)
        path = root.joinpath(*subject._INCLUDE_SEGMENTS[:idx + 1])
    # Drop empty descendants before the chosen component.
    import shutil
    shutil.rmtree(path)
    with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_DIRECTORY_UNAVAILABLE"):
        inspect(root)


@pytest.mark.parametrize("segment", ["var", "lib", "repocache", "server", "etc", "nginx", "conf.d"])
def test_symlinked_component_refused(layout, segment):
    root, state, nginx = layout
    path_segments = (subject._STATE_SEGMENTS if segment in subject._STATE_SEGMENTS
                     else subject._INCLUDE_SEGMENTS)
    path = root.joinpath(*path_segments[:path_segments.index(segment) + 1])
    replaced = path.with_name(path.name + "-original")
    path.rename(replaced)
    path.symlink_to(replaced, target_is_directory=True)
    with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_DIRECTORY_UNAVAILABLE_OR_SYMLINK"):
        inspect(root)


@pytest.mark.parametrize("mode", [0o777, 0o770, 0o733])
def test_writable_ancestor_refused(layout, mode):
    root, _, _ = layout
    path = root / "var/lib"
    path.chmod(mode)
    with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_DIRECTORY_UNSAFE"):
        inspect(root)


def test_root_fd_validation(layout):
    root, _, _ = layout
    with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_INSPECTION_ARGUMENT_INVALID"):
        subject._inspect_under_root(True, owner_uid=os.getuid())
    with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_INSPECTION_ARGUMENT_INVALID"):
        subject._inspect_under_root(-1, owner_uid=os.getuid())
    with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_INSPECTION_ARGUMENT_INVALID"):
        subject._inspect_under_root(0, owner_uid=True)
    with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_DIRECTORY_UNAVAILABLE"):
        subject._inspect_under_root(2**30, owner_uid=os.getuid())


def test_owner_mismatch_refused(layout):
    root, _, _ = layout
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_DIRECTORY_UNSAFE"):
            subject._inspect_under_root(fd, owner_uid=100001 if os.getuid() != 100001 else 100002)
    finally:
        os.close(fd)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666, 0o000])
def test_state_file_mode_fail_closed(layout, mode):
    root, state, _ = layout
    path = make_state(state)
    path.chmod(mode)
    with pytest.raises(subject.ProtectedStateInspectionError) as exc:
        inspect(root)
    assert str(exc.value) in {"PROTECTED_STATE_METADATA_UNSAFE", "PROTECTED_STATE_OPEN_REFUSED"}


def test_state_symlink_and_dangling_symlink_refused(layout):
    root, state, _ = layout
    sensitive = state / "private-operator-key"
    sensitive.write_bytes(b"not-for-reading")
    (state / subject.STATE_FILE_NAME).symlink_to(sensitive)
    with pytest.raises(subject.ProtectedStateInspectionError, match="PROTECTED_STATE_OPEN_REFUSED"):
        inspect(root)
    assert sensitive.read_bytes() == b"not-for-reading"
    (state / subject.STATE_FILE_NAME).unlink()
    (state / subject.STATE_FILE_NAME).symlink_to("missing-target")
    with pytest.raises(subject.ProtectedStateInspectionError, match="PROTECTED_STATE_OPEN_REFUSED"):
        inspect(root)


def test_state_hardlink_refused(layout):
    root, state, _ = layout
    path = make_state(state)
    os.link(path, state / "second-hardlink")
    with pytest.raises(subject.ProtectedStateInspectionError, match="PROTECTED_STATE_METADATA_UNSAFE"):
        inspect(root)


def test_state_fifo_refused_without_blocking(layout):
    root, state, _ = layout
    os.mkfifo(state / subject.STATE_FILE_NAME)
    with pytest.raises(subject.ProtectedStateInspectionError, match="PROTECTED_STATE_METADATA_UNSAFE"):
        inspect(root)


def test_state_boundary_and_oversize(layout):
    root, state, _ = layout
    exact = b"a" * subject.MAX_STATE_BYTES
    path = make_state(state, exact)
    assert inspect(root)["state_file"]["sha256"] == hashlib.sha256(exact).hexdigest()
    path.write_bytes(exact + b"b")
    with pytest.raises(subject.ProtectedStateInspectionError, match="PROTECTED_STATE_OVERSIZE"):
        inspect(root)


def test_empty_state_refused(layout):
    root, state, _ = layout
    make_state(state, b"")
    with pytest.raises(subject.ProtectedStateInspectionError, match="PROTECTED_STATE_METADATA_UNSAFE"):
        inspect(root)


def test_changed_state_during_read_refused(layout, monkeypatch):
    root, state, _ = layout
    path = make_state(state, b"before")
    original = subject.os.read
    done = False
    def change(fd, size):
        nonlocal done
        data = original(fd, size)
        if data and not done:
            done = True
            path.write_bytes(b"after-longer")
        return data
    monkeypatch.setattr(subject.os, "read", change)
    with pytest.raises(subject.ProtectedStateInspectionError, match="PROTECTED_STATE_CHANGED"):
        inspect(root)


def test_state_name_replacement_refused(layout, monkeypatch):
    root, state, _ = layout
    path = make_state(state, b"before")
    original = subject.os.read
    done = False
    def switch(fd, size):
        nonlocal done
        data = original(fd, size)
        if data and not done:
            done = True
            path.unlink()
            make_state(state, b"before")
        return data
    monkeypatch.setattr(subject.os, "read", switch)
    with pytest.raises(subject.ProtectedStateInspectionError, match="PROTECTED_STATE_CHANGED"):
        inspect(root)


def test_include_symlink_refused(layout):
    root, _, nginx = layout
    secret = nginx / "not-an-include"
    secret.write_bytes(b"secret")
    (nginx / MANAGED_INCLUDE_NAME).symlink_to(secret)
    from repocache.server_managed_include_fd_v1 import ManagedIncludeObservationError
    with pytest.raises(ManagedIncludeObservationError, match="INCLUDE_OPEN_UNSAFE"):
        inspect(root)


def test_include_other_owner_refused_without_adoption(layout, monkeypatch):
    root, _, nginx = layout
    make_include(nginx)
    normal = subject.observe_managed_include_at
    def spoof(fd):
        result = normal(fd)
        result["observation"]["uid"] = 100001 if os.getuid() != 100001 else 100002
        return result
    monkeypatch.setattr(subject, "observe_managed_include_at", spoof)
    with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_INCLUDE_OWNER_MISMATCH"):
        inspect(root)


def test_no_subprocess_network_or_mutations(layout, monkeypatch):
    root, _, _ = layout
    import socket
    import subprocess
    def deny(*args, **kwargs):
        raise AssertionError("unexpected subprocess/network")
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(subprocess, "run", deny)
    result = inspect(root)
    assert result["authorizes_write"] is False


def test_public_entry_rejects_nondefault_layout_before_any_open(monkeypatch):
    doc = {"deployment": {"paths": {
        "state_root": "/tmp/foreign-root", "generated_include": subject._FIXED_INCLUDE}}}
    monkeypatch.setattr(subject, "validate_install_document", lambda value, *, for_apply: value)
    monkeypatch.setattr(subject.os, "open", lambda *a, **kw: pytest.fail("opened untrusted path"))
    with pytest.raises(subject.ProtectedStateInspectionError, match="MANAGED_LAYOUT_NOT_YET_SUPPORTED"):
        subject.inspect_default_server_state(doc)
