"""Bounded Linux fixed-path lock + manifest reconciliation tests (#31)."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path

import pytest

from repocache.server_locked_manifest_reconcile_v1 import (
    LockedManifestInspectionError,
    _inspect_locked_under_root,
    _match_manifest,
)
from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME, JOURNAL_TMP_NAME, LOCK_NAME, STAGE_NAME,
    ProtectedStateStoreError, _commit_under_root, _locked,
)


@pytest.fixture
def layout(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir(mode=0o700)
    current = root
    for name in ("var", "lib", "repocache", "server"):
        current = current / name
        current.mkdir(mode=0o700)
    state_dir = current
    (state_dir / LOCK_NAME).write_bytes(b"")
    (state_dir / LOCK_NAME).chmod(0o600)

    include_dir = root
    for name in ("etc", "nginx", "conf.d"):
        include_dir = include_dir / name
        include_dir.mkdir(mode=0o700)
    rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield rootfd, state_dir, include_dir, os.geteuid()
    finally:
        os.close(rootfd)


def inspect(layout, generation=0):
    fd, _, _, owner = layout
    return _inspect_locked_under_root(
        fd, owner_uid=owner, expected_generation=generation
    )


def state(generation=1):
    return {
        "state_schema_version": 1,
        "state_generation": generation,
        "configuration_sha256": "a" * 64,
        "repositories": [],
        "ownership_manifest": [],
    }


def persist(layout, value, expected=0):
    fd, _, _, owner = layout
    return _commit_under_root(
        fd, value, expected_generation=expected, owner_uid=owner
    )


def include(layout, data=b"# managed test\n"):
    name = layout[2] / "repocache-managed.conf"
    name.write_bytes(data)
    name.chmod(0o640)
    return name


def test_empty_layout_inert_and_no_disk_effect(layout):
    _, state_dir, include_dir, _ = layout
    before = sorted(p.name for p in state_dir.iterdir())
    report = inspect(layout)
    assert report["status"] == "LOCKED_READ_ONLY_RECONCILIATION"
    assert report["include_status"] == "NO_MANAGED_INCLUDE"
    assert report["state_generation"] == 0
    assert report["exclusive_state_lock_held_during_inspection"] is True
    assert report["authorizes_write"] is False
    assert report["authorizes_nginx_reload"] is False
    assert report["authorizes_catalog_publication"] is False
    assert report["operator_authorization_verified"] is False
    assert report["protected_manifest_provenance_verified"] is False
    assert report["nginx_syntax_verified"] is False
    assert sorted(p.name for p in state_dir.iterdir()) == before
    assert list(include_dir.iterdir()) == []
    assert inspect(layout) == report


def test_existing_inert_protected_state_uses_actual_generation(layout):
    persist(layout, state())
    _, state_dir, _, _ = layout
    before = (state_dir / "state-v1.json").read_bytes()
    result = inspect(layout, 1)
    assert result["state_generation"] == 1
    assert result["manifest_entry_present"] is False
    assert (state_dir / "state-v1.json").read_bytes() == before
    with pytest.raises(LockedManifestInspectionError, match="GENERATION_STALE"):
        inspect(layout, 0)


@pytest.mark.parametrize("invalid", [-1, True, 2**63, None, "0"])
def test_generation_invalid_without_effects(layout, invalid):
    _, folder, _, _ = layout
    with pytest.raises(LockedManifestInspectionError, match="ARGUMENT_INVALID"):
        inspect(layout, invalid)
    assert sorted(p.name for p in folder.iterdir()) == [LOCK_NAME]


def test_existing_file_without_manifest_refused_even_if_safe(layout):
    path = include(layout)
    previous = path.read_bytes()
    with pytest.raises(LockedManifestInspectionError, match="FOREIGN"):
        inspect(layout)
    assert path.read_bytes() == previous


def test_existing_state_does_not_adopt_foreign_include(layout):
    persist(layout, state())
    path = include(layout)
    with pytest.raises(LockedManifestInspectionError, match="FOREIGN"):
        inspect(layout, 1)
    assert path.is_file()


@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink", "fifo"])
def test_unsafe_managed_include_refused_and_not_modified(layout, kind, tmp_path):
    path = layout[2] / "repocache-managed.conf"
    if kind in ("symlink", "dangling"):
        path.symlink_to(
            tmp_path / "external" if kind == "dangling" else "/etc/hosts"
        )
    elif kind == "hardlink":
        source = tmp_path / "outside"
        source.write_bytes(b"foreign")
        os.link(source, path)
    else:
        os.mkfifo(path, mode=0o600)
    with pytest.raises(ValueError):
        inspect(layout)
    assert path.is_symlink() if kind in ("symlink", "dangling") else path.exists()


def test_generation_and_lock_stay_together(layout):
    fd, _, _, owner = layout
    with _locked(fd, owner):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            inspect(layout)


def test_pending_transaction_requires_explicit_recovery(layout):
    fd, state_dir, _, owner = layout

    def crash(phase):
        if phase == "journal_durable":
            raise RuntimeError("interrupted")

    with pytest.raises(RuntimeError):
        _commit_under_root(
            fd, state(), expected_generation=0,
            owner_uid=owner, inject_fault=crash
        )
    before = (state_dir / JOURNAL_NAME).read_bytes()
    with pytest.raises(LockedManifestInspectionError, match="RECOVERY_REQUIRED"):
        inspect(layout, 0)
    assert (state_dir / JOURNAL_NAME).read_bytes() == before
    assert not (state_dir / "state-v1.json").exists()


def test_orphan_pending_temp_refused_without_cleanup(layout):
    _, state_dir, _, _ = layout
    temp = state_dir / JOURNAL_TMP_NAME
    temp.write_bytes(b"partial journal")
    temp.chmod(0o600)
    with pytest.raises(LockedManifestInspectionError, match="RECOVERY_REQUIRED"):
        inspect(layout)
    assert temp.read_bytes() == b"partial journal"


def test_orphan_stage_refused_without_cleanup(layout):
    _, state_dir, _, _ = layout
    temp = state_dir / STAGE_NAME
    temp.write_bytes(b"unfinished")
    temp.chmod(0o600)
    with pytest.raises(LockedManifestInspectionError, match="RECOVERY_REQUIRED"):
        inspect(layout)
    assert temp.read_bytes() == b"unfinished"


def test_unsafe_state_directory_refused(layout):
    _, state_dir, _, _ = layout
    state_dir.chmod(0o777)
    with pytest.raises(ValueError):
        inspect(layout)


def test_untrusted_root_fd_or_uid_refused(layout):
    fd, _, _, owner = layout
    with pytest.raises(LockedManifestInspectionError):
        _inspect_locked_under_root(
            fd, owner_uid=owner, expected_generation=False
        )
    with pytest.raises(ValueError):
        _inspect_locked_under_root(
            fd, owner_uid=owner + 1, expected_generation=0
        )


def manifest_record(uid=0):
    return {
        "schema_version": 1, "generation": 1,
        "path": "/etc/nginx/conf.d/repocache-managed.conf",
        "sha256": hashlib.sha256(b"# managed test\n").hexdigest(),
        "uid": uid, "gid": 0, "mode": 0o640, "dev": 12, "ino": 34,
    }


def observed(uid=0):
    m = manifest_record(uid)
    return {
        "kind": "regular", "sha256": m["sha256"],
        "uid": m["uid"], "gid": m["gid"], "mode": m["mode"],
        "dev": m["dev"], "ino": m["ino"], "nlink": 1,
    }


def test_pure_metadata_match_does_not_infer_authorization():
    assert _match_manifest(
        [manifest_record()], observed(), expected_owner_uid=0
    ) == "MANIFEST_MATCHES_OBSERVED_INCLUDE"


@pytest.mark.parametrize("field", ["sha256", "uid", "gid", "mode", "dev", "ino"])
def test_every_owned_inode_field_must_match(field):
    obs = observed()
    obs[field] = ("f" * 64) if field == "sha256" else obs[field] + 1
    with pytest.raises(LockedManifestInspectionError):
        _match_manifest([manifest_record()], obs, expected_owner_uid=0)


def test_manifest_missing_and_foreign_paths_fail_closed():
    with pytest.raises(LockedManifestInspectionError, match="MISSING"):
        _match_manifest([manifest_record()], None, expected_owner_uid=0)
    with pytest.raises(LockedManifestInspectionError, match="FOREIGN"):
        _match_manifest([], observed(), expected_owner_uid=0)


def test_observed_hardlink_or_special_kind_refused():
    obs = observed()
    obs["nlink"] = 2
    with pytest.raises(LockedManifestInspectionError, match="UNSAFE"):
        _match_manifest([manifest_record()], obs, expected_owner_uid=0)
    obs = observed()
    obs["kind"] = "symlink"
    with pytest.raises(LockedManifestInspectionError, match="UNSAFE"):
        _match_manifest([manifest_record()], obs, expected_owner_uid=0)


def test_no_network_service_or_subprocess_side_effects(layout, monkeypatch):
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected external operation")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert inspect(layout)["authorizes_write"] is False


def test_errors_never_echo_sensitive_bytes(layout):
    payload = b"private-token-will-not-be-shown"
    include(layout, payload)
    with pytest.raises(ValueError) as err:
        inspect(layout)
    assert payload.decode() not in str(err.value)
    assert str(layout[2]) not in str(err.value)


def test_current_namespace_root_entry_rejects_unprivileged_without_open(
    monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 1001)

    def unexpected(*args, **kwargs):
        raise AssertionError("must not open any host path")
    monkeypatch.setattr(module.os, "open", unexpected)
    with pytest.raises(
        LockedManifestInspectionError, match="ROOT_PRIVILEGE_REQUIRED"
    ):
        module.inspect_current_namespace_locked_manifest(expected_generation=0)


@pytest.mark.parametrize("bad", [True, -1, None, "1", 2**63])
def test_current_namespace_root_entry_validates_generation_before_open(
    monkeypatch, bad,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    with pytest.raises(
        LockedManifestInspectionError, match="ARGUMENT_INVALID"
    ):
        module.inspect_current_namespace_locked_manifest(expected_generation=bad)


def test_current_namespace_root_entry_pins_real_root_before_and_after(
    monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    visited = []

    def observe(fd, *, owner_uid, expected_generation):
        assert owner_uid == 0
        assert expected_generation == 6
        assert os.fstat(fd).st_ino == os.stat("/").st_ino
        visited.append(os.fstat(fd).st_ino)
        return {
            "authorizes_write": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }
    monkeypatch.setattr(module, "_inspect_locked_under_root", observe)
    report = module.inspect_current_namespace_locked_manifest(
        expected_generation=6
    )
    assert report["current_namespace_root_path_verified"] is True
    assert report["authorizes_write"] is False
    assert report["authorizes_nginx_reload"] is False
    assert report["authorizes_catalog_publication"] is False
    assert len(visited) == 1


def test_current_namespace_root_entry_rejects_caller_root_substitution(
    layout, monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    fd, _, _, _ = layout
    real_open = os.open
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)

    def substitute(path, flags, *args, **kwargs):
        if path == "/":
            return os.dup(fd)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", substitute)
    with pytest.raises(
        LockedManifestInspectionError,
        match="ROOT_(CHANGED|UNVERIFIED)",
    ):
        module.inspect_current_namespace_locked_manifest(
            expected_generation=0
        )


def test_current_namespace_root_fd_is_not_a_fixture_authorization(layout):
    import repocache.server_locked_manifest_reconcile_v1 as module
    fd, _, _, _ = layout
    with pytest.raises(LockedManifestInspectionError):
        module._verify_current_root_fd(fd)
