"""Adversarial, unprivileged fixture tests for the unwired #53 probe.

The fixture builds expected hashes locally. Production must NEVER treat an
inventory built from the suspect runtime as independently trusted authority.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

import pytest

from scripts.runtime_integrity_probe import (
    ExpectedRegularFile,
    IntegrityMismatch,
    verify_regular_tree,
)


@pytest.fixture
def prepared(tmp_path: Path):
    root = tmp_path / "generation"
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    files = {
        "bin/repocache": (b"#!/bin/sh\n# fixture: never executed\n", 0o755),
        "lib/module.py": (b"value = 'known-good'\n", 0o644),
    }
    inventory = {}
    for name, (content, mode) in files.items():
        target = root / name
        target.write_bytes(content)
        target.chmod(mode)
        inventory[name] = ExpectedRegularFile(hashlib.sha256(content).hexdigest(), mode)
    return root, inventory


def verify(root: Path, inventory, **kwargs):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return verify_regular_tree(fd, inventory, owner_uid=os.getuid(), **kwargs)
    finally:
        os.close(fd)


def test_exact_file_bytes_metadata_and_whole_tree_pass(prepared):
    root, inventory = prepared
    result = verify(root, inventory)
    assert result.files == 2
    assert result.bytes_hashed == sum((root / name).stat().st_size for name in inventory)


@pytest.mark.parametrize("tamper", [
    "same-size-edit",
    "removed-entry",
    "unlisted-python-module",
    "unexpected-empty-directory",
    "new-bytecode",
    "symlink-file",
    "symlink-directory",
    "hardlinked-file",
    "world-writable-file",
    "world-writable-directory",
    "unexpected-fifo",
    "changed-executable-mode",
])
def test_runtime_tampering_is_refused(prepared, tmp_path, tamper):
    root, inventory = prepared
    executable = root / "bin/repocache"
    module = root / "lib/module.py"
    outside = tmp_path / "outside"
    outside.write_text("sentinel", encoding="utf-8")
    if tamper == "same-size-edit":
        data = module.read_bytes()
        module.write_bytes(b"X" + data[1:])
    elif tamper == "removed-entry":
        executable.unlink()
    elif tamper == "unlisted-python-module":
        (root / "lib/injected.py").write_bytes(b"pass\n")
    elif tamper == "unexpected-empty-directory":
        (root / "lib/other").mkdir()
    elif tamper == "new-bytecode":
        (root / "lib/__pycache__").mkdir()
        (root / "lib/__pycache__/module.pyc").write_bytes(b"untrusted")
    elif tamper == "symlink-file":
        module.unlink()
        module.symlink_to(outside)
    elif tamper == "symlink-directory":
        (root / "lib/module.py").unlink()
        (root / "lib").rmdir()
        (root / "lib").symlink_to(tmp_path)
    elif tamper == "hardlinked-file":
        os.link(module, root / "lib/alias.py")
    elif tamper == "world-writable-file":
        module.chmod(0o666)
    elif tamper == "world-writable-directory":
        (root / "lib").chmod(0o777)
    elif tamper == "unexpected-fifo":
        os.mkfifo(root / "lib/incoming")
    else:
        executable.chmod(0o644)
    with pytest.raises(IntegrityMismatch):
        verify(root, inventory)
    assert outside.read_text(encoding="utf-8") == "sentinel"


@pytest.mark.parametrize("path", [
    "/absolute", "../escape", "a/../b", "a/./b", "a//b", "a/",
    "a/\x00b", "a" * 1025, "lib/bad\udcff.py", "lib/bad\ud800.py",
])
def test_invalid_inventory_path_is_refused(prepared, path):
    root, inventory = prepared
    bad = {path: next(iter(inventory.values()))}
    with pytest.raises(IntegrityMismatch):
        verify(root, bad)


def test_corrupted_trusted_expected_digest_is_refused(prepared):
    root, inventory = prepared
    inventory["lib/module.py"] = ExpectedRegularFile("f" * 64, 0o644)
    with pytest.raises(IntegrityMismatch, match="bytes changed"):
        verify(root, inventory)


def test_invalid_expected_mode_is_refused(prepared):
    root, inventory = prepared
    inventory["lib/module.py"] = ExpectedRegularFile("a" * 64, 0o666)
    with pytest.raises(IntegrityMismatch, match="Invalid expected inventory"):
        verify(root, inventory)


def test_expected_file_directory_collision_is_refused(prepared):
    root, inventory = prepared
    inventory["lib"] = ExpectedRegularFile("a" * 64, 0o644)
    with pytest.raises(IntegrityMismatch, match="collision"):
        verify(root, inventory)


@pytest.mark.parametrize("limits", [
    {"max_entries": 1},
    {"max_file_bytes": 1},
    {"max_total_bytes": 1},
    {"max_entries": 0},
])
def test_explicit_resource_bounds_fail_closed(prepared, limits):
    root, inventory = prepared
    with pytest.raises(IntegrityMismatch):
        verify(root, inventory, **limits)


def test_untrusted_runtime_is_never_executed(prepared, monkeypatch):
    root, inventory = prepared
    # The payload is a shell script that would not be valid trusted Python.
    # A successful measurement demonstrates bytes were read, not launched.
    def refuse_execution(*_args, **_kwargs):
        pytest.fail("Runtime execution or subprocess invocation is forbidden")

    monkeypatch.setattr(os, "system", refuse_execution)
    assert verify(root, inventory).files == 2


def test_changed_file_during_measurement_is_refused(prepared, monkeypatch):
    root, inventory = prepared
    real_read = os.read
    changed = False

    def mutate_while_reading(fd, count):
        nonlocal changed
        chunk = real_read(fd, count)
        if not changed and chunk:
            changed = True
            # Mutating the second file after it is opened changes its inode
            # metadata. No module import or candidate execution is needed.
            (root / "lib/module.py").write_bytes(b"changed during read\n")
        return chunk

    monkeypatch.setattr(os, "read", mutate_while_reading)
    with pytest.raises(IntegrityMismatch):
        verify(root, inventory)
    assert changed


@pytest.mark.parametrize("target_kind", ["file", "directory"])
def test_nofollow_open_refuses_concurrent_symlink_replacement(
        prepared, tmp_path, monkeypatch, target_kind):
    """Exercise the metadata-to-open race without following attacker links.

    This tests a *detected* mutation, not a race-free launch boundary.
    """
    root, inventory = prepared
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "module.py").write_bytes(b"untrusted-but-never-read")
    if target_kind == "file":
        victim = root / "lib/module.py"
        displaced = root / "lib/displaced.py"
        opened_name = "module.py"
    else:
        victim = root / "lib"
        displaced = root / "displaced-lib"
        opened_name = "lib"

    original_open = os.open
    replaced = False

    def replace_at_open(path, flags, *args, **kwargs):
        nonlocal replaced
        if path == opened_name and kwargs.get("dir_fd") is not None and not replaced:
            replaced = True
            victim.rename(displaced)
            victim.symlink_to(outside, target_is_directory=target_kind == "directory")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_at_open)
    with pytest.raises(IntegrityMismatch):
        verify(root, inventory)
    assert replaced
    assert (outside / "module.py").read_bytes() == b"untrusted-but-never-read"


@pytest.mark.parametrize("change_runtime", [False, True])
def test_authenticated_inventory_expectations_are_pinned_during_scan(
        prepared, monkeypatch, change_runtime):
    """Caller mutation cannot retarget an in-progress expected-hash lookup.

    This checks snapshot consistency, NOT expected-inventory authentication.
    """
    root, inventory = prepared
    module = root / "lib/module.py"
    mutated = b"value = 'untrusted replacement'\n"
    original_read = os.read
    changed = False

    def mutate_after_first_chunk(fd, count):
        nonlocal changed
        chunk = original_read(fd, count)
        if chunk and not changed:
            changed = True
            if change_runtime:
                module.write_bytes(mutated)
            inventory["lib/module.py"] = ExpectedRegularFile(
                hashlib.sha256(mutated).hexdigest(), 0o644)
        return chunk

    monkeypatch.setattr(os, "read", mutate_after_first_chunk)
    if change_runtime:
        with pytest.raises(IntegrityMismatch):
            verify(root, inventory)
    else:
        assert verify(root, inventory).files == 2
    assert changed
    assert inventory["lib/module.py"].sha256 == hashlib.sha256(mutated).hexdigest()
