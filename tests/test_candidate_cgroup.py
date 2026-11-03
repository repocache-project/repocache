"""Fail-closed cgroup-v2 delegation contract (NOT a native host acceptance)."""
from __future__ import annotations

import os
import stat

import pytest

from repocache import candidate_cgroup


@pytest.fixture
def delegated(tmp_path, monkeypatch):
    root = tmp_path / "cgroup2"
    service = root / "system.slice/repocache-candidate.service"
    manager = service / "repocache-manager"
    candidates = service / "repocache-candidates"
    manager.mkdir(parents=True)
    candidates.mkdir()
    proc = tmp_path / "proc_cgroup"
    proc.write_text("0::/system.slice/repocache-candidate.service/repocache-manager\n")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(f"32 22 0:27 / {root} rw - cgroup2 cgroup rw\n")
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: os.stat(root).st_uid or 1000)
    for node in (service, candidates):
        (node / "cgroup.subtree_control").write_text("cpu memory pids\n")
    (candidates / "cgroup.procs").write_text("")
    for key in (*candidate_cgroup.LEAF_LIMITS, "cgroup.kill"):
        (candidates / key).write_text("")
    return root, service, manager, candidates, proc, mountinfo


def _gate(data):
    root, _, _, _, proc, mountinfo = data
    return candidate_cgroup.require_delegation(
        root=root, proc_cgroup=proc, mountinfo=mountinfo)


def test_explicit_delegated_hierarchy_can_pass_read_only_gate(delegated):
    result = _gate(delegated)
    assert result.manager.name == "repocache-manager"
    assert result.candidates.name == "repocache-candidates"


@pytest.mark.parametrize("source,contents", [
    ("proc", "2:cpu,cpuacct:/system.slice/repocache-candidate.service/repocache-manager\n"),
    ("proc", "0::/system.slice/not-repocache.service/repocache-manager\n"),
    ("proc", "0::/system.slice/repocache-candidate.service/other\n"),
    ("proc", "0::/system.slice/repocache-candidate.service/../repocache-manager\n"),
    ("proc", "0::/system.slice/repocache-candidate.service/repocache-manager\n2:cpu:/bad\n"),
    ("mount", "32 22 0:27 / /not-this-root rw - cgroup2 cgroup rw\n"),
    ("mount", "32 22 0:27 / /sys/fs/cgroup rw - cgroup cgroup rw\n"),
])
def test_noncanonical_hierarchy_refuses(delegated, source, contents):
    _, _, _, _, proc, mountinfo = delegated
    (proc if source == "proc" else mountinfo).write_text(contents)
    with pytest.raises(candidate_cgroup.CgroupGateError):
        _gate(delegated)


@pytest.mark.parametrize("case", [
    "no-cpu", "no-memory", "no-pids", "parent-populated",
    "symlink-candidates", "missing-kill", "shared-candidates",
])
def test_missing_or_unsafe_delegation_fails_closed(delegated, case):
    _, service, _, candidates, _, _ = delegated
    if case.startswith("no-"):
        missing = case[3:]
        (candidates / "cgroup.subtree_control").write_text(
            " ".join(sorted(candidate_cgroup.REQUIRED_CONTROLLERS - {missing})))
    elif case == "parent-populated":
        (candidates / "cgroup.procs").write_text("123\n")
    elif case == "symlink-candidates":
        target = candidates.parent / "original"
        candidates.rename(target)
        candidates.symlink_to(target, target_is_directory=True)
    elif case == "missing-kill":
        (candidates / "cgroup.kill").unlink()
    elif case == "shared-candidates":
        candidates.chmod(0o777)
    with pytest.raises(candidate_cgroup.CgroupGateError):
        _gate(delegated)


def test_hierarchy_rejects_root_uid(delegated, monkeypatch):
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: 0)
    with pytest.raises(candidate_cgroup.CgroupGateError, match="root"):
        _gate(delegated)


def test_limit_controller_contract_and_readback(tmp_path, monkeypatch):
    leaf = tmp_path / "leaf"
    leaf.mkdir(mode=0o700)
    (leaf / "cgroup.procs").write_text("")
    for name, initial in candidate_cgroup.LEAF_LIMITS.items():
        (leaf / name).write_text(initial)
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: os.stat(leaf).st_uid)
    candidate_cgroup.write_leaf_limits(leaf)
    for key, value in candidate_cgroup.LEAF_LIMITS.items():
        assert (leaf / key).read_text() == value


@pytest.mark.parametrize("case", ["populated", "missing", "symlink", "readback"])
def test_limit_configuration_must_never_silently_continue(tmp_path, monkeypatch, case):
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    (leaf / "cgroup.procs").write_text("42" if case == "populated" else "")
    for name in candidate_cgroup.LEAF_LIMITS:
        (leaf / name).write_text("unlimited")
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: os.stat(leaf).st_uid)
    if case == "missing":
        (leaf / "memory.max").unlink()
    elif case == "symlink":
        control = leaf / "memory.max"
        control.unlink()
        control.symlink_to(leaf / "cpu.max")
    elif case == "readback":
        monkeypatch.setattr(candidate_cgroup, "_read",
                            lambda p: "wrong" if p.name == "memory.max"
                            else p.read_text())
    with pytest.raises(candidate_cgroup.CgroupGateError):
        candidate_cgroup.write_leaf_limits(leaf)


def test_no_interpreter_or_shell_is_launched_by_cgroup_preflight(
        delegated, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("preflight must not launch a process")
    monkeypatch.setattr(candidate_cgroup.os, "system", forbidden)
    _gate(delegated)
