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
    (candidates / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    # The kernel cgroup.kill controller is write-only, unlike cgroup.procs.
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
    "descendant-populated",
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
    elif case == "descendant-populated":
        (candidates / "cgroup.events").write_text("populated 1\n")
    with pytest.raises(candidate_cgroup.CgroupGateError):
        _gate(delegated)


def test_hierarchy_rejects_root_uid(delegated, monkeypatch):
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: 0)
    with pytest.raises(candidate_cgroup.CgroupGateError, match="root"):
        _gate(delegated)


def test_limit_controller_contract_and_readback(delegated, monkeypatch):
    _, _, _, candidates, _, _ = delegated
    leaf = candidates / ("candidate-" + "a" * 32)
    leaf.mkdir(mode=0o700)
    (leaf / "cgroup.procs").write_text("")
    for name, initial in candidate_cgroup.LEAF_LIMITS.items():
        (leaf / name).write_text(initial)
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: os.stat(leaf).st_uid)
    candidate_cgroup.write_leaf_limits(_gate(delegated), leaf)
    for key, value in candidate_cgroup.LEAF_LIMITS.items():
        assert (leaf / key).read_text() == value


@pytest.mark.parametrize("case", ["populated", "missing", "symlink", "readback"])
def test_limit_configuration_must_never_silently_continue(delegated, monkeypatch, case):
    _, _, _, candidates, _, _ = delegated
    leaf = candidates / ("candidate-" + "b" * 32)
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
        candidate_cgroup.write_leaf_limits(_gate(delegated), leaf)


def test_no_interpreter_or_shell_is_launched_by_cgroup_preflight(
        delegated, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("preflight must not launch a process")
    monkeypatch.setattr(candidate_cgroup.os, "system", forbidden)
    _gate(delegated)


def test_write_only_cgroup_kill_gate_is_not_read(delegated, monkeypatch):
    _, _, _, candidates, _, _ = delegated
    kill = candidates / "cgroup.kill"
    kill.chmod(0o200)
    original = candidate_cgroup._read

    def forbid_kill_reads(path):
        if path == kill:
            raise AssertionError("cgroup.kill must never be read or probed")
        return original(path)

    monkeypatch.setattr(candidate_cgroup, "_read", forbid_kill_reads)
    assert _gate(delegated).candidates == candidates
    assert kill.stat().st_size == 0


def test_limit_write_refuses_unrelated_directory(delegated, tmp_path):
    other = tmp_path / ("candidate-" + "c" * 32)
    other.mkdir()
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="outside verified delegation"):
        candidate_cgroup.write_leaf_limits(_gate(delegated), other)


def test_limit_write_refuses_untrusted_leaf_name(delegated):
    _, _, _, candidates, _, _ = delegated
    wrong = candidates / "candidate-../escape"
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="outside verified delegation"):
        candidate_cgroup.write_leaf_limits(_gate(delegated), wrong)



def _configured_leaf(delegated, suffix="d"):
    _, _, _, candidates, _, _ = delegated
    leaf = candidates / ("candidate-" + suffix * 32)
    leaf.mkdir(mode=0o700)
    (leaf / "cgroup.procs").write_text("")
    for name, value in candidate_cgroup.LEAF_LIMITS.items():
        (leaf / name).write_text(value)
    return leaf


def _trusted_command(marker):
    # Testing only: a harmless system Python payload, not a third-party wheel.
    code = "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('ran')"
    return ["/usr/bin/prlimit", "--", "/usr/bin/python3",
            "-I", "-S", "-c", code, str(marker)]


def test_pre_exec_wrapper_places_child_before_executing_payload(
        delegated, tmp_path):
    import subprocess
    leaf = _configured_leaf(delegated)
    marker = tmp_path / "payload-executed"
    argv = candidate_cgroup.entry_argv(
        _gate(delegated), leaf, _trusted_command(marker))
    assert argv[:4] == ["/usr/bin/python3", "-I", "-S", "-c"]
    assert argv[5] == str(leaf / "cgroup.procs")
    result = subprocess.run(argv, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr[-400:]
    assert (leaf / "cgroup.procs").read_text() == "0"
    assert marker.read_text() == "ran"


@pytest.mark.parametrize("case", [
    "missing", "symlink", "directory", "unconfigured", "populated",
    "wrong-argv", "wrong-path",
])
def test_pre_exec_refuses_before_payload_if_membership_is_untrusted(
        delegated, tmp_path, case):
    import subprocess
    leaf = _configured_leaf(delegated, "e")
    marker = tmp_path / "must-not-execute"
    cmd = _trusted_command(marker)
    if case == "unconfigured":
        (leaf / "memory.max").write_text("max")
    elif case == "populated":
        (leaf / "cgroup.procs").write_text("12345")
    elif case == "wrong-argv":
        cmd[0] = "/bin/sh"
    elif case == "wrong-path":
        leaf = tmp_path / ("candidate-" + "f" * 32)
        leaf.mkdir()
    if case in ("unconfigured", "populated", "wrong-argv", "wrong-path"):
        with pytest.raises(candidate_cgroup.CgroupGateError):
            candidate_cgroup.entry_argv(_gate(delegated), leaf, cmd)
    else:
        argv = candidate_cgroup.entry_argv(_gate(delegated), leaf, cmd)
        procs = leaf / "cgroup.procs"
        procs.unlink()
        if case == "symlink":
            procs.symlink_to(tmp_path / "outside")
        elif case == "directory":
            procs.mkdir()
        result = subprocess.run(argv, text=True, capture_output=True, timeout=10)
        assert result.returncode != 0
    assert not marker.exists()


def test_entry_requires_pinned_resource_limits(delegated):
    leaf = _configured_leaf(delegated)
    (leaf / "cpu.max").unlink()
    with pytest.raises(candidate_cgroup.CgroupGateError):
        candidate_cgroup.entry_argv(
            _gate(delegated), leaf, ["/usr/bin/prlimit", "--", "/bin/true"])
