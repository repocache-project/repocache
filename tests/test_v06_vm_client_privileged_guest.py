"""Booted privileged fixture must refuse before IO when the VM guard fails."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci_v06_vm_client_privileged_guest as guest


@pytest.mark.parametrize("platform", ["debian13", "almalinux10", "unknown"])
def test_guest_refuses_before_inspecting_sources_when_native_guard_fails(monkeypatch, platform):
    def denied(_):
        raise AssertionError("guard")
    monkeypatch.setattr(guest, "guarded_native_guest", denied)
    monkeypatch.setattr(guest, "installed_sources", lambda *_:
                        pytest.fail("source inventory reached before guard"))
    with pytest.raises(AssertionError, match="guard"):
        guest.main(platform)


@pytest.mark.parametrize("path", ["/etc/yum.repos.d", "/var/tmp",
                                 "/var/tmp/unrelated", "/tmp/repocache-booted-label-abc"])
def test_fixture_context_refuses_nonfixture_path_before_policy_command(monkeypatch, path):
    monkeypatch.setattr(guest, "guarded_native_guest", lambda *_: None)
    monkeypatch.setattr(guest.os, "getresuid", lambda: (0, 0, 0))
    monkeypatch.setattr(guest.subprocess, "run", lambda *_a, **_kw:
                        pytest.fail("policy command reached outside fixture"))
    with pytest.raises(AssertionError):
        with guest._alma_fixture_file_context(Path(path)):
            pytest.fail("nonfixture accepted")


def test_fixture_context_removes_exact_rule_on_failure(monkeypatch, tmp_path):
    from types import SimpleNamespace
    root = Path("/var/tmp/repocache-booted-label-abc")
    monkeypatch.setattr(guest, "guarded_native_guest", lambda *_: None)
    monkeypatch.setattr(guest.os, "getresuid", lambda: (0, 0, 0))
    monkeypatch.setattr(Path, "resolve", lambda self, **_kw: self)
    monkeypatch.setattr(Path, "stat", lambda self: SimpleNamespace(st_uid=0, st_mode=0o40700))
    entries = []
    calls = []
    def command(argv, **kwargs):
        assert argv[:2] == ["/usr/sbin/semanage", "fcontext"]
        args = argv[2:]
        calls.append(args)
        if args[0] == "-a":
            assert args[1:3] == ["-t", "tmp_t"]
            entries.append(args[-1])
        elif args[0] == "-d":
            entries.remove(args[-1])
        else:
            assert args == ["-l", "-C"]
        return SimpleNamespace(stdout="\\n".join(entries))
    monkeypatch.setattr(guest.subprocess, "run", command)
    with pytest.raises(RuntimeError, match="test interruption"):
        with guest._alma_fixture_file_context(root):
            assert len(entries) == 1
            raise RuntimeError("test interruption")
    assert entries == []
    assert calls[1][-1] == calls[-2][-1]


@pytest.mark.parametrize("path", ["/etc", "/tmp", "/tmp/unrelated", "/var/tmp/repocache-booted-approval-test"])
def test_apt_read_order_rejects_nonfixture_before_native_command(monkeypatch, path):
    monkeypatch.setattr(Path, "resolve", lambda self, **_kw: self)
    monkeypatch.setattr(guest.subprocess, "run", lambda *_a, **_kw:
                        pytest.fail("APT invoked outside fixture"))
    with pytest.raises(AssertionError):
        guest._apt_source_read_order(Path(path))
