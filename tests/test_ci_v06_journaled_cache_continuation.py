"""CI-only chained NGINX install/cache smoke refusal and privilege tests."""
from __future__ import annotations

import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ci_v06_journaled_cache_continuation as stage


def valid_report():
    return {
        "schema_version": 1,
        "status": "DISPOSABLE_JOURNALED_NATIVE_INSTALL_PASS",
        "distribution": "debian",
        "actual_distro_package_transaction": True,
        "real_nginx_syntax_test_passed": True,
        "real_state_bootstrap_durable": True,
        "real_exclusive_lock_held_during_subprocesses": True,
        "pending_journal_survived_package_effects": True,
        "repeated_install_refused_without_reconciliation": True,
        "installed_server_ready": False,
        "host_root_provenance_verified": False,
        "systemd_pid1_verified": False,
        "selinux_enforcing_verified": False,
        "authorizes_host_installation": False,
    }


class FakePath:
    def __init__(self, name):
        self.name = name

    def is_file(self):
        return self.name == "/.dockerenv"

    def read_text(self, *, encoding):
        assert encoding == "ascii"
        return {
            "/proc/1/comm": "sh\n",
            "/etc/os-release": "ID=debian\nVERSION_ID=13\n",
        }[self.name]


def _mock_preconditions(monkeypatch, report=None, *, mode=0o644):
    raw = json.dumps(valid_report() if report is None else report).encode()
    events = []
    native_file = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
    parsed_file = SimpleNamespace(
        st_mode=stat.S_IFREG | mode, st_uid=0, st_nlink=1,
        st_size=len(raw),
    )
    fake_os = SimpleNamespace(
        environ={"REPOCACHE_NATIVE_TEST_CONTAINER": stage._MARKER},
        geteuid=lambda: 0,
        O_RDONLY=0, O_NOFOLLOW=0x20000, O_CLOEXEC=0x80000,
        open=lambda path, flags: events.append(("open", path, flags)) or 55,
        fstat=lambda fd: parsed_file,
        read=lambda fd, size: raw,
        close=lambda fd: events.append(("close", fd)),
        lstat=lambda path: native_file,
    )
    monkeypatch.setattr(stage, "Path", FakePath)
    monkeypatch.setattr(stage, "validate_os_identity",
                        lambda raw_os, py: "debian")
    monkeypatch.setattr(stage, "os", fake_os)
    return events


def test_no_disposable_marker_refuses_before_any_host_mutation(monkeypatch):
    monkeypatch.setattr(stage, "os", SimpleNamespace(
        environ={}, geteuid=lambda: 0,
    ))
    with pytest.raises(stage.ContainerContinuationError,
                       match="DOCKER_ROOT_REQUIRED"):
        stage._require_disposable_native_install()


def test_prior_real_native_stage_requires_valid_root_owned_record(monkeypatch):
    events = _mock_preconditions(monkeypatch)
    stage._require_disposable_native_install()
    assert events == [
        ("open", stage._REPORT, 0x20000 | 0x80000),
        ("close", 55),
    ]


@pytest.mark.parametrize("changed", [
    {"status": "FAIL"},
    {"distribution": "almalinux"},
    {"actual_distro_package_transaction": False},
    {"real_nginx_syntax_test_passed": False},
    {"real_exclusive_lock_held_during_subprocesses": False},
    {"pending_journal_survived_package_effects": False},
    {"repeated_install_refused_without_reconciliation": False},
    {"authorizes_host_installation": True},
    {"installed_server_ready": True},
    {"host_root_provenance_verified": True},
])
def test_unproven_native_install_never_starts_smoke(monkeypatch, changed):
    report = valid_report()
    report.update(changed)
    _mock_preconditions(monkeypatch, report)
    with pytest.raises(stage.ContainerContinuationError,
                       match="PRIOR_INSTALL_NOT_PROVEN"):
        stage._require_disposable_native_install()


def test_world_writable_report_refused(monkeypatch):
    _mock_preconditions(monkeypatch, mode=0o666)
    with pytest.raises(stage.ContainerContinuationError,
                       match="PRIOR_REPORT_UNTRUSTED"):
        stage._require_disposable_native_install()


class Executed(Exception):
    pass


def test_rootless_handoff_happens_before_fixed_cache_smoke_exec(monkeypatch):
    events = []
    def fake_exec(path, args, env):
        events.append(("execve", path, args, dict(env)))
        raise Executed()
    ids = {"uid": 0}
    monkeypatch.setattr(stage, "_require_disposable_native_install",
                        lambda: events.append(("validated",)))
    monkeypatch.setattr(stage, "os", SimpleNamespace(
        setgroups=lambda groups: events.append(("groups", groups)),
        setgid=lambda gid: events.append(("gid", gid)),
        setuid=lambda uid: (events.append(("uid", uid)), ids.update(uid=uid)),
        geteuid=lambda: ids["uid"],
        execve=fake_exec,
    ))
    with pytest.raises(Executed):
        stage.run()
    assert [row[0] for row in events] == [
        "validated", "groups", "gid", "uid", "execve",
    ]
    assert events[1:4] == [("groups", []), ("gid", 65534),
                          ("uid", 65534)]
    assert events[-1][1] == "/usr/bin/python3"
    assert events[-1][2] == [
        "/usr/bin/python3", "-B", stage._CACHE_SMOKE,
    ]
    assert events[-1][3] == {
        "PATH": "/usr/sbin:/usr/bin:/bin", "HOME": "/tmp",
        "TMPDIR": "/tmp", "LC_ALL": "C",
        "PYTHONPATH": "/workspace/src",
        "REPOCACHE_DISPOSABLE_NGINX_SMOKE": "1",
    }


def test_failed_privilege_drop_does_not_run_rootless_target(monkeypatch):
    events = []
    monkeypatch.setattr(stage, "_require_disposable_native_install",
                        lambda: None)
    monkeypatch.setattr(stage, "os", SimpleNamespace(
        setgroups=lambda x: events.append(("groups", x)),
        setgid=lambda x: events.append(("gid", x)),
        setuid=lambda x: events.append(("uid", x)),
        geteuid=lambda: 0,
        execve=lambda *a: pytest.fail("must not exec before UID drop"),
    ))
    with pytest.raises(stage.ContainerContinuationError,
                       match="PRIVILEGE_DROP_UNVERIFIED"):
        stage.run()


def test_untrusted_exception_message_never_reaches_stdout(monkeypatch, capsys):
    monkeypatch.setattr(stage.sys, "argv", ["script"])
    monkeypatch.setattr(stage, "run", lambda: (_ for _ in ()).throw(
        ValueError("SECRET /var/private/key.pem"),
    ))
    assert stage.main() == 2
    output = capsys.readouterr().out
    assert "SECRET" not in output
    assert "private" not in output
    assert "CONTAINER_CONTINUATION_UNVERIFIED" in output


def test_cli_refuses_arguments_without_host_access(monkeypatch, capsys):
    monkeypatch.setattr(stage.sys, "argv", ["script", "--apply"])
    monkeypatch.setattr(stage, "run",
                        lambda: pytest.fail("must not inspect host"))
    assert stage.main() == 2
    assert "ARGUMENTS_REFUSED" in capsys.readouterr().out
