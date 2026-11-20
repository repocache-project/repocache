"""Safety and integration contracts for native journal + managed NGINX include (#27)."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import ci_v06_native_nginx_journal_include_transaction as locked


def test_real_native_package_lock_rehearsal_refuses_non_docker_context(
    monkeypatch,
):
    def deny():
        raise ValueError("DISPOSABLE_NATIVE_CONTAINER_REQUIRED")

    monkeypatch.setattr(locked, "_require_disposable_context", deny)
    monkeypatch.setattr(
        locked, "bootstrap_protected_namespace_under_root",
        lambda *_a, **_k: pytest.fail("must not bootstrap a non-disposable root"),
    )
    monkeypatch.setattr(
        locked, "run_rehearsal",
        lambda *_a, **_k: pytest.fail("package manager must not run"),
    )
    with pytest.raises(ValueError, match="^DISPOSABLE_NATIVE_CONTAINER_REQUIRED$"):
        locked.run()


@pytest.mark.parametrize("returncode,valid", [(0, True), (1, False), (2, False)])
def test_nginx_syntax_is_native_fixed_argv_with_held_lock(
    monkeypatch, returncode, valid,
):
    observed = []

    def check_lock(distribution, report):
        assert distribution == "debian"
        assert report is observed
        observed.append("CONTENDED")

    def invoke(argv, **kwargs):
        assert argv == ["/usr/sbin/nginx", "-t", "-q"]
        assert kwargs["check"] is False
        assert kwargs["cwd"] == "/"
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["stdout"] is subprocess.PIPE
        assert kwargs["stderr"] is subprocess.PIPE
        assert kwargs["timeout"] == 20
        assert observed == ["CONTENDED"]
        return subprocess.CompletedProcess(argv, returncode, b"", b"secret nginx error")

    monkeypatch.setattr(locked, "_verify_pending_lock", check_lock)
    monkeypatch.setattr(locked.subprocess, "run", invoke)
    assert locked._syntax_check("debian", observed) is valid
    assert observed == ["CONTENDED"]


def test_native_syntax_cannot_run_when_protected_lock_is_not_held(monkeypatch):
    def deny(*args, **kwargs):
        raise ValueError("NATIVE_EXCLUSIVE_LOCK_NOT_HELD")

    monkeypatch.setattr(locked, "_verify_pending_lock", deny)
    monkeypatch.setattr(
        locked.subprocess, "run",
        lambda *_a, **_k: pytest.fail("nginx invoked after lock failure"),
    )
    with pytest.raises(ValueError, match="^NATIVE_EXCLUSIVE_LOCK_NOT_HELD$"):
        locked._syntax_check("debian", [])


def test_rehearsal_failure_is_redacted_and_non_authorizing(monkeypatch, capsys):
    monkeypatch.setattr(
        locked, "run",
        lambda: (_ for _ in ()).throw(ValueError("SECRET_HOST_CONFIG_OR_TOKEN")),
    )
    assert locked.main() == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "SECRET_HOST_CONFIG_OR_TOKEN" not in captured.out
    assert json.loads(captured.out) == {
        "schema_version": 1,
        "status": "FAIL",
        "code": "LOCKED_NATIVE_INCLUDE_REHEARSAL_UNVERIFIED",
        "authorizes_host_installation": False,
    }


def test_rehearsal_does_not_expose_callback_exception(monkeypatch, capsys):
    monkeypatch.setattr(
        locked, "run",
        lambda: (_ for _ in ()).throw(
            locked.LockedNativeIncludeTestError("LOCK_NOT_HELD")
        ),
    )
    assert locked.main() == 1
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": 1, "status": "FAIL",
        "code": "LOCKED_NATIVE_INCLUDE_REHEARSAL_UNVERIFIED",
        "authorizes_host_installation": False,
    }


def test_managed_name_and_package_journal_paths_are_fixed():
    assert locked._INCLUDE.as_posix() == "/etc/nginx/conf.d/repocache-managed.conf"
    assert locked._STAGE.as_posix() == "/etc/nginx/conf.d/.repocache-managed.stage"
    assert locked._BACKUP.as_posix() == "/etc/nginx/conf.d/.repocache-managed.rollback"
    assert locked._MARKER.as_posix().startswith(
        "/var/lib/repocache/server/.native-nginx-v1."
    )
    assert locked._VALID.endswith(b"\n")
    assert locked._INVALID.endswith(b"\n")
    assert locked._PRIOR.endswith(b"\n")


def test_two_distro_workflow_guards_scope_and_explicit_negative_authority():
    source = (
        ROOT / ".github/workflows/server-v06-native-journal-include.yml"
    ).read_text(encoding="utf-8")
    script = (
        ROOT / "scripts/ci_v06_native_nginx_journal_include_transaction.py"
    ).read_text(encoding="utf-8")
    for required in (
        "debian:trixie-slim", "almalinux:10", "merge_group:",
        "target=/workspace,readonly",
        "REPOCACHE_NATIVE_TEST_CONTAINER=CONFIRMED_DISPOSABLE_DOCKER_ONLY",
        "DISPOSABLE_NATIVE_JOURNAL_LOCKED_INCLUDE_RESTORE_PASS",
        "single_exclusive_state_lock_through_native_and_include_checks",
        "real_nginx_parser_rejected_invalid_owned_fragment",
        "durable_pending_package_journal_preserved",
        "native_package_effects_reconciled",
        "booted_systemd_tested", "selinux_enforcing_tested",
        "authorizes_host_installation",
    ):
        assert required in source
    assert "sudo " not in source
    assert "systemctl start" not in source
    assert "systemctl reload" not in source
    assert "chmod 777" not in script
    assert "shell=True" not in script
    assert "os.system(" not in script
    assert "exec(" not in script
    assert "os.unlink(_MARKER)" not in script
    assert "_prepare_native_journal_under_root(" in script
    assert "rehearse_managed_include_under_root(" in script
