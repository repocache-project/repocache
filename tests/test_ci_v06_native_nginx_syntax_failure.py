"""Safety and result-contract tests for disposable NGINX syntax failure (#27)."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "scripts"))

import ci_v06_native_nginx_syntax_failure as fault


def test_native_fault_rehearsal_must_refuse_nondisposable_context(monkeypatch):
    def deny():
        raise ValueError("DISPOSABLE_NATIVE_CONTAINER_REQUIRED")

    monkeypatch.setattr(fault, "_require_disposable_context", deny)
    monkeypatch.setattr(
        fault, "bootstrap_protected_namespace_under_root",
        lambda *_a, **_k: pytest.fail("protected state unexpectedly created"),
    )
    monkeypatch.setattr(
        fault, "run_rehearsal",
        lambda *_a, **_k: pytest.fail("native package manager unexpectedly invoked"),
    )
    with pytest.raises(ValueError, match="^DISPOSABLE_NATIVE_CONTAINER_REQUIRED$"):
        fault.run()


def test_syntax_fixture_refuses_symlink_before_subprocess(tmp_path, monkeypatch):
    real = tmp_path / "foreign.conf"
    real.write_bytes(b"PRIVATE_UPSTREAM_CONFIGURATION")
    link = tmp_path / "nginx.conf"
    link.symlink_to(real)
    monkeypatch.setattr(fault, "_NGINX_CONFIG", link)
    monkeypatch.setattr(
        fault.subprocess, "run",
        lambda *_a, **_k: pytest.fail("NGINX syntax check invoked on symlink"),
    )
    with pytest.raises(
        fault.NativeSyntaxFailureTestError,
        match="^INSTALLED_NGINX_CONFIG_MISSING$",
    ):
        fault._restore_after_real_syntax_failure(
            ["/usr/sbin/nginx", "-t", "-q"], {},
        )
    assert real.read_bytes() == b"PRIVATE_UPSTREAM_CONFIGURATION"


def test_reject_noncanonical_nginx_syntax_invocation(monkeypatch):
    monkeypatch.setattr(
        fault.os, "open",
        lambda *_a, **_k: pytest.fail("noncanonical command opened file"),
    )
    with pytest.raises(
        fault.NativeSyntaxFailureTestError,
        match="^UNEXPECTED_SYNTAX_COMMAND$",
    ):
        fault._restore_after_real_syntax_failure(
            ["/usr/sbin/nginx", "-s", "reload"], {},
        )


def test_failure_payload_redacts_untrusted_exception(monkeypatch, capsys):
    monkeypatch.setattr(
        fault, "run", lambda: (_ for _ in ()).throw(
            ValueError("SECRET_OPERATOR_PATH_OR_TOKEN")
        ),
    )
    assert fault.main() == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "SECRET_OPERATOR_PATH_OR_TOKEN" not in captured.out
    assert json.loads(captured.out) == {
        "schema_version": 1, "status": "FAIL",
        "code": "NATIVE_SYNTAX_FAILURE_REHEARSAL_UNVERIFIED",
        "real_host_installation_authorized": False,
    }


def test_fixed_refusal_code_survives_redaction(monkeypatch, capsys):
    monkeypatch.setattr(
        fault, "run", lambda: (_ for _ in ()).throw(
            fault.NativeSyntaxFailureTestError("FRESH_LOCK_NOT_DURABLE")
        ),
    )
    assert fault.main() == 1
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": 1, "status": "FAIL",
        "code": "FRESH_LOCK_NOT_DURABLE",
        "real_host_installation_authorized": False,
    }


def test_real_two_distro_workflow_asserts_no_host_authority():
    source = (
        _ROOT / ".github/workflows/server-v06-nginx-syntax-failure.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "debian:trixie-slim", "almalinux:10", "merge_group:",
        "target=/workspace,readonly",
        "DISPOSABLE_NATIVE_SYNTAX_FAILURE_RECOVERY_PASS",
        "root_owned_pending_effects_marker_preserved",
        "exclusive_lock_retained_during_native_commands",
        "real_host_installation_authorized",
        "booted_systemd_tested", "selinux_enforcing_tested",
    ):
        assert required in source
    assert "sudo " not in source
    assert "systemctl start" not in source
