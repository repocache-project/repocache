"""CI-only journaled native installation sequencing refuses unsafe hosts (#27)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import ci_v06_journaled_native_server_install as integration


def test_without_disposable_gate_refuses_before_any_mutation(monkeypatch):
    monkeypatch.delenv("REPOCACHE_NATIVE_TEST_CONTAINER", raising=False)
    monkeypatch.setattr(integration, "bootstrap_protected_namespace_under_root",
                        lambda *_a, **_kw: pytest.fail("filesystem mutation reached"))
    monkeypatch.setattr(integration, "_retain_native_package_journal_lock_under_root",
                        lambda *_a, **_kw: pytest.fail("journal mutation reached"))
    monkeypatch.setattr(integration, "run_rehearsal",
                        lambda *_a, **_kw: pytest.fail("native package reached"))
    monkeypatch.setattr(integration, "_verify_readonly_preflight",
                        lambda *_a, **_kw: pytest.fail("CI preflight reached outside disposable gate"))
    with pytest.raises(integration.NativeIntegrationError,
                       match="^DISPOSABLE_NATIVE_CONTAINER_REQUIRED$"):
        integration.run()


def _readonly_report():
    return {
        "schema_version": 1, "kind": "repocache.server.vm-preflight.partial",
        "status": "NOT VERIFIED", "read_only": True, "authorizes_installation": False,
        "checks": [{
            "check": "supported_os_and_python", "status": "PASS",
            "code": "SUPPORTED_OS_AND_PYTHON_VERSION",
            "guidance": "Local observation only.",
        }],
    }


@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("code", ["SYSTEMD_CLIENT_MISSING", "STATE_OR_LOG_SPACE_EXHAUSTED", "TLS_REFERENCE_OWNER_OR_LINK_UNSAFE"])
def test_positive_native_preflight_refuses_unexpected_local_failures(monkeypatch, code, installed):
    report = {
        "supported_os_and_python": {"status": "PASS", "code": "SUPPORTED_OS_AND_PYTHON_VERSION"},
        "architecture_supported": {"status": "PASS", "code": "SUPPORTED_NATIVE_ARCHITECTURE"},
        "native_python_identity": {"status": "PASS", "code": "NATIVE_PYTHON_INODE_OBSERVED_ONLY"},
        "nginx_native_binary": {"status": "PASS" if installed else "FAIL", "code": "NGINX_EXECUTABLE_OBSERVED_ONLY" if installed else "NGINX_EXECUTABLE_MISSING"},
        "failed_check": {"status": "FAIL", "code": code},
    }
    monkeypatch.setattr(integration, "_run_readonly_preflight", lambda *a, **kw: report)
    with pytest.raises(integration.NativeIntegrationError, match="POSITIVE_LOCAL_CHECK_FAILED"):
        integration._verify_readonly_preflight({}, installed=installed)


@pytest.mark.parametrize("fault", ["none", "authority", "mutation", "guidance", "status", "malformed"])
def test_native_preflight_acceptance_checks_boundary_and_preservation(tmp_path, monkeypatch, fault):
    native = tmp_path / "nginx"
    native.mkdir()
    config = native / "nginx.conf"
    config.write_text("unrelated configuration")
    monkeypatch.setattr(integration, "_PREFLIGHT_PATHS", (native, tmp_path / "absent-state"))

    def fake_run(command, **kwargs):
        assert command[:3] == ["/usr/bin/python3", "-I", "-B"]
        assert "--intent" in command and command[-1] == "install"
        assert kwargs["stdin"] is integration.subprocess.DEVNULL
        assert kwargs["timeout"] == 30
        result = _readonly_report()
        if fault == "authority":
            result["authorizes_installation"] = True
        elif fault == "mutation":
            config.write_text("changed")
        elif fault == "guidance":
            result["checks"][0]["guidance"] = ""
        elif fault == "status":
            result["status"] = "PASS"
        return SimpleNamespace(
            returncode=3, stdout=b"bad JSON" if fault == "malformed" else json.dumps(result).encode(),
            stderr=b"",
        )

    monkeypatch.setattr(integration.subprocess, "run", fake_run)
    if fault == "none":
        assert integration._run_readonly_preflight({})["supported_os_and_python"]["status"] == "PASS"
        assert config.read_text() == "unrelated configuration"
    else:
        with pytest.raises(integration.NativeIntegrationError):
            integration._run_readonly_preflight({})


def test_cli_never_leaks_untrusted_exception_details(monkeypatch, capsys):
    def failure():
        raise ValueError("secret /path/to/private.pem token")
    monkeypatch.setattr(integration, "run", failure)
    assert integration.main() == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "secret" not in captured.out
    assert "private" not in captured.out
    report = json.loads(captured.out)
    assert report == {
        "schema_version": 1, "status": "FAIL",
        "code": "NATIVE_INTEGRATION_UNVERIFIED",
        "authorizes_host_installation": False,
    }


def test_static_error_code_preserved_without_shell_text(monkeypatch, capsys):
    def failure():
        raise integration.NativeIntegrationError(
            "DISPOSABLE_NATIVE_CONTAINER_REQUIRED"
        )
    monkeypatch.setattr(integration, "run", failure)
    assert integration.main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["code"] == "DISPOSABLE_NATIVE_CONTAINER_REQUIRED"
    assert report["authorizes_host_installation"] is False


@pytest.mark.parametrize("bad", [
    b"foreign", b"{}", b'{"journal_schema_version":2}',
])
def test_invalid_marker_cannot_reach_package_callback(
    tmp_path, monkeypatch, bad,
):
    state = tmp_path / "server"
    state.mkdir()
    (state / integration.LOCK_NAME).write_bytes(b"")
    marker = state / integration.NATIVE_PENDING_NAME
    marker.write_bytes(bad)
    marker.chmod(0o600)
    monkeypatch.setattr(integration, "_STATE", state)
    with pytest.raises(integration.NativeIntegrationError):
        integration._verify_pending_lock("debian", [])


def test_linked_marker_is_never_accepted(tmp_path, monkeypatch):
    state = tmp_path / "server"
    state.mkdir()
    target = tmp_path / "foreign"
    target.write_bytes(b"untrusted")
    (state / integration.LOCK_NAME).write_bytes(b"")
    (state / integration.NATIVE_PENDING_NAME).symlink_to(target)
    monkeypatch.setattr(integration, "_STATE", state)
    with pytest.raises(integration.NativeIntegrationError,
                       match="^NATIVE_JOURNAL_NOT_DURABLE$"):
        integration._verify_pending_lock("almalinux", [])


def test_no_host_install_authority_in_success_schema():
    src = (ROOT / "scripts/ci_v06_journaled_native_server_install.py").read_text()
    for token in (
        '"installed_server_ready": False',
        '"host_root_provenance_verified": False',
        '"systemd_pid1_verified": False',
        '"selinux_enforcing_verified": False',
        '"authorizes_host_installation": False',
        '"real_exclusive_lock_held_during_subprocesses": True',
        '_retain_native_package_journal_lock_under_root',
    ):
        assert token in src



def test_postpackage_stage_requires_read_only_correlated_binary_unit():
    source = (ROOT / "scripts/ci_v06_journaled_native_server_install.py").read_text()
    assert 'inspect_current_namespace_native_postpackage_candidate(' in source
    assert '"native_binary_and_vendor_unit_correlated_in_container": True' in source
    assert '"native_postpackage_correlation_authorizes_no_reentry": True' in source
    for flag in (
        "native_package_signature_verified",
        "installed_host_root_authenticated",
        "systemd_pid1_and_service_verified",
        "selinux_enforcing_verified",
        "operator_approval_verified",
        "package_effects_reconciled",
        "authorizes_native_marker_removal",
        "authorizes_package_installation",
        "authorizes_nginx_reload",
        "authorizes_host_mutation",
    ):
        assert flag in source
