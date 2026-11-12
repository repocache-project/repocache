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
    with pytest.raises(integration.NativeIntegrationError,
                       match="^DISPOSABLE_NATIVE_CONTAINER_REQUIRED$"):
        integration.run()


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
