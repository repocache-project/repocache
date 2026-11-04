"""Read-only operator CLI integration of partial native preflight (#26).

Tests are pure userspace/fixture evidence, not booted-host certification.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repocache import cli
from repocache import server_host_checks_v1 as host
from repocache.server_preflight_v1 import (
    NativeHostFacts, assess_native_host,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
RUNNER = CliRunner()


def _report(*, supported: bool = True, manager: bool = True):
    return assess_native_host(NativeHostFacts(
        os_release=("ID=debian\nVERSION_ID=13\n" if supported
                    else "ID=ubuntu\nVERSION_ID=24.04\n"),
        python_version=(3, 13), machine="x86_64", euid=1000,
        native_manager_visible=manager, running_in_venv=False,
    ))


@pytest.mark.parametrize("placement", ["local", "global"])
def test_valid_preflight_always_non_authorizing_redacted_json(monkeypatch, placement):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Read-only deployment preflight attempted a mutating command")

    monkeypatch.setattr(cli, "command", forbidden)
    monkeypatch.setattr(cli, "nginx_config", forbidden)
    monkeypatch.setattr(host, "inspect_deployment_host",
                        lambda document, intent: _report(manager=False))
    args = (["--json"] if placement == "global" else [])
    args += ["deployment", "preflight", "--file", str(EXAMPLE)]
    if placement == "local":
        args.append("--json")
    result = RUNNER.invoke(cli.app, args)
    assert result.exit_code == 1, result.output
    data = json.loads(result.stdout)
    assert data["schema_version"] == 1 and data["ok"] is False
    assert data["error"]["code"] == "PREFLIGHT_NOT_READY"
    assert data["status"] == "FAIL"
    assert data["can_install"] is False
    assert data["authorizes_installation"] is False
    assert any(x["code"] == "NATIVE_PACKAGE_MANAGER_MISSING"
               for x in data["checks"])
    assert str(EXAMPLE) not in result.stdout
    assert "https://" not in result.stdout


def test_observed_positive_facts_still_return_not_verified(monkeypatch):
    monkeypatch.setattr(host, "inspect_deployment_host",
                        lambda document, intent: _report())
    result = RUNNER.invoke(cli.app, [
        "deployment", "preflight", "--file", str(EXAMPLE), "--json",
    ])
    assert result.exit_code == 1, result.output
    response = json.loads(result.stdout)
    assert response["status"] == "NOT_VERIFIED"
    assert response["ok"] is False
    assert response["can_install"] is False


@pytest.mark.parametrize("case", ["invalid", "missing", "symlink", "fifo"])
def test_invalid_input_fails_before_host_inspection(tmp_path, monkeypatch, case):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Invalid deployment JSON reached native host inspection")

    monkeypatch.setattr(host, "inspect_deployment_host", forbidden)
    path = tmp_path / "secret-private-input.json"
    if case == "invalid":
        path.write_text('{"SECRET":"operator-supplied-private-value"}',
                        encoding="utf-8")
        code = "CONFIG_INVALID"
    elif case == "missing":
        code = "CONFIG_UNAVAILABLE"
    elif case == "symlink":
        path.symlink_to(EXAMPLE)
        code = "CONFIG_UNAVAILABLE"
    else:
        import os
        os.mkfifo(path)
        code = "CONFIG_UNAVAILABLE"
    result = RUNNER.invoke(cli.app, [
        "deployment", "preflight", "--file", str(path), "--json",
    ])
    assert result.exit_code == 2, result.output
    data = json.loads(result.stdout)
    assert data["error"]["code"] == code
    assert str(path) not in result.stdout
    assert "operator-supplied-private-value" not in result.stdout


def test_failed_observation_is_sanitized_and_non_authorizing(monkeypatch):
    def denied(*_args, **_kwargs):
        raise PermissionError("do not echo synthetic-private-path")

    monkeypatch.setattr(host, "inspect_deployment_host", denied)
    result = RUNNER.invoke(cli.app, [
        "deployment", "preflight", "--file", str(EXAMPLE), "--json",
    ])
    assert result.exit_code == 1, result.output
    data = json.loads(result.stdout)
    assert data["error"]["code"] == "PREFLIGHT_UNAVAILABLE"
    assert "synthetic-private-path" not in result.stdout


def test_text_mode_and_help_do_not_authorize_or_activate(monkeypatch):
    monkeypatch.setattr(host, "inspect_deployment_host",
                        lambda document, intent: _report())
    result = RUNNER.invoke(cli.app, [
        "deployment", "preflight", "--file", str(EXAMPLE),
    ])
    assert result.exit_code == 1, result.output
    assert "no installation or activation" in result.stdout.lower()
    assert "PREFLIGHT_NOT_READY" in result.output
    help_result = RUNNER.invoke(cli.app, ["deployment", "--help"])
    assert help_result.exit_code == 0, help_result.output
    assert "preflight" in help_result.output


@pytest.mark.parametrize("release,python", [
    ("ID=debian\nVERSION_ID=13\n", (3, 13)),
    ("ID=almalinux\nVERSION_ID=10\n", (3, 12)),
])
def test_preflight_repeats_without_local_file_mutation(
    tmp_path, monkeypatch, release, python,
):
    """Exercise the real read-only probes with both supported OS identities.

    The runner is still an Ubuntu userspace fixture, NOT either native host.
    """
    config = tmp_path / "candidate.json"
    config.write_bytes(EXAMPLE.read_bytes())
    existing = tmp_path / "existing-nginx-and-state-sentinel"
    existing.write_bytes(b"third-party data must remain untouched")
    original = {
        p.name: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in (config, existing)
    }

    monkeypatch.setattr(
        host, "capture_native_host_facts",
        lambda: NativeHostFacts(
            os_release=release, python_version=python,
            machine="x86_64", euid=1000,
            native_manager_visible=True, running_in_venv=False,
        ),
    )
    args = [
        "deployment", "preflight", "--file", str(config), "--json",
    ]
    first = RUNNER.invoke(cli.app, args, input="")
    second = RUNNER.invoke(cli.app, args, input="")
    assert first.exit_code == second.exit_code == 1
    assert json.loads(first.stdout) == json.loads(second.stdout)
    result = json.loads(first.stdout)
    assert result["ok"] is False and result["can_install"] is False
    assert result["authorizes_installation"] is False
    assert any(item["check"] == "supported_os_and_python"
               and item["status"] == "PASS" for item in result["checks"])
    assert result["status"] in ("FAIL", "NOT_VERIFIED")
    assert str(config) not in first.stdout
    assert set(path.name for path in tmp_path.iterdir()) == set(original)
    assert {
        p.name: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in (config, existing)
    } == original


def test_read_only_existing_validation_output_unchanged():
    result = RUNNER.invoke(cli.app, [
        "config", "validate", "--file", str(EXAMPLE), "--json",
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["status"] == "VALIDATION_ONLY"
    assert data["ok"] is True
    assert data["authorizes_installation"] is False
