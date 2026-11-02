"""CLI config validate: bounded, non-mutating server-install v1 input (#107).

No test here validates a live server installation or trusts a proposed
active state as evidence of actual NGINX exposure.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repocache import cli


EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
RUNNER = CliRunner()


def _invoke(path: Path, *flags: str):
    return RUNNER.invoke(cli.app, [*flags, "config", "validate", "--file", str(path), "--json"])


def test_valid_file_reports_only_read_only_intent(tmp_path, monkeypatch):
    def forbidden(*_a, **_kw):
        raise AssertionError("An inert CLI validator attempted an operational side effect")

    monkeypatch.setattr(cli, "command", forbidden)
    monkeypatch.setattr(cli, "nginx_config", forbidden)
    monkeypatch.setattr(cli, "publish_catalog", forbidden, raising=False)
    path = tmp_path / "input.json"
    value = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    value["repositories"][0]["desired_state"] = "active"
    path.write_text(json.dumps(value), encoding="utf-8")
    original = path.read_bytes()
    result = _invoke(path)
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report == {
        "schema_version": 1, "ok": True, "status": "VALIDATION_ONLY",
        "kind": "repocache.server.install", "repository_count": 2,
        "active_intent_count": 1, "authorizes_installation": False,
    }
    assert path.read_bytes() == original
    assert sorted(p.name for p in tmp_path.iterdir()) == ["input.json"]


@pytest.mark.parametrize("arguments", [
    lambda p: ["--json", "config", "validate", "--file", str(p)],
    lambda p: ["config", "validate", "--json", "--file", str(p)],
])
def test_global_json_and_action_json_placement_equivalent(arguments):
    result = RUNNER.invoke(cli.app, arguments(EXAMPLE))
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["status"] == "VALIDATION_ONLY"


def test_invalid_payload_refused_without_echoing_untrusted_content(tmp_path):
    secret = "synthetic-private-secret"
    bad = tmp_path / "configuration.json"
    bad.write_text('{"unknown":"' + secret + '"}', encoding="utf-8")
    result = _invoke(bad)
    assert result.exit_code == 2, result.output
    error = json.loads(result.stdout)
    assert error["error"]["code"] == "CONFIG_INVALID"
    assert secret not in result.output
    assert error["ok"] is False


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo"])
def test_special_files_refused_before_read_or_blocking(tmp_path, kind):
    source = tmp_path / "trusted.json"
    source.write_bytes(EXAMPLE.read_bytes())
    target = tmp_path / "untrusted"
    if kind == "symlink":
        target.symlink_to(source)
    elif kind == "directory":
        target.mkdir()
    else:
        import os
        os.mkfifo(target)
    result = _invoke(target)
    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout)["error"]["code"] == "CONFIG_UNAVAILABLE"
    assert source.read_bytes() == EXAMPLE.read_bytes()


def test_missing_file_refused_without_printing_file_name(tmp_path):
    unavailable = tmp_path / "private-cannot-log.json"
    result = _invoke(unavailable)
    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout)["error"]["code"] == "CONFIG_UNAVAILABLE"
    assert unavailable.name not in result.output


def test_unreadable_file_is_refused_without_exposing_path_or_os_error(tmp_path, monkeypatch):
    """Simulate EACCES regardless of runner UID (including root)."""
    unreadable = tmp_path / "private-credential-file.json"
    original = EXAMPLE.read_bytes()
    unreadable.write_bytes(original)
    actual_os_open = cli.os.open

    def denied_open(path, flags, *args, **kwargs):
        if Path(path) == unreadable:
            raise PermissionError(13, "synthetic-access-denied", str(unreadable))
        return actual_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(cli.os, "open", denied_open)
    for json_mode in (True, False):
        args = ["config", "validate", "--file", str(unreadable)]
        if json_mode:
            args.append("--json")
        result = RUNNER.invoke(cli.app, args)
        assert result.exit_code == 2, result.output
        if json_mode:
            assert json.loads(result.stdout)["error"]["code"] == "CONFIG_UNAVAILABLE"
        assert unreadable.name not in result.output
        assert "synthetic-access-denied" not in result.output
    assert unreadable.read_bytes() == original


def test_oversized_input_refused_without_exposing_its_data(tmp_path):
    huge = tmp_path / "huge.json"
    huge.write_bytes(b'{"data":"' + b"x" * (1024 * 1024 + 5) + b'"}')
    result = _invoke(huge)
    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout)["error"]["code"] == "CONFIG_INVALID"


def test_text_mode_is_noninteractive_and_explicit_about_no_activation(tmp_path):
    path = tmp_path / "config.json"
    path.write_bytes(EXAMPLE.read_bytes())
    result = RUNNER.invoke(cli.app, ["config", "validate", "--file", str(path)])
    assert result.exit_code == 0, result.output
    assert "no activation" in result.output.lower()
    assert path.read_bytes() == EXAMPLE.read_bytes()


def test_config_object_help_does_not_read_a_file_or_start_nginx(monkeypatch):
    def forbidden(*_a, **_kw):
        raise AssertionError("help attempted operational action")
    monkeypatch.setattr(cli, "command", forbidden)
    monkeypatch.setattr(cli, "nginx_config", forbidden)
    result = RUNNER.invoke(cli.app, ["config", "--help"])
    assert result.exit_code == 0, result.output
    assert "validate" in result.output
