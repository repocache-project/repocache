"""Non-authorizing, deterministic server v0.6 preflight CLI tests (#26)."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

from repocache.server_preflight_v1 import (
    NativePreflightReport, PreflightCheck, PreflightStatus,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/server_v06_preflight.py"


@pytest.fixture
def entry():
    spec = importlib.util.spec_from_file_location("server_v06_preflight", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def document(tmp_path):
    target = tmp_path / "deployment.json"
    target.write_bytes((ROOT / "docs/examples/server-install-v1.json").read_bytes())
    return target


def _report(*, fail=False):
    return NativePreflightReport((
        PreflightCheck("supported_os_and_python",
                       PreflightStatus.FAIL if fail else PreflightStatus.PASS,
                       "UNSUPPORTED_OS_OR_PYTHON" if fail
                       else "SUPPORTED_OS_AND_PYTHON_VERSION"),
        PreflightCheck("managed_state_and_rollback", PreflightStatus.NOT_VERIFIED,
                       "PROTECTED_STATE_ROLLBACK_UNVERIFIED"),
    ))


@pytest.mark.parametrize("intent", ["inspect", "install"])
def test_partial_diagnostics_never_authorize(entry, document, monkeypatch, capsys, intent):
    observed = []
    def fake(data, *, intent):
        observed.append((data["schema_version"], intent))
        return _report()
    monkeypatch.setattr(entry, "inspect_deployment_host", fake)
    before = document.read_bytes()
    assert entry.run(["--document", str(document), "--intent", intent]) == 3
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "NOT VERIFIED"
    assert output["read_only"] is True
    assert output["authorizes_installation"] is False
    assert all(set(item) == {"check", "status", "code", "guidance"}
               for item in output["checks"])
    assert document.read_bytes() == before
    assert observed == [(1, intent)]


def test_host_failure_is_not_ready(entry, document, monkeypatch, capsys):
    monkeypatch.setattr(entry, "inspect_deployment_host",
                        lambda *_args, **_kw: _report(fail=True))
    assert entry.run(["--document", str(document)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "FAIL"
    assert not result["authorizes_installation"]


@pytest.mark.parametrize("corruption", [
    b'{"kind":"repocache.server.install","kind":"repocache.server.install"}',
    b"invalid-json", b"\xef\xbb\xbf{}", b"\xff" * 3,
    b" " * (1024 * 1024 + 1),
])
def test_invalid_input_refused_before_host_probe(entry, document, monkeypatch, capsys,
                                                 corruption):
    document.write_bytes(corruption)
    monkeypatch.setattr(entry, "inspect_deployment_host",
                        lambda *_a, **_kw: pytest.fail("reached host observation"))
    assert entry.run(["--document", str(document)]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["error"]["code"] == "INVALID_INPUT_OR_HOST_OBSERVATION"
    assert out["authorizes_installation"] is False


def test_symlinks_and_hardlinks_refused(entry, document, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(entry, "inspect_deployment_host",
                        lambda *_a, **_kw: pytest.fail("unsafe link reached probe"))
    link = tmp_path / "deployment-link.json"
    link.symlink_to(document)
    assert entry.run(["--document", str(link)]) == 2
    capsys.readouterr()
    os.link(document, tmp_path / "other-link.json")
    assert entry.run(["--document", str(document)]) == 2
    assert "INVALID_INPUT_OR_HOST_OBSERVATION" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [
    ["--document", "../sensitive/private.pem"],
    ["--document", "/nonexistent/private-key-file"],
    ["--document", "/tmp/test", "--intent", "approve"],
])
def test_invalid_path_or_option_redacted(entry, monkeypatch, capsys, argv):
    monkeypatch.setattr(entry, "inspect_deployment_host",
                        lambda *_a, **_kw: pytest.fail("invalid request reached probe"))
    assert entry.run(argv) == 2
    captured = capsys.readouterr()
    assert "private" not in captured.out + captured.err
    assert json.loads(captured.out)["authorizes_installation"] is False


def test_repeated_read_only_execution_is_deterministic(
    entry, document, monkeypatch, capsys,
):
    monkeypatch.setattr(entry, "inspect_deployment_host",
                        lambda *_a, **_kw: _report())
    assert entry.run(["--document", str(document)]) == 3
    first = capsys.readouterr().out
    assert entry.run(["--document", str(document)]) == 3
    assert capsys.readouterr().out == first


def test_document_parent_symlink_refused_before_host_observation(
    entry, document, tmp_path, monkeypatch, capsys,
):
    """A safe leaf through a symlinked parent is not a pinned document."""
    parent = tmp_path / "linked-parent"
    parent.symlink_to(document.parent, target_is_directory=True)
    monkeypatch.setattr(entry, "inspect_deployment_host",
                        lambda *_args, **_kw: pytest.fail("host probe reached"))
    assert entry.run(["--document", str(parent / document.name)]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["error"]["code"] == "INVALID_INPUT_OR_HOST_OBSERVATION"


@pytest.mark.parametrize("unsafe", (
    "/tmp//untrusted.json",
    "/tmp/./untrusted.json",
    "/tmp/../untrusted.json",
    "/" + "long" * 1100,
    "/tmp/" + "a" * 256,
))
def test_unbounded_or_noncanonical_document_path_refused(
    entry, unsafe, monkeypatch, capsys,
):
    monkeypatch.setattr(entry, "inspect_deployment_host",
                        lambda *_args, **_kw: pytest.fail("unsafe probe"))
    assert entry.run(["--document", unsafe]) == 2
    assert json.loads(capsys.readouterr().out)["authorizes_installation"] is False


def test_read_only_document_descriptor_does_not_leak(
    entry, document, monkeypatch, capsys,
):
    monkeypatch.setattr(entry, "inspect_deployment_host",
                        lambda *_args, **_kw: _report())
    # Linux gives an exact count of the process's open descriptors.
    before = set(os.listdir("/proc/self/fd"))
    for _ in range(5):
        assert entry.run(["--document", str(document)]) == 3
        capsys.readouterr()
    assert set(os.listdir("/proc/self/fd")) == before
