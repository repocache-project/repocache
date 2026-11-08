"""Read-only native readiness diagnostic: all real host gates remain separate."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from repocache import candidate_cgroup, candidate_sandbox

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/ci_candidate_native_readiness.py"


@pytest.fixture
def probe():
    spec = importlib.util.spec_from_file_location("native_readiness", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_readiness_accepts_only_complete_prerequisites_and_never_claims_release(
        probe, monkeypatch):
    called = []
    monkeypatch.setattr(probe, "_os_release", lambda: "almalinux10")
    monkeypatch.setattr(probe, "_nonroot", lambda: called.append("nonroot"))
    monkeypatch.setattr(probe, "_systemd_pid1",
                        lambda: called.append("systemd"))
    monkeypatch.setattr(probe, "_not_container",
                        lambda: called.append("not-container"))
    monkeypatch.setattr(probe, "_selinux",
                        lambda target: called.append("selinux:" + target))
    monkeypatch.setattr(candidate_cgroup, "require_delegation",
                        lambda: called.append("delegation"))
    monkeypatch.setattr(candidate_cgroup, "require_staging_tmpfs",
                        lambda parent: called.append("staging"))
    monkeypatch.setattr(candidate_sandbox, "require_executor",
                        lambda: called.append("bwrap"))
    result = probe.run_probe()
    assert result["status"] == "READINESS_ONLY_PASS"
    assert called == [
        "nonroot", "systemd", "not-container", "selinux:almalinux10",
        "delegation", "staging", "bwrap",
    ]
    for requirement in ("native_resource_exhaustion", "supervisor_sigkill_recovery",
                        "selinux_escape_tests", "real_publisher_signed_candidate"):
        assert result[requirement] == "NOT_VERIFIED"
    assert json.loads(json.dumps(result)) == result


@pytest.mark.parametrize("failed", ["os", "nonroot", "systemd", "container", "selinux",
                                    "delegation", "staging", "bwrap"])
def test_readiness_refuses_missing_gate_without_fallback(
        probe, monkeypatch, failed):
    order = []

    def check(name):
        def run(*args, **kwargs):
            order.append(name)
            if name == failed:
                raise probe.NativeReadinessError("simulated native gate denied")
            return "debian13" if name == "os" else None
        return run

    monkeypatch.setattr(probe, "_os_release", check("os"))
    monkeypatch.setattr(probe, "_nonroot", check("nonroot"))
    monkeypatch.setattr(probe, "_systemd_pid1", check("systemd"))
    monkeypatch.setattr(probe, "_not_container", check("container"))
    monkeypatch.setattr(probe, "_selinux", check("selinux"))
    monkeypatch.setattr(candidate_cgroup, "require_delegation",
                        check("delegation"))
    monkeypatch.setattr(candidate_cgroup, "require_staging_tmpfs",
                        check("staging"))
    monkeypatch.setattr(candidate_sandbox, "require_executor", check("bwrap"))
    result = probe.run_probe()
    assert result["status"] == "BLOCKED"
    assert failed in order
    assert "bwrap" not in order if failed != "bwrap" else "bwrap" in order
    assert result["native_resource_exhaustion"] == "NOT_VERIFIED"


def test_native_readiness_main_outputs_json_and_fails_closed(
        probe, monkeypatch, capsys):
    def unsupported():
        raise probe.NativeReadinessError("not a supported host")
    monkeypatch.setattr(probe, "_os_release", unsupported)
    monkeypatch.setattr(probe, "_nonroot", lambda: None)
    monkeypatch.setattr(probe, "_systemd_pid1", lambda: None)
    assert probe.main() == 2
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "BLOCKED"
    assert data["checks"]["supported_os"].startswith("FAIL:")



def test_actual_runner_invocation_produces_readiness_not_native_acceptance():
    """Run the actual CLI, not only mocks, in this disposable CI environment."""
    import os
    import subprocess
    import sys

    result = subprocess.run([sys.executable, str(SCRIPT)],
                            capture_output=True, text=True, timeout=15,
                            check=False)
    assert result.returncode in (0, 2), result.stderr[-500:]
    data = json.loads(result.stdout)
    assert data["scope"] == "read-only native readiness only"
    assert data["status"] in {"BLOCKED", "READINESS_ONLY_PASS"}
    for criterion in ("native_resource_exhaustion", "supervisor_sigkill_recovery",
                      "selinux_escape_tests", "real_publisher_signed_candidate"):
        assert data[criterion] == "NOT_VERIFIED"
    if os.environ.get("GITHUB_ACTIONS") == "true":
        # GitHub's disposable runners are not booted target distro kernels.
        assert data["status"] == "BLOCKED"
        assert result.returncode == 2
