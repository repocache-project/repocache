"""Verify CI fault injection cannot certify a different native failure (#27)."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from repocache import server_native_package_trust_v1 as native

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import smoke_server_native_package_metadata as smoke


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
@pytest.mark.parametrize("fault", ["none", "gpgme", "rpm_key", "network", "candidate", "signature_success"])
def test_negative_acceptance_requires_native_absence_and_signature_failure(
    monkeypatch, capsys, distribution, fault,
):
    monkeypatch.setattr(native, "_trusted_key", lambda _path: True)
    seen = []

    def run(command, **kwargs):
        stage = smoke.redacted_native_stage(command)
        seen.append(stage)
        assert not any(word in command for word in ("install", "upgrade", "remove"))
        work = Path(kwargs["cwd"])
        source = (work / "sources.list" if distribution == "debian"
                  else work / "repos/repocache.repo")
        bad_key = work / "invalid-test-signing-key"
        if bad_key.exists():
            assert str(bad_key) in source.read_text()
            if distribution == "debian":
                assert "APT::Get::AllowUnauthenticated=false" in command
            else:
                assert "--setopt=rc-appstream.repo_gpgcheck=1" in command
            output = {
                "gpgme": "gpgme_op_import() error: No data SECRET-NATIVE-OUTPUT",
                "rpm_key": "Error: Compute cert len failed SECRET-NATIVE-OUTPUT",
                "network": "curl error: Could not resolve SECRET-NATIVE-OUTPUT",
            }.get(fault, "GPG error: NO_PUBKEY SECRET-NATIVE-OUTPUT")
            return SimpleNamespace(returncode=0 if fault == "signature_success" else 1,
                                   stdout="", stderr=output)
        if stage.endswith("candidate"):
            assert command[-1] == "repocache-acceptance-absent-package-7e941a"
            output = ("nginx:\n Candidate: 1.0\n" if distribution == "debian"
                      else "nginx\n") if fault == "candidate" else ""
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(smoke.subprocess, "run", run)
    document = json.loads((ROOT / "docs/examples/server-install-v1.json").read_text())
    release = f"ID={distribution}\nVERSION_ID={'13' if distribution == 'debian' else '10'}\n"
    version = (3, 13) if distribution == "debian" else (3, 12)
    if fault in ("none", "gpgme", "rpm_key"):
        smoke.verify_negative_metadata(release, version, document, distribution)
        assert len(seen) == 3  # Two metadata refreshes and one missing query.
        records = [json.loads(row) for row in capsys.readouterr().out.splitlines()]
        assert [row["code"] for row in records] == [
            "NATIVE_PACKAGE_NOT_AVAILABLE", "NATIVE_MANAGER_FAILED",
        ]
        assert all(row["passed"] and not row["authorizes_installation"] for row in records)
    else:
        with pytest.raises(ValueError, match="native negative metadata acceptance failed"):
            smoke.verify_negative_metadata(release, version, document, distribution)
    assert "SECRET-NATIVE-OUTPUT" not in capsys.readouterr().out


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_unexpected_generated_source_cannot_pass_as_native_signature_refusal(
    tmp_path, monkeypatch, distribution,
):
    source = (tmp_path / "sources.list" if distribution == "debian"
              else tmp_path / "repos/repocache.repo")
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("unexpected source")
    monkeypatch.setattr(smoke.subprocess, "run",
                        lambda *a, **kw: pytest.fail("unrecognized source executed"))
    runner = smoke.NegativeMetadataRunner(distribution, "bad_metadata_key")
    command = (["/usr/bin/apt-get", "update"] if distribution == "debian"
               else ["/usr/bin/dnf", "makecache"])
    with pytest.raises(ValueError, match="unexpected generated native source"):
        runner(command, cwd=str(tmp_path))
    assert not runner.signature_refused
    assert source.read_text() == "unexpected source"
