"""Signed non-activating client helper candidate and isolation checks."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

import pytest

from repocache import signatures, upgrade
from scripts import stage_native_client_helper as stage
from test_native_root_worker_stage import candidate
from test_v06_release_source_inventory import _candidate_source


def test_deterministic_closed_client_helper_archive(tmp_path):
    source = _candidate_source(tmp_path)
    first = stage.build(source)
    assert first == stage.build(source)
    assert first.startswith(b"#!/usr/bin/python3 -IS\n")
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert archive.namelist() == ["__main__.py", *(m + ".py" for m in stage.MODULES)]
        assert not any("server" in name or "sandbox" in name for name in archive.namelist())
        assert "recovery_journal_v1.py" in archive.namelist()
        assert "recoverable_fallback_pair_lab.py" not in archive.namelist()
        assert "transaction_atomic_lab.py" not in archive.namelist()
    executable = tmp_path / stage.HELPER
    executable.write_bytes(first)
    executable.chmod(0o700)
    (tmp_path / "root_source_boundary.py").write_text("raise RuntimeError('ambient import')\n")
    output = subprocess.run(
        [sys.executable, "-IS", str(executable), "--json", "status"],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(tmp_path)},
        check=False, capture_output=True, timeout=15,
    )
    assert not output.stderr
    report = json.loads(output.stdout)
    assert report["write_eligible"] is False
    if os.geteuid() == 0:
        assert output.returncode == 0
        assert report["commit_available"] is False
    else:
        assert output.returncode == 3
        assert report["error"]["code"] == "ROOT_REQUIRED"


def _stage(candidate, output, **override):
    archive, digest, commit, _ = candidate
    options = {"commit": commit, "archive_sha256": digest,
               "system": {"ID": "debian", "VERSION_ID": "13"}}
    options.update(override)
    return stage.stage_authenticated_client_helper(archive.parent, output, **options)


def test_signed_candidate_stages_exact_helper_without_host_write(candidate, tmp_path):
    output = tmp_path / "client-helper-stage"
    report = _stage(candidate, output)
    assert not report["authorizes_source_mutation"]
    assert not report["authorizes_host_installation"]
    assert report == json.loads((output / stage.RECEIPT).read_bytes())
    helper = output / stage.HELPER
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == report["helper_sha256"]
    assert stat.S_IMODE(helper.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / stage.RECEIPT).stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        _stage(candidate, output)
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == report["helper_sha256"]


@pytest.mark.parametrize("fault", ["archive", "signature", "commit", "digest", "unsupported-os"])
def test_invalid_signed_candidate_leaves_no_client_helper(candidate, tmp_path, fault):
    archive, _, _, detached = candidate
    options = {}
    if fault == "archive":
        archive.write_bytes(b"foreign")
    elif fault == "signature":
        detached.write_bytes(b"\x00" * 64)
    elif fault == "commit":
        options["commit"] = "d" * 40
    elif fault == "digest":
        options["archive_sha256"] = "e" * 64
    else:
        options["system"] = {"ID": "debian", "VERSION_ID": "12"}
    output = tmp_path / "refused"
    with pytest.raises((signatures.SignatureError, upgrade.UpgradeError,
                        stage.ClientHelperStageError)):
        _stage(candidate, output, **options)
    assert not output.exists()


def test_client_helper_stager_in_closed_v06_inventory_only():
    from scripts import build_release
    path = "scripts/stage_native_client_helper.py"
    assert path in build_release.release_files_for_version("0.6.0")
    assert path in upgrade.release_files_for_version("0.6.0")
    for version in ("0.4.0", "0.5.0"):
        assert path not in build_release.release_files_for_version(version)
        assert path not in upgrade.release_files_for_version(version)



def test_private_writer_archive_is_import_only_and_disjoint_from_installed_helper(tmp_path):
    source = _candidate_source(tmp_path)
    helper = stage.build(source)
    private = stage._build_private_writer(source)
    assert private == stage._build_private_writer(source) and private != helper
    assert stage.build(source) == helper
    with zipfile.ZipFile(io.BytesIO(private)) as archive:
        assert archive.namelist() == ["__main__.py",
                                     *(m + ".py" for m in stage._PRIVATE_WRITER_MODULES)]
        assert archive.read("__main__.py") == b"raise SystemExit(3)\n"
        assert set(stage._PRIVATE_WRITER_MODULES) - set(stage.MODULES) == {
            "transaction_stage", "transaction_atomic_lab", "recoverable_fallback_pair_lab"}
        for name in stage._PRIVATE_WRITER_MODULES:
            assert archive.read(name + ".py") == (source / "client" / (name + ".py")).read_bytes()
    path = tmp_path / "private-writer.zip"
    path.write_bytes(private)
    path.chmod(0o600)
    for args in ([], ["--apply"], ["--json", "status"], ["recover", "0"*64]):
        result = subprocess.run([sys.executable, "-IS", "-B", str(path), *args],
                                cwd=tmp_path, capture_output=True, timeout=10)
        assert result.returncode == 3 and not result.stdout and not result.stderr


def test_private_writer_profile_refuses_untrusted_guest_before_asset_reads(monkeypatch, tmp_path):
    from scripts import ci_v06_vm_signed_client_guest as guest
    def deny(platform):
        assert platform == "debian13"
        raise RuntimeError("untrusted guest")
    def unexpected(*args, **kwargs):
        pytest.fail("private writer profile reached authentication")
    monkeypatch.setattr(guest, "guarded_native_guest", deny)
    monkeypatch.setattr(stage, "_authenticated_payload", unexpected)
    with pytest.raises(RuntimeError, match="untrusted guest"):
        stage._authenticated_private_writer_fixture(
            tmp_path, platform="debian13", commit="a"*40, archive_sha256="b"*64)


def test_private_writer_profile_never_uses_normal_publisher_key(candidate, monkeypatch):
    archive, digest, commit, _ = candidate
    # The fixture's normal test publisher is deliberately not the guarded
    # native campaign key. Verify using the unchanged signature verifier.
    monkeypatch.setattr(stage, "_build_private_writer",
                        lambda *_: pytest.fail("unexpected private writer build"))
    with pytest.raises(stage.ClientHelperStageError, match="TEST_KEY_REQUIRED"):
        stage._authenticated_payload(
            archive.parent, commit=commit, archive_sha256=digest,
            system={"ID": "debian", "VERSION_ID": "13"}, private_writer=True)
