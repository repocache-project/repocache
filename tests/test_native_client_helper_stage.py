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
