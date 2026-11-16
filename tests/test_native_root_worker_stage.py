"""Exercise authenticated worker staging with disposable Ed25519 keys."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import time

import pytest

from repocache import signatures, upgrade
from scripts import build_release, stage_native_root_worker as stage
from test_signatures import _openssl, _sign
from test_v06_release_source_inventory import _candidate_source


def _combined() -> bool:
    return os.environ.get("REPOCACHE_REQUIRE_CANONICAL_WORKER_VERIFIER") == "1"


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    source = _candidate_source(tmp_path)
    monkeypatch.setattr(build_release, "ROOT", source)
    archive, _checksum = build_release.build_release(tmp_path / "assets", "v0.6.0")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    now = int(time.time())
    payload = {
        "schema": 1, "repository": stage.EXPECTED_REPOSITORY, "key_id": "worker-test",
        "channel": "stable", "version": "0.6.0", "commit": "a" * 40,
        "archive": stage.ARCHIVE, "archive_sha256": digest,
        "policy_sha256": hashlib.sha256((source / "release-policy.json").read_bytes()).hexdigest(),
        "wheelhouse_sha256": "b" * 64, "issued_at": now - 30, "expires_at": now + 3600,
    }
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        signatures._parse(raw)
    except signatures.SignatureError:
        if _combined():
            raise
        pytest.skip("canonical v0.6 issuer verifier from #249 runs in combined CI")

    private = tmp_path / "private.pem"
    trust = tmp_path / "etc" / "repocache" / "trust.d"
    trust.mkdir(parents=True, mode=0o700)
    public = trust / "worker-test.pem"
    _openssl("genpkey", "-algorithm", "Ed25519", "-out", str(private))
    _openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
    if os.geteuid() == 0:
        monkeypatch.setattr(signatures, "TRUST_DIR", trust)
    else:
        monkeypatch.setattr(signatures, "_trusted_key", lambda _key_id: public)
    manifest = archive.with_name(archive.name + ".manifest.json")
    manifest.write_bytes(raw)
    detached = manifest.with_name(manifest.name + ".sig")
    detached.write_bytes(_sign(raw, private, tmp_path))
    return archive, digest, payload["commit"], detached


def _stage(candidate, output, **overrides):
    archive, digest, commit, _detached = candidate
    options = {"commit": commit, "archive_sha256": digest,
               "system": None if _combined() else {"ID": "debian", "VERSION_ID": "13"}}
    options.update(overrides)
    return stage.stage_authenticated_worker(archive.parent, output, **options)


def test_authenticated_stage_binds_closed_files_and_never_overwrites(candidate, tmp_path):
    output = tmp_path / "worker-stage"
    report = _stage(candidate, output)
    assert report["authorizes_host_installation"] is False
    assert report["authorizes_service_activation"] is False
    assert report["archive_sha256"] == candidate[1]
    assert report["files"].keys() == {stage.WORKER, *stage.UNITS}
    assert {p.name for p in output.iterdir()} == {*report["files"], stage.RECEIPT}
    assert report == json.loads((output / stage.RECEIPT).read_bytes())
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for name, digest in report["files"].items():
        file = output / name
        assert hashlib.sha256(file.read_bytes()).hexdigest() == digest
        assert stat.S_IMODE(file.stat().st_mode) == (0o700 if name == stage.WORKER else 0o600)
    assert (output / stage.WORKER).read_bytes().startswith(b"#!/usr/bin/python3 -IS\n")
    with pytest.raises(FileExistsError):
        _stage(candidate, output)
    assert report == json.loads((output / stage.RECEIPT).read_bytes())


@pytest.mark.parametrize("fault", ["archive", "signature", "commit", "digest", "unsupported-os"])
def test_invalid_candidate_or_pin_leaves_no_output(candidate, tmp_path, fault):
    archive, _digest, _commit, detached = candidate
    options = {}
    if fault == "archive":
        archive.write_bytes(b"unverified archive bytes")
    elif fault == "signature":
        detached.write_bytes(b"\x00" * 64)
    elif fault == "commit":
        options["commit"] = "d" * 40
    elif fault == "digest":
        options["archive_sha256"] = "f" * 64
    else:
        options["system"] = {"ID": "debian", "VERSION_ID": "12"}
    output = tmp_path / "worker-stage"
    with pytest.raises((signatures.SignatureError, stage.WorkerStageError, upgrade.UpgradeError)):
        _stage(candidate, output, **options)
    assert not output.exists()


def test_stage_refuses_symlinked_asset(tmp_path):
    outside = tmp_path / "unrelated"
    outside.write_bytes(b"must not be opened through the candidate name")
    (tmp_path / stage.ARCHIVE).symlink_to(outside)
    output = tmp_path / "worker-stage"
    with pytest.raises(OSError):
        stage.stage_authenticated_worker(tmp_path, output, commit="a" * 40, archive_sha256="b" * 64)
    assert not output.exists()


def test_stage_refuses_malformed_pin_before_enumerating_assets(tmp_path):
    with pytest.raises(stage.WorkerStageError, match="INVALID_EXPECTED_IDENTITY"):
        stage.stage_authenticated_worker(
            Path("must-not-be-opened"), tmp_path / "worker-stage",
            commit="not-a-commit", archive_sha256="b" * 64,
        )
