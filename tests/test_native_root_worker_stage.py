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
from repocache.server_protected_state_store_v1 import LOCK_NAME
from scripts import build_release, install_native_root_worker as install
from scripts import stage_native_root_worker as stage
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
    with pytest.raises(stage.WorkerStageError, match="WORKER_STAGE_INVALID_ASSET"):
        stage.stage_authenticated_worker(tmp_path, output, commit="a" * 40, archive_sha256="b" * 64)
    assert not output.exists()


def test_stage_refuses_malformed_pin_before_enumerating_assets(tmp_path):
    with pytest.raises(stage.WorkerStageError, match="INVALID_EXPECTED_IDENTITY"):
        stage.stage_authenticated_worker(
            Path("must-not-be-opened"), tmp_path / "worker-stage",
            commit="not-a-commit", archive_sha256="b" * 64,
        )



@pytest.mark.skipif(os.geteuid() != 0, reason="requires a disposable root-owned filesystem")
def test_authenticated_installed_readback_refuses_drift(candidate, tmp_path):
    archive, digest, commit, _ = candidate
    payloads, _ = stage._authenticated_payloads(
        archive.parent, commit=commit, archive_sha256=digest,
        system=None if _combined() else {"ID": "debian", "VERSION_ID": "13"},
    )
    root = tmp_path / "installed-fixture"
    worker_dir = root / "usr/libexec/repocache"
    unit_dir = root / "etc/systemd/system"
    worker_dir.mkdir(parents=True)
    unit_dir.mkdir(parents=True)
    for name, raw in payloads.items():
        destination = (worker_dir if name == stage.WORKER else unit_dir) / name
        destination.write_bytes(raw)
        destination.chmod(0o755 if name == stage.WORKER else 0o644)
    stage._audit_worker_files(root, payloads)
    unit = unit_dir / stage.UNITS[0]
    before = unit.read_bytes()
    unit.write_bytes(bytes([before[0] ^ 1]) + before[1:])
    with pytest.raises(stage.WorkerStageError, match="WORKER_INSTALL_CONTENT_MISMATCH"):
        stage._audit_worker_files(root, payloads)
    unit.write_bytes(before)
    unit.chmod(0o666)
    with pytest.raises(stage.WorkerStageError, match="WORKER_INSTALL_METADATA_MISMATCH"):
        stage._audit_worker_files(root, payloads)
    unit.unlink()
    unit.symlink_to(stage.UNITS[1])
    with pytest.raises(OSError):
        stage._audit_worker_files(root, payloads)



def _placement_root(tmp_path):
    root = tmp_path / "root-placement"
    state = root / "var/lib/repocache/server"
    state.mkdir(parents=True, mode=0o700)
    lock = state / LOCK_NAME
    lock.touch(mode=0o600)
    lock.chmod(0o600)
    (root / "usr/libexec/repocache").mkdir(parents=True)
    (root / "etc/systemd/system").mkdir(parents=True)
    return root, state


_UNIT_PATHS = ("/etc/systemd/system", "/usr/lib/systemd/system")


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a disposable root-owned filesystem")
def test_authenticated_placement_recovers_interrupted_atomic_publish(candidate, tmp_path, monkeypatch):
    archive, digest, commit, _ = candidate
    payloads, receipt = stage._authenticated_payloads(
        archive.parent, commit=commit, archive_sha256=digest,
        system=None if _combined() else {"ID": "debian", "VERSION_ID": "13"},
    )
    root, state = _placement_root(tmp_path)
    current_finish = install._finish_link

    def interrupted(*_args):
        raise InterruptedError("injected after the atomic no-replace link")

    monkeypatch.setattr(install, "_finish_link", interrupted)
    with pytest.raises(InterruptedError):
        install._place_worker_files(root, payloads, receipt, unit_paths=_UNIT_PATHS)
    worker = root / "usr/libexec/repocache" / stage.WORKER
    assert worker.stat().st_nlink == 2
    assert len(tuple(state.glob(".native-worker-placement.pending-*"))) == 1
    with pytest.raises(stage.WorkerStageError, match="OTHER_CANDIDATE"):
        install._place_worker_files(root, payloads, {**receipt, "source_sha": "d" * 40},
                                    unit_paths=_UNIT_PATHS)
    monkeypatch.setattr(install, "_finish_link", current_finish)
    install._place_worker_files(root, payloads, receipt, unit_paths=_UNIT_PATHS)
    stage._audit_worker_files(root, payloads)
    assert worker.stat().st_nlink == 1
    assert not tuple(state.glob(".native-worker-placement.pending-*"))
    assert len(tuple(state.glob(".native-worker-placement.complete-*"))) == 1
    before = worker.stat()
    install._place_worker_files(root, payloads, receipt, unit_paths=_UNIT_PATHS)
    assert worker.stat().st_ino == before.st_ino
    assert worker.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a disposable root-owned filesystem")
@pytest.mark.parametrize("conflict,code", [
    ("etc/systemd/system/repocache-control.service", "FOREIGN_EXISTING_DESTINATION"),
    ("usr/lib/systemd/system/repocache-control.socket", "FOREIGN_UNIT_OR_OVERRIDE"),
    ("etc/systemd/system/repocache-control.service.d/test.conf", "FOREIGN_UNIT_OR_OVERRIDE"),
    ("etc/systemd/system/sockets.target.wants/repocache-control.socket", "FOREIGN_UNIT_DEPENDENCY"),
    ("run/repocache/server-control.sock", "LIVE_CONTROL_SOCKET"),
])
def test_placement_preserves_foreign_paths_before_any_write(tmp_path, conflict, code):
    root, state = _placement_root(tmp_path)
    foreign = root / conflict
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_bytes(b"foreign transport or unit file")
    payloads = {name: b"test bytes" for name in (stage.WORKER, *stage.UNITS)}
    with pytest.raises(stage.WorkerStageError, match=code):
        install._place_worker_files(root, payloads, {"source_sha": "a" * 40},
                                    unit_paths=_UNIT_PATHS)
    assert foreign.read_bytes() == b"foreign transport or unit file"
    assert not tuple(state.glob(".native-worker-placement.*"))
    assert not (root / "usr/libexec/repocache" / stage.WORKER).exists()


def test_systemd_unit_paths_use_the_running_manager_and_refuse_unusable_values(monkeypatch):
    seen = []
    class Result:
        returncode = 0
        stdout = b"/etc/systemd/system /usr/lib/systemd/system\n"

    def run(argv, **kwargs):
        seen.append(argv)
        assert kwargs["timeout"] == 12
        return Result()

    monkeypatch.setattr(install.subprocess, "run", run)
    assert install._systemd_unit_paths() == _UNIT_PATHS
    assert seen == [[
        "/usr/bin/systemctl", "--system", "--no-pager", "show", "--property=UnitPath", "--value",
    ]]
    Result.stdout = b"/etc/systemd/system /untrusted/../path\n"
    with pytest.raises(stage.WorkerStageError, match="UNIT_PATH_UNVERIFIED"):
        install._systemd_unit_paths()



def test_stage_does_not_open_a_fifo_for_io(tmp_path):
    os.mkfifo(tmp_path / stage.ARCHIVE)
    with pytest.raises(stage.WorkerStageError, match="WORKER_STAGE_INVALID_ASSET"):
        stage.stage_authenticated_worker(tmp_path, tmp_path / "unused",
                                         commit="a" * 40, archive_sha256="b" * 64)
