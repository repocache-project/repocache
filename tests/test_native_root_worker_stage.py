"""Exercise authenticated worker staging with disposable Ed25519 keys."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import pytest

from repocache import signatures, upgrade
from repocache.server_protected_state_store_v1 import LOCK_NAME
from scripts import build_release, install_native_root_worker as install
from scripts import stage_native_root_worker as stage
from test_signatures import _openssl, _sign
from test_v06_release_source_inventory import _candidate_source
from test_server_proposed_state_v2_store import document, snapshot


def _combined() -> bool:
    return os.environ.get("REPOCACHE_REQUIRE_CANONICAL_WORKER_VERIFIER") == "1"


@pytest.mark.parametrize("operation", ["place", "stage"])
def test_unsupported_native_target_refused_before_any_worker_or_proposal_effect(monkeypatch, operation, tmp_path):
    from repocache.server_native_root_control_entrypoint_v1 import NativeControlDispatchError
    def refuse():
        raise NativeControlDispatchError("NATIVE_ROOT_CONTROL_DISTRO_UNAVAILABLE")
    def forbidden(*a, **kw):
        pytest.fail("host context, asset reads or persistent placement reached")
    monkeypatch.setattr(install, "_native_distro", refuse)
    monkeypatch.setattr(install, "require_native_host_preconditions", forbidden)
    monkeypatch.setattr(stage, "_authenticated_payloads", forbidden)
    monkeypatch.setattr(stage, "verify_installed_worker", forbidden)
    monkeypatch.setattr(install, "_place_worker_files", forbidden)
    monkeypatch.setattr(install, "_stage_proposal_under_root", forbidden)
    with pytest.raises(NativeControlDispatchError):
        if operation == "place":
            install.install_authenticated_worker(tmp_path, commit="a" * 40, archive_sha256="b" * 64)
        else:
            install.stage_authenticated_proposal(tmp_path, tmp_path / "proposal", commit="a" * 40,
                archive_sha256="b" * 64, proposal_sha256="c" * 64)
    assert not list(tmp_path.iterdir())


def test_initial_proposal_matches_adopted_snapshot_and_allocates_stable_ids():
    config = document(count=3, generation=0)

    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")

    assert install._initial_proposal(encoded(config), "d" * 64) == encoded(snapshot(count=3))
    for row in config["repositories"][1:]:
        del row["id"]
    raw = encoded(config)
    first = install._initial_proposal(raw, "d" * 64)
    assert install._initial_proposal(raw, "d" * 64) == first
    proposed = json.loads(first)
    ids = [row["id"] for row in proposed["repository_records"]]
    assert ids[0] == "repo-0"
    assert len(set(ids)) == 3
    assert all(row.startswith("repo-") and len(row) == 37 for row in ids[1:])
    assert all(row["status"] == "allocated" for row in proposed["id_reservations"])
    assert proposed["approval_reference"]["expected_generation"] == 0
    assert json.loads(raw) == config


@pytest.mark.parametrize("fault", ["generation", "decision", "duplicate", "unsafe-upstream"])
def test_initial_proposal_refuses_invalid_input(fault):
    config = document(count=2, generation=0)
    decision = "d" * 64
    if fault == "generation":
        config["expected_state_generation"] = 1
    elif fault == "decision":
        decision = "not-a-sha256"
    elif fault == "duplicate":
        config["repositories"][1]["id"] = "repo-0"
    else:
        config["repositories"][0]["upstream"]["base_url"] = "https://127.0.0.1/debian/"
    with pytest.raises(ValueError):
        install._initial_proposal(json.dumps(config).encode(), decision)


def test_partial_repair_preserves_reservations_and_exact_no_change():
    old = snapshot(count=2)
    prior = snapshot(count=1, generation=2, previous=old)
    prior_raw = json.dumps(prior, sort_keys=True, separators=(",", ":")).encode()
    prior_sha = hashlib.sha256(prior_raw).hexdigest()
    proposed = document(count=0, generation=2)
    raw = json.dumps(proposed).encode()
    assert install._repair_proposal(raw, prior_raw, prior_sha, "e" * 64) == prior_raw
    proposed["deployment"]["cache_policy"]["global"]["inactive_seconds"] += 1
    result = json.loads(install._repair_proposal(
        json.dumps(proposed).encode(), prior_raw, prior_sha, "e" * 64,
    ))
    assert result["state_generation"] == 3
    assert result["id_reservations"] == prior["id_reservations"]
    assert result["repository_records"] == prior["repository_records"]
    assert result["approval_reference"]["expected_generation"] == 2


@pytest.mark.parametrize("fault", ["digest", "stale", "new-id", "version", "decision"])
def test_partial_repair_refuses_invalid_predecessor_or_intent(fault):
    prior = snapshot(count=1)
    proposed = document(count=1, generation=1)
    decision = "d" * 64
    if fault == "stale":
        proposed["expected_state_generation"] = 0
    elif fault == "new-id":
        proposed["repositories"][0]["id"] = "unallocated"
    elif fault == "version":
        prior["state_schema_version"] = 1
    elif fault == "decision":
        decision = "bad-decision"
    prior_raw = json.dumps(prior, sort_keys=True, separators=(",", ":")).encode()
    digest = "0" * 64 if fault == "digest" else hashlib.sha256(prior_raw).hexdigest()
    with pytest.raises(ValueError):
        install._repair_proposal(json.dumps(proposed).encode(), prior_raw, digest, decision)


def test_prepare_initial_proposal_authenticates_before_input_or_output(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise stage.WorkerStageError("WORKER_STAGE_SIGNED_IDENTITY_MISMATCH")

    monkeypatch.setattr(stage, "_authenticated_payloads", refuse)
    output = tmp_path / "proposal.json"
    with pytest.raises(stage.WorkerStageError, match="SIGNED_IDENTITY_MISMATCH"):
        install.prepare_authenticated_proposal(
            tmp_path, tmp_path / "missing-input.json", output,
            commit="a" * 40, archive_sha256="b" * 64, decision_sha256="d" * 64,
        )
    assert not output.exists()


def test_prepare_initial_proposal_refuses_shared_output_parent(tmp_path, monkeypatch):
    monkeypatch.setattr(stage, "_authenticated_payloads", lambda *args, **kwargs: ({}, {}))
    source = tmp_path / "reviewed-install.json"
    source.write_text(json.dumps(document(count=1, generation=0)))
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o777)
    output = parent / "proposal.json"
    with pytest.raises(stage.WorkerStageError, match="PROPOSAL_OUTPUT_UNSAFE"):
        install.prepare_authenticated_proposal(
            tmp_path, source, output,
            commit="a" * 40, archive_sha256="b" * 64, decision_sha256="d" * 64,
        )
    assert not output.exists()


@pytest.mark.parametrize("repair", [False, True])
def test_prepare_proposal_has_private_no_replace_output(candidate, tmp_path, monkeypatch, repair):
    authenticate = stage._authenticated_payloads

    def compatible(*args, **kwargs):
        if not _combined():
            kwargs["system"] = {"ID": "debian", "VERSION_ID": "13"}
        return authenticate(*args, **kwargs)

    monkeypatch.setattr(stage, "_authenticated_payloads", compatible)
    archive, digest, commit, _detached = candidate
    source = tmp_path / "reviewed-install.json"
    config = document(count=1, generation=int(repair))
    options = {}
    if repair:
        prior = tmp_path / "previous-state.json"
        prior.write_bytes(json.dumps(snapshot(count=1), sort_keys=True, separators=(",", ":")).encode())
        options = {"previous": prior, "previous_sha256": hashlib.sha256(prior.read_bytes()).hexdigest()}
        config["deployment"]["cache_policy"]["global"]["inactive_seconds"] += 1
    source.write_text(json.dumps(config))
    output = tmp_path / "private" / "reviewed-state.json"
    output.parent.mkdir(mode=0o700)
    receipt = install.prepare_authenticated_proposal(
        archive.parent, source, output,
        commit=commit, archive_sha256=digest, decision_sha256="d" * 64, **options,
    )
    raw = output.read_bytes()
    assert receipt["proposed_state_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["requires_operator_review"]
    assert receipt["state_generation"] == 1 + int(repair)
    assert receipt["expected_state_sha256"] == options.get("previous_sha256")
    assert not receipt["authorizes_service_activation"]
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        install.prepare_authenticated_proposal(
            archive.parent, source, output,
            commit=commit, archive_sha256=digest, decision_sha256="d" * 64, **options,
        )
    assert output.read_bytes() == raw


@pytest.mark.parametrize("options", [
    ["--prepare-initial-v2-proposal", "install.json"],
    ["--decision-sha256", "d" * 64],
    ["--proposal-output", "output.json"],
    ["--prepare-v2-repair", "install.json", "--proposal-output", "out.json", "--decision-sha256", "d" * 64],
    ["--previous-v2-state", "state.json", "--previous-state-sha256", "e" * 64],
    ["--expected-state-sha256", "e" * 64],
    ["--prepare-initial-v2-proposal", "install.json", "--stage-v2-proposal", "state.json"],
])
def test_invalid_preparation_cli_never_falls_back_to_host_placement(monkeypatch, options):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid preparation reached a host operation")

    monkeypatch.setattr(install, "install_authenticated_worker", unexpected)
    monkeypatch.setattr(install, "stage_authenticated_proposal", unexpected)
    monkeypatch.setattr(install, "prepare_authenticated_proposal", unexpected)
    monkeypatch.setattr(sys, "argv", [
        "install_native_root_worker.py", "--assets", "incoming",
        "--commit", "a" * 40, "--archive-sha256", "b" * 64, *options,
    ])
    with pytest.raises(SystemExit) as error:
        install.main()
    assert error.value.code == 2


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
    # The private NGINX config is signed and staged, but installed only by
    # the separately authorized service activation operation.
    assert report["files"].keys() == {stage.WORKER, *stage.UNITS, stage.CONFIG}
    assert (output / stage.CONFIG).read_bytes() == (
        Path(__file__).resolve().parents[1] / stage.CONFIG_SOURCE
    ).read_bytes()
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
    with pytest.raises(stage.WorkerStageError, match="WORKER_STAGE_INVALID_ASSET"):
        stage._audit_worker_files(root, payloads)



def _placement_root(tmp_path, *, worker_parent=True, protected_state=True):
    root = tmp_path / "root-placement"
    state = root / "var/lib/repocache/server"
    (root / "var/lib").mkdir(parents=True)
    if protected_state:
        state.mkdir(parents=True, mode=0o700)
        lock = state / LOCK_NAME
        lock.touch(mode=0o600)
        lock.chmod(0o600)
    (root / "usr").mkdir()
    if worker_parent:
        (root / "usr/libexec/repocache").mkdir(parents=True)
    (root / "etc/systemd/system").mkdir(parents=True)
    return root, state


_UNIT_PATHS = ("/etc/systemd/system", "/usr/lib/systemd/system")


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a disposable root-owned filesystem")
def test_clean_placement_prepares_only_fixed_protected_and_public_directories(tmp_path):
    root, state = _placement_root(tmp_path, worker_parent=False, protected_state=False)
    payloads = {name: b"fixed signed payload" for name in (stage.WORKER, *stage.UNITS)}
    receipt = {"source_sha": "a" * 40}
    previous_umask = os.umask(0o077)
    try:
        install._place_worker_files(root, payloads, receipt, unit_paths=_UNIT_PATHS,
                                    prepare_namespace=True)
    finally:
        os.umask(previous_umask)
    catalog = state.parent / "public"
    for path, mode in ((state.parent, 0o711), (state, 0o700),
                       (catalog, 0o755), (state / LOCK_NAME, 0o600)):
        info = path.stat()
        assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, mode)
    assert not list(catalog.iterdir())
    if _combined():
        # Use an inherited directory descriptor so the probe tests these
        # three directories, rather than the test runner's private parents.
        fd = os.open(root / "var/lib", os.O_RDONLY | os.O_DIRECTORY)
        try:
            check = subprocess.run(
                [sys.executable, "-I", "-c",
                 "from pathlib import Path; import os, sys; "
                 "base = Path('/proc/self/fd') / sys.argv[1] / 'repocache'; "
                 "assert list((base / 'public').iterdir()) == []; "
                 "assert not os.access(base / 'server', os.X_OK)",
                 str(fd)],
                user=65534, group=65534, extra_groups=(), pass_fds=(fd,),
                capture_output=True,
            )
        finally:
            os.close(fd)
        assert check.returncode == 0, check.stderr.decode()
    lock_inode = (state / LOCK_NAME).stat().st_ino
    install._place_worker_files(root, payloads, receipt, unit_paths=_UNIT_PATHS,
                                prepare_namespace=True)
    assert (state / LOCK_NAME).stat().st_ino == lock_inode
    stage._audit_worker_files(root, payloads)


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a disposable root-owned filesystem")
def test_clean_placement_refuses_incompatible_existing_namespace(tmp_path):
    root, state = _placement_root(tmp_path, worker_parent=False)
    state.parent.chmod(0o700)
    original = state.parent.stat()
    payloads = {name: b"fixed signed payload" for name in (stage.WORKER, *stage.UNITS)}
    with pytest.raises(ValueError, match="OWNERSHIP_OR_MOUNT_UNVERIFIED"):
        install._place_worker_files(root, payloads, {"source_sha": "a" * 40},
                                    unit_paths=_UNIT_PATHS, prepare_namespace=True)
    assert state.parent.stat() == original
    assert not (state.parent / "public").exists()
    assert not (root / "usr/libexec").exists()
    assert {path.name for path in state.iterdir()} == {LOCK_NAME}


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a disposable root-owned filesystem")
def test_clean_placement_recovers_interrupted_worker_directory_creation(tmp_path, monkeypatch):
    root, state = _placement_root(tmp_path, worker_parent=False)
    payloads = {name: b"fixed signed payload" for name in (stage.WORKER, *stage.UNITS)}
    receipt = {"source_sha": "a" * 40}
    mkdir = os.mkdir

    def interrupted(name, *, mode, dir_fd):
        mkdir(name, mode, dir_fd=dir_fd)
        raise InterruptedError("after mkdir, before directory sync")

    with monkeypatch.context() as point:
        point.setattr(install.os, "mkdir", interrupted)
        with pytest.raises(InterruptedError):
            install._place_worker_files(root, payloads, receipt, unit_paths=_UNIT_PATHS)
    assert list(state.glob(".native-worker-placement.pending-*"))
    assert (root / "usr/libexec").is_dir()
    assert not (root / "usr/libexec/repocache").exists()
    assert not list((root / "etc/systemd/system").iterdir())

    install._place_worker_files(root, payloads, receipt, unit_paths=_UNIT_PATHS)
    stage._audit_worker_files(root, payloads)
    assert not list(state.glob(".native-worker-placement.pending-*"))
    assert len(list(state.glob(".native-worker-placement.complete-*"))) == 1
    worker_parent = root / "usr/libexec/repocache"
    before = worker_parent.stat()
    install._place_worker_files(root, payloads, receipt, unit_paths=_UNIT_PATHS)
    assert worker_parent.stat().st_ino == before.st_ino
    assert worker_parent.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a disposable root-owned filesystem")
def test_worker_directory_must_not_follow_existing_link(tmp_path):
    root, state = _placement_root(tmp_path, worker_parent=False)
    foreign = root / "alien"
    foreign.mkdir()
    (root / "usr/libexec").symlink_to(foreign, target_is_directory=True)
    payloads = {name: b"fixed signed payload" for name in (stage.WORKER, *stage.UNITS)}
    with pytest.raises(OSError):
        install._place_worker_files(
            root, payloads, {"source_sha": "a" * 40}, unit_paths=_UNIT_PATHS,
        )
    assert not list(foreign.iterdir())
    assert not list(state.glob(".native-worker-placement.*"))
    assert not list((root / "etc/systemd/system").iterdir())


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
    local_receipt = state / install._RUNTIME_RECEIPT
    raw = stage._json_line(receipt)
    assert local_receipt.read_bytes() == raw
    assert stat.S_IMODE(local_receipt.stat().st_mode) == 0o600
    assert (state / (install._MARKER + "complete-" + hashlib.sha256(raw).hexdigest())).is_file()
    receipt_before = local_receipt.stat()
    install._place_worker_files(root, payloads, receipt, unit_paths=_UNIT_PATHS)
    assert local_receipt.stat().st_ino == receipt_before.st_ino
    assert local_receipt.stat().st_mtime_ns == receipt_before.st_mtime_ns
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
    root, state = _placement_root(tmp_path, worker_parent=False)
    foreign = root / conflict
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_bytes(b"foreign transport or unit file")
    payloads = {name: b"test bytes" for name in (stage.WORKER, *stage.UNITS)}
    with pytest.raises(stage.WorkerStageError, match=code):
        install._place_worker_files(root, payloads, {"source_sha": "a" * 40},
                                    unit_paths=_UNIT_PATHS)
    assert foreign.read_bytes() == b"foreign transport or unit file"
    assert not tuple(state.glob(".native-worker-placement.*"))
    assert not (root / "usr/libexec/repocache").exists()


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


def test_native_installer_requires_signed_worker_before_reading_install_document(
    tmp_path, monkeypatch,
):
    from scripts import install_native_root_worker as host
    monkeypatch.setattr(host, "_native_distro", lambda: "debian")
    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: {})
    def invalid(*_args, **_kwargs):
        raise stage.WorkerStageError("WORKER_STAGE_SIGNED_IDENTITY_MISMATCH")
    monkeypatch.setattr(stage, "verify_installed_worker", invalid)
    with pytest.raises(stage.WorkerStageError, match="SIGNED_IDENTITY_MISMATCH"):
        host.install_authenticated_native_nginx(
            tmp_path, tmp_path / "not-found.json", "a" * 64,
            commit="b" * 40, archive_sha256="c" * 64,
        )
    assert not list(tmp_path.iterdir())


def test_native_installer_refuses_unpinned_document_without_package_effects(
    tmp_path, monkeypatch,
):
    from scripts import install_native_root_worker as host
    monkeypatch.setattr(host, "_native_distro", lambda: "debian")
    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: {})
    monkeypatch.setattr(stage, "verify_installed_worker", lambda *a, **kw: {
        "status": "AUTHENTICATED_WORKER_FILES_MATCH",
        "source_sha": "b" * 40, "archive_sha256": "c" * 64,
        "authorizes_host_installation": False,
        "authorizes_service_activation": False,
    })
    def forbidden(*_args, **_kwargs):
        pytest.fail("native manager, journal or systemd reached without document trust")
    monkeypatch.setattr(host, "_execute_native_nginx_install_locked", forbidden)
    source = tmp_path / "reviewed.json"
    source.write_text(json.dumps(document(count=1, generation=0)))
    for digest in ("bad", "a" * 64):
        with pytest.raises(ValueError, match="NATIVE_DOCUMENT_PIN"):
            host.install_authenticated_native_nginx(
                tmp_path, source, digest, commit="b" * 40, archive_sha256="c" * 64,
            )


def test_native_install_cli_refuses_missing_document_digest_before_host_actions(
    tmp_path,
):
    from scripts import install_native_root_worker as host
    result = subprocess.run(
        [sys.executable, "-I", str(Path(host.__file__)),
         "--assets", str(tmp_path), "--commit", "a" * 40,
         "--archive-sha256", "b" * 64,
         "--install-native-nginx", str(tmp_path / "reviewed.json")],
        capture_output=True, timeout=15, check=False,
    )
    assert result.returncode == 2
    assert b"--document-sha256" in result.stderr
    assert not list(tmp_path.iterdir())


def test_native_package_signature_receipt_must_match_pinned_candidate(
    tmp_path, monkeypatch,
):
    from scripts import install_native_root_worker as host
    monkeypatch.setattr(host, "_native_distro", lambda: "debian")
    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: {})
    monkeypatch.setattr(stage, "verify_installed_worker", lambda *a, **kw: {
        "status": "AUTHENTICATED_WORKER_FILES_MATCH",
        "source_sha": "0" * 40, "archive_sha256": "c" * 64,
        "authorizes_host_installation": False,
        "authorizes_service_activation": False,
    })
    with pytest.raises(ValueError, match="NATIVE_SIGNED_WORKER_AUDIT_UNVERIFIED"):
        host.install_authenticated_native_nginx(
            tmp_path, tmp_path / "unread.json", "a" * 64,
            commit="b" * 40, archive_sha256="c" * 64,
        )
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(os.geteuid() != 0, reason="requires disposable root-owned fixture")
@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_synthetic_signed_candidate_enters_exact_native_journal_once(
    candidate, tmp_path, monkeypatch, distribution,
):
    """Signed source -> pinned installed bytes -> parsed intent -> locked journal.

    All host-specific service, package and preflight side effects are mocked;
    this is NOT a native systemd, real signing-key or publisher acceptance test.
    """
    from types import SimpleNamespace
    from test_server_native_nginx_package_journal_v1 import _synthetic_host_native_package
    from repocache.server_native_nginx_package_journal_v1 import (
        NATIVE_PENDING_NAME, NATIVE_COMPLETE_NAME,
    )
    archive, digest, commit, detached = candidate
    system = None if _combined() else {"ID": "debian", "VERSION_ID": "13"}
    sysroot = tmp_path / "isolated-host"
    sysroot.mkdir(mode=0o700)
    source_payloads, placement_receipt = stage._authenticated_payloads(
        archive.parent, commit=commit, archive_sha256=digest, system=system,
    )
    for parent, names, mode in (
        ("usr/libexec/repocache", [stage.WORKER], 0o755),
        ("etc/systemd/system", stage.UNITS, 0o644),
    ):
        folder = sysroot / parent
        folder.mkdir(parents=True, mode=0o700)
        for name in names:
            dest = folder / name
            dest.write_bytes(source_payloads[name])
            dest.chmod(mode)

    state = sysroot / "var/lib/repocache/server"
    state.mkdir(parents=True, mode=0o700)
    # Match the native OS pre-existing /var/cache anchor. The signed
    # installer must create ONLY the fixed missing nginx cache leaf.
    (sysroot / "var" / "cache").mkdir(parents=True, mode=0o755)
    (state / LOCK_NAME).write_bytes(b"")
    (state / LOCK_NAME).chmod(0o600)
    receipt_raw = stage._json_line(placement_receipt)
    receipt_path = state / install._RUNTIME_RECEIPT
    receipt_path.write_bytes(receipt_raw)
    receipt_path.chmod(0o600)
    marker = state / (install._MARKER + "complete-" + hashlib.sha256(receipt_raw).hexdigest())
    marker.touch(mode=0o600)
    install_document = tmp_path / "reviewed-native-install.json"
    install_document.write_bytes(
        (json.dumps(document(count=1, generation=0), sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    pinned_document = hashlib.sha256(install_document.read_bytes()).hexdigest()
    old_execute = install._execute_native_nginx_install_locked
    real_payloads = stage._authenticated_payloads
    authenticated = []

    def verify_synthetic_installed_bytes(assets, *, commit, archive_sha256):
        payloads, receipt = real_payloads(
            assets, commit=commit, archive_sha256=archive_sha256, system=system,
        )
        stage._audit_worker_files(sysroot, payloads)
        authenticated.append(receipt["manifest_sha256"])
        return {**receipt, "status": "AUTHENTICATED_WORKER_FILES_MATCH"}

    monkeypatch.setattr(stage, "verify_installed_worker", verify_synthetic_installed_bytes)
    monkeypatch.setattr(install, "_native_distro", lambda: distribution)
    monkeypatch.setattr(install, "require_native_host_preconditions", lambda: {})
    monkeypatch.setattr(
        install, "inspect_native_nginx_local_boundary",
        lambda **_kw: SimpleNamespace(
            distribution=distribution, code="LOCAL_READ_ONLY_SNAPSHOT_OBSERVED",
        ),
    )
    host, effects = _synthetic_host_native_package(monkeypatch, distribution)

    fake_root = os.open(sysroot, os.O_RDONLY | os.O_DIRECTORY)
    try:
        def isolated_native_effects(_real_host_root, **kwargs):
            return old_execute(fake_root, **kwargs)
        monkeypatch.setattr(
            host, "_execute_native_nginx_install_locked", isolated_native_effects,
        )
        first = host.install_authenticated_native_nginx(
            archive.parent, install_document, pinned_document,
            commit=commit, archive_sha256=digest,
        )
        assert first["status"] == "AUTHENTICATED_NATIVE_NGINX_PACKAGE_INSTALLED"
        assert first["authorizes_service_activation"] is False
        assert authenticated
        assert ("INSTALL",) in effects["commands"]
        assert not (state / NATIVE_PENDING_NAME).exists()
        receipt = (state / NATIVE_COMPLETE_NAME).read_bytes()
        actions_before_retry = list(effects["actions"])
        with pytest.raises(ValueError):
            host.install_authenticated_native_nginx(
                archive.parent, install_document, pinned_document,
                commit=commit, archive_sha256=digest,
            )
        assert effects["actions"] == actions_before_retry
        assert (state / NATIVE_COMPLETE_NAME).read_bytes() == receipt

        # The document, signature and installed root-owned bytes are each
        # independently rechecked before any further native side effects.
        install_document.write_bytes(b"tampered")
        with pytest.raises(ValueError):
            host.install_authenticated_native_nginx(
                archive.parent, install_document, pinned_document,
                commit=commit, archive_sha256=digest,
            )
        assert effects["actions"] == actions_before_retry
        detached.write_bytes(b"invalid synthetic signature")
        with pytest.raises((signatures.SignatureError, stage.WorkerStageError)):
            host.install_authenticated_native_nginx(
                archive.parent, install_document, pinned_document,
                commit=commit, archive_sha256=digest,
            )
        assert (state / NATIVE_COMPLETE_NAME).read_bytes() == receipt
    finally:
        os.close(fake_root)


def test_executable_candidate_requires_native_host_before_asset_access(monkeypatch, tmp_path):
    monkeypatch.setattr(install, "_native_distro", lambda: "debian")
    def refuse():
        raise RuntimeError("fixture host refused")
    monkeypatch.setattr(install, "require_native_host_preconditions", refuse)
    monkeypatch.setattr(stage, "_authenticated_payloads",
                        lambda *a, **kw: pytest.fail("asset access before native host proof"))
    with pytest.raises(RuntimeError, match="fixture host refused"):
        install._stage_authenticated_native_executable_candidate(
            tmp_path, commit="a" * 40, archive_sha256="b" * 64)

@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_executable_candidate_selects_retained_native_effects_lock(
    monkeypatch, tmp_path, distribution,
):
    monkeypatch.setattr(install, "_native_distro", lambda: distribution)
    monkeypatch.setattr(install, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(stage, "_authenticated_payloads",
                        lambda *a, **kw: ({}, {"fixture": True}))

    def stop_at_lock(root_fd, owner_uid, *, allow_native_package_parent_changes=False):
        assert root_fd >= 0 and owner_uid == 0
        assert allow_native_package_parent_changes is True
        raise RuntimeError("fixture stopped before host access")

    monkeypatch.setattr(install, "_locked", stop_at_lock)
    with pytest.raises(RuntimeError, match="fixture stopped before host access"):
        install._stage_authenticated_native_executable_candidate(
            tmp_path, commit="a" * 40, archive_sha256="b" * 64)


@pytest.mark.parametrize("fault", ["invalid-pin", "debian", "release", "placement",
                                   "wal", "package", "child", "wrong-report", "none",
                                   "rolled", "rolled-refusal", "prepare", "prepare-wal",
                                   "prepare-manifest", "prepare-boot", "prepare-report"])
def test_prepared_dedicated_installer_bridge_uses_fresh_child_lock(monkeypatch, tmp_path, fault):
    from contextlib import contextmanager
    from types import SimpleNamespace
    wal = b"test WAL"
    receipt = {"source_sha": "a"*40}
    expected = stage._json_line(receipt)
    marker = install._MARKER + "complete-" + hashlib.sha256(expected).hexdigest()
    state = tmp_path / "state"
    state.mkdir()
    (state / marker).touch()
    calls = []
    locked = False
    def auth(*args, **kwargs):
        calls.append("release")
        if fault == "release":
            raise stage.WorkerStageError("UNAUTHENTICATED")
        return {stage.CONFIG: install._BOOTSTRAP_CONFIG, stage.WORKER: b"worker"}, receipt
    monkeypatch.setattr(install, "_native_distro", lambda: "debian" if fault == "debian" else "almalinux")
    monkeypatch.setattr(install, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(stage, "_authenticated_payloads", auth)
    monkeypatch.setattr(stage, "_audit_worker_files", lambda *a: None)
    @contextmanager
    def lock(root, owner, **kw):
        nonlocal locked
        assert owner == 0 and kw == {"allow_native_package_parent_changes": True}
        locked = True
        fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)
            locked = False
    monkeypatch.setattr(install, "_locked", lock)
    from repocache import server_native_v2_transaction_v1 as tx
    from repocache import server_native_egress_candidate_v1 as egress
    preparing = fault.startswith("prepare")
    manifest = b"committed manifest"
    monkeypatch.setattr(egress, "_read_boot_egress_receipt",
                        lambda *a, **kw: b"existing boot" if fault == "prepare-boot" else None)
    def read(fd, name, uid, limit):
        assert locked
        if name == tx._OWNED_MANIFEST:
            return b"foreign" if fault == "prepare-manifest" else manifest
        if name == tx._OWNED_WAL_TMP:
            return None
        if name == install._RUNTIME_RECEIPT:
            return b"foreign" if fault == "placement" else expected
        if name == install._OWNED_WAL:
            return None if fault == "wal" or (preparing and fault != "prepare-wal") else wal
        assert name == marker
        return b""
    monkeypatch.setattr(install, "_read_file", read)
    monkeypatch.setattr(install, "_require_audited_native_package_for_activation", lambda *a, **kw: None)
    monkeypatch.setattr(install, "_native_workspace_is_root_owned", lambda path: True)
    @contextmanager
    def workspace(**kw):
        yield str(tmp_path)
    monkeypatch.setattr(install.tempfile, "TemporaryDirectory", workspace)
    monkeypatch.setattr(install, "_candidate_native_identity", lambda *a: "nginx-core-0:1.2-3.x86_64")
    def authenticate(*args):
        assert locked
        calls.append("rpm")
        if fault == "package":
            raise stage.WorkerStageError("PACKAGE_REFUSED")
        return "e"*64, "f"*64
    monkeypatch.setattr(install, "_authenticate_candidate_rpm", authenticate)
    def child(argv, **kw):
        assert not locked
        assert argv == ("/usr/bin/python3", "-IS", "-B", "-c",
                        install._DEDICATED_PREPARE_CHILD if preparing else install._DEDICATED_RECOVERY_CHILD)
        compile(argv[-1], "<fixed-recovery-child>", "exec")
        assert kw["shell"] is False and kw["close_fds"] is True and "pass_fds" not in kw
        data = json.loads(kw["input"])
        assert data["worker_sha256"] == hashlib.sha256(b"worker").hexdigest()
        assert data["placement_sha256"] == hashlib.sha256(expected).hexdigest()
        assert data["native_payload_sha256"] == "e"*64 and data["binary_sha256"] == "f"*64
        assert data["executable_receipt_sha256"] == "c"*64
        assert data["profile_receipt_sha256"] == "d"*64
        calls.append("child")
        if preparing:
            assert data["generation_manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
            assert "wal_sha256" not in data and "boot_receipt_sha256" not in data
            report = {"status": "NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED",
                      "generation_manifest_sha256": data["generation_manifest_sha256"],
                      "receipt_sha256": "9"*64, "committed_resources_verified": True,
                      "authorizes_nginx_activation": fault == "prepare-report",
                      "authorizes_catalog_publication": False}
        else:
            assert data["boot_receipt_sha256"] == "9"*64
            report = {"status": "OWNED_DEDICATED_WAL_ROLLBACK_OBSERVED",
                      "wal_sha256": hashlib.sha256(wal).hexdigest(),
                      "recovery_required": False, "catalog_observed": fault != "wrong-report"}
        return SimpleNamespace(returncode=2 if fault == "child" else 0,
                               stdout=json.dumps(report).encode(), stderr=b"")
    monkeypatch.setattr(install.subprocess, "run", child)
    options = dict(commit="a"*40, archive_sha256="b"*64,
                   executable_receipt_sha256="invalid" if fault == "invalid-pin" else "c"*64,
                   profile_receipt_sha256="d"*64, boot_receipt_sha256="9"*64,
                   wal_sha256=hashlib.sha256(wal).hexdigest())
    if preparing:
        boot_pins = {key: value for key, value in options.items()
                     if key not in ("boot_receipt_sha256", "wal_sha256")}
        boot_pins["generation_manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
        if fault == "prepare":
            assert install._prepare_authenticated_committed_dedicated_nginx(
                tmp_path, **boot_pins)["committed_resources_verified"]
        else:
            with pytest.raises(stage.WorkerStageError):
                install._prepare_authenticated_committed_dedicated_nginx(tmp_path, **boot_pins)
    elif fault in ("rolled", "rolled-refusal"):
        def retained(root, fd):
            assert locked
            calls.append("history")
            if fault == "rolled-refusal":
                raise stage.WorkerStageError("HISTORY_REFUSED")
            return {key: value for key, value in options.items()
                    if key not in ("commit", "archive_sha256")}
        monkeypatch.setattr(tx, "_retained_rolled_dedicated_recovery_pins_locked", retained)
        release = {key: options[key] for key in ("commit", "archive_sha256")}
        if fault == "rolled":
            assert install._recover_authenticated_rolled_dedicated_nginx(
                tmp_path, **release)["catalog_observed"]
        else:
            with pytest.raises(stage.WorkerStageError):
                install._recover_authenticated_rolled_dedicated_nginx(tmp_path, **release)
    elif fault == "none":
        assert install._recover_authenticated_prepared_dedicated_nginx(tmp_path, **options)["catalog_observed"]
    else:
        with pytest.raises(stage.WorkerStageError):
            install._recover_authenticated_prepared_dedicated_nginx(tmp_path, **options)
    assert calls == ([] if fault in ("invalid-pin", "debian") else
                     ["release"] if fault in ("release", "placement", "wal",
                                               "prepare-wal", "prepare-manifest", "prepare-boot") else
                     ["release", "rpm"] if fault == "package" else
                     ["release", "history"] if fault == "rolled-refusal" else
                     ["release", "history", "rpm", "child"] if fault == "rolled" else
                     ["release", "rpm", "child"])
    assert not locked
