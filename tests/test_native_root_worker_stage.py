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
                                   "rolled", "rolled-refusal", "rolled-pins-changed",
                                   "rolled-pins-match", "prepare", "prepare-wal",
                                   "prepare-manifest", "prepare-boot", "prepare-report",
                                   "start", "start-wal", "start-boot", "start-report",
                                   "rollover", "rollover-wal", "rollover-boot", "rollover-report",
                                   "pending-rollover", "pending-rollover-missing-wal",
                                   "pending-rollover-wal", "pending-rollover-report",
                                   "pending-prepare", "pending-prepare-missing-wal",
                                   "pending-prepare-wal", "pending-prepare-boot",
                                   "pending-prepare-report", "pending-resume",
                                   "pending-resume-wal", "pending-resume-boot",
                                   "pending-resume-report", "pending-resume-digest",
                                   "pending-start", "pending-start-wal", "pending-start-boot",
                                   "pending-start-report", "pending-start-missing-wal",
                                   "committed-resume", "committed-resume-boot",
                                   "committed-resume-wal", "committed-resume-digest",
                                   "rolled-start", "rolled-start-changed", "rolled-start-wal",
                                   "rolled-start-active", "rolled-start-active-report",
                                   "profile-stage", "profile-stage-wal", "profile-stage-boot",
                                   "profile-stage-manifest", "profile-stage-existing",
                                   "profile-stage-report", "profile-load", "profile-load-repeat",
                                   "profile-load-wal", "profile-load-boot",
                                   "profile-load-manifest", "profile-load-report",
                                   "profile-load-authority", "storage", "storage-wal",
                                   "storage-boot", "storage-manifest", "storage-report",
                                   "storage-authority", "storage-int-report",
                                   "runtime", "runtime-wal", "runtime-boot",
                                   "runtime-manifest", "runtime-report", "runtime-authority",
                                   "pending-storage", "pending-storage-wal", "pending-storage-report",
                                   "pending-runtime", "pending-runtime-wal", "pending-runtime-report"])
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
    pending_rolling = fault.startswith("pending-rollover")
    rolling = fault.startswith("rollover") or pending_rolling
    pending_first = fault.startswith("pending-prepare")
    committed_resume = fault.startswith("committed-resume")
    resuming = fault.startswith("pending-resume") or committed_resume
    pending_start = fault.startswith("pending-start")
    pending_storage = fault.startswith("pending-storage")
    pending_runtime = fault.startswith("pending-runtime")
    pending_placement = pending_storage or pending_runtime
    pending = pending_first or pending_rolling or (resuming and not committed_resume) or pending_start or pending_placement
    staging_profile = fault.startswith("profile-stage")
    loading_profile = fault.startswith("profile-load")
    preparing = (fault.startswith("prepare") or rolling or pending_first or resuming
                 or staging_profile or loading_profile)
    if fault == "profile-stage-existing":
        from repocache.server_native_nginx_effective_unit_v1 import _NAMESPACE_PROFILE_RECEIPT
        (state / _NAMESPACE_PROFILE_RECEIPT).touch()
    rolled_start = fault.startswith("rolled-start")
    runtime = fault.startswith("runtime") or pending_runtime
    storage = fault.startswith("storage") or pending_storage or runtime
    starting = fault.startswith("start") or pending_start or rolled_start or storage
    manifest = b"committed manifest"
    boot = b"exact boot"
    monkeypatch.setattr(egress, "_read_boot_egress_receipt",
                        lambda *a, **kw: b"existing boot" if fault in ("prepare-boot", "start-boot", "rollover-boot", "pending-prepare-boot", "pending-resume-boot", "pending-start-boot", "committed-resume-boot", "profile-stage-boot", "profile-load-boot", "storage-boot", "runtime-boot")
                        else boot if starting or rolling or resuming else None)
    def read(fd, name, uid, limit):
        assert locked
        if name == tx._OWNED_MANIFEST:
            return b"foreign" if fault in ("prepare-manifest", "profile-stage-manifest", "profile-load-manifest", "storage-manifest", "runtime-manifest") else manifest
        if name == tx._OWNED_WAL_TMP:
            return None
        if name == install._RUNTIME_RECEIPT:
            return b"foreign" if fault == "placement" else expected
        if name == install._OWNED_WAL:
            if pending:
                return (None if fault.endswith("-missing-wal") else
                        b"foreign WAL" if fault.endswith("-wal") else wal)
            return None if (fault == "wal" or (preparing and fault not in ("prepare-wal", "rollover-wal", "committed-resume-wal", "profile-stage-wal", "profile-load-wal"))
                            or (starting and fault not in ("start-wal", "rolled-start-wal", "storage-wal", "runtime-wal"))) else wal
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
                        install._DEDICATED_PROFILE_CHILD if staging_profile else
                        install._DEDICATED_PROFILE_LOAD_CHILD if loading_profile else
                        install._DEDICATED_COMMITTED_RESUME_CHILD if committed_resume else
                        install._DEDICATED_PENDING_RESUME_CHILD if resuming else
                        install._DEDICATED_PENDING_ROLLOVER_CHILD if pending_rolling else
                        install._DEDICATED_PENDING_PREPARE_CHILD if pending_first else
                        install._DEDICATED_ROLLOVER_CHILD if rolling else
                        install._DEDICATED_PREPARE_CHILD if preparing else
                        install._DEDICATED_PENDING_START_CHILD if pending_start else
                        install._DEDICATED_ROLLED_START_CHILD if rolled_start else
                        install._DEDICATED_PENDING_RUNTIME_CHILD if pending_runtime else
                        install._DEDICATED_PENDING_STORAGE_CHILD if pending_storage else
                        install._DEDICATED_RUNTIME_CHILD if runtime else
                        install._DEDICATED_STORAGE_CHILD if storage else
                        install._DEDICATED_START_CHILD if starting else install._DEDICATED_RECOVERY_CHILD)
        compile(argv[-1], "<fixed-recovery-child>", "exec")
        assert kw["shell"] is False and kw["close_fds"] is True and "pass_fds" not in kw
        data = json.loads(kw["input"])
        assert data["worker_sha256"] == hashlib.sha256(b"worker").hexdigest()
        assert data["placement_sha256"] == hashlib.sha256(expected).hexdigest()
        assert data["native_payload_sha256"] == "e"*64 and data["binary_sha256"] == "f"*64
        assert data["executable_receipt_sha256"] == "c"*64
        if staging_profile:
            assert "profile_receipt_sha256" not in data
        else:
            assert data["profile_receipt_sha256"] == "d"*64
        calls.append("child")
        if staging_profile:
            report = {"status": "OWNED_DEDICATED_PROFILE_STAGED",
                      "generation_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                      "executable_receipt_sha256": "c"*64, "receipt_sha256": "d"*64,
                      "receipt_matches_owned_dropin": True, "authorizes_systemctl": False,
                      "authorizes_nginx_activation": False,
                      "authorizes_catalog_publication": fault == "profile-stage-report"}
        elif loading_profile:
            assert data["generation_manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
            assert "boot_receipt_sha256" not in data and "wal_sha256" not in data
            report = {"status": "OWNED_DEDICATED_PROFILE_LOADED",
                      "generation_manifest_sha256": data["generation_manifest_sha256"],
                      "executable_receipt_sha256": "c"*64,
                      "receipt_sha256": "0"*64 if fault == "profile-load-report" else "d"*64,
                      "profile_loaded": True, "daemon_reloaded": fault != "profile-load-repeat",
                      "receipt_matches_owned_dropin": True,
                      "authorizes_systemctl": fault == "profile-load-authority",
                      "authorizes_nginx_activation": False, "authorizes_catalog_publication": False}
        elif preparing:
            assert data["generation_manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
            if resuming:
                assert data["boot_receipt_sha256"] == hashlib.sha256(boot).hexdigest()
            else:
                assert "boot_receipt_sha256" not in data
            if pending:
                assert data["wal_sha256"] == hashlib.sha256(wal).hexdigest()
            else:
                assert "wal_sha256" not in data
            if rolling:
                assert data["previous_boot_receipt_sha256"] == hashlib.sha256(boot).hexdigest()
            else:
                assert "previous_boot_receipt_sha256" not in data
            report = {"status": "NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED",
                      "generation_manifest_sha256": data["generation_manifest_sha256"],
                      "receipt_sha256": hashlib.sha256(boot).hexdigest() if fault == "rollover-report" else "9"*64,
                      "committed_resources_verified": True,
                      "authorizes_nginx_activation": fault == "prepare-report",
                      "authorizes_catalog_publication": False}
            if pending:
                del report["committed_resources_verified"]
                report.update(prior_resources_verified=True, recovery_required=True,
                              catalog_withdrawn=not fault.endswith("-report"),
                              wal_sha256=data["wal_sha256"])
            if resuming and not fault.endswith("-digest"):
                report["receipt_sha256"] = data["boot_receipt_sha256"]
        elif storage:
            assert data["generation_manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
            assert data["boot_receipt_sha256"] == hashlib.sha256(boot).hexdigest()
            assert ("wal_sha256" in data) is pending_placement
            report = {"status": ("OWNED_DEDICATED_PREPARED_WAL_RUNTIME_PREPARED" if runtime
                                 else "OWNED_DEDICATED_PREPARED_WAL_STORAGE_PREPARED") if pending_placement else (
                                 "OWNED_DEDICATED_COMMITTED_RUNTIME_PREPARED" if runtime
                                 else "OWNED_DEDICATED_COMMITTED_STORAGE_PREPARED"),
                      **({"scratch_count": True if fault == "runtime-report" else 5} if runtime else {}),
                      **{key: data[key] for key in ("generation_manifest_sha256",
                            "boot_receipt_sha256", "profile_receipt_sha256", "executable_receipt_sha256")},
                      "storage": {"repository_cache_roots_verified": [], "metrics_file_verified": False,
                                  "selinux_enforcing_labels_verified": 1 if fault == "storage-int-report" else True,
                                  "actual_service_write_verified": fault == "storage-report"},
                      "authorizes_systemctl": fault in ("storage-authority", "runtime-authority"),
                      "authorizes_nginx_activation": False, "authorizes_catalog_publication": False}
            if pending_placement:
                report.update(wal_sha256=data["wal_sha256"], recovery_required=True,
                              catalog_withdrawn=not fault.endswith("-report"))
        elif starting:
            assert data["generation_manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
            assert data["boot_receipt_sha256"] == hashlib.sha256(boot).hexdigest()
            if pending_start:
                assert data["wal_sha256"] == hashlib.sha256(wal).hexdigest()
            else:
                assert "wal_sha256" not in data
            report = {"status": "OWNED_DEDICATED_COMMITTED_START_OBSERVED",
                      "generation_manifest_sha256": data["generation_manifest_sha256"],
                      "boot_receipt_sha256": data["boot_receipt_sha256"],
                      "catalog_observed": True, "service_storage_mounts_verified": True,
                      "service_scratch_mounts_verified": True, "enablement_changed": fault == "start-report",
                      "main_pid": 43, "listener_inode": 47}
            if fault.startswith("rolled-start-active"):
                report.update(status="OWNED_DEDICATED_COMMITTED_ACTIVE_VERIFIED",
                              enablement_changed=fault == "rolled-start-active-report")
            if pending_start:
                report.update(status="OWNED_DEDICATED_PREPARED_WAL_START_OBSERVED",
                              catalog_observed=fault == "pending-start-report",
                              catalog_withdrawn=True, recovery_required=True,
                              wal_sha256=data["wal_sha256"])
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
        if rolling:
            boot_pins["previous_boot_receipt_sha256"] = hashlib.sha256(boot).hexdigest()
        if pending:
            boot_pins["wal_sha256"] = hashlib.sha256(wal).hexdigest()
        if resuming:
            boot_pins["boot_receipt_sha256"] = hashlib.sha256(boot).hexdigest()
        if staging_profile:
            del boot_pins["profile_receipt_sha256"]
        invoke = (install._stage_authenticated_committed_dedicated_profile if staging_profile
                  else install._load_authenticated_committed_dedicated_profile if loading_profile
                  else install._resume_authenticated_committed_dedicated_nginx if committed_resume
                  else install._resume_authenticated_prepared_wal_dedicated_nginx if resuming
                  else install._rollover_authenticated_prepared_wal_dedicated_nginx if pending_rolling
                  else install._prepare_authenticated_prepared_wal_dedicated_nginx if pending_first
                  else install._rollover_authenticated_committed_dedicated_nginx if rolling
                  else install._prepare_authenticated_committed_dedicated_nginx)
        if fault == "profile-stage":
            assert invoke(tmp_path, **boot_pins)["receipt_matches_owned_dropin"]
        elif fault in ("profile-load", "profile-load-repeat"):
            assert invoke(tmp_path, **boot_pins)["daemon_reloaded"] is (fault == "profile-load")
        elif fault in ("prepare", "rollover", "pending-rollover", "pending-prepare", "pending-resume",
                     "committed-resume"):
            assert invoke(tmp_path, **boot_pins)[
                "prior_resources_verified" if pending else "committed_resources_verified"]
        else:
            with pytest.raises(stage.WorkerStageError):
                invoke(tmp_path, **boot_pins)
    elif starting:
        start_pins = {key: value for key, value in options.items() if key != "wal_sha256"}
        start_pins["generation_manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
        start_pins["boot_receipt_sha256"] = hashlib.sha256(boot).hexdigest()
        if pending_start or pending_placement:
            start_pins["wal_sha256"] = hashlib.sha256(wal).hexdigest()
        invoke = (install._start_authenticated_prepared_wal_dedicated_nginx if pending_start
                  else install._prepare_authenticated_prepared_wal_dedicated_runtime if pending_runtime
                  else install._prepare_authenticated_prepared_wal_dedicated_storage if pending_storage
                  else install._prepare_authenticated_committed_dedicated_runtime if runtime
                  else install._prepare_authenticated_committed_dedicated_storage if storage
                  else install._start_authenticated_committed_dedicated_nginx)
        if rolled_start:
            release = {key: start_pins.pop(key) for key in ("commit", "archive_sha256")}
            def retain_committed(root, fd):
                assert locked
                calls.append("history")
                return {**start_pins, **({"boot_receipt_sha256": "0"*64}
                                        if fault == "rolled-start-changed" else {})}
            monkeypatch.setattr(tx, "_retained_rolled_committed_dedicated_pins_locked", retain_committed)
            def invoke_rolled():
                return install._authenticated_prepared_dedicated_bridge(
                    tmp_path, **release, recovery_pins=None, start=True,
                    expected_rolled_pins=start_pins)
            if fault in ("rolled-start", "rolled-start-active"):
                assert invoke_rolled()["catalog_observed"] is True
            else:
                with pytest.raises(stage.WorkerStageError):
                    invoke_rolled()
        elif fault in ("storage", "runtime", "pending-storage", "pending-runtime"):
            report = invoke(tmp_path, **start_pins)
            if pending_placement:
                assert report["wal_sha256"] == start_pins["wal_sha256"]
                assert report["catalog_withdrawn"] and report["recovery_required"]
            assert report["storage"]["selinux_enforcing_labels_verified"]
            if runtime:
                assert report["scratch_count"] == 5
        elif fault in ("start", "pending-start"):
            assert invoke(tmp_path, **start_pins)["catalog_observed"] is (not pending_start)
        else:
            with pytest.raises(stage.WorkerStageError):
                invoke(tmp_path, **start_pins)
    elif fault in ("rolled", "rolled-refusal", "rolled-pins-changed", "rolled-pins-match"):
        def retained(root, fd):
            assert locked
            calls.append("history")
            if fault == "rolled-refusal":
                raise stage.WorkerStageError("HISTORY_REFUSED")
            return {key: value for key, value in options.items()
                    if key not in ("commit", "archive_sha256")}
        monkeypatch.setattr(tx, "_retained_rolled_dedicated_recovery_pins_locked", retained)
        release = {key: options[key] for key in ("commit", "archive_sha256")}
        if fault.startswith("rolled-pins"):
            expected_pins = {key: value for key, value in options.items()
                             if key not in ("commit", "archive_sha256")}
            if fault == "rolled-pins-changed":
                expected_pins["wal_sha256"] = "0"*64
            release["expected_pins"] = expected_pins
        if fault in ("rolled", "rolled-pins-match"):
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
                                               "prepare-wal", "prepare-manifest", "prepare-boot",
                                               "start-wal", "start-boot", "rollover-wal",
                                               "rollover-boot", "pending-rollover-missing-wal",
                                               "pending-rollover-wal", "pending-prepare-missing-wal",
                                               "pending-prepare-wal", "pending-prepare-boot",
                                               "pending-resume-wal", "pending-resume-boot",
                                               "pending-start-wal", "pending-start-boot",
                                               "pending-start-missing-wal",
                                               "committed-resume-boot", "committed-resume-wal",
                                               "profile-stage-wal", "profile-stage-boot",
                                               "profile-stage-manifest", "profile-stage-existing",
                                               "profile-load-wal", "profile-load-boot",
                                               "profile-load-manifest", "storage-wal",
                                               "storage-boot", "storage-manifest",
                                               "runtime-wal", "runtime-boot", "runtime-manifest",
                                               "pending-storage-wal", "pending-runtime-wal") else
                     ["release", "rpm"] if fault == "package" else
                     ["release", "history"] if fault in ("rolled-refusal", "rolled-pins-changed",
                                                           "rolled-start-changed", "rolled-start-wal") else
                     ["release", "history", "rpm", "child"] if fault in (
                         "rolled", "rolled-pins-match", "rolled-start", "rolled-start-active",
                         "rolled-start-active-report") else
                     ["release", "rpm", "child"])
    assert not locked


@pytest.mark.parametrize("fault", ["none", "missing", "duplicate", "oversize", "malformed", "broken"])
def test_signed_worker_policy_member_is_bounded_and_unique(fault):
    import io
    import zipfile
    from repocache.server_native_nginx_executable_v1 import _POLICY_MEMBER
    raw = b"policy_module(repocache_nginx, 1.0.0)\n"
    if fault == "broken":
        with pytest.raises(stage.WorkerStageError):
            stage._signed_owned_policy_from_worker(b"not a zip")
        return
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        if fault != "missing":
            value = (b"a" * 16385 if fault == "oversize" else
                     b"unrelated policy\n" if fault == "malformed" else raw)
            archive.writestr(_POLICY_MEMBER, value)
        if fault == "duplicate":
            with pytest.warns(UserWarning):
                archive.writestr(_POLICY_MEMBER, raw)
    if fault == "none":
        result = stage._signed_owned_policy_from_worker(data.getvalue())
        assert result["policy_bytes"] == raw
        assert result["policy_sha256"] == hashlib.sha256(raw).hexdigest()
        assert result["authorizes_policy_installation"] is False
        assert result["runtime_selinux_policy_verified"] is False
    else:
        with pytest.raises(stage.WorkerStageError):
            stage._signed_owned_policy_from_worker(data.getvalue())


@pytest.mark.parametrize("raw,accepted", [
    ("100 base pp\n400 repocache_nginx pp\n", True),
    ("400 repocache_nginx pp disabled\n", True),
    ("100 repocache_nginx cil\n400 repocache_nginx pp\n", True),
    ("400 repocache_nginx pp\n400 repocache_nginx pp\n", False),
    ("unexpected row\n", False),
    ("", False),
])
def test_fixed_policy_full_inventory_preserves_priority_and_disabled_state(monkeypatch, raw, accepted):
    from types import SimpleNamespace
    from scripts import ci_selinux_nginx_egress_guest as guest
    def command(*args, **kwargs):
        assert args == ("/usr/sbin/semodule", "-lfull") and not kwargs
        return SimpleNamespace(stdout=raw)
    monkeypatch.setattr(guest, "command", command)
    if accepted:
        assert guest._fixed_policy_inventory() == {tuple(line.split()) for line in raw.splitlines()}
    else:
        with pytest.raises(AssertionError):
            guest._fixed_policy_inventory()


@pytest.mark.parametrize("fault", ["stage", "restore", "proposal", "wal", "authority", "child", "mixed"])
def test_initial_installer_bridge_pins_proposal_and_stopped_result(monkeypatch, tmp_path, fault):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from repocache import server_native_v2_transaction_v1 as tx
    from repocache import server_root_control_fixed_candidate_v1 as intake
    receipt = {"source_sha": "a"*40}
    raw = stage._json_line(receipt)
    marker = install._MARKER + "complete-" + hashlib.sha256(raw).hexdigest()
    (tmp_path / marker).touch()
    wal = b"exact wal"
    proposal = b"exact proposal"
    restoring = fault in ("restore", "wal")
    locked = False
    calls = []
    @contextmanager
    def lock(root, owner, **kw):
        nonlocal locked
        assert owner == 0 and kw == {"allow_native_package_parent_changes": True}
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        locked = True
        try:
            yield fd
        finally:
            locked = False
            os.close(fd)
    monkeypatch.setattr(install, "_locked", lock)
    monkeypatch.setattr(install, "_native_distro", lambda: "almalinux")
    monkeypatch.setattr(install, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(stage, "_authenticated_payloads", lambda *a, **kw:
                        ({stage.CONFIG: install._BOOTSTRAP_CONFIG, stage.WORKER: b"worker"}, receipt))
    monkeypatch.setattr(stage, "_audit_worker_files", lambda *a: None)
    def read(fd, name, uid, limit):
        assert locked
        if name == install._RUNTIME_RECEIPT:
            return raw
        if name == marker:
            return b""
        if name == tx._OWNED_WAL:
            return wal if restoring else None
        assert name == tx._OWNED_WAL_TMP
        return None
    monkeypatch.setattr(install, "_read_file", read)
    @contextmanager
    def layout(root, state, *, recovering):
        assert locked and recovering is restoring
        yield state, 11, 12, lambda: None
    monkeypatch.setattr(tx, "_owned_layout_locked", layout)
    monkeypatch.setattr(tx, "_read_owned_resources", lambda *a: {})
    monkeypatch.setattr(tx, "_validate_owned_resources", lambda *a, **kw: None)
    monkeypatch.setattr(intake, "_load_private_under_root", lambda *a, **kw:
                        ({"expected_generation": 0, "expected_state_sha256": None}, proposal))
    monkeypatch.setattr(install, "_require_audited_native_package_for_activation", lambda *a, **kw: None)
    monkeypatch.setattr(install, "_native_workspace_is_root_owned", lambda *a: True)
    @contextmanager
    def work(**kw):
        yield str(tmp_path)
    monkeypatch.setattr(install.tempfile, "TemporaryDirectory", work)
    monkeypatch.setattr(install, "_candidate_native_identity", lambda *a: "nginx-core-0:1.2-3.x86_64")
    monkeypatch.setattr(install, "_authenticate_candidate_rpm", lambda *a: ("e"*64, "f"*64))
    def child(argv, **kw):
        assert not locked
        assert argv[-1] == (install._DEDICATED_INITIAL_RESTORE_CHILD if restoring else
                            install._DEDICATED_INITIAL_STAGE_CHILD)
        compile(argv[-1], "<initial-child>", "exec")
        pins = json.loads(kw["input"])
        assert pins["worker_sha256"] == hashlib.sha256(b"worker").hexdigest()
        assert "boot_receipt_sha256" not in pins and "profile_receipt_sha256" not in pins
        calls.append("child")
        report = dict(status="OWNED_INITIAL_INSTALLED_BOOTSTRAP_RESTORED" if restoring else
                      "OWNED_INITIAL_INSTALLED_GENERATION_STAGED",
                      wal_sha256=hashlib.sha256(wal).hexdigest(), catalog_withdrawn=True,
                      recovery_required=not restoring, executable_receipt_sha256="c"*64,
                      authorizes_systemctl=False, authorizes_nginx_activation=False,
                      authorizes_catalog_publication=fault == "authority")
        if not restoring:
            report.update(proposal_sha256=hashlib.sha256(proposal).hexdigest(),
                          generation_manifest_sha256="d"*64)
        return SimpleNamespace(returncode=2 if fault == "child" else 0,
                               stdout=json.dumps(report).encode(), stderr=b"")
    monkeypatch.setattr(install.subprocess, "run", child)
    pins = dict(commit="a"*40, archive_sha256="b"*64, executable_receipt_sha256="c"*64)
    def invoke():
        if fault == "mixed":
            return install._authenticated_prepared_dedicated_bridge(
                tmp_path, commit="a"*40, archive_sha256="b"*64, recovery_pins={},
                initial_action="stage", prepare=True)
        if restoring:
            return install._restore_authenticated_initial_dedicated_generation(
                tmp_path, **pins, wal_sha256="0"*64 if fault == "wal" else hashlib.sha256(wal).hexdigest())
        return install._stage_authenticated_initial_dedicated_generation(
            tmp_path, **pins, proposal_sha256="0"*64 if fault == "proposal" else hashlib.sha256(proposal).hexdigest())
    if fault in ("stage", "restore"):
        assert invoke()["catalog_withdrawn"] is True
    else:
        with pytest.raises(stage.WorkerStageError):
            invoke()
    assert calls == (["child"] if fault in ("stage", "restore", "authority", "child") else [])


@pytest.mark.parametrize("action", ["profile", "load", "boot", "boot-resume", "boot-rollover",
                                    "storage", "runtime", "start", "finish"])
@pytest.mark.parametrize("fault", ["none", "wal", "manifest", "child-report"])
def test_initial_pending_installer_pins_phase_and_successor(monkeypatch, tmp_path, action, fault):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from repocache import server_native_v2_transaction_v1 as tx
    from repocache import server_native_egress_candidate_v1 as egress
    receipt = {"source_sha": "a"*40}
    raw = stage._json_line(receipt)
    marker = install._MARKER + "complete-" + hashlib.sha256(raw).hexdigest()
    (tmp_path / marker).touch()
    wal, manifest, boot = b"exact wal", b"exact manifest", b"exact boot"
    locked = False
    calls = []
    @contextmanager
    def lock(root, owner, **kw):
        nonlocal locked
        assert owner == 0 and kw == {"allow_native_package_parent_changes": True}
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        locked = True
        try:
            yield fd
        finally:
            locked = False
            os.close(fd)
    monkeypatch.setattr(install, "_locked", lock)
    monkeypatch.setattr(install, "_native_distro", lambda: "almalinux")
    monkeypatch.setattr(install, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(stage, "_authenticated_payloads", lambda *a, **kw:
                        ({stage.CONFIG: install._BOOTSTRAP_CONFIG, stage.WORKER: b"worker"}, receipt))
    monkeypatch.setattr(stage, "_audit_worker_files", lambda *a: None)
    def read(fd, name, uid, limit):
        assert locked
        if name == install._RUNTIME_RECEIPT:
            return raw
        if name == marker:
            return b""
        if name == tx._OWNED_WAL:
            return wal
        if name == tx._OWNED_MANIFEST:
            return manifest
        assert name == tx._OWNED_WAL_TMP
        return None
    monkeypatch.setattr(install, "_read_file", read)
    monkeypatch.setattr(egress, "_read_boot_egress_receipt", lambda *a:
                        None if action in ("profile", "load", "boot") else boot)
    monkeypatch.setattr(install, "_require_audited_native_package_for_activation", lambda *a, **kw: None)
    monkeypatch.setattr(install, "_native_workspace_is_root_owned", lambda *a: True)
    @contextmanager
    def work(**kw):
        yield str(tmp_path)
    monkeypatch.setattr(install.tempfile, "TemporaryDirectory", work)
    monkeypatch.setattr(install, "_candidate_native_identity", lambda *a: "nginx-core-0:1.2-3.x86_64")
    monkeypatch.setattr(install, "_authenticate_candidate_rpm", lambda *a: ("e"*64, "f"*64))
    pins = dict(executable_receipt_sha256="c"*64,
                generation_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                wal_sha256=hashlib.sha256(wal).hexdigest())
    if action != "profile":
        pins["profile_receipt_sha256"] = "d"*64
    if action == "boot-rollover":
        pins["previous_boot_receipt_sha256"] = hashlib.sha256(boot).hexdigest()
    elif action in ("boot-resume", "storage", "runtime", "start", "finish"):
        pins["boot_receipt_sha256"] = hashlib.sha256(boot).hexdigest()

    def child(argv, **kw):
        assert not locked
        assert argv[-1] == install._DEDICATED_INITIAL_PENDING_CHILDREN[action]
        compile(argv[-1], "<initial-pending-child>", "exec")
        assert "transaction._installed_initial_dedicated_pending(pins, " + repr(action) + ")" in argv[-1]
        data = json.loads(kw["input"])
        assert all(data[key] == value for key, value in pins.items())
        calls.append(action)
        report = dict(pins, initial_resources_verified=True, catalog_withdrawn=True,
                      recovery_required=True, authorizes_systemctl=False,
                      authorizes_nginx_activation=False, authorizes_catalog_publication=False)
        if action in ("profile", "load"):
            report.update(status=("OWNED_DEDICATED_PROFILE_STAGED" if action == "profile"
                                  else "OWNED_DEDICATED_PROFILE_LOADED"),
                          receipt_sha256="d"*64, receipt_matches_owned_dropin=True,
                          profile_loaded=True, daemon_reloaded=True)
        elif action.startswith("boot"):
            report.update(status="NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED",
                          receipt_sha256=(pins["boot_receipt_sha256"] if action == "boot-resume" else "1"*64))
        elif action in ("storage", "runtime"):
            report.update(status=("OWNED_DEDICATED_INITIAL_WAL_STORAGE_PREPARED" if action == "storage"
                                  else "OWNED_DEDICATED_INITIAL_WAL_RUNTIME_PREPARED"))
            report["storage"] = dict(selinux_enforcing_labels_verified=True)
            if action == "runtime":
                report["scratch_count"] = 5
        elif action == "start":
            report.update(status="OWNED_DEDICATED_INITIAL_WAL_START_OBSERVED",
                          catalog_observed=False, service_storage_mounts_verified=True,
                          service_scratch_mounts_verified=True, enablement_changed=False,
                          main_pid=43, listener_inode=47)
        else:
            report.update(status="OWNED_DEDICATED_INITIAL_WAL_COMMIT_OBSERVED",
                          generation=1, recovery_required=False, catalog_observed=True)
        if fault == "child-report":
            report["wal_sha256"] = "0"*64
        return SimpleNamespace(returncode=0, stdout=json.dumps(report).encode(), stderr=b"")
    monkeypatch.setattr(install.subprocess, "run", child)
    monkeypatch.setattr(tx, "_closed_committed_dedicated_storage_report",
                        lambda report: report == {"selinux_enforcing_labels_verified": True})
    if fault == "wal":
        pins["wal_sha256"] = "0"*64
    elif fault == "manifest":
        pins["generation_manifest_sha256"] = "0"*64
    def invoke():
        return install._authenticated_initial_dedicated_pending(
            tmp_path, commit="a"*40, archive_sha256="b"*64, action=action, recovery_pins=pins)
    if fault == "none":
        assert invoke()["wal_sha256"] == pins["wal_sha256"]
    else:
        with pytest.raises(stage.WorkerStageError):
            invoke()
    assert calls == ([action] if fault in ("none", "child-report") else [])

@pytest.mark.skipif(os.geteuid() != 0, reason="requires disposable root-owned workspace")
@pytest.mark.parametrize("fault", [
    "none", "invalid-digest", "debian", "disabled", "alternate-priority",
    "missing-enabled", "duplicate", "digest", "extra", "symlink", "writable",
    "inventory-drift", "failed-command", "timeout", "label-drift", "workspace-drift",
])
def test_installer_compiled_policy_observation_is_readonly_and_exact(monkeypatch, fault):
    from types import SimpleNamespace

    raw = b"compiled module fixture"
    digest = hashlib.sha256(raw).hexdigest()
    calls = []
    hosts = []
    monkeypatch.setattr(install, "_native_distro",
                        lambda: "debian" if fault == "debian" else "almalinux")
    monkeypatch.setattr(install, "require_native_host_preconditions", lambda: hosts.append(True))

    class Labels:
        def __init__(self, distribution, *, dedicated):
            assert (distribution, dedicated) == ("almalinux", True)

        def finish(self):
            if fault == "label-drift":
                raise stage.WorkerStageError("fixture label drift")

    monkeypatch.setattr(install, "_Labels", Labels)

    def run(argv, **kw):
        assert argv[0] == "/usr/sbin/semodule"
        assert kw["timeout"] == 120 and kw["env"]["LC_ALL"] == "C"
        args = argv[1:]
        calls.append(args)
        output = b""
        if args == ("-lfull",):
            output = b"100 base pp\n400 repocache_nginx pp\n"
            if fault == "disabled":
                output = output.rstrip() + b" disabled\n"
            elif fault == "alternate-priority":
                output += b"100 repocache_nginx pp\n"
            elif fault == "duplicate":
                output += b"400 repocache_nginx pp\n"
            elif fault == "inventory-drift" and calls.count(args) > 1:
                output += b"100 other pp\n"
        elif args == ("-l",):
            output = b"base\nrepocache_nginx\n" if fault != "missing-enabled" else b"base\n"
        else:
            assert args == ("-X", "400", "--hll", "-E", "repocache_nginx")
            path = Path(kw["cwd"])
            assert stat.S_IMODE(path.stat().st_mode) == 0o700 and not list(path.iterdir())
            leaf = path / "repocache_nginx.pp"
            if fault == "symlink":
                leaf.symlink_to("/etc/passwd")
            else:
                leaf.write_bytes(b"wrong" if fault == "digest" else raw)
                leaf.chmod(0o666 if fault == "writable" else 0o600)
            if fault == "extra":
                (path / "foreign").touch()
            if fault == "workspace-drift":
                path.chmod(0o755)
        if fault == "timeout":
            raise subprocess.TimeoutExpired(argv, 120)
        return SimpleNamespace(stdout=output, returncode=1 if fault == "failed-command" else 0)

    monkeypatch.setattr(install.subprocess, "run", run)
    if fault == "none":
        report = install._observe_fixed_dedicated_policy(digest)
        assert report["stored_hll_verified"] is True
        assert report["compiled_policy_sha256"] == digest and report["enabled_priority"] == 400
        assert all(value is False for key, value in report.items()
                   if key.startswith("authorizes_") or key in (
                       "signed_source_compilation_verified", "runtime_selinux_policy_verified"))
        assert hosts == [True, True]
        assert calls == [("-lfull",), ("-l",),
                         ("-X", "400", "--hll", "-E", "repocache_nginx"),
                         ("-lfull",), ("-l",)]
    else:
        with pytest.raises(stage.WorkerStageError):
            install._observe_fixed_dedicated_policy("bad" if fault == "invalid-digest" else digest)
        if fault in ("invalid-digest", "debian"):
            assert not calls and not hosts
        elif fault in ("disabled", "alternate-priority", "missing-enabled", "duplicate"):
            assert not any("-E" in args for args in calls)

@pytest.mark.parametrize("fault", ["debian", "signature", "wrong-commit", "wrong-worker"])
def test_compile_authenticated_policy_refuses_before_native_build(monkeypatch, tmp_path, fault):
    from types import SimpleNamespace
    calls = []
    worker = b"exact signed worker fixture"
    monkeypatch.setattr(install, "_native_distro",
                        lambda: "debian" if fault == "debian" else "almalinux")
    monkeypatch.setattr(install, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(install, "_Labels", lambda *args, **kw: SimpleNamespace(finish=lambda: None))

    def authenticate(assets, *, commit, archive_sha256, system):
        assert (assets, commit, archive_sha256, system) == (tmp_path, "a"*40, "b"*64, None)
        calls.append("signature")
        if fault == "signature":
            raise stage.WorkerStageError("fixture unsigned release")
        return {stage.WORKER: worker}, {
            "source_sha": "c"*40 if fault == "wrong-commit" else commit,
            "archive_sha256": archive_sha256,
            "files": {stage.WORKER: "0"*64 if fault == "wrong-worker" else hashlib.sha256(worker).hexdigest()},
        }

    monkeypatch.setattr(stage, "_authenticated_payloads", authenticate)
    monkeypatch.setattr(stage, "_signed_owned_policy_from_worker",
                        lambda *args: pytest.fail("policy parser reached without signed identity"))
    monkeypatch.setattr(install.subprocess, "run", lambda *args, **kw: pytest.fail("native build reached"))
    with pytest.raises(stage.WorkerStageError):
        install._compile_authenticated_fixed_dedicated_policy(
            tmp_path, commit="a"*40, archive_sha256="b"*64)
    assert calls == ([] if fault == "debian" else ["signature"])

@pytest.mark.skipif(os.geteuid() != 0, reason="requires disposable root-owned workspace")
@pytest.mark.parametrize("fault", [
    "none", "missing-tool", "tool-symlink", "tool-writable", "tool-drift",
    "source-drift", "output-symlink", "output-hardlink", "output-writable",
    "output-empty", "workspace-drift", "failed-build", "timeout", "label-drift",
])
def test_authenticated_policy_compilation_pins_native_inputs_and_output(monkeypatch, tmp_path, fault):
    from types import SimpleNamespace
    worker = b"exact signed worker fixture"
    raw = b"policy_module(repocache_nginx, 1.0.0)\n"
    compiled = b"exact compiled module fixture"
    root = tmp_path / "native-root"
    make = root / "usr/bin/make"
    makefile = root / "usr/share/selinux/devel/Makefile"
    for leaf in (make, makefile):
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.write_bytes(b"native build input")
        leaf.chmod(0o644)
    make.chmod(0o755)
    if fault == "missing-tool":
        makefile.unlink()
    if fault == "tool-symlink":
        makefile.unlink()
        makefile.symlink_to(make)
    if fault == "tool-writable":
        makefile.chmod(0o666)
    original_open = os.open

    def open_root(name, flags, mode=0o777, *, dir_fd=None):
        if name == "/" and dir_fd is None:
            name = root
        return original_open(name, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(install.os, "open", open_root)
    monkeypatch.setattr(install, "_native_distro", lambda: "almalinux")
    monkeypatch.setattr(install, "require_native_host_preconditions", lambda: None)

    def finish():
        if fault == "label-drift":
            raise stage.WorkerStageError("fixture label drift")

    monkeypatch.setattr(install, "_Labels", lambda *args, **kw: SimpleNamespace(finish=finish))
    monkeypatch.setattr(stage, "_authenticated_payloads", lambda *args, **kw: (
        {stage.WORKER: worker}, {"source_sha": "a"*40, "archive_sha256": "b"*64,
                                "files": {stage.WORKER: hashlib.sha256(worker).hexdigest()}}))
    monkeypatch.setattr(stage, "_signed_owned_policy_from_worker",
                        lambda value: {"policy_bytes": raw} if value == worker else pytest.fail("wrong worker"))
    calls = []

    def run(argv, **kw):
        place = Path(kw["cwd"])
        assert argv == ("/usr/bin/make", "-C", str(place), "-f",
                        "/usr/share/selinux/devel/Makefile", "repocache_nginx.pp")
        assert kw["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
        assert kw["timeout"] == 120
        source = place / "repocache_nginx.te"
        output = place / "repocache_nginx.pp"
        assert source.read_bytes() == raw and stat.S_IMODE(source.stat().st_mode) == 0o600
        assert not output.exists() and stat.S_IMODE(place.stat().st_mode) == 0o700
        calls.append(place)
        if fault == "tool-drift":
            makefile.write_bytes(b"changed")
        if fault == "source-drift":
            source.write_bytes(raw + b"\n")
        if fault == "workspace-drift":
            place.chmod(0o755)
        if fault == "output-symlink":
            output.symlink_to(source)
        elif fault == "output-hardlink":
            os.link(source, output)
        else:
            output.write_bytes(b"" if fault == "output-empty" else compiled)
            output.chmod(0o666 if fault == "output-writable" else 0o600)
        if fault == "timeout":
            raise subprocess.TimeoutExpired(argv, 120)
        return SimpleNamespace(returncode=1 if fault == "failed-build" else 0)

    monkeypatch.setattr(install.subprocess, "run", run)
    if fault == "none":
        value, report = install._compile_authenticated_fixed_dedicated_policy(
            tmp_path, commit="a"*40, archive_sha256="b"*64)
        assert value == compiled
        assert report["policy_sha256"] == hashlib.sha256(raw).hexdigest()
        assert report["compiled_policy_sha256"] == hashlib.sha256(compiled).hexdigest()
        assert report["signed_source_compilation_observed"] is True
        assert all(value is False for key, value in report.items()
                   if key.startswith("authorizes_") or key in (
                       "runtime_selinux_policy_verified", "native_toolchain_provenance_verified"))
    else:
        with pytest.raises(stage.WorkerStageError):
            install._compile_authenticated_fixed_dedicated_policy(
                tmp_path, commit="a"*40, archive_sha256="b"*64)
    if fault in ("missing-tool", "tool-symlink", "tool-writable"):
        assert not calls
    else:
        assert len(calls) == 1 and not calls[0].exists()

@pytest.mark.parametrize("package,identity,valid", [
    ("nginx-core", "nginx-core-0:1.28.0-2.el10.x86_64", True),
    ("make", "make-1:4.4.1-9.el10.x86_64", True),
    ("selinux-policy-devel", "selinux-policy-devel-0:42.1-1.el10.noarch", True),
    ("policycoreutils", "policycoreutils-0:3.8-1.el10.x86_64", True),
    ("selinux-policy-devel", "selinux-policy-devel-0:42.1-1.el10.x86_64", False),
    ("make", "make-0:4.4-1.el10.x86_64\nmake-0:4.5-1.el10.x86_64", False),
    ("make", "--installroot=/tmp", False),
    ("policycoreutils", "foreign-0:1-1.x86_64", False),
    ("foreign", "foreign-0:1-1.x86_64", False),
])
def test_fixed_native_rpm_identity_and_member_scope(package, identity, valid):
    if valid:
        install._fixed_alma_rpm_identity(package, identity)
        member = install._FIXED_ALMA_RPM_MEMBERS[package][0]
        assert install._fixed_alma_rpm_member_digest(
            package, "/foreign\t" + "f"*64 + "\n" + member + "\t" + "a"*64) == "a"*64
    else:
        with pytest.raises(stage.WorkerStageError):
            install._fixed_alma_rpm_identity(package, identity)


@pytest.mark.parametrize("fault", ["missing", "duplicate", "bad-digest", "foreign-path", "oversize"])
def test_fixed_native_rpm_member_refuses_ambiguous_or_foreign_digest(fault):
    member = "/usr/share/selinux/devel/Makefile\t" + "a"*64
    rows = {
        "missing": "", "duplicate": member + "\n" + member,
        "bad-digest": member[:-1] + "G",
        "foreign-path": "/tmp" + member, "oversize": member + "\n" + "x"*65536,
    }[fault]
    with pytest.raises(stage.WorkerStageError):
        install._fixed_alma_rpm_member_digest("selinux-policy-devel", rows)


@pytest.mark.parametrize("fault", ["partial", "foreign", "invalid-identity"])
def test_native_rpm_candidate_scope_refuses_before_metadata_refresh(monkeypatch, tmp_path, fault):
    from repocache import server_native_package_trust_v1 as trust
    monkeypatch.setattr(trust, "_dnf_commands", lambda *args: pytest.fail("DNF reached"))
    identities = {"make": "make-0:4.4-1.x86_64"} if fault == "partial" else (
        {"foreign": "foreign-0:1-1.x86_64"} if fault == "foreign" else
        {"nginx-core": "nginx-core-0:1-1.noarch"})
    with pytest.raises(stage.WorkerStageError):
        install._authenticate_fixed_alma_rpm_members(tmp_path, identities)


@pytest.mark.parametrize("fault", ["none", "debian", "owner", "owner-drift", "file-drift",
                                   "digest", "missing-package", "signature"])
def test_fixed_policy_native_tool_proof_binds_all_three_members(monkeypatch, tmp_path, fault):
    from types import SimpleNamespace
    packages = install._FIXED_POLICY_PACKAGES
    identities = {package: package + "-0:1.0-1.el10." + install._FIXED_ALMA_RPM_MEMBERS[package][1]
                  for package in packages}
    observed = {package: ((1, number), hashlib.sha256(package.encode()).hexdigest())
                for number, package in enumerate(sorted(packages))}
    calls = []
    snapshots = []
    monkeypatch.setattr(install, "_native_distro", lambda: "debian" if fault == "debian" else "almalinux")
    monkeypatch.setattr(install, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(install, "_Labels", lambda *args, **kw: SimpleNamespace(finish=lambda: None))
    monkeypatch.setattr(install, "_native_workspace_is_root_owned", lambda work: True)

    def snapshot():
        snapshots.append(True)
        if fault == "file-drift" and len(snapshots) > 1:
            return {**observed, "make": ((1, 999), observed["make"][1])}
        return observed.copy()

    monkeypatch.setattr(install, "_fixed_policy_tool_snapshot", snapshot)

    def command(argv, work):
        assert argv[:2] == ["/usr/bin/rpm", "-qf"] and len(argv) == 4
        package = next(key for key in packages if install._FIXED_ALMA_RPM_MEMBERS[key][0] == argv[-1])
        calls.append(package)
        if fault == "owner" or (fault == "owner-drift" and len(calls) > 3):
            return "foreign-0:1-1.x86_64"
        return identities[package]

    monkeypatch.setattr(install, "_native_package_command", command)
    authenticated = []

    def authenticate(work, pins):
        assert pins == identities
        authenticated.append(True)
        if fault == "signature":
            raise stage.WorkerStageError("fixture signature refusal")
        result = {package: ("a"*64, observed[package][1]) for package in packages}
        if fault == "digest":
            result["make"] = ("a"*64, "0"*64)
        if fault == "missing-package":
            del result["make"]
        return result

    monkeypatch.setattr(install, "_authenticate_fixed_alma_rpm_members", authenticate)
    if fault == "none":
        report = install._authenticate_fixed_policy_tools()
        assert report["native_fixed_tool_payloads_verified"] is True
        assert not report["native_toolchain_provenance_verified"]
        assert all(value is False for key, value in report.items() if key.startswith("authorizes_"))
        assert set(report["packages"]) == packages
        assert len(calls) == 6 and len(snapshots) == 2 and authenticated == [True]
    else:
        with pytest.raises(stage.WorkerStageError):
            install._authenticate_fixed_policy_tools()
        if fault == "debian":
            assert not calls and not snapshots and not authenticated
        elif fault == "owner":
            assert len(calls) == 1 and not authenticated

@pytest.mark.skipif(os.geteuid() != 0, reason="requires disposable root-owned workspace")
@pytest.mark.parametrize("scope,fault", [
    ("nginx", "none"), ("policy", "none"), ("policy", "foreign-url"),
    ("policy", "duplicate-url"), ("policy", "signature"), ("policy", "payload-changed"),
    ("policy", "identity"), ("policy", "member"), ("policy", "algorithm"),
    ("policy", "trust-anchor"),
])
def test_fixed_signed_rpm_member_verifier_keeps_native_trust_boundary(monkeypatch, tmp_path, scope, fault):
    from repocache import server_native_package_trust_v1 as trust
    packages = {"nginx-core"} if scope == "nginx" else install._FIXED_POLICY_PACKAGES
    identities = {p: p + "-0:1.0-1.el10." + install._FIXED_ALMA_RPM_MEMBERS[p][1] for p in packages}
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    reference = tmp_path / "native-rpmdb"
    reference.mkdir(mode=0o700)
    query = ["dnf", "repoquery", "--available", "--queryformat=%{name}", "nginx"]
    monkeypatch.setattr(trust, "_dnf_commands", lambda place: (["dnf", "makecache"], query))
    monkeypatch.setattr(install, "_trusted_key", lambda key: fault != "trust-anchor")
    original_open = os.open
    original_temp = install.tempfile.TemporaryDirectory

    def open_reference(name, flags, mode=0o777, *, dir_fd=None):
        if name == "/usr/lib/sysimage/rpm" and dir_fd is None:
            name = reference
        return original_open(name, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(install.os, "open", open_reference)
    monkeypatch.setattr(install.tempfile, "TemporaryDirectory",
                        lambda **kw: original_temp(prefix=kw["prefix"], dir=tmp_path))
    label = b"system_u:object_r:rpm_var_lib_t:s0\0"

    def get_label(fd, name):
        assert name == "security.selinux" and stat.S_ISDIR(os.fstat(fd).st_mode)
        return label

    def set_label(fd, name, raw):
        assert name == "security.selinux" and raw == label
        assert os.fstat(fd).st_ino != reference.stat().st_ino

    monkeypatch.setattr(install.os, "getxattr", get_label)
    monkeypatch.setattr(install.os, "setxattr", set_label)
    calls = []
    dbs = set()

    def command(argv, place):
        assert place == work
        calls.append(tuple(argv))
        if argv == ["dnf", "makecache"]:
            return ""
        if argv[:2] == ["dnf", "-q"]:
            assert argv[2:5] == ["repoquery", "--available", "--location"]
            package = next(p for p in packages if identities[p] == argv[-1])
            url = ("https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/Packages/"
                   + package + "-1.0-1.el10." + install._FIXED_ALMA_RPM_MEMBERS[package][1] + ".rpm")
            if fault == "foreign-url":
                return url.replace("repo.almalinux.org", "untrusted.example.invalid")
            return url + "\n" + url.replace("BaseOS", "AppStream") if fault == "duplicate-url" else url
        if argv[0] == "/usr/bin/curl":
            assert argv[1:9] == ["--fail", "--silent", "--show-error", "--proto", "=https", "--tlsv1.2",
                                  "--max-filesize", "33554432"]
            assert "--location" not in argv
            leaf = Path(argv[argv.index("--output") + 1])
            assert leaf.parent == work and not leaf.exists() and leaf.stem in packages
            leaf.write_bytes(("fixture RPM " + leaf.stem).encode())
            leaf.chmod(0o600)
            return ""
        assert argv[0] in ("/usr/bin/rpm", "/usr/bin/rpmkeys") and argv[1] == "--dbpath"
        db = Path(argv[2])
        assert db.parent == tmp_path and db.name.startswith("repocache-native-executable-rpmdb-")
        dbs.add(db)
        if argv[3] == "--initdb":
            assert argv[0] == "/usr/bin/rpm" and len(argv) == 4
            return ""
        if argv[3] == "--import":
            assert argv[0] == "/usr/bin/rpm" and argv[4] == install._NATIVE["almalinux"][2]
            return ""
        payload = Path(argv[-1])
        package = payload.stem
        assert payload.parent == work and package in packages
        if argv[0] == "/usr/bin/rpmkeys":
            assert argv[3] == "--checksig"
            if fault == "payload-changed":
                payload.write_bytes(b"changed after signature")
            return str(payload) + (": BAD" if fault == "signature" else ": digests signatures OK")
        assert argv[3] == "-qp"
        fmt = argv[4]
        if fmt == "--queryformat=%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}":
            return "foreign-0:1-1.x86_64" if fault == "identity" else identities[package]
        if fmt == "--queryformat=%{FILEDIGESTALGO}":
            return "1" if fault == "algorithm" else "8"
        assert fmt == "--queryformat=[%{FILENAMES}\\t%{FILEDIGESTS}\\n]"
        member = install._FIXED_ALMA_RPM_MEMBERS[package][0]
        return "/foreign\t" + "a"*64 if fault == "member" else member + "\t" + "b"*64

    monkeypatch.setattr(install, "_native_package_command", command)
    if fault == "none":
        if scope == "nginx":
            report = {"nginx-core": install._authenticate_candidate_rpm(work, identities["nginx-core"])}
        else:
            report = install._authenticate_fixed_alma_rpm_members(work, identities)
        assert report == {p: (hashlib.sha256(("fixture RPM " + p).encode()).hexdigest(), "b"*64)
                          for p in packages}
        assert len(dbs) == 1
        assert calls.count(("dnf", "makecache")) == 1
        assert len([call for call in calls if call[0] == "/usr/bin/rpmkeys"]) == len(packages)
    else:
        with pytest.raises(stage.WorkerStageError):
            install._authenticate_fixed_alma_rpm_members(work, identities)
        if fault in ("foreign-url", "duplicate-url", "trust-anchor"):
            assert not any(call[0] == "/usr/bin/curl" for call in calls)
    assert not any(db.exists() for db in dbs)


@pytest.mark.skipif(os.geteuid() != 0, reason="requires disposable root-owned tool files")
@pytest.mark.parametrize("fault", ["none", "symlink", "hardlink", "mode", "ancestor", "replacement"])
def test_fixed_policy_tool_snapshot_retains_native_path_identities(monkeypatch, tmp_path, fault):
    root = tmp_path / "native-root"
    for package in install._FIXED_POLICY_PACKAGES:
        name, _, mode = install._FIXED_ALMA_RPM_MEMBERS[package]
        leaf = root / name.lstrip("/")
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.write_bytes(package.encode())
        leaf.chmod(mode)
    target = root / "usr/bin/make"
    other = root / "foreign"
    other.write_bytes(b"make")
    other.chmod(0o755)
    if fault == "symlink":
        target.unlink()
        target.symlink_to(other)
    elif fault == "hardlink":
        target.unlink()
        os.link(other, target)
    elif fault == "mode":
        target.chmod(0o775)
    elif fault == "ancestor":
        target.parent.chmod(0o777)
    original_open = os.open

    def open_root(name, flags, mode=0o777, *, dir_fd=None):
        if name == "/" and dir_fd is None:
            name = root
        return original_open(name, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(install.os, "open", open_root)
    if fault == "replacement":
        original_read = stage._asset_bytes

        def replace(directory, name, *args, **kw):
            data = original_read(directory, name, *args, **kw)
            if name == "make":
                target.rename(target.with_name("old-make"))
                target.write_bytes(data)
                target.chmod(0o755)
            return data

        monkeypatch.setattr(stage, "_asset_bytes", replace)
    if fault == "none":
        report = install._fixed_policy_tool_snapshot()
        assert set(report) == install._FIXED_POLICY_PACKAGES
        for package, (identity, digest) in report.items():
            leaf = root / install._FIXED_ALMA_RPM_MEMBERS[package][0].lstrip("/")
            assert identity[:2] == (leaf.stat().st_dev, leaf.stat().st_ino)
            assert digest == hashlib.sha256(package.encode()).hexdigest()
    else:
        with pytest.raises(stage.WorkerStageError):
            install._fixed_policy_tool_snapshot()
