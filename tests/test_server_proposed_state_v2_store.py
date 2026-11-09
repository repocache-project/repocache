"""Linux FD fixture-only v2 durability, crash and legacy-migration refusals."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from repocache.server_repository_plan_v1 import (
    RepositoryPlanError, _canonical_identity, plan_repository_change,
)
from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME as LEGACY_JOURNAL,
    JOURNAL_TMP_NAME as LEGACY_JOURNAL_TMP,
    LOCK_NAME,
    ProtectedStateStoreError,
    _commit_under_root as commit_legacy,
    _recover_under_root as recover_legacy,
    _locked,
)
from repocache.server_proposed_state_v2_store import (
    MAX_V2_STATE_BYTES, V2_JOURNAL, V2_JOURNAL_TMP, V2_ROLLBACK,
    V2_STAGE, V2_STATE,
    ProposedV2PersistenceError,
    _commit_proposed_v2_under_root as commit,
    _recover_proposed_v2_under_root as recover,
    _preview_persisted_v2_nginx_candidate_under_root as render_persisted,
    _preview_proposed_v2_nginx_before_commit_under_root as precommit_nginx,
    _preview_v1_migration_blockers_under_root as preview_v1_migration,
    _preview_proposed_v2_recovery_under_root as preview_v2_recovery,
)


@pytest.fixture
def fixture_root(tmp_path):
    root = tmp_path / "mock-root"
    root.mkdir(mode=0o700)
    folder = root
    for segment in ("var", "lib", "repocache", "server"):
        folder = folder / segment
        folder.mkdir(mode=0o700)
    (folder / LOCK_NAME).write_bytes(b"")
    (folder / LOCK_NAME).chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd, folder, os.geteuid()
    finally:
        os.close(fd)


def document(count=2, *, generation=1):
    example = (Path(__file__).resolve().parents[1] /
               "docs/examples/server-install-v1.json")
    source = json.loads(example.read_text(encoding="utf-8"))
    source["expected_state_generation"] = generation
    original = source["repositories"][0]
    repos = []
    for index in range(count):
        row = copy.deepcopy(original)
        row["id"] = f"repo-{index}"
        row["upstream"]["base_url"] = (
            f"https://mirror{index}.example.invalid/debian/"
        )
        row["upstream"]["allowed_hosts"] = [
            f"mirror{index}.example.invalid"
        ]
        repos.append(row)
    source["repositories"] = repos
    return source


def snapshot(count=2, *, generation=1, previous=None, doc=None):
    config = copy.deepcopy(doc if doc is not None else document(count))
    config["expected_state_generation"] = generation
    raw = json.dumps(
        config, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    records = [{
        "id": row["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(row).encode("utf-8")
        ).hexdigest(),
        "desired_state": row["desired_state"],
        "observed_state": "not-activated",
    } for row in config["repositories"]]
    reserved = [{
        "id": rec["id"],
        "canonical_identity_sha256": rec["canonical_identity_sha256"],
        "status": "allocated",
    } for rec in records]
    if previous is not None:
        existing = {rec["id"] for rec in reserved}
        for row in previous["id_reservations"]:
            if row["id"] not in existing:
                reserved.append({**row, "status": "retired"})
    sha = hashlib.sha256(raw).hexdigest()
    return {
        "state_schema_version": 2,
        "state_generation": generation,
        "configuration_base64": base64.b64encode(raw).decode("ascii"),
        "configuration_sha256": sha,
        "repository_records": records,
        "id_reservations": reserved,
        "approval_reference": {
            "source": "operator",
            "decision_sha256": "d" * 64,
            "configuration_sha256": sha,
            "expected_generation": generation - 1,
        },
    }


def apply(layout, candidate, expected=0, inject=None):
    fd, _, uid = layout
    return commit(
        fd, candidate, expected_generation=expected,
        owner_uid=uid, inject_fault=inject,
    )


def rollback(layout):
    fd, _, uid = layout
    return recover(fd, owner_uid=uid)


def assert_no_authority(report):
    for field in (
        "operator_authorization_verified",
        "host_root_provenance_verified",
        "authorizes_installation",
        "authorizes_nginx_reload",
        "authorizes_catalog_publication",
        "authorizes_cache_cleanup",
    ):
        assert report[field] is False


def test_v2_bootstrap_reads_exact_canonical_bytes_and_recovers_clean(fixture_root):
    _, folder, _ = fixture_root
    requested = snapshot(33)
    report = apply(fixture_root, requested)
    assert report["status"] == "COMMITTED_INERT_V2"
    assert report["state_generation"] == 1
    assert_no_authority(report)
    raw = (folder / V2_STATE).read_bytes()
    assert json.loads(raw) == requested
    assert (folder / V2_STATE).stat().st_mode & 0o777 == 0o600
    assert not (folder / V2_JOURNAL).exists()
    assert not (folder / V2_STAGE).exists()
    assert rollback(fixture_root)["status"] == "CLEAN"
    assert (folder / V2_STATE).read_bytes() == raw


def test_v2_noop_does_not_create_generation_or_change_inode(fixture_root):
    _, folder, _ = fixture_root
    first = snapshot(2)
    apply(fixture_root, first)
    before = (folder / V2_STATE).stat()
    second = snapshot(2, generation=2, previous=first)
    status = apply(fixture_root, second, expected=1)
    assert status["status"] == "NO_CHANGE_INERT_V2"
    assert status["state_generation"] == 1
    assert (folder / V2_STATE).stat().st_ino == before.st_ino
    assert not (folder / V2_JOURNAL).exists()
    assert rollback(fixture_root)["state_generation"] == 1


def test_v2_retirement_durable_and_stale_cas_refused(fixture_root):
    _, folder, _ = fixture_root
    first = snapshot()
    apply(fixture_root, first)
    reduced = document(1)
    later = snapshot(generation=2, previous=first, doc=reduced)
    assert apply(fixture_root, later, expected=1)["state_generation"] == 2
    saved = json.loads((folder / V2_STATE).read_bytes())
    assert len(saved["repository_records"]) == 1
    assert len(saved["id_reservations"]) == 2
    assert saved["id_reservations"][-1]["status"] == "retired"
    with pytest.raises(ProposedV2PersistenceError, match="STALE_GENERATION"):
        apply(fixture_root, snapshot(generation=2), expected=1)
    assert json.loads((folder / V2_STATE).read_bytes()) == saved


@pytest.mark.parametrize(
    "phase",
    ["journal_tmp_durable", "journal_durable", "stage_durable", "replace_durable"],
)
@pytest.mark.parametrize("bootstrap", [True, False])
def test_v2_crash_recovery_restores_exact_previous_bytes(
    fixture_root, phase, bootstrap,
):
    _, folder, _ = fixture_root
    previous = None
    baseline = None
    generation = 0
    if not bootstrap:
        previous = snapshot()
        apply(fixture_root, previous)
        baseline = (folder / V2_STATE).read_bytes()
        generation = 1
    candidate = snapshot(
        count=1, generation=generation + 1,
        previous=previous,
    )
    def interrupt(point):
        if point == phase:
            raise RuntimeError("synthetic crash")

    with pytest.raises(RuntimeError, match="synthetic crash"):
        apply(fixture_root, candidate, expected=generation, inject=interrupt)
    journal_file = (V2_JOURNAL_TMP if phase == "journal_tmp_durable"
                    else V2_JOURNAL)
    assert (folder / journal_file).exists()
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        apply(fixture_root, candidate, expected=generation)
    report = rollback(fixture_root)
    assert report["status"] in (
        "DISCARDED_UNPUBLISHED_V2_JOURNAL", "ROLLED_BACK_INERT_V2"
    )
    assert report["state_generation"] == generation
    assert_no_authority(report)
    assert not (folder / V2_JOURNAL).exists()
    assert not (folder / V2_JOURNAL_TMP).exists()
    assert not (folder / V2_STAGE).exists()
    if baseline is None:
        assert not (folder / V2_STATE).exists()
    else:
        assert (folder / V2_STATE).read_bytes() == baseline
    assert rollback(fixture_root)["status"] == "CLEAN"
    assert apply(fixture_root, candidate, expected=generation)["status"] == (
        "COMMITTED_INERT_V2"
    )


def test_v2_recovery_refuses_changed_authoritative_bytes(fixture_root):
    _, folder, _ = fixture_root
    start = snapshot()
    apply(fixture_root, start)
    future = snapshot(count=1, generation=2, previous=start)
    def crash(point):
        if point == "replace_durable":
            raise RuntimeError("crash")
    with pytest.raises(RuntimeError):
        apply(fixture_root, future, expected=1, inject=crash)
    altered = (folder / V2_STATE).read_bytes().replace(
        b'"state_schema_version":2', b'"state_schema_version":9'
    )
    assert altered != (folder / V2_STATE).read_bytes()
    (folder / V2_STATE).write_bytes(altered)
    with pytest.raises(ProposedV2PersistenceError, match="STATE_DRIFT"):
        rollback(fixture_root)
    assert (folder / V2_STATE).read_bytes() == altered
    assert (folder / V2_JOURNAL).is_file()


def test_v2_recovery_retry_after_simulated_rename_failure(
    fixture_root, monkeypatch,
):
    import repocache.server_proposed_state_v2_store as module
    _, folder, _ = fixture_root
    first = snapshot()
    apply(fixture_root, first)
    raw = (folder / V2_STATE).read_bytes()
    next_state = snapshot(count=1, generation=2, previous=first)

    def crash(phase):
        if phase == "replace_durable":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError):
        apply(fixture_root, next_state, expected=1, inject=crash)
    original = os.replace

    def fail_rollback(src, dst, *args, **kwargs):
        if src == V2_ROLLBACK:
            raise OSError("synthetic rename refusal")
        return original(src, dst, *args, **kwargs)

    monkeypatch.setattr(module.os, "replace", fail_rollback)
    with pytest.raises(ProposedV2PersistenceError, match="ROLLBACK_IO_REFUSED"):
        rollback(fixture_root)
    assert (folder / V2_JOURNAL).exists()
    monkeypatch.setattr(module.os, "replace", original)
    assert rollback(fixture_root)["status"] == "ROLLED_BACK_INERT_V2"
    assert (folder / V2_STATE).read_bytes() == raw
    assert rollback(fixture_root)["status"] == "CLEAN"


def test_v2_orphan_stage_refused_without_deletion(fixture_root):
    _, folder, _ = fixture_root
    (folder / V2_STAGE).write_bytes(b"unexpected")
    (folder / V2_STAGE).chmod(0o600)
    with pytest.raises(ProposedV2PersistenceError, match="ORPHAN"):
        rollback(fixture_root)
    assert (folder / V2_STAGE).read_bytes() == b"unexpected"


def test_v2_symlink_and_lock_contention_refused(fixture_root, tmp_path):
    fd, folder, uid = fixture_root
    (folder / V2_STATE).symlink_to(tmp_path / "external")
    with pytest.raises(ProtectedStateStoreError):
        rollback(fixture_root)
    (folder / V2_STATE).unlink()
    with _locked(fd, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            apply(fixture_root, snapshot())


def test_v2_never_adopts_existing_v1_state(fixture_root):
    fd, folder, uid = fixture_root
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }
    commit_legacy(
        fd, legacy, owner_uid=uid, expected_generation=0
    )
    initial = (folder / "state-v1.json").read_bytes()
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_MIGRATION_REQUIRED"):
        apply(fixture_root, snapshot())
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_MIGRATION_REQUIRED"):
        rollback(fixture_root)
    assert (folder / "state-v1.json").read_bytes() == initial
    assert not (folder / V2_STATE).exists()


def test_v2_never_adopts_unfinished_v1_journal(fixture_root):
    fd, folder, uid = fixture_root
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }

    def interrupted(phase):
        if phase == "journal_durable":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError):
        commit_legacy(
            fd, legacy, owner_uid=uid, expected_generation=0,
            inject_fault=interrupted,
        )
    assert (folder / LEGACY_JOURNAL).is_file()
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_RECOVERY_REQUIRED"):
        apply(fixture_root, snapshot())
    assert (folder / LEGACY_JOURNAL).is_file()
    assert not (folder / V2_STATE).exists()


def test_v2_full_500_repository_snapshot_is_durable(fixture_root):
    _, folder, _ = fixture_root
    candidate = snapshot(500)
    report = apply(fixture_root, candidate)
    assert report["state_generation"] == 1
    raw = (folder / V2_STATE).read_bytes()
    assert 1_000_000 > len(raw) > 90_000
    assert json.loads(raw)["repository_records"][499]["id"] == "repo-499"
    assert rollback(fixture_root)["status"] == "CLEAN"


def test_v2_large_retired_ledger_fits_separate_bounds(fixture_root):
    _, folder, _ = fixture_root
    candidate = snapshot(2)
    for i in range(2, 10_000):
        candidate["id_reservations"].append({
            "id": f"retired-{i}",
            "canonical_identity_sha256": hashlib.sha256(
                f"history-{i}".encode()
            ).hexdigest(),
            "status": "retired",
        })
    report = apply(fixture_root, candidate)
    assert report["status"] == "COMMITTED_INERT_V2"
    raw = (folder / V2_STATE).read_bytes()
    assert 1_000_000 < len(raw) < MAX_V2_STATE_BYTES
    assert rollback(fixture_root)["status"] == "CLEAN"


def test_v2_invalid_candidate_causes_no_disk_effect(fixture_root):
    _, folder, _ = fixture_root
    bad = snapshot()
    bad["configuration_sha256"] = "0" * 64
    before = sorted(p.name for p in folder.iterdir())
    with pytest.raises(ProposedV2PersistenceError, match="SNAPSHOT_INVALID"):
        apply(fixture_root, bad)
    assert sorted(p.name for p in folder.iterdir()) == before



def test_legacy_writer_and_reader_refuse_existing_v2_state(fixture_root):
    from repocache.server_locked_manifest_reconcile_v1 import (
        _inspect_locked_under_root,
    )
    fd, folder, uid = fixture_root
    proposed = snapshot()
    apply(fixture_root, proposed)
    v2_bytes = (folder / V2_STATE).read_bytes()
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        commit_legacy(fd, legacy, expected_generation=0, owner_uid=uid)
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        recover_legacy(fd, owner_uid=uid)
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        _inspect_locked_under_root(
            fd, owner_uid=uid, expected_generation=0,
        )
    assert not (folder / "state-v1.json").exists()
    assert (folder / V2_STATE).read_bytes() == v2_bytes


def test_legacy_writer_refuses_interrupted_v2_journal(fixture_root):
    fd, folder, uid = fixture_root
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }

    def crash(phase):
        if phase == "journal_durable":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError):
        apply(fixture_root, snapshot(), inject=crash)
    pending = (folder / V2_JOURNAL).read_bytes()
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        commit_legacy(fd, legacy, expected_generation=0, owner_uid=uid)
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        recover_legacy(fd, owner_uid=uid)
    assert (folder / V2_JOURNAL).read_bytes() == pending
    assert not (folder / "state-v1.json").exists()
    assert rollback(fixture_root)["status"] == "ROLLED_BACK_INERT_V2"


def test_legacy_writer_refuses_dangling_v2_symlink(fixture_root):
    fd, folder, uid = fixture_root
    link = folder / V2_STATE
    link.symlink_to(folder / "missing-target")
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        commit_legacy(fd, legacy, expected_generation=0, owner_uid=uid)
    assert link.is_symlink()
    assert not (folder / "state-v1.json").exists()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires Linux fork")
@pytest.mark.parametrize(
    "phase",
    ["journal_tmp_durable", "journal_durable", "stage_durable", "replace_durable"],
)
@pytest.mark.parametrize("upgrade", [False, True])
def test_real_process_exit_and_recovery_in_second_process(
    fixture_root, phase, upgrade,
):
    """A child exits without Python cleanup after fsync; new PID recovers."""
    _, folder, _ = fixture_root
    old = snapshot() if upgrade else None
    generation = 1 if upgrade else 0
    old_bytes = None
    if upgrade:
        apply(fixture_root, old)
        old_bytes = (folder / V2_STATE).read_bytes()
    proposal = snapshot(count=1, generation=generation + 1, previous=old)

    pid = os.fork()
    if pid == 0:
        def stop(point):
            if point == phase:
                os._exit(73)
        try:
            apply(fixture_root, proposal, expected=generation, inject=stop)
        except BaseException:
            os._exit(74)
        os._exit(75)

    waited, status = os.waitpid(pid, 0)
    assert waited == pid and os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 73
    pending = V2_JOURNAL_TMP if phase == "journal_tmp_durable" else V2_JOURNAL
    assert (folder / pending).is_file()
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        apply(fixture_root, proposal, expected=generation)

    other = os.fork()
    if other == 0:
        try:
            report = rollback(fixture_root)
            assert report["state_generation"] == generation
            assert report["status"] in (
                "DISCARDED_UNPUBLISHED_V2_JOURNAL", "ROLLED_BACK_INERT_V2",
            )
            assert_no_authority(report)
        except BaseException:
            os._exit(76)
        os._exit(0)

    waited, status = os.waitpid(other, 0)
    assert waited == other and os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert not (folder / V2_JOURNAL).exists()
    assert not (folder / V2_JOURNAL_TMP).exists()
    assert not (folder / V2_STAGE).exists()
    if old_bytes is None:
        assert not (folder / V2_STATE).exists()
    else:
        assert (folder / V2_STATE).read_bytes() == old_bytes
    assert rollback(fixture_root)["status"] == "CLEAN"
    assert apply(fixture_root, proposal, expected=generation)["status"] == (
        "COMMITTED_INERT_V2"
    )



def two_layout_active_snapshot():
    source = (Path(__file__).resolve().parents[1] /
              "docs/examples/server-install-v1.json")
    doc = json.loads(source.read_text(encoding="utf-8"))
    doc["expected_state_generation"] = 1
    doc["repositories"][1]["id"] = "almalinux-baseos"
    for repository in doc["repositories"]:
        repository["desired_state"] = "active"
    return snapshot(generation=1, doc=doc)


def pinned_two_layouts():
    return {
        name: {"mirror.example.invalid": ["8.8.8.8", "2001:4860:4860::8888"]}
        for name in ("debian-trixie-main", "almalinux-baseos")
    }


def persisted_render(layout, *, generation=1, pins=None):
    fd, _, uid = layout
    return render_persisted(
        fd, owner_uid=uid, expected_generation=generation,
        candidate_pins_by_repository=(
            pinned_two_layouts() if pins is None else pins
        ),
        ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
    )


def test_locked_persisted_v2_produces_only_non_authorizing_nginx_candidate(
    fixture_root,
):
    _, folder, _ = fixture_root
    state = two_layout_active_snapshot()
    apply(fixture_root, state)
    before = (folder / V2_STATE).read_bytes()
    result = persisted_render(fixture_root)
    assert result["status"] == "LOCKED_FIXTURE_V2_NGINX_CANDIDATE_ONLY"
    assert result["proposed_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main",
    ]
    assert "proxy_ssl_verify on;" in result["server_location_fragment"]
    assert "proxy_ssl_server_name on;" in result["server_location_fragment"]
    assert "proxy_pass https://" in result["server_location_fragment"]
    assert "proxy_pass http://" not in result["server_location_fragment"]
    assert result["persisted_config_bytes_and_digest_consistent"] is True
    assert result["exclusive_state_lock_held_during_preview"] is True
    for key in (
        "trusted_host_root_verified", "operator_authorization_verified",
        "live_include_manifest_verified", "nginx_syntax_verified",
        "active_exposure_verified", "authorizes_nginx_activation",
        "authorizes_catalog_publication",
    ):
        assert result[key] is False
    assert (folder / V2_STATE).read_bytes() == before
    assert not (folder / V2_JOURNAL).exists()


@pytest.mark.parametrize("bad", [
    {}, {"debian-trixie-main": {"mirror.example.invalid": ["8.8.8.8"]}},
    {**pinned_two_layouts(), "unknown-repo": {"mirror.example.invalid": ["8.8.8.8"]}},
    {**pinned_two_layouts(), "almalinux-baseos": {
        "mirror.example.invalid": ["169.254.169.254"],
    }},
    {**pinned_two_layouts(), "almalinux-baseos": {
        "wrong.example.invalid": ["8.8.8.8"],
    }},
])
def test_locked_persisted_v2_refuses_missing_extra_unsafe_pins(
    fixture_root, bad,
):
    _, folder, _ = fixture_root
    apply(fixture_root, two_layout_active_snapshot())
    original = (folder / V2_STATE).read_bytes()
    with pytest.raises(ProposedV2PersistenceError, match="NGINX_CANDIDATE_REFUSED"):
        persisted_render(fixture_root, pins=bad)
    assert (folder / V2_STATE).read_bytes() == original
    assert not (folder / V2_JOURNAL).exists()


def test_locked_persisted_v2_refuses_stale_and_uncommitted_state(fixture_root):
    fd, folder, uid = fixture_root
    with pytest.raises(ProposedV2PersistenceError, match="STATE_ABSENT"):
        persisted_render(fixture_root)
    old = two_layout_active_snapshot()
    apply(fixture_root, old)
    with pytest.raises(ProposedV2PersistenceError, match="STALE_GENERATION"):
        persisted_render(fixture_root, generation=2)

    updated = snapshot(count=1, generation=2, previous=old)
    def stop(phase):
        if phase == "journal_durable":
            raise RuntimeError("interrupt")

    with pytest.raises(RuntimeError):
        apply(fixture_root, updated, expected=1, inject=stop)
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        persisted_render(fixture_root)
    assert rollback(fixture_root)["state_generation"] == 1
    assert persisted_render(fixture_root)["proposed_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main",
    ]


def test_locked_persisted_v2_renderer_refuses_lock_contention(fixture_root):
    fd, _, uid = fixture_root
    apply(fixture_root, two_layout_active_snapshot())
    with _locked(fd, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            persisted_render(fixture_root)


@pytest.mark.skipif(
    shutil.which("nginx") is None,
    reason="disposable distro-packaged nginx unavailable",
)
def test_persisted_v2_nginx_t_succeeds_without_touching_live_config(
    fixture_root, tmp_path,
):
    ca = next((
        p for p in (
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ) if Path(p).is_file()
    ), None)
    if ca is None:
        pytest.skip("disposable container CA bundle unavailable")
    state = two_layout_active_snapshot()
    apply(fixture_root, state)
    fd, folder, uid = fixture_root
    pinned = render_persisted(
        fd, owner_uid=uid, expected_generation=1,
        candidate_pins_by_repository=pinned_two_layouts(),
        ca_bundle_path=ca,
    )
    assert pinned["nginx_syntax_verified"] is False
    before = (folder / V2_STATE).read_bytes()
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'nginx-error.log'} notice;\n"
        "events {}\nhttp { access_log off;\n"
        + pinned["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19991;\n"
        + pinned["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    finished = subprocess.run(
        [shutil.which("nginx"), "-t", "-c", str(conf), "-p", str(tmp_path)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert finished.returncode == 0, finished.stderr
    assert (folder / V2_STATE).read_bytes() == before
    assert not (folder / V2_JOURNAL).exists()


@pytest.mark.skipif(
    shutil.which("nginx") is None,
    reason="disposable distro-packaged nginx unavailable",
)
def test_nginx_live_rollback_in_sandbox(fixture_root, tmp_path):
    """Exercise a REAL isolated NGINX master, not production host activation.

    The v2 state/renderer are read-only input. This demonstrates that invalid
    syntax leaves the old worker serving, and that a reload of a valid
    candidate can be compensated by reloading the previous known-good bytes.
    It does NOT implement the privileged transaction or prove host recovery.
    """
    import socket
    import time

    nginx = shutil.which("nginx")
    ca = next((
        p for p in (
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ) if Path(p).is_file()
    ), None)
    if ca is None:
        pytest.skip("disposable container CA bundle unavailable")
    apply(fixture_root, two_layout_active_snapshot())
    fd, state_dir, uid = fixture_root
    persisted_before = (state_dir / V2_STATE).read_bytes()
    candidate = render_persisted(
        fd, owner_uid=uid, expected_generation=1,
        candidate_pins_by_repository=pinned_two_layouts(),
        ca_bundle_path=ca,
    )
    assert candidate["authorizes_nginx_activation"] is False

    sock = tmp_path / "nginx.sock"
    conf = tmp_path / "nginx.conf"
    master_pid = tmp_path / "nginx.pid"
    log = tmp_path / "nginx-error.log"
    assert len(os.fsencode(sock)) < 100  # Linux sockaddr_un path boundary

    def config(body):
        return (
            f"pid {master_pid};\n"
            f"error_log {log} notice;\n"
            "worker_processes 1;\nevents { worker_connections 32; }\n"
            "http { access_log off;\n"
            + candidate["http_upstream_fragment"]
            + f"server {{ listen unix:{sock};\n"
            + f'location = /__test_health {{ return 200 "{body}"; }}\n'
            + candidate["server_location_fragment"]
            + "}\n}\n"
        ).encode("utf-8")

    previous = config("known-good")
    replacement = config("candidate")
    invalid = previous.replace(
        b"return 200 \"known-good\";",
        b"return 200 \"known-good\"; invalid_directive;",
    )
    assert invalid != previous

    def stage(raw):
        # Atomic config replacement here is ONLY in a disposable temp tree.
        stage_file = tmp_path / "nginx.stage"
        with stage_file.open("wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(stage_file, conf)

    def command(*args):
        return subprocess.run(
            [nginx, *args, "-c", str(conf), "-p", str(tmp_path)],
            capture_output=True, text=True, timeout=10, check=False,
        )

    def response():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(1)
            conn.connect(str(sock))
            conn.sendall(
                b"GET /__test_health HTTP/1.0\r\n"
                b"Host: localhost\r\nConnection: close\r\n\r\n"
            )
            received = bytearray()
            while len(received) < 8192:
                part = conn.recv(8192 - len(received))
                if not part:
                    break
                received.extend(part)
            return bytes(received)

    def wait_for(expected, process):
        last = None
        for _ in range(100):
            if process.poll() is not None:
                pytest.fail("isolated NGINX master exited")
            try:
                last = response()
                if (b" 200 " in last.split(b"\r\n", 1)[0]
                        and last.endswith(expected)):
                    return
            except (OSError, TimeoutError):
                pass
            time.sleep(0.05)
        pytest.fail(f"isolated NGINX response did not reach {expected!r}: {last!r}")

    stage(previous)
    tested = command("-t")
    assert tested.returncode == 0, tested.stderr
    process = subprocess.Popen(
        [nginx, "-c", str(conf), "-p", str(tmp_path), "-g", "daemon off;"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        wait_for(b"known-good", process)

        # Syntax-failure path: never signal the running service; restore the
        # exact previous bytes and show the old worker remained responsive.
        stage(invalid)
        tested = command("-t")
        assert tested.returncode != 0
        wait_for(b"known-good", process)
        stage(previous)
        assert conf.read_bytes() == previous
        assert command("-t").returncode == 0

        # Post-reload compensation: verify a new live worker configuration,
        # simulate failure of a later activation gate, and restore the old
        # running response by an actual controlled reload in this sandbox.
        stage(replacement)
        assert command("-t").returncode == 0
        reloaded = command("-s", "reload")
        assert reloaded.returncode == 0, reloaded.stderr
        wait_for(b"candidate", process)
        stage(previous)
        assert conf.read_bytes() == previous
        assert command("-t").returncode == 0
        restored = command("-s", "reload")
        assert restored.returncode == 0, restored.stderr
        wait_for(b"known-good", process)

        assert (state_dir / V2_STATE).read_bytes() == persisted_before
        assert not (state_dir / V2_JOURNAL).exists()
        assert not (state_dir / V2_STAGE).exists()
    finally:
        if process.poll() is None:
            command("-s", "quit")
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


def _legacy_state(*, generation=1, digest="a"):
    return {
        "state_schema_version": 1,
        "state_generation": generation,
        "configuration_sha256": digest * 64,
        "repositories": [],
        "ownership_manifest": [],
    }


def test_v1_migration_preflight_never_claims_lossless_conversion(fixture_root):
    fd, folder, uid = fixture_root
    commit_legacy(fd, _legacy_state(), owner_uid=uid, expected_generation=0)
    path = folder / "state-v1.json"
    raw, inode = path.read_bytes(), path.stat().st_ino
    before = sorted(p.name for p in folder.iterdir())
    result = preview_v1_migration(fd, owner_uid=uid)
    assert result["status"] == "LEGACY_V1_MIGRATION_BLOCKED"
    assert result["state_generation"] == 1
    assert result["legacy_repository_count"] == 0
    assert result["legacy_manifest_entry_count"] == 0
    assert result["v1_snapshot_read_under_exclusive_lock"] is True
    assert result["v1_recovery_pending"] is False
    for key in (
        "independent_configuration_bytes_verified",
        "historic_id_reservations_verified",
        "live_nginx_include_verified",
        "versioned_migration_protocol_approved",
        "authorizes_migration",
    ):
        assert result[key] is False
    assert_no_authority(result)
    assert path.read_bytes() == raw and path.stat().st_ino == inode
    assert sorted(p.name for p in folder.iterdir()) == before
    assert not (folder / V2_STATE).exists()


def test_v1_migration_preflight_refuses_absence_and_pending_journal(fixture_root):
    fd, folder, uid = fixture_root
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_STATE_ABSENT"):
        preview_v1_migration(fd, owner_uid=uid)
    commit_legacy(fd, _legacy_state(), owner_uid=uid, expected_generation=0)
    previous = (folder / "state-v1.json").read_bytes()

    def stop(phase):
        if phase == "journal_durable":
            raise RuntimeError("interrupted v1 write")

    with pytest.raises(RuntimeError, match="interrupted v1 write"):
        commit_legacy(
            fd, _legacy_state(generation=2, digest="b"),
            owner_uid=uid, expected_generation=1, inject_fault=stop,
        )
    original_journal = (folder / LEGACY_JOURNAL).read_bytes()
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_RECOVERY_REQUIRED"):
        preview_v1_migration(fd, owner_uid=uid)
    assert (folder / LEGACY_JOURNAL).read_bytes() == original_journal
    assert (folder / "state-v1.json").read_bytes() == previous
    assert recover_legacy(fd, owner_uid=uid)["state_generation"] == 1
    assert preview_v1_migration(fd, owner_uid=uid)["authorizes_migration"] is False


def test_v1_migration_preflight_refuses_v2_coexistence_and_lock_contention(
    fixture_root,
):
    fd, folder, uid = fixture_root
    commit_legacy(fd, _legacy_state(), owner_uid=uid, expected_generation=0)
    with _locked(fd, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            preview_v1_migration(fd, owner_uid=uid)
    v2_link = folder / V2_STATE
    v2_link.symlink_to(folder / "missing-foreign-state")
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        preview_v1_migration(fd, owner_uid=uid)
    assert v2_link.is_symlink()
    assert (folder / "state-v1.json").is_file()


@pytest.mark.parametrize("phase,pending", [
    ("journal_tmp_durable", LEGACY_JOURNAL_TMP),
    ("journal_durable", LEGACY_JOURNAL),
])
def test_v1_migration_preflight_prioritizes_interrupted_bootstrap(
    fixture_root, phase, pending,
):
    fd, folder, uid = fixture_root

    def stop(point):
        if point == phase:
            raise RuntimeError("interrupted initial v1 commit")

    with pytest.raises(RuntimeError, match="interrupted initial v1 commit"):
        commit_legacy(
            fd, _legacy_state(), owner_uid=uid,
            expected_generation=0, inject_fault=stop,
        )
    original = (folder / pending).read_bytes()
    assert not (folder / "state-v1.json").exists()
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_RECOVERY_REQUIRED"):
        preview_v1_migration(fd, owner_uid=uid)
    assert (folder / pending).read_bytes() == original
    assert not (folder / V2_STATE).exists()
    recover_legacy(fd, owner_uid=uid)
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_STATE_ABSENT"):
        preview_v1_migration(fd, owner_uid=uid)


def test_current_namespace_v1_migration_refuses_nonroot_before_open(monkeypatch):
    import repocache.server_proposed_state_v2_store as module

    monkeypatch.setattr(module.os, "geteuid", lambda: 1000)

    def forbidden(*args, **kwargs):
        pytest.fail("unprivileged diagnostic opened a host path")

    monkeypatch.setattr(module.os, "open", forbidden)
    with pytest.raises(
        ProposedV2PersistenceError,
        match="CURRENT_NAMESPACE_ROOT_PRIVILEGE_REQUIRED",
    ):
        module.inspect_current_namespace_v1_migration_blockers()


def test_current_namespace_v1_migration_diagnoses_only_pinned_root(monkeypatch):
    import repocache.server_proposed_state_v2_store as module

    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    steps = []

    def verify(fd):
        assert os.fstat(fd).st_ino == os.stat("/").st_ino
        steps.append("pinned")

    def preview(fd, *, owner_uid):
        assert owner_uid == 0
        assert os.fstat(fd).st_ino == os.stat("/").st_ino
        steps.append("preview")
        return {
            "status": "LEGACY_V1_MIGRATION_BLOCKED",
            "state_generation": 1,
            "authorizes_migration": False,
        }

    monkeypatch.setattr(module, "_verify_current_root_fd", verify)
    monkeypatch.setattr(module, "_preview_v1_migration_blockers_under_root", preview)
    report = module.inspect_current_namespace_v1_migration_blockers()
    assert steps == ["pinned", "preview", "pinned"]
    assert report["status"] == "LEGACY_V1_MIGRATION_BLOCKED"
    assert report["current_namespace_root_path_verified"] is True
    for field in (
        "trusted_host_root_verified", "operator_authorization_verified",
        "authorizes_migration", "authorizes_nginx_reload",
        "authorizes_catalog_publication",
    ):
        assert report[field] is False


def test_current_namespace_v1_migration_refuses_substituted_root(
    fixture_root, monkeypatch,
):
    import repocache.server_proposed_state_v2_store as module
    from repocache.server_locked_manifest_reconcile_v1 import (
        LockedManifestInspectionError,
    )

    fd, _, _ = fixture_root
    original_open = os.open
    opened = []
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)

    def substitute(path, flags, *args, **kwargs):
        if path == "/":
            clone = os.dup(fd)
            opened.append(clone)
            return clone
        return original_open(path, flags, *args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("substitute root reached v1 migration diagnosis")

    monkeypatch.setattr(module.os, "open", substitute)
    monkeypatch.setattr(module, "_preview_v1_migration_blockers_under_root", forbidden)
    with pytest.raises(
        LockedManifestInspectionError, match="CURRENT_NAMESPACE_ROOT_",
    ):
        module.inspect_current_namespace_v1_migration_blockers()
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_current_namespace_v1_migration_closes_root_after_refusal(monkeypatch):
    import repocache.server_proposed_state_v2_store as module

    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    visited = []

    def refused(fd, *, owner_uid):
        assert owner_uid == 0
        visited.append(fd)
        raise ProposedV2PersistenceError("PROPOSED_V2_PERSISTENCE_TEST_REFUSAL")

    monkeypatch.setattr(module, "_preview_v1_migration_blockers_under_root", refused)
    with pytest.raises(ProposedV2PersistenceError, match="TEST_REFUSAL"):
        module.inspect_current_namespace_v1_migration_blockers()
    assert len(visited) == 1
    with pytest.raises(OSError):
        os.fstat(visited[0])


def v2_recovery_preview(layout):
    fd, _, uid = layout
    return preview_v2_recovery(fd, owner_uid=uid)


def test_v2_read_only_recovery_preview_clean_and_committed(fixture_root):
    _, folder, _ = fixture_root
    before = sorted(p.name for p in folder.iterdir())
    empty = v2_recovery_preview(fixture_root)
    assert empty["status"] == "CLEAN"
    assert empty["state_generation"] == 0
    assert empty["v2_recovery_pending"] is False
    assert_no_authority(empty)
    assert sorted(p.name for p in folder.iterdir()) == before
    apply(fixture_root, snapshot())
    saved = (folder / V2_STATE).read_bytes()
    done = v2_recovery_preview(fixture_root)
    assert done["status"] == "CLEAN"
    assert done["state_generation"] == 1
    assert done["v2_recovery_pending"] is False
    assert done["read_only_under_exclusive_lock"] is True
    for field in ("authorizes_v2_recovery", "authorizes_v1_migration",
                  "host_service_recovery_verified"):
        assert done[field] is False
    assert_no_authority(done)
    assert (folder / V2_STATE).read_bytes() == saved


@pytest.mark.parametrize("bootstrap", [True, False])
@pytest.mark.parametrize("phase,status", [
    ("journal_tmp_durable", "UNPUBLISHED_V2_JOURNAL_ONLY"),
    ("journal_durable", "INTERRUPTED_BEFORE_V2_REPLACE"),
    ("stage_durable", "INTERRUPTED_BEFORE_V2_REPLACE"),
    ("replace_durable", "INTERRUPTED_AFTER_V2_REPLACE"),
])
def test_v2_read_only_recovery_preview_crash_windows(
    fixture_root, bootstrap, phase, status,
):
    _, folder, _ = fixture_root
    previous = None
    generation = 0
    if not bootstrap:
        previous = snapshot()
        apply(fixture_root, previous)
        generation = 1
    candidate = snapshot(
        count=1, generation=generation + 1, previous=previous,
    )

    def interrupt(point):
        if point == phase:
            raise RuntimeError("synthetic interruption")

    with pytest.raises(RuntimeError, match="synthetic interruption"):
        apply(fixture_root, candidate, expected=generation, inject=interrupt)
    names = sorted(p.name for p in folder.iterdir())
    existing = {
        p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()
    }
    report = v2_recovery_preview(fixture_root)
    assert report["status"] == status
    assert report["read_only_under_exclusive_lock"] is True
    assert report["v2_recovery_pending"] is True
    assert report["v2_published_journal_present"] is (
        phase != "journal_tmp_durable"
    )
    assert report["rollback_temp_requires_rebuild"] is False
    assert_no_authority(report)
    assert report["authorizes_v2_recovery"] is False
    assert report["host_service_recovery_verified"] is False
    assert sorted(p.name for p in folder.iterdir()) == names
    assert {
        p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()
    } == existing
    assert rollback(fixture_root)["state_generation"] == generation
    assert v2_recovery_preview(fixture_root)["status"] == "CLEAN"


def test_v2_read_only_recovery_preview_refuses_state_drift(fixture_root):
    _, folder, _ = fixture_root
    initial = snapshot()
    apply(fixture_root, initial)
    proposed = snapshot(count=1, generation=2, previous=initial)

    def interrupt(point):
        if point == "replace_durable":
            raise RuntimeError("interrupted")

    with pytest.raises(RuntimeError, match="interrupted"):
        apply(fixture_root, proposed, expected=1, inject=interrupt)
    divergent = snapshot(count=2, generation=2, previous=initial)
    raw = json.dumps(
        divergent, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    (folder / V2_STATE).write_bytes(raw)
    journal = (folder / V2_JOURNAL).read_bytes()
    with pytest.raises(ProposedV2PersistenceError, match="STATE_DRIFT"):
        v2_recovery_preview(fixture_root)
    assert (folder / V2_STATE).read_bytes() == raw
    assert (folder / V2_JOURNAL).read_bytes() == journal


def test_v2_read_only_recovery_preview_refuses_orphan_and_held_lock(
    fixture_root,
):
    fd, folder, uid = fixture_root
    with _locked(fd, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            v2_recovery_preview(fixture_root)
    (folder / V2_STAGE).write_bytes(b"foreign-temp")
    (folder / V2_STAGE).chmod(0o600)
    with pytest.raises(ProposedV2PersistenceError, match="ORPHAN"):
        v2_recovery_preview(fixture_root)
    assert (folder / V2_STAGE).read_bytes() == b"foreign-temp"


def test_v2_read_only_recovery_preview_never_mutates_host(
    fixture_root, monkeypatch,
):
    import repocache.server_proposed_state_v2_store as module

    apply(fixture_root, snapshot())

    def forbid(*args, **kwargs):
        pytest.fail("recovery preview must never mutate files")

    monkeypatch.setattr(module.os, "replace", forbid)
    monkeypatch.setattr(module.os, "unlink", forbid)
    monkeypatch.setattr(module.os, "remove", forbid)
    report = v2_recovery_preview(fixture_root)
    assert report["status"] == "CLEAN"
    assert report["authorizes_v2_recovery"] is False


@pytest.mark.parametrize("malformed", [
    b"foreign-journal-data",
    b'{"journal_schema_version":2}',
    b'{"journal_schema_version":2,"previous_sha256":null,'
    b'"previous_base64":null,"next_sha256":"not-a-digest"}',
])
def test_unpublished_v2_journal_refuses_corruption_without_deletion(
    fixture_root, malformed,
):
    fd, folder, uid = fixture_root
    pending = folder / V2_JOURNAL_TMP
    pending.write_bytes(malformed)
    pending.chmod(0o600)
    for operation in (
        lambda: preview_v2_recovery(fd, owner_uid=uid),
        lambda: recover(fd, owner_uid=uid),
    ):
        with pytest.raises(ProposedV2PersistenceError, match="JOURNAL_INVALID"):
            operation()
        assert pending.read_bytes() == malformed
        assert not (folder / V2_STATE).exists()
        assert not (folder / V2_JOURNAL).exists()


@pytest.mark.parametrize("bootstrap", [True, False])
def test_unpublished_v2_journal_refuses_prior_state_drift_without_deletion(
    fixture_root, bootstrap,
):
    fd, folder, uid = fixture_root
    previous = None
    generation = 0
    if not bootstrap:
        previous = snapshot()
        apply(fixture_root, previous)
        generation = 1

    def interrupt(point):
        if point == "journal_tmp_durable":
            raise RuntimeError("interrupted before journal publication")

    with pytest.raises(RuntimeError, match="interrupted before journal"):
        apply(
            fixture_root,
            snapshot(count=1, generation=generation + 1, previous=previous),
            expected=generation, inject=interrupt,
        )
    pending = folder / V2_JOURNAL_TMP
    journal_bytes = pending.read_bytes()
    # Valid but unrelated state must never be accepted as the previous
    # generation of an unpublished journal, even in a fixture bootstrap.
    unrelated = snapshot(count=2, generation=generation + 1, previous=previous)
    state_bytes = json.dumps(
        unrelated, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")
    (folder / V2_STATE).write_bytes(state_bytes)
    (folder / V2_STATE).chmod(0o600)
    for operation in (
        lambda: preview_v2_recovery(fd, owner_uid=uid),
        lambda: recover(fd, owner_uid=uid),
    ):
        with pytest.raises(ProposedV2PersistenceError, match="STATE_DRIFT"):
            operation()
        assert pending.read_bytes() == journal_bytes
        assert (folder / V2_STATE).read_bytes() == state_bytes
        assert not (folder / V2_JOURNAL).exists()


@pytest.mark.parametrize("bootstrap", [True, False])
@pytest.mark.parametrize("tamper", ["unrelated-bytes", "matching-digest-invalid-transition"])
def test_published_v2_journal_refuses_foreign_or_invalid_stage_without_deletion(
    fixture_root, bootstrap, tamper,
):
    fd, folder, uid = fixture_root
    previous = None
    generation = 0
    if not bootstrap:
        previous = snapshot()
        apply(fixture_root, previous)
        generation = 1

    def interrupt(point):
        if point == "stage_durable":
            raise RuntimeError("interrupted after stage")

    with pytest.raises(RuntimeError, match="interrupted after stage"):
        apply(
            fixture_root,
            snapshot(count=1, generation=generation + 1, previous=previous),
            expected=generation, inject=interrupt,
        )
    journal_file = folder / V2_JOURNAL
    stage_file = folder / V2_STAGE
    if tamper == "unrelated-bytes":
        stage_bytes = b"foreign-stage"
        code = "STAGE_DRIFT"
    else:
        # Re-sign the fixture-only journal digest to match an otherwise valid
        # snapshot with the wrong next generation. Digest equality alone is
        # not sufficient to authorize deletion of a staged file.
        invalid_transition = snapshot(
            count=1, generation=generation + 2, previous=previous,
        )
        stage_bytes = json.dumps(
            invalid_transition, sort_keys=True, ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        entry = json.loads(journal_file.read_bytes())
        entry["next_sha256"] = hashlib.sha256(stage_bytes).hexdigest()
        journal_file.write_bytes(json.dumps(
            entry, sort_keys=True, ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8"))
        code = "STAGE_INVALID"
    stage_file.write_bytes(stage_bytes)
    baseline = {
        name: (folder / name).read_bytes()
        for name in (V2_JOURNAL, V2_STAGE)
    }
    if previous is not None:
        baseline[V2_STATE] = (folder / V2_STATE).read_bytes()
    for operation in (
        lambda: preview_v2_recovery(fd, owner_uid=uid),
        lambda: recover(fd, owner_uid=uid),
    ):
        with pytest.raises(ProposedV2PersistenceError, match=code):
            operation()
        for name, raw in baseline.items():
            assert (folder / name).read_bytes() == raw
        if previous is None:
            assert not (folder / V2_STATE).exists()
        assert not (folder / V2_ROLLBACK).exists()


def test_v2_recovery_refuses_foreign_rollback_bytes_without_deletion(
    fixture_root, monkeypatch,
):
    import repocache.server_proposed_state_v2_store as module

    fd, folder, uid = fixture_root
    first = snapshot()
    apply(fixture_root, first)

    def interrupt(point):
        if point == "replace_durable":
            raise RuntimeError("interrupted after replace")

    with pytest.raises(RuntimeError, match="interrupted after replace"):
        apply(
            fixture_root, snapshot(count=1, generation=2, previous=first),
            expected=1, inject=interrupt,
        )
    original = os.replace

    def fail_rollback(src, dst, *args, **kwargs):
        if src == V2_ROLLBACK:
            raise OSError("injected rollback rename failure")
        return original(src, dst, *args, **kwargs)

    monkeypatch.setattr(module.os, "replace", fail_rollback)
    with pytest.raises(ProposedV2PersistenceError, match="ROLLBACK_IO_REFUSED"):
        recover(fd, owner_uid=uid)
    monkeypatch.setattr(module.os, "replace", original)
    rollback_file = folder / V2_ROLLBACK
    assert rollback_file.exists()
    rollback_file.write_bytes(b"foreign-rollback")
    baseline = {
        name: (folder / name).read_bytes()
        for name in (V2_JOURNAL, V2_STATE, V2_ROLLBACK)
    }
    for operation in (
        lambda: preview_v2_recovery(fd, owner_uid=uid),
        lambda: recover(fd, owner_uid=uid),
    ):
        with pytest.raises(ProposedV2PersistenceError, match="ROLLBACK_DRIFT"):
            operation()
        for name, raw in baseline.items():
            assert (folder / name).read_bytes() == raw


@pytest.mark.parametrize("bootstrap", [True, False])
def test_published_v2_journal_refuses_invalid_replaced_state_transition(
    fixture_root, bootstrap,
):
    fd, folder, uid = fixture_root
    previous = None
    generation = 0
    if not bootstrap:
        previous = snapshot()
        apply(fixture_root, previous)
        generation = 1

    def interrupt(point):
        if point == "replace_durable":
            raise RuntimeError("interrupted after replace")

    with pytest.raises(RuntimeError, match="interrupted after replace"):
        apply(
            fixture_root,
            snapshot(count=1, generation=generation + 1, previous=previous),
            expected=generation, inject=interrupt,
        )
    assert not (folder / V2_STAGE).exists()
    # A valid v2 envelope and matching journal digest are not proof that
    # replacement bytes are the legitimate next state of this transaction.
    unrelated = snapshot(
        count=1, generation=generation + 2, previous=previous,
    )
    replacement_bytes = json.dumps(
        unrelated, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    journal_file = folder / V2_JOURNAL
    journal = json.loads(journal_file.read_bytes())
    journal["next_sha256"] = hashlib.sha256(replacement_bytes).hexdigest()
    journal_bytes = json.dumps(
        journal, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    (folder / V2_STATE).write_bytes(replacement_bytes)
    journal_file.write_bytes(journal_bytes)
    for operation in (
        lambda: preview_v2_recovery(fd, owner_uid=uid),
        lambda: recover(fd, owner_uid=uid),
    ):
        with pytest.raises(ProposedV2PersistenceError, match="REPLACED_STATE_INVALID"):
            operation()
        assert (folder / V2_STATE).read_bytes() == replacement_bytes
        assert journal_file.read_bytes() == journal_bytes
        assert not (folder / V2_ROLLBACK).exists()


@pytest.mark.skipif(
    shutil.which("nginx") is None,
    reason="disposable distro-packaged nginx unavailable",
)
def test_v2_lifecycle_nginx_live_sandbox(fixture_root, tmp_path):
    """Link merged #95 planner, #31 fixture v2 journal and actual disposable NGINX.

    A real isolated daemon is reloaded, but staging/commits are intentionally
    separate, unauthenticated TEST actions. No live host state, systemd,
    catalog or privileged transaction is touched or certified.
    """
    import socket
    import time

    nginx = shutil.which("nginx")
    ca = next((name for name in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(name).is_file()), None)
    if ca is None:
        pytest.skip("disposable distro CA unavailable")
    fd, folder, uid = fixture_root
    repo_id = "integration-apt"
    origin = "fixture-new.example.invalid"
    cache_root = tmp_path / "managed-cache"
    cache_root.mkdir(mode=0o700)
    current = document(count=1)
    current["repositories"][0]["desired_state"] = "disabled"
    current["deployment"]["paths"]["cache_root"] = str(cache_root)
    previous = snapshot(generation=1, doc=current)
    assert apply(fixture_root, previous)["state_generation"] == 1
    historical = {"repo-0"}

    sock = tmp_path / "s"
    assert len(os.fsencode(sock)) < 100
    conf = tmp_path / "nginx.conf"
    pid = tmp_path / "nginx.pid"
    log = tmp_path / "nginx-error.log"

    def render(generation, pins):
        candidate = render_persisted(
            fd, owner_uid=uid, expected_generation=generation,
            candidate_pins_by_repository=pins, ca_bundle_path=ca,
        )
        assert candidate["persisted_config_bytes_and_digest_consistent"]
        assert candidate["exclusive_state_lock_held_during_preview"]
        for key in (
            "operator_authorization_verified",
            "nginx_syntax_verified",
            "active_exposure_verified",
            "authorizes_nginx_activation",
            "authorizes_catalog_publication",
        ):
            assert candidate[key] is False
        return candidate

    def config(candidate, label):
        # The health endpoint proves ONLY a sandbox NGINX worker reload.
        # Real package/cache paths in the candidate remain unreachable.
        for identifier in candidate["proposed_repository_ids"]:
            (cache_root / identifier).mkdir(mode=0o700, exist_ok=True)
        return (
            f"pid {pid};\nerror_log {log} notice;\n"
            "worker_processes 1;\nevents { worker_connections 64; }\n"
            "http { access_log off;\n"
            + candidate["http_upstream_fragment"]
            + f"server {{ listen unix:{sock};\n"
            + f'location = /__fixture_health {{ return 200 "{label}"; }}\n'
            + candidate["server_location_fragment"]
            + "}\n}\n"
        ).encode("utf-8")

    def stage(raw):
        destination = tmp_path / "nginx.next"
        with destination.open("wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(destination, conf)

    def command(*args):
        return subprocess.run(
            [nginx, *args, "-c", str(conf), "-p", str(tmp_path)],
            capture_output=True, text=True, timeout=10, check=False,
        )

    def health():
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(1)
            client.connect(str(sock))
            client.sendall(
                b"GET /__fixture_health HTTP/1.0\r\n"
                b"Host: localhost\r\nConnection: close\r\n\r\n"
            )
            answer = bytearray()
            while len(answer) < 8192:
                part = client.recv(8192 - len(answer))
                if not part:
                    break
                answer.extend(part)
            return bytes(answer)

    def assert_live(label, process):
        for _ in range(100):
            assert process.poll() is None, "isolated NGINX master exited"
            try:
                answer = health()
                if (b" 200 " in answer.split(b"\r\n", 1)[0]
                        and answer.endswith(label.encode("ascii"))):
                    return
            except (OSError, TimeoutError):
                pass
            time.sleep(0.05)
        pytest.fail(f"isolated NGINX never served {label!r}")

    initial = render(1, {})
    assert initial["proposed_repository_ids"] == []
    initial_raw = config(initial, "generation-1")
    stage(initial_raw)
    assert command("-t").returncode == 0
    master = subprocess.Popen(
        [nginx, "-c", str(conf), "-p", str(tmp_path), "-g", "daemon off;"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert_live("generation-1", master)

        def transition(operation, generation, *, proposal=None, reservations=None):
            planned = plan_repository_change(
                current, current_generation=generation,
                operation=operation,
                repository_id=None if operation == "add" else repo_id,
                proposed_repository=proposal,
                reserved_ids=reservations,
            )
            assert planned["changed"] is True
            proposed_doc = planned["candidate_document"]
            succeeding = snapshot(
                generation=generation + 1, doc=proposed_doc,
                previous=previous,
            )
            return proposed_doc, succeeding

        def activate(generation, pins):
            output = render(generation, pins)
            assert output["proposed_repository_ids"] == sorted(pins)
            staged = config(output, f"generation-{generation}")
            stage(staged)
            checked = command("-t")
            assert checked.returncode == 0, checked.stderr
            reloaded = command("-s", "reload")
            assert reloaded.returncode == 0, reloaded.stderr
            assert_live(f"generation-{generation}", master)
            return output

        # First added as disabled: no NGINX route is exposed even in the
        # disposable generated candidate.
        new_repo = copy.deepcopy(current["repositories"][0])
        new_repo.update({"id": repo_id, "desired_state": "disabled"})
        new_repo["upstream"]["base_url"] = (
            "https://fixture-new.example.invalid/debian/"
        )
        new_repo["upstream"]["allowed_hosts"] = [origin]
        current_next, state_next = transition(
            "add", 1, proposal=new_repo, reservations=historical,
        )
        assert apply(fixture_root, state_next, expected=1)["state_generation"] == 2
        previous, current = state_next, copy.deepcopy(current_next)
        # The #95 pure planner leaves candidates at the expected OLD CAS
        # generation; only the fixture's committed next revision is rebased.
        current["expected_state_generation"] = 2
        # Keep the simulated historical ledger separate from persisted
        # reservations; only the fixture store validates the latter.
        historical.add(repo_id)
        added = activate(2, {})
        assert added["server_location_fragment"] == ""

        # Enable with the merged #95 planner; persist the exact validated
        # generation, then syntax-check and live-reload a new route.
        current_next, state_next = transition("enable", 2)
        assert apply(fixture_root, state_next, expected=2)["state_generation"] == 3
        previous, current = state_next, copy.deepcopy(current_next)
        # The #95 pure planner leaves candidates at the expected OLD CAS
        # generation; only the fixture's committed next revision is rebased.
        current["expected_state_generation"] = 3
        pins = {repo_id: {origin: ["8.8.8.8"]}}
        enabled = activate(3, pins)
        assert f"/__repocache/repos/{repo_id}/" in enabled["server_location_fragment"]
        sentinel = cache_root / repo_id / "retained.bin"
        sentinel.write_bytes(b"owned-test-cache-sentinel")
        known_good = conf.read_bytes()
        durable = (folder / V2_STATE).read_bytes()

        # Kill at durable journal stage while preparing disable; renderer
        # must refuse pending recovery, while the old live worker keeps
        # serving. The explicit private fixture recovery restores exact bytes.
        current_next, state_next = transition("disable", 3)
        def crash(point):
            if point == "stage_durable":
                raise RuntimeError("injected interruption")
        with pytest.raises(RuntimeError, match="injected interruption"):
            apply(fixture_root, state_next, expected=3, inject=crash)
        with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
            render(3, pins)
        assert conf.read_bytes() == known_good
        assert_live("generation-3", master)
        assert rollback(fixture_root)["state_generation"] == 3
        assert (folder / V2_STATE).read_bytes() == durable
        assert not (folder / V2_JOURNAL).exists()
        assert not (folder / V2_STAGE).exists()

        # Retry the same intended generation after explicit recovery.
        assert apply(fixture_root, state_next, expected=3)["state_generation"] == 4
        previous, current = state_next, copy.deepcopy(current_next)
        # The #95 pure planner leaves candidates at the expected OLD CAS
        # generation; only the fixture's committed next revision is rebased.
        current["expected_state_generation"] = 4
        disabled = activate(4, {})
        assert disabled["server_location_fragment"] == ""
        assert sentinel.read_bytes() == b"owned-test-cache-sentinel"

        current_next, state_next = transition("remove", 4)
        assert apply(fixture_root, state_next, expected=4)["state_generation"] == 5
        previous, current = state_next, copy.deepcopy(current_next)
        # The #95 pure planner leaves candidates at the expected OLD CAS
        # generation; only the fixture's committed next revision is rebased.
        current["expected_state_generation"] = 5
        removed = activate(5, {})
        assert removed["server_location_fragment"] == ""
        assert sentinel.read_bytes() == b"owned-test-cache-sentinel"
        saved = json.loads((folder / V2_STATE).read_bytes())
        assert any(
            item["id"] == repo_id and item["status"] == "retired"
            for item in saved["id_reservations"]
        )
        assert not any(
            item["id"] == repo_id for item in saved["repository_records"]
        )
        with pytest.raises(RepositoryPlanError, match="historically reserved"):
            plan_repository_change(
                current, current_generation=5, operation="add",
                proposed_repository=new_repo, reserved_ids=historical,
            )
        assert rollback(fixture_root)["status"] == "CLEAN"
        assert master.poll() is None
    finally:
        if master.poll() is None:
            command("-s", "quit")
            try:
                master.wait(timeout=5)
            except subprocess.TimeoutExpired:
                master.terminate()
                try:
                    master.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    master.kill()
                    master.wait(timeout=3)


def precommit(layout, candidate, *, expected, pins=None, ca=None):
    fd, _, uid = layout
    return precommit_nginx(
        fd, candidate, owner_uid=uid,
        expected_generation=expected,
        candidate_pins_by_repository={} if pins is None else pins,
        ca_bundle_path=(
            "/etc/ssl/certs/ca-certificates.crt" if ca is None else ca
        ),
    )


def test_v2_precommit_bootstrap_renders_without_creating_state(fixture_root):
    _, folder, _ = fixture_root
    new = snapshot(count=1)
    before = sorted(folder.iterdir())
    candidate = precommit(fixture_root, new, expected=0)
    assert candidate["status"] == "LOCKED_FIXTURE_V2_PRECOMMIT_NGINX_CANDIDATE_ONLY"
    assert candidate["expected_state_generation"] == 0
    assert candidate["proposed_state_generation"] == 1
    assert candidate["would_change_v2_state"] is True
    assert candidate["v2_canonical_transition_validated"] is True
    assert candidate["persisted_predecessor_rechecked_under_lock"] is True
    assert candidate["proposed_repository_ids"] == []
    for field in (
        "trusted_host_root_verified", "operator_authorization_verified",
        "live_include_manifest_verified", "nginx_syntax_verified",
        "active_exposure_verified", "authorizes_state_commit",
        "authorizes_nginx_activation", "authorizes_nginx_reload",
        "authorizes_catalog_publication", "authorizes_cache_cleanup",
    ):
        assert candidate[field] is False
    assert sorted(folder.iterdir()) == before
    assert not (folder / V2_STATE).exists()
    assert apply(fixture_root, new)["state_generation"] == 1
    persisted = persisted_render(fixture_root, generation=1, pins={})
    for fragment in ("http_upstream_fragment", "server_location_fragment",
                     "proposed_repository_ids", "pin_count"):
        assert candidate[fragment] == persisted[fragment]


def test_v2_precommit_active_route_parity_and_idempotent_generation(fixture_root):
    _, folder, _ = fixture_root
    current = snapshot(count=1)
    apply(fixture_root, current)
    next_doc = document(count=1)
    next_doc["repositories"][0]["desired_state"] = "active"
    next_state = snapshot(generation=2, previous=current, doc=next_doc)
    pins = {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}}
    original = (folder / V2_STATE).read_bytes()
    inode = (folder / V2_STATE).stat().st_ino
    rendered = precommit(fixture_root, next_state, expected=1, pins=pins)
    assert rendered["proposed_state_generation"] == 2
    assert rendered["proposed_repository_ids"] == ["repo-0"]
    assert "proxy_ssl_verify on;" in rendered["server_location_fragment"]
    assert rendered["authorizes_nginx_reload"] is False
    assert (folder / V2_STATE).read_bytes() == original
    assert (folder / V2_STATE).stat().st_ino == inode
    assert not (folder / V2_JOURNAL).exists()
    assert apply(fixture_root, next_state, expected=1)["state_generation"] == 2
    persisted = persisted_render(fixture_root, generation=2, pins=pins)
    for fragment in ("http_upstream_fragment", "server_location_fragment",
                     "proposed_repository_ids", "pin_count"):
        assert rendered[fragment] == persisted[fragment]
    unchanged_next = snapshot(generation=3, previous=next_state, doc=next_doc)
    noop = precommit(fixture_root, unchanged_next, expected=2, pins=pins)
    assert noop["would_change_v2_state"] is False
    assert noop["expected_state_generation"] == 2
    assert noop["proposed_state_generation"] == 2
    assert noop["server_location_fragment"] == persisted["server_location_fragment"]
    before_noop = (folder / V2_STATE).read_bytes()
    assert apply(fixture_root, unchanged_next, expected=2)["status"] == "NO_CHANGE_INERT_V2"
    assert (folder / V2_STATE).read_bytes() == before_noop


@pytest.mark.parametrize("case", ["stale", "absent", "wrong-pins", "unsafe-ip",
                                  "invalid-transition", "legacy-state"])
def test_v2_precommit_negative_inputs_have_no_disk_side_effects(fixture_root, case):
    _, folder, uid = fixture_root
    old = snapshot(count=1)
    if case != "absent" and case != "legacy-state":
        apply(fixture_root, old)
    future = snapshot(count=1, generation=2, previous=old)
    bad_pins = {}
    expected = 1
    if case == "stale":
        expected = 0
    if case == "absent":
        expected = 1
    if case == "wrong-pins":
        future_doc = document(count=1)
        future_doc["repositories"][0]["desired_state"] = "active"
        future = snapshot(generation=2, previous=old, doc=future_doc)
        bad_pins = {}
    if case == "unsafe-ip":
        future_doc = document(count=1)
        future_doc["repositories"][0]["desired_state"] = "active"
        future = snapshot(generation=2, previous=old, doc=future_doc)
        bad_pins = {"repo-0": {"mirror0.example.invalid": ["127.0.0.1"]}}
    if case == "invalid-transition":
        future = copy.deepcopy(future)
        future["id_reservations"] = []
    if case == "legacy-state":
        legacy = {
            "state_schema_version": 1, "state_generation": 1,
            "configuration_sha256": "a" * 64,
            "repositories": [], "ownership_manifest": [],
        }
        commit_legacy(fixture_root[0], legacy, owner_uid=uid, expected_generation=0)
    before = {p.name: (p.read_bytes(), p.stat().st_ino)
              for p in folder.iterdir() if p.is_file()}
    matches = {
        "stale": "STALE_GENERATION",
        "absent": "STALE_GENERATION",
        "wrong-pins": "NGINX_CANDIDATE_REFUSED",
        "unsafe-ip": "NGINX_CANDIDATE_REFUSED",
        "invalid-transition": "SNAPSHOT_INVALID",
        "legacy-state": "LEGACY_MIGRATION_REQUIRED",
    }
    with pytest.raises((ProposedV2PersistenceError, ProtectedStateStoreError),
                       match=matches[case]):
        precommit(fixture_root, future, expected=expected, pins=bad_pins)
    assert {p.name: (p.read_bytes(), p.stat().st_ino)
            for p in folder.iterdir() if p.is_file()} == before


def test_v2_precommit_pending_recovery_and_lock_contention_refused(fixture_root):
    fd, folder, uid = fixture_root
    current = snapshot(count=1)
    apply(fixture_root, current)
    future = snapshot(count=1, generation=2, previous=current)
    with _locked(fd, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            precommit(fixture_root, future, expected=1)
    def crash(point):
        if point == "journal_durable":
            raise RuntimeError("synthetic crash")
    with pytest.raises(RuntimeError, match="synthetic crash"):
        apply(fixture_root, future, expected=1, inject=crash)
    pending = (folder / V2_JOURNAL).read_bytes()
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        precommit(fixture_root, future, expected=1)
    assert (folder / V2_JOURNAL).read_bytes() == pending
    assert rollback(fixture_root)["state_generation"] == 1
    assert precommit(fixture_root, future, expected=1)["would_change_v2_state"] is False


def test_v2_precommit_refuses_out_of_band_state_change_while_locked(
    fixture_root, monkeypatch,
):
    import repocache.server_proposed_state_v2_store as module
    _, folder, _ = fixture_root
    old = snapshot(count=1)
    apply(fixture_root, old)
    future = snapshot(count=1, generation=2, previous=old)
    unrelated = snapshot(count=2, generation=1)
    raw_unrelated = json.dumps(
        unrelated, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")
    original_render = module.render_repository_nginx_bundle_candidate
    def altered_state(*args, **kwargs):
        # Synthetic non-cooperating root writer; bypass flock intentionally.
        path = folder / V2_STATE
        with path.open("wb") as stream:
            stream.write(raw_unrelated)
            stream.flush()
            os.fsync(stream.fileno())
        return original_render(*args, **kwargs)
    monkeypatch.setattr(module, "render_repository_nginx_bundle_candidate",
                        altered_state)
    with pytest.raises(ProposedV2PersistenceError,
                       match="STATE_CHANGED_DURING_PREVIEW"):
        precommit(fixture_root, future, expected=1)
    assert (folder / V2_STATE).read_bytes() == raw_unrelated
    assert not (folder / V2_JOURNAL).exists()


@pytest.mark.skipif(
    shutil.which("nginx") is None,
    reason="distro packaged nginx unavailable",
)
def test_v2_precommit_disposable_packaged_nginx_t(fixture_root, tmp_path):
    nginx = shutil.which("nginx")
    ca = next((p for p in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(p).is_file()), None)
    if ca is None:
        pytest.skip("distro CA bundle unavailable")
    config = document(count=1)
    cache_root = tmp_path / "managed-cache"
    config["deployment"]["paths"]["cache_root"] = str(cache_root)
    config["repositories"][0]["desired_state"] = "active"
    state = snapshot(generation=1, doc=config)
    candidate = precommit(
        fixture_root, state, expected=0,
        pins={"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}},
        ca=ca,
    )
    assert candidate["nginx_syntax_verified"] is False
    (cache_root / "repo-0").mkdir(parents=True, mode=0o700)
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'nginx-error.log'} notice;\n"
        "events {}\nhttp { access_log off;\n"
        + candidate["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19991;\n"
        + candidate["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    observed = subprocess.run(
        [nginx, "-t", "-c", str(conf), "-p", str(tmp_path)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert observed.returncode == 0, observed.stderr
    assert not (fixture_root[1] / V2_STATE).exists()
    assert candidate["authorizes_state_commit"] is False
    assert candidate["authorizes_nginx_activation"] is False
