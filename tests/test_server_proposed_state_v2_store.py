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
    _commit_preflighted_proposed_v2_under_root as commit_preflighted,
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

        def before_commit(state, generation, pins):
            # Stage and syntax-check a *separate* disposable NGINX file
            # before the v2 fixture commits; never touch the active conf.
            predecessor = (folder / V2_STATE).read_bytes()
            live_before = conf.read_bytes()
            preview = precommit(
                fixture_root, state, expected=generation - 1,
                pins=pins, ca=ca,
            )
            assert preview["would_change_v2_state"] is True
            assert preview["proposed_state_generation"] == generation
            assert preview["proposed_repository_ids"] == sorted(pins)
            assert preview["authorizes_state_commit"] is False
            assert preview["authorizes_nginx_reload"] is False
            assert preview["authorizes_catalog_publication"] is False
            scratch = tmp_path / f"nginx-precommit-{generation}.conf"
            scratch.write_bytes(config(preview, f"generation-{generation}"))
            syntax = subprocess.run(
                [nginx, "-t", "-c", str(scratch), "-p", str(tmp_path)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            assert syntax.returncode == 0, syntax.stderr
            assert (folder / V2_STATE).read_bytes() == predecessor
            assert conf.read_bytes() == live_before
            assert not (folder / V2_JOURNAL).exists()
            return preview

        def activate(generation, pins, preview):
            output = render(generation, pins)
            assert output["proposed_repository_ids"] == sorted(pins)
            # The precommit and actual persisted-generation renderer MUST
            # derive identical fragments, rather than use stale pins.
            for key in ("http_upstream_fragment", "server_location_fragment",
                        "proposed_repository_ids", "pin_count"):
                assert output[key] == preview[key]
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
        preadded = before_commit(state_next, 2, {})
        assert apply(fixture_root, state_next, expected=1)["state_generation"] == 2
        previous, current = state_next, copy.deepcopy(current_next)
        # The #95 pure planner leaves candidates at the expected OLD CAS
        # generation; only the fixture's committed next revision is rebased.
        current["expected_state_generation"] = 2
        # Keep the simulated historical ledger separate from persisted
        # reservations; only the fixture store validates the latter.
        historical.add(repo_id)
        added = activate(2, {}, preadded)
        assert added["server_location_fragment"] == ""

        # Enable with the merged #95 planner; persist the exact validated
        # generation, then syntax-check and live-reload a new route.
        current_next, state_next = transition("enable", 2)
        pins = {repo_id: {origin: ["8.8.8.8"]}}
        preenabled = before_commit(state_next, 3, pins)
        assert apply(fixture_root, state_next, expected=2)["state_generation"] == 3
        previous, current = state_next, copy.deepcopy(current_next)
        # The #95 pure planner leaves candidates at the expected OLD CAS
        # generation; only the fixture's committed next revision is rebased.
        current["expected_state_generation"] = 3
        enabled = activate(3, pins, preenabled)
        assert f"/__repocache/repos/{repo_id}/" in enabled["server_location_fragment"]
        sentinel = cache_root / repo_id / "retained.bin"
        sentinel.write_bytes(b"owned-test-cache-sentinel")
        known_good = conf.read_bytes()
        durable = (folder / V2_STATE).read_bytes()

        # Kill at durable journal stage while preparing disable; renderer
        # must refuse pending recovery, while the old live worker keeps
        # serving. The explicit private fixture recovery restores exact bytes.
        current_next, state_next = transition("disable", 3)
        predisabled = before_commit(state_next, 4, {})
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

        # Explicit recovery invalidates any prior precommit observation.
        # Rebuild it and rerun syntax before retrying the same CAS revision.
        predisabled = before_commit(state_next, 4, {})
        assert apply(fixture_root, state_next, expected=3)["state_generation"] == 4
        previous, current = state_next, copy.deepcopy(current_next)
        # The #95 pure planner leaves candidates at the expected OLD CAS
        # generation; only the fixture's committed next revision is rebased.
        current["expected_state_generation"] = 4
        disabled = activate(4, {}, predisabled)
        assert disabled["server_location_fragment"] == ""
        assert sentinel.read_bytes() == b"owned-test-cache-sentinel"

        current_next, state_next = transition("remove", 4)
        preremoved = before_commit(state_next, 5, {})
        assert apply(fixture_root, state_next, expected=4)["state_generation"] == 5
        previous, current = state_next, copy.deepcopy(current_next)
        # The #95 pure planner leaves candidates at the expected OLD CAS
        # generation; only the fixture's committed next revision is rebased.
        current["expected_state_generation"] = 5
        removed = activate(5, {}, preremoved)
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
    # A genuine new repository avoids the store's correct idempotent no-op.
    future = snapshot(count=2, generation=2, previous=current)
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
    assert precommit(fixture_root, future, expected=1)["would_change_v2_state"] is True


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


def test_adopted_v2_initial_history_overflow_refused_before_disk_write(fixture_root):
    """A 10001st historic ID can never be silently pruned at first boot."""
    _, folder, _ = fixture_root
    from repocache.server_locked_manifest_reconcile_v1 import (
        INITIAL_V2_MAX_ALL_TIME_IDS,
    )
    next_state = snapshot(2)
    for n in range(2, INITIAL_V2_MAX_ALL_TIME_IDS + 1):
        next_state["id_reservations"].append({
            "id": f"retired-{n}",
            "canonical_identity_sha256": hashlib.sha256(
                f"historical-{n}".encode("ascii")
            ).hexdigest(),
            "status": "retired",
        })
    assert len(next_state["id_reservations"]) == INITIAL_V2_MAX_ALL_TIME_IDS + 1
    before = {p.name: (p.read_bytes(), p.stat().st_ino)
              for p in folder.iterdir() if p.is_file()}
    with pytest.raises(ProposedV2PersistenceError, match="SNAPSHOT_INVALID"):
        apply(fixture_root, next_state)
    assert {p.name: (p.read_bytes(), p.stat().st_ino)
            for p in folder.iterdir() if p.is_file()} == before
    assert not (folder / V2_STATE).exists()
    assert not (folder / V2_JOURNAL).exists()
    assert not (folder / V2_STAGE).exists()


def locked_preflight_commit(layout, candidate, *, expected, pins=None, inject=None,
                            validate=None, ca=None, activate=None):
    fd, _, uid = layout
    return commit_preflighted(
        fd, candidate, owner_uid=uid, expected_generation=expected,
        candidate_pins_by_repository={} if pins is None else pins,
        ca_bundle_path=(
            "/etc/ssl/certs/ca-certificates.crt" if ca is None else ca
        ),
        inject_fault=inject, validate_nginx_candidate=validate,
        verify_fixture_activation=activate,
    )


def test_v2_same_lock_preflight_commit_bootstrap_and_no_activation(fixture_root):
    _, folder, _ = fixture_root
    new = snapshot(count=1)
    candidate = locked_preflight_commit(fixture_root, new, expected=0)
    assert candidate["state_commit_status"] == "COMMITTED_INERT_V2"
    assert candidate["state_generation"] == 1
    assert candidate["state_preflight_and_commit_share_exclusive_lock"] is True
    assert candidate["status"] == (
        "LOCKED_FIXTURE_V2_STATE_ONLY_COMMIT_NGINX_NOT_ACTIVATED"
    )
    assert candidate["proposed_repository_ids"] == []
    assert (folder / V2_STATE).exists()
    assert not (folder / V2_JOURNAL).exists()
    assert not (folder / V2_STAGE).exists()
    for flag in (
        "fixture_only", "nginx_syntax_verified", "active_exposure_verified",
        "operator_authorization_verified", "trusted_host_root_verified",
        "authorizes_state_commit", "authorizes_nginx_activation",
        "authorizes_nginx_reload", "authorizes_catalog_publication",
        "authorizes_cache_cleanup",
    ):
        assert candidate[flag] is (flag == "fixture_only")
    persisted = persisted_render(fixture_root, generation=1, pins={})
    for part in ("http_upstream_fragment", "server_location_fragment",
                 "pin_count", "proposed_repository_ids"):
        assert persisted[part] == candidate[part]


def test_v2_same_lock_preflight_commit_updates_active_and_preserves_noop_inode(
    fixture_root,
):
    _, folder, _ = fixture_root
    current = snapshot(count=1)
    apply(fixture_root, current)
    updated_doc = document(count=1)
    updated_doc["repositories"][0]["desired_state"] = "active"
    updated = snapshot(generation=2, previous=current, doc=updated_doc)
    pins = {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}}
    preview = precommit(fixture_root, updated, expected=1, pins=pins)
    candidate = locked_preflight_commit(fixture_root, updated, expected=1, pins=pins)
    assert candidate["state_commit_status"] == "COMMITTED_INERT_V2"
    assert candidate["candidate_generation"] == 2
    assert candidate["proposed_repository_ids"] == ["repo-0"]
    assert candidate["server_location_fragment"] == preview["server_location_fragment"]
    assert candidate["http_upstream_fragment"] == preview["http_upstream_fragment"]
    assert (folder / V2_STATE).exists()
    unchanged = snapshot(generation=3, previous=updated, doc=updated_doc)
    before = (folder / V2_STATE).read_bytes()
    ino = (folder / V2_STATE).stat().st_ino
    noop = locked_preflight_commit(fixture_root, unchanged, expected=2, pins=pins)
    assert noop["state_commit_status"] == "NO_CHANGE_INERT_V2"
    assert noop["candidate_generation"] == 2
    assert noop["state_generation"] == 2
    assert (folder / V2_STATE).read_bytes() == before
    assert (folder / V2_STATE).stat().st_ino == ino


@pytest.mark.parametrize("case", [
    "stale", "wrong-pins", "unsafe-pin", "lock-held",
])
def test_v2_same_lock_preflight_commit_refuses_before_state_mutation(
    fixture_root, case,
):
    fd, folder, uid = fixture_root
    current = snapshot(count=1)
    apply(fixture_root, current)
    updated_doc = document(count=1)
    updated_doc["repositories"][0]["desired_state"] = "active"
    updated = snapshot(generation=2, previous=current, doc=updated_doc)
    pins = {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}}
    if case == "wrong-pins":
        pins = {}
    if case == "unsafe-pin":
        pins = {"repo-0": {"mirror0.example.invalid": ["169.254.169.254"]}}
    expected = 0 if case == "stale" else 1
    before = {p.name: (p.read_bytes(), p.stat().st_ino)
              for p in folder.iterdir() if p.is_file()}
    if case == "lock-held":
        with _locked(fd, uid):
            with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
                locked_preflight_commit(
                    fixture_root, updated, expected=expected, pins=pins,
                )
    else:
        with pytest.raises(ProposedV2PersistenceError):
            locked_preflight_commit(
                fixture_root, updated, expected=expected, pins=pins,
            )
    assert {p.name: (p.read_bytes(), p.stat().st_ino)
            for p in folder.iterdir() if p.is_file()} == before
    assert not (folder / V2_JOURNAL).exists()


def test_v2_same_lock_preflight_commit_detects_foreign_writer_before_journal(
    fixture_root, monkeypatch,
):
    import repocache.server_proposed_state_v2_store as module
    _, folder, _ = fixture_root
    current = snapshot(count=1)
    apply(fixture_root, current)
    next_state = snapshot(count=2, generation=2, previous=current)
    unrelated = snapshot(count=2)
    bytes_unrelated = json.dumps(
        unrelated, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")
    original_render = module.render_repository_nginx_bundle_candidate

    def foreign_edit(*args, **kwargs):
        # A synthetic root writer that intentionally ignores advisory flock.
        with (folder / V2_STATE).open("wb") as stream:
            stream.write(bytes_unrelated)
            stream.flush()
            os.fsync(stream.fileno())
        return original_render(*args, **kwargs)

    monkeypatch.setattr(module, "render_repository_nginx_bundle_candidate",
                        foreign_edit)
    with pytest.raises(ProposedV2PersistenceError,
                       match="STATE_CHANGED_DURING_PREFLIGHT"):
        locked_preflight_commit(fixture_root, next_state, expected=1)
    assert (folder / V2_STATE).read_bytes() == bytes_unrelated
    assert not (folder / V2_JOURNAL).exists()


def test_v2_same_lock_preflight_commit_crash_requires_explicit_recovery(
    fixture_root,
):
    _, folder, _ = fixture_root
    current = snapshot(count=1)
    apply(fixture_root, current)
    original = (folder / V2_STATE).read_bytes()
    next_state = snapshot(count=2, generation=2, previous=current)

    def abort(phase):
        if phase == "journal_durable":
            raise RuntimeError("simulated durable crash")

    with pytest.raises(RuntimeError, match="simulated durable crash"):
        locked_preflight_commit(
            fixture_root, next_state, expected=1, inject=abort,
        )
    assert (folder / V2_STATE).read_bytes() == original
    assert (folder / V2_JOURNAL).exists()
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        locked_preflight_commit(fixture_root, next_state, expected=1)
    assert rollback(fixture_root)["status"] == "ROLLED_BACK_INERT_V2"
    assert (folder / V2_STATE).read_bytes() == original
    done = locked_preflight_commit(fixture_root, next_state, expected=1)
    assert done["state_commit_status"] == "COMMITTED_INERT_V2"




def test_v2_same_lock_fixture_validation_runs_before_journal_and_is_detached(
    fixture_root,
):
    fd, folder, uid = fixture_root
    proposed = snapshot(count=1)
    observed = []

    def validate(candidate):
        # A separate attempt to take the same lock must fail while the
        # validation callback is running. No state or journal exists yet.
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            with _locked(fd, uid):
                pytest.fail("the shared state lock was not held")
        assert not (folder / V2_STATE).exists()
        assert not (folder / V2_JOURNAL).exists()
        assert not (folder / V2_JOURNAL_TMP).exists()
        assert candidate["proposed_repository_ids"] == []
        candidate["proposed_repository_ids"].append("forged")
        observed.append(True)

    result = locked_preflight_commit(
        fixture_root, proposed, expected=0, validate=validate,
    )
    assert observed == [True]
    assert result["fixture_validation_callback_executed"] is True
    assert result["proposed_repository_ids"] == []
    assert result["nginx_syntax_verified"] is False
    assert result["authorizes_nginx_reload"] is False
    assert result["authorizes_catalog_publication"] is False
    assert (folder / V2_STATE).exists()
    assert not (folder / V2_JOURNAL).exists()


@pytest.mark.parametrize("exception", [RuntimeError, ValueError, OSError])
def test_v2_same_lock_fixture_validation_failure_keeps_state_unmodified(
    fixture_root, exception,
):
    _, folder, _ = fixture_root
    previous = snapshot(count=1)
    apply(fixture_root, previous)
    next_state = snapshot(count=2, generation=2, previous=previous)
    before = {p.name: (p.read_bytes(), p.stat().st_ino)
              for p in folder.iterdir() if p.is_file()}

    def reject(_candidate):
        assert not (folder / V2_JOURNAL).exists()
        assert not (folder / V2_STAGE).exists()
        raise exception("test-only unsanitized secret: must not escape")

    with pytest.raises(ProposedV2PersistenceError,
                       match="NGINX_FIXTURE_VALIDATION_REFUSED") as exc:
        locked_preflight_commit(
            fixture_root, next_state, expected=1, validate=reject,
        )
    assert "secret" not in str(exc.value)
    assert {p.name: (p.read_bytes(), p.stat().st_ino)
            for p in folder.iterdir() if p.is_file()} == before


def test_v2_same_lock_validation_catches_out_of_band_state_edit(fixture_root):
    _, folder, _ = fixture_root
    prior = snapshot(count=1)
    apply(fixture_root, prior)
    proposed = snapshot(count=2, generation=2, previous=prior)
    foreign = snapshot(count=2)
    raw = json.dumps(foreign, sort_keys=True, ensure_ascii=True,
                     separators=(",", ":")).encode("utf-8")

    def mutate(_candidate):
        # A malicious same-UID writer ignored flock, after rendering.
        with (folder / V2_STATE).open("wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    with pytest.raises(ProposedV2PersistenceError,
                       match="STATE_CHANGED_DURING_PREFLIGHT"):
        locked_preflight_commit(
            fixture_root, proposed, expected=1, validate=mutate,
        )
    assert (folder / V2_STATE).read_bytes() == raw
    assert not (folder / V2_JOURNAL).exists()


def test_v2_same_lock_non_callable_validator_refused_without_mutation(
    fixture_root,
):
    _, folder, _ = fixture_root
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    with pytest.raises(ProposedV2PersistenceError,
                       match="NGINX_VALIDATOR_INVALID"):
        locked_preflight_commit(
            fixture_root, snapshot(count=1), expected=0, validate="nginx -t",
        )
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


@pytest.mark.skipif(shutil.which("nginx") is None,
                    reason="distro-packaged nginx unavailable")
@pytest.mark.parametrize("invalid_syntax", [False, True])
def test_v2_same_lock_disposable_native_nginx_syntax_before_state_write(
    fixture_root, tmp_path, invalid_syntax,
):
    """A real nginx -t can run under the same fixture lock, never on host."""
    _, folder, _ = fixture_root
    native_ca = next((
        p for p in (
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ) if Path(p).is_file()
    ), None)
    if native_ca is None:
        pytest.skip("distro CA bundle unavailable")
    config = document(count=1)
    config["repositories"][0]["desired_state"] = "active"
    proposed = snapshot(count=1, doc=config)
    pins = {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}}
    observed = []

    def validate(candidate):
        assert not (folder / V2_STATE).exists()
        assert not (folder / V2_JOURNAL).exists()
        conf = tmp_path / "nginx.conf"
        conf.write_text(
            f"pid {tmp_path / 'nginx.pid'};\n"
            f"error_log {tmp_path / 'error.log'} notice;\n"
            + ("events { invalid_directive; }\n" if invalid_syntax
               else "events {}\n")
            + "http { access_log off;\n"
            + candidate["http_upstream_fragment"]
            + "server { listen 127.0.0.1:19991;\n"
            + candidate["server_location_fragment"]
            + "}\n}\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [shutil.which("nginx"), "-t", "-c", str(conf),
             "-p", str(tmp_path)],
            capture_output=True, text=True, timeout=10, check=False,
        )
        observed.append(result.returncode == 0)
        if result.returncode:
            raise ValueError("disposable nginx syntax error")

    if invalid_syntax:
        with pytest.raises(ProposedV2PersistenceError,
                           match="NGINX_FIXTURE_VALIDATION_REFUSED"):
            locked_preflight_commit(
                fixture_root, proposed, expected=0, pins=pins,
                validate=validate, ca=native_ca,
            )
        assert observed == [False]
        assert not (folder / V2_STATE).exists()
        assert not (folder / V2_JOURNAL).exists()
    else:
        result = locked_preflight_commit(
            fixture_root, proposed, expected=0, pins=pins,
            validate=validate, ca=native_ca,
        )
        assert observed == [True]
        assert result["state_generation"] == 1
        assert result["fixture_validation_callback_executed"] is True
        assert result["nginx_syntax_verified"] is False
        assert result["authorizes_nginx_reload"] is False
        assert (folder / V2_STATE).exists()


@pytest.mark.parametrize("operation", ["commit", "preflight", "recover"])
def test_private_v2_fixture_writers_refuse_actual_namespace_root(operation):
    """Neither privileged nor unprivileged callers may use the live '/' FD."""
    current_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        uid = os.geteuid()
        with pytest.raises(
            ProposedV2PersistenceError,
            match="CURRENT_NAMESPACE_ROOT_WRITES_REFUSED",
        ):
            if operation == "commit":
                commit(current_fd, snapshot(count=1), owner_uid=uid,
                       expected_generation=0)
            elif operation == "preflight":
                commit_preflighted(
                    current_fd, snapshot(count=1), owner_uid=uid,
                    expected_generation=0, candidate_pins_by_repository={},
                    ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
                )
            else:
                recover(current_fd, owner_uid=uid)
    finally:
        os.close(current_fd)


@pytest.mark.parametrize("invalid_fd", [-1, True, None, "root"])
def test_private_v2_fixture_writer_refuses_bad_root_fd(invalid_fd):
    with pytest.raises(ProposedV2PersistenceError,
                       match="FIXTURE_ROOT_INVALID"):
        commit(invalid_fd, snapshot(count=1),
               owner_uid=os.geteuid(), expected_generation=0)


@pytest.mark.parametrize("bad_result", [
    False, True, 0, 1, "", "valid", {}, {"returncode": 0},
])
def test_v2_same_lock_validation_requires_explicit_none_success(
    fixture_root, bad_result,
):
    """A discarded subprocess return code must never count as validation."""
    _, folder, _ = fixture_root
    original = snapshot(count=1)
    apply(fixture_root, original)
    next_state = snapshot(count=2, generation=2, previous=original)
    before = {p.name: (p.read_bytes(), p.stat().st_ino)
              for p in folder.iterdir() if p.is_file()}
    with pytest.raises(ProposedV2PersistenceError,
                       match="NGINX_FIXTURE_VALIDATION_REFUSED"):
        locked_preflight_commit(
            fixture_root, next_state, expected=1,
            validate=lambda _candidate: bad_result,
        )
    assert {p.name: (p.read_bytes(), p.stat().st_ino)
            for p in folder.iterdir() if p.is_file()} == before


def test_v2_journal_spans_post_replace_fixture_activation_barrier(
    fixture_root,
):
    """Fixture preflight->durable journal->state->activation->cleanup order."""
    fd, folder, uid = fixture_root
    current = snapshot(count=1)
    apply(fixture_root, current)
    old = (folder / V2_STATE).read_bytes()
    proposed = snapshot(count=2, generation=2, previous=current)
    events = []

    def preflight(_candidate):
        assert (folder / V2_STATE).read_bytes() == old
        assert not (folder / V2_JOURNAL).exists()
        events.append("before-journal")

    def activated(candidate):
        assert candidate["proposed_repository_ids"] == []
        assert (folder / V2_JOURNAL).is_file()
        assert not (folder / V2_STAGE).exists()
        assert json.loads((folder / V2_STATE).read_bytes()) == proposed
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            with _locked(fd, uid):
                pytest.fail("exclusive state lock released too early")
        candidate["proposed_repository_ids"].append("forged")
        events.append("after-replace-before-journal-release")

    result = locked_preflight_commit(
        fixture_root, proposed, expected=1, validate=preflight,
        activate=activated,
    )
    assert events == ["before-journal", "after-replace-before-journal-release"]
    assert result["fixture_validation_callback_executed"] is True
    assert result["fixture_activation_barrier_executed"] is True
    assert result["proposed_repository_ids"] == []
    assert result["nginx_syntax_verified"] is False
    assert result["authorizes_nginx_reload"] is False
    assert result["authorizes_catalog_publication"] is False
    assert (folder / V2_STATE).read_bytes() != old
    assert not (folder / V2_JOURNAL).exists()


@pytest.mark.parametrize("failure", ["exception", "false", "true", "status"])
def test_v2_fixture_activation_failure_retains_durable_recovery_barrier(
    fixture_root, failure,
):
    _, folder, _ = fixture_root
    current = snapshot(count=1)
    apply(fixture_root, current)
    previous_raw = (folder / V2_STATE).read_bytes()
    proposed = snapshot(count=2, generation=2, previous=current)

    def activation(_candidate):
        assert (folder / V2_JOURNAL).is_file()
        assert json.loads((folder / V2_STATE).read_bytes()) == proposed
        if failure == "exception":
            raise RuntimeError("private fixture string not to leak")
        return {"status": "ok"} if failure == "status" else (failure == "true")

    with pytest.raises(ProposedV2PersistenceError,
                       match="ACTIVATION_FIXTURE_REFUSED") as caught:
        locked_preflight_commit(
            fixture_root, proposed, expected=1, activate=activation,
        )
    assert "private fixture string" not in str(caught.value)
    assert (folder / V2_JOURNAL).is_file()
    assert json.loads((folder / V2_STATE).read_bytes()) == proposed
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        locked_preflight_commit(fixture_root, proposed, expected=1)
    restored = rollback(fixture_root)
    assert restored["status"] == "ROLLED_BACK_INERT_V2"
    assert (folder / V2_STATE).read_bytes() == previous_raw
    assert not (folder / V2_JOURNAL).exists()


def test_v2_noop_avoids_fixture_activation_without_mutating_old_inode(
    fixture_root,
):
    _, folder, _ = fixture_root
    old = snapshot(count=1)
    apply(fixture_root, old)
    repeated = snapshot(count=1, generation=2, previous=old)
    before = (folder / V2_STATE).stat()

    def forbidden(_candidate):
        pytest.fail("identical state should not invoke an activation effect")

    result = locked_preflight_commit(
        fixture_root, repeated, expected=1, activate=forbidden,
    )
    assert result["state_commit_status"] == "NO_CHANGE_INERT_V2"
    assert result["fixture_activation_barrier_executed"] is False
    assert (folder / V2_STATE).stat().st_ino == before.st_ino
    assert not (folder / V2_JOURNAL).exists()


def test_v2_post_replace_fixture_barrier_refuses_noncooperating_state_writer(
    fixture_root,
):
    _, folder, _ = fixture_root
    current = snapshot(count=1)
    apply(fixture_root, current)
    proposed = snapshot(count=2, generation=2, previous=current)
    foreign = snapshot(count=1, generation=2, previous=current)
    foreign_raw = json.dumps(
        foreign, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")

    def foreign_write(_candidate):
        with (folder / V2_STATE).open("wb") as stream:
            stream.write(foreign_raw)
            stream.flush()
            os.fsync(stream.fileno())

    with pytest.raises(
        ProposedV2PersistenceError, match="STATE_CHANGED_DURING_FIXTURE_ACTIVATION",
    ):
        locked_preflight_commit(
            fixture_root, proposed, expected=1, activate=foreign_write,
        )
    assert (folder / V2_STATE).read_bytes() == foreign_raw
    assert (folder / V2_JOURNAL).is_file()
    with pytest.raises(ProposedV2PersistenceError):
        rollback(fixture_root)
    assert (folder / V2_STATE).read_bytes() == foreign_raw


def test_v2_invalid_activation_callback_refused_before_any_state_write(
    fixture_root,
):
    _, folder, _ = fixture_root
    before = {p.name: (p.read_bytes(), p.stat().st_ino)
              for p in folder.iterdir() if p.is_file()}
    with pytest.raises(
        ProposedV2PersistenceError, match="FIXTURE_ACTIVATION_VALIDATOR_INVALID",
    ):
        locked_preflight_commit(
            fixture_root, snapshot(count=1), expected=0, activate="systemctl",
        )
    assert {p.name: (p.read_bytes(), p.stat().st_ino)
            for p in folder.iterdir() if p.is_file()} == before


def test_fixture_flow_strict_order_and_catalog_only_after_live_probe():
    from repocache.server_fixture_activation_flow_v1 import (
        run_fixture_activation_flow,
    )
    observed = []
    candidate = {
        "status": "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY",
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "proposed_repository_ids": ["repo-0"],
    }

    def phase(name):
        def execute():
            observed.append(name)
            return None
        return execute

    def stage(value):
        assert value is candidate
        observed.append("stage")

    run_fixture_activation_flow(
        candidate, stage_managed_candidate=stage,
        syntax_check=phase("syntax"),
        reload_candidate=phase("reload"),
        verify_live_exposure=phase("live"),
        publish_derived_catalog=phase("publish"),
        verify_derived_catalog=phase("verified"),
        compensate=phase("compensate"),
    )
    assert observed == [
        "stage", "syntax", "reload", "live", "publish", "verified",
    ]


@pytest.mark.parametrize("phase", [
    "stage", "syntax", "reload", "live", "publish", "verified",
])
@pytest.mark.parametrize("return_bad", [False, True])
def test_fixture_flow_failure_always_compensates_once(phase, return_bad):
    from repocache.server_fixture_activation_flow_v1 import (
        FixtureActivationFlowError, run_fixture_activation_flow,
    )
    candidate = {
        "status": "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY",
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "proposed_repository_ids": ["repo-0"],
    }
    observed = []

    def step(name):
        def execute(*_args):
            observed.append(name)
            if name == phase:
                if return_bad:
                    return False  # must not be mistaken for success
                raise RuntimeError("PRIVATE ORIGINAL ERROR MUST NOT LEAK")
        return execute

    with pytest.raises(FixtureActivationFlowError,
                       match="FIXTURE_ACTIVATION_STEP_FAILED") as exc:
        run_fixture_activation_flow(
            candidate,
            stage_managed_candidate=step("stage"),
            syntax_check=step("syntax"),
            reload_candidate=step("reload"),
            verify_live_exposure=step("live"),
            publish_derived_catalog=step("publish"),
            verify_derived_catalog=step("verified"),
            compensate=step("compensate"),
        )
    assert observed.count("compensate") == 1
    assert observed[-1] == "compensate"
    assert "PRIVATE ORIGINAL" not in str(exc.value)


@pytest.mark.parametrize("compensate_bad", ["exception", "return"])
def test_fixture_flow_failed_compensation_is_explicit(compensate_bad):
    from repocache.server_fixture_activation_flow_v1 import (
        FixtureActivationFlowError, run_fixture_activation_flow,
    )
    candidate = {
        "status": "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY",
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "proposed_repository_ids": [],
    }

    def bad():
        raise RuntimeError("secret synthetic path")

    def compensate():
        if compensate_bad == "return":
            return False
        raise RuntimeError("secret synthetic recovery error")

    with pytest.raises(FixtureActivationFlowError,
                       match="FIXTURE_ACTIVATION_COMPENSATION_FAILED") as exc:
        run_fixture_activation_flow(
            candidate, stage_managed_candidate=lambda _: None,
            syntax_check=bad,
            reload_candidate=lambda: None,
            verify_live_exposure=lambda: None,
            publish_derived_catalog=lambda: None,
            verify_derived_catalog=lambda: None,
            compensate=compensate,
        )
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize("invalid", [
    {}, {"status": "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY"},
    {"status": "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY",
     "authorizes_nginx_activation": True,
     "authorizes_catalog_publication": False,
     "proposed_repository_ids": []},
    {"status": "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY",
     "authorizes_nginx_activation": False,
     "authorizes_catalog_publication": False,
     "proposed_repository_ids": ["b", "a"]},
])
def test_fixture_flow_refuses_invalid_candidates_before_any_callbacks(invalid):
    from repocache.server_fixture_activation_flow_v1 import (
        FixtureActivationFlowError, run_fixture_activation_flow,
    )

    def forbidden(*args):
        pytest.fail("invalid candidate must never invoke any callback")

    with pytest.raises(FixtureActivationFlowError,
                       match="FIXTURE_ACTIVATION_CANDIDATE_INVALID"):
        run_fixture_activation_flow(
            invalid,
            stage_managed_candidate=forbidden, syntax_check=forbidden,
            reload_candidate=forbidden, verify_live_exposure=forbidden,
            publish_derived_catalog=forbidden,
            verify_derived_catalog=forbidden, compensate=forbidden,
        )


@pytest.mark.parametrize("fail_after_catalog", [False, True])
@pytest.mark.skipif(
    shutil.which("nginx") is None,
    reason="disposable distro-packaged NGINX is required",
)
def test_v2_locked_real_nginx_reload_catalog_compensation_rehearsal(
    fixture_root, tmp_path, fail_after_catalog,
):
    """Exercise real, isolated NGINX + fixture catalog under the v2 state WAL.

    This has no native systemd, root-owned installed helper or durable
    multi-resource recovery: callback compensation is NOT crash-safe.
    """
    from repocache.server_fixture_activation_flow_v1 import (
        run_fixture_activation_flow,
    )
    import socket
    import time

    nginx = shutil.which("nginx")
    ca = next((p for p in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(p).is_file()), None)
    if ca is None:
        pytest.skip("disposable CA bundle not installed")

    fd, folder, _ = fixture_root
    previous = snapshot(count=1)
    apply(fixture_root, previous)
    previous_state = (folder / V2_STATE).read_bytes()
    updated_doc = document(count=1)
    updated_doc["repositories"][0]["desired_state"] = "active"
    proposed = snapshot(generation=2, previous=previous, doc=updated_doc)
    pins = {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}}

    conf = tmp_path / "nginx.conf"
    stage_file = tmp_path / "nginx.stage"
    next_file = tmp_path / "nginx.candidate"
    pid = tmp_path / "nginx.pid"
    log = tmp_path / "error.log"
    sock = tmp_path / "nginx.sock"
    catalog = tmp_path / "derived-fixture-catalog.json"
    catalog_tmp = tmp_path / "catalog.stage"
    assert len(os.fsencode(sock)) < 100
    previous_catalog = b'{"status":"fixture-previous"}\n'
    catalog.write_bytes(previous_catalog)

    def config(body, candidate=None):
        return (
            f"pid {pid};\nerror_log {log} notice;\n"
            "worker_processes 1;\nevents { worker_connections 32; }\n"
            "http { access_log off;\n"
            + (candidate["http_upstream_fragment"] if candidate else "")
            + f"server {{ listen unix:{sock};\n"
            + f'location = /__test_health {{ return 200 "{body}"; }}\n'
            + (candidate["server_location_fragment"] if candidate else "")
            + "}\n}\n"
        ).encode("utf-8")

    old_nginx = config("known-good")
    def atomically_stage(raw):
        with stage_file.open("wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(stage_file, conf)

    def nginx_command(*args, config_file=None):
        path = conf if config_file is None else config_file
        return subprocess.run(
            [nginx, *args, "-c", str(path), "-p", str(tmp_path)],
            capture_output=True, text=True, timeout=10, check=False,
        )

    def health():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            connection.connect(str(sock))
            connection.sendall(
                b"GET /__test_health HTTP/1.0\r\n"
                b"Host: localhost\r\nConnection: close\r\n\r\n"
            )
            chunks = bytearray()
            while len(chunks) < 4096:
                block = connection.recv(4096 - len(chunks))
                if not block:
                    break
                chunks.extend(block)
        return bytes(chunks)

    def wait_health(expected, process):
        for _ in range(100):
            assert process.poll() is None, "isolated NGINX process exited"
            try:
                reply = health()
                if (b" 200 " in reply.split(b"\r\n", 1)[0]
                        and reply.endswith(expected)):
                    return
            except (OSError, TimeoutError):
                pass
            time.sleep(0.05)
        pytest.fail("disposable NGINX health did not match expected")

    atomically_stage(old_nginx)
    assert nginx_command("-t").returncode == 0
    process = subprocess.Popen(
        [nginx, "-c", str(conf), "-p", str(tmp_path), "-g", "daemon off;"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    events = []

    try:
        wait_health(b"known-good", process)

        # This is the pre-journal syntax validator; neither state nor
        # catalog/configuration may have mutated when it runs.
        def validate_before_journal(candidate):
            assert (folder / V2_STATE).read_bytes() == previous_state
            assert not (folder / V2_JOURNAL).exists()
            assert conf.read_bytes() == old_nginx
            next_file.write_bytes(config("activated", candidate))
            assert nginx_command("-t", config_file=next_file).returncode == 0
            events.append("preflight")

        def activate(candidate):
            assert (folder / V2_JOURNAL).is_file()
            assert (folder / V2_STATE).read_bytes() != previous_state

            def stage(_candidate):
                assert _candidate["proposed_repository_ids"] == ["repo-0"]
                atomically_stage(next_file.read_bytes())
                events.append("stage")

            def syntax():
                assert nginx_command("-t").returncode == 0
                events.append("syntax")

            def reload():
                result = nginx_command("-s", "reload")
                assert result.returncode == 0, "isolated reload failed"
                events.append("reload")

            def exposure():
                wait_health(b"activated", process)
                assert candidate["server_location_fragment"].encode() in conf.read_bytes()
                events.append("exposure")

            def publish():
                assert "exposure" in events
                payload = json.dumps({
                    "schema_version": 1,
                    "status": "fixture-only-observed-candidate",
                    "active_ids": candidate["proposed_repository_ids"],
                }, sort_keys=True, separators=(",", ":")).encode("utf-8")
                with catalog_tmp.open("wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(catalog_tmp, catalog)
                events.append("publish")

            def verify_catalog():
                assert json.loads(catalog.read_bytes())["active_ids"] == ["repo-0"]
                events.append("verify")
                if fail_after_catalog:
                    raise RuntimeError("synthetic post-publication failure")

            def compensate():
                atomically_stage(old_nginx)
                assert nginx_command("-t").returncode == 0
                assert nginx_command("-s", "reload").returncode == 0
                wait_health(b"known-good", process)
                with catalog_tmp.open("wb") as handle:
                    handle.write(previous_catalog)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(catalog_tmp, catalog)
                events.append("compensate")

            return run_fixture_activation_flow(
                candidate, stage_managed_candidate=stage,
                syntax_check=syntax, reload_candidate=reload,
                verify_live_exposure=exposure,
                publish_derived_catalog=publish,
                verify_derived_catalog=verify_catalog,
                compensate=compensate,
            )

        if fail_after_catalog:
            with pytest.raises(
                ProposedV2PersistenceError,
                match="ACTIVATION_FIXTURE_REFUSED",
            ):
                locked_preflight_commit(
                    fixture_root, proposed, expected=1, pins=pins,
                    ca=ca, validate=validate_before_journal,
                    activate=activate,
                )
            assert events == [
                "preflight", "stage", "syntax", "reload", "exposure",
                "publish", "verify", "compensate",
            ]
            assert (folder / V2_JOURNAL).is_file()
            assert conf.read_bytes() == old_nginx
            assert catalog.read_bytes() == previous_catalog
            wait_health(b"known-good", process)
            assert rollback(fixture_root)["status"] == "ROLLED_BACK_INERT_V2"
            assert (folder / V2_STATE).read_bytes() == previous_state
            assert not (folder / V2_JOURNAL).exists()
        else:
            report = locked_preflight_commit(
                fixture_root, proposed, expected=1, pins=pins,
                ca=ca, validate=validate_before_journal,
                activate=activate,
            )
            assert report["state_generation"] == 2
            assert report["fixture_activation_barrier_executed"] is True
            assert not report["authorizes_nginx_activation"]
            assert not report["authorizes_catalog_publication"]
            assert events == [
                "preflight", "stage", "syntax", "reload", "exposure",
                "publish", "verify",
            ]
            assert not (folder / V2_JOURNAL).exists()
            assert json.loads(catalog.read_bytes())["active_ids"] == ["repo-0"]
            wait_health(b"activated", process)
    finally:
        if process.poll() is None:
            nginx_command("-s", "quit")
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


# Fixed-name three-resource v2 journal: deliberately private Linux fixtures.
def _multi_resource_fixture():
    from repocache import server_fixture_multi_resource_wal_v1 as multi
    return multi


def _catalog_fixture(ids):
    return json.dumps({
        "schema_version": 1,
        "status": "fixture-only-observed-candidate",
        "active_ids": ids,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _multi_snapshot(count, *, generation=1, previous=None, active=False):
    doc = document(count=count)
    if active:
        for row in doc["repositories"]:
            row["desired_state"] = "active"
    return snapshot(generation=generation, previous=previous, doc=doc)


def test_multi_resource_durable_bootstrap_and_active_only_fixture_catalog(
    fixture_root,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    new = _multi_snapshot(1, active=True)
    result = multi._commit_fixture_multi_resource_under_root(
        fd, new, owner_uid=uid, expected_generation=0,
        include_bytes=b"# disposable managed NGINX candidate\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    assert result["status"] == "COMMITTED_INERT_FIXTURE_MULTI_RESOURCE"
    assert result["state_generation"] == 1
    assert result["durable_shadow_wal_exercised"] is True
    assert result["host_activation_verified"] is False
    assert result["authorizes_nginx_reload"] is False
    assert result["authorizes_catalog_publication"] is False
    assert json.loads((folder / V2_STATE).read_bytes()) == new
    assert (folder / multi.INCLUDE).read_bytes() == (
        b"# disposable managed NGINX candidate\n"
    )
    assert json.loads((folder / multi.CATALOG).read_bytes())["active_ids"] == ["repo-0"]
    assert (folder / multi.MANIFEST).is_file()
    assert all(not (folder / name).exists()
               for name in (multi.JOURNAL, multi.JOURNAL_TMP, multi.STAGE))
    assert all((folder / name).stat().st_mode & 0o777 == 0o600
               for name in (V2_STATE, multi.INCLUDE, multi.CATALOG, multi.MANIFEST))
    assert multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )["status"] == "CLEAN_INERT_FIXTURE"


@pytest.mark.parametrize("phase", [
    "journal_tmp_durable", "journal_durable", "include_durable",
    "state_durable", "catalog_durable", "manifest_durable",
])
@pytest.mark.parametrize("bootstrap", [True, False])
def test_multi_resource_crash_recovery_returns_all_exact_previous_bytes(
    fixture_root, phase, bootstrap,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    prior = None
    old_gen = 0
    if not bootstrap:
        prior = _multi_snapshot(1, active=True)
        multi._commit_fixture_multi_resource_under_root(
            fd, prior, owner_uid=uid, expected_generation=0,
            include_bytes=b"# prior NGINX\n",
            catalog_bytes=_catalog_fixture(["repo-0"]),
        )
        old_gen = 1
    old = {name: (folder / name).read_bytes() if (folder / name).exists()
           else None for name in multi.ORDER}
    next_state = _multi_snapshot(
        2, generation=old_gen + 1, previous=prior, active=True,
    )

    def interrupt(point):
        if point == phase:
            raise RuntimeError("disposable process interruption")

    with pytest.raises(RuntimeError, match="disposable process interruption"):
        multi._commit_fixture_multi_resource_under_root(
            fd, next_state, owner_uid=uid, expected_generation=old_gen,
            include_bytes=b"# next NGINX\n",
            catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
            inject_fault=interrupt,
        )
    # Ordinary state APIs must NOT claim clean or bypass this journal.
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        apply(fixture_root, _multi_snapshot(1))
    with pytest.raises(
        ProposedV2PersistenceError, match="MULTI_RESOURCE_RECOVERY_REQUIRED",
    ):
        rollback(fixture_root)
    with pytest.raises(
        ProposedV2PersistenceError, match="MULTI_RESOURCE_RECOVERY_REQUIRED",
    ):
        preview_v2_recovery(fd, owner_uid=uid)
    recovery = multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )
    assert recovery["status"] in (
        "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE",
        "DISCARDED_UNPUBLISHED_INERT_FIXTURE_JOURNAL",
    )
    assert recovery["host_recovery_verified"] is False
    assert recovery["nginx_service_reloaded"] is False
    assert recovery["catalog_publication_verified"] is False
    for name, bytes_before in old.items():
        path = folder / name
        assert (path.read_bytes() if path.exists() else None) == bytes_before
    assert all(not (folder / name).exists()
               for name in (multi.JOURNAL, multi.JOURNAL_TMP, multi.STAGE))
    assert multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )["status"] == "CLEAN_INERT_FIXTURE"
    retried = multi._commit_fixture_multi_resource_under_root(
        fd, next_state, owner_uid=uid, expected_generation=old_gen,
        include_bytes=b"# next NGINX\n",
        catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
    )
    assert retried["status"] == "COMMITTED_INERT_FIXTURE_MULTI_RESOURCE"


@pytest.mark.parametrize("target", ["state", "include", "catalog", "manifest"])
def test_multi_resource_recovery_refuses_external_drift_without_erasure(
    fixture_root, target,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    new = _multi_snapshot(1, active=True)

    def crash(point):
        if point == "manifest_durable":
            raise RuntimeError("simulated abrupt process exit")

    with pytest.raises(RuntimeError):
        multi._commit_fixture_multi_resource_under_root(
            fd, new, owner_uid=uid, expected_generation=0,
            include_bytes=b"# candidate nginx\n",
            catalog_bytes=_catalog_fixture(["repo-0"]),
            inject_fault=crash,
        )
    name = {"state": V2_STATE, "include": multi.INCLUDE,
            "catalog": multi.CATALOG, "manifest": multi.MANIFEST}[target]
    path = folder / name
    altered = path.read_bytes() + b"external modification"
    path.write_bytes(altered)
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="FOREIGN_RESOURCE_DRIFT"):
        multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    assert path.read_bytes() == altered
    assert (folder / multi.JOURNAL).is_file()


def test_multi_resource_foreign_symlink_refused_without_following(
    fixture_root, tmp_path,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root

    def crash(phase):
        if phase == "include_durable":
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError):
        multi._commit_fixture_multi_resource_under_root(
            fd, _multi_snapshot(1), owner_uid=uid, expected_generation=0,
            include_bytes=b"# nginx candidate\n",
            catalog_bytes=_catalog_fixture([]), inject_fault=crash,
        )
    secret = tmp_path / "unrelated-secret"
    secret.write_bytes(b"keep out")
    include = folder / multi.INCLUDE
    include.unlink()
    include.symlink_to(secret)
    with pytest.raises((multi.FixtureMultiResourceError, ProtectedStateStoreError)):
        multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    assert include.is_symlink()
    assert secret.read_bytes() == b"keep out"
    assert (folder / multi.JOURNAL).is_file()



@pytest.mark.parametrize("corruption", [
    "duplicate-key", "noncanonical-whitespace", "nonfinite", "wrong-type",
    "invalid-utf8",
])
def test_multi_resource_refuses_ambiguous_catalog_before_any_write(
    fixture_root, corruption,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    valid = _catalog_fixture(["repo-0"])
    if corruption == "duplicate-key":
        candidate = valid.replace(
            b'"status":', b'"status":"fixture-only-observed-candidate","status":',
            1,
        )
    elif corruption == "noncanonical-whitespace":
        candidate = b"{ " + valid[1:]
    elif corruption == "nonfinite":
        candidate = valid.replace(b'["repo-0"]', b'["repo-0",NaN]')
    elif corruption == "wrong-type":
        candidate = valid.replace(b'["repo-0"]', b'[42]')
    else:
        candidate = valid + bytes([0xff])
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="CATALOG_INVALID"):
        multi._commit_fixture_multi_resource_under_root(
            fd, _multi_snapshot(1, active=True),
            owner_uid=uid, expected_generation=0,
            include_bytes=b"# inert NGINX fixture",
            catalog_bytes=candidate,
        )
    assert not (folder / V2_STATE).exists()
    assert not (folder / multi.JOURNAL).exists()
    assert not (folder / multi.JOURNAL_TMP).exists()


def test_multi_resource_recovery_refuses_digest_rebound_ambiguous_catalog(
    fixture_root,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    multi._commit_fixture_multi_resource_under_root(
        fd, _multi_snapshot(1, active=True),
        owner_uid=uid, expected_generation=0,
        include_bytes=b"# known-good NGINX fixture",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    state = (folder / V2_STATE).read_bytes()
    include = (folder / multi.INCLUDE).read_bytes()
    duplicate = _catalog_fixture(["repo-0"]).replace(
        b'"status":', b'"status":"fixture-only-observed-candidate","status":',
        1,
    )
    (folder / multi.CATALOG).write_bytes(duplicate)
    # Even a forged, internally matching owner manifest must not turn
    # ambiguous discovery bytes into a clean recovered generation.
    forged_manifest = multi._manifest(state, include, duplicate)
    (folder / multi.MANIFEST).write_bytes(forged_manifest)
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="OWNER_MANIFEST_MISSING_OR_DRIFT"):
        multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    assert (folder / V2_STATE).read_bytes() == state
    assert (folder / multi.CATALOG).read_bytes() == duplicate
    assert (folder / multi.MANIFEST).read_bytes() == forged_manifest
    assert not (folder / multi.JOURNAL).exists()


@pytest.mark.parametrize("active_ids", [[], ["repo-0", "repo-0"], ["unknown"]])
def test_multi_resource_refuses_inaccurate_active_catalog_before_write(
    fixture_root, active_ids,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="CATALOG_INVALID"):
        multi._commit_fixture_multi_resource_under_root(
            fd, _multi_snapshot(1, active=True),
            owner_uid=uid, expected_generation=0,
            include_bytes=b"# nginx candidate\n",
            catalog_bytes=_catalog_fixture(active_ids),
        )
    assert not (folder / multi.JOURNAL).exists()
    assert not (folder / V2_STATE).exists()


def test_multi_resource_manifest_rejects_unowned_prior_files(fixture_root):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    (folder / multi.INCLUDE).write_bytes(b"# foreign configuration\n")
    (folder / multi.INCLUDE).chmod(0o600)
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="FOREIGN_BOOTSTRAP_RESOURCE"):
        multi._commit_fixture_multi_resource_under_root(
            fd, _multi_snapshot(1),
            owner_uid=uid, expected_generation=0,
            include_bytes=b"# new configuration\n",
            catalog_bytes=_catalog_fixture([]),
        )
    assert (folder / multi.INCLUDE).read_bytes() == b"# foreign configuration\n"
    assert not (folder / multi.JOURNAL).exists()


def test_multi_resource_manifest_detects_foreign_modification_on_update(
    fixture_root,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    old = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, old, owner_uid=uid, expected_generation=0,
        include_bytes=b"# known-good\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    (folder / multi.INCLUDE).write_bytes(b"# mutated by external actor\n")
    next_state = _multi_snapshot(2, generation=2, previous=old, active=True)
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="OWNER_MANIFEST_MISSING_OR_DRIFT"):
        multi._commit_fixture_multi_resource_under_root(
            fd, next_state, owner_uid=uid, expected_generation=1,
            include_bytes=b"# new candidate\n",
            catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
        )
    assert not (folder / multi.JOURNAL).exists()
    assert (folder / multi.INCLUDE).read_bytes() == (
        b"# mutated by external actor\n"
    )



def test_multi_resource_prepublication_barrier_orders_catalog_after_effects(
    fixture_root,
):
    """A test callback cannot publish a new catalog before exposure checks."""
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    old_state = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, old_state, owner_uid=uid, expected_generation=0,
        include_bytes=b"# previous candidate\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    prior_catalog = (folder / multi.CATALOG).read_bytes()
    prior_manifest = (folder / multi.MANIFEST).read_bytes()
    next_state = _multi_snapshot(
        2, generation=2, previous=old_state, active=True,
    )
    events = []

    def prepublication():
        events.append("before_catalog")
        assert (folder / multi.JOURNAL).is_file()
        assert (folder / V2_STATE).read_bytes() == multi._canonical(
            next_state, limit=multi.LIMITS[V2_STATE],
        )
        assert (folder / multi.INCLUDE).read_bytes() == b"# next candidate\n"
        assert (folder / multi.CATALOG).read_bytes() == prior_catalog
        assert (folder / multi.MANIFEST).read_bytes() == prior_manifest
        return None

    def after_publication():
        events.append("after_catalog")
        assert (folder / multi.JOURNAL).is_file()
        assert (folder / multi.CATALOG).read_bytes() == _catalog_fixture(
            ["repo-0", "repo-1"],
        )
        assert (folder / multi.MANIFEST).read_bytes() != prior_manifest
        return None

    result = multi._commit_fixture_multi_resource_under_root(
        fd, next_state, owner_uid=uid, expected_generation=1,
        include_bytes=b"# next candidate\n",
        catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
        verify_fixture_exposure_before_publish=prepublication,
        verify_fixture_effects=after_publication,
    )
    assert events == ["before_catalog", "after_catalog"]
    assert result["prepublication_fixture_barrier_executed"] is True
    assert result["authorizes_catalog_publication"] is False
    assert multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )["status"] == "CLEAN_INERT_FIXTURE"


@pytest.mark.parametrize("failure", [
    "raise", "non-none", "catalog-race", "state-race", "manifest-race",
    "journal-race",
])
def test_multi_resource_prepublication_failure_never_publishes_catalog(
    fixture_root, failure,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    previous = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, previous, owner_uid=uid, expected_generation=0,
        include_bytes=b"# old\n", catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    old = {n: (folder / n).read_bytes() for n in multi.ORDER}
    candidate = _multi_snapshot(2, generation=2, previous=previous, active=True)

    def prepublication():
        if failure == "raise":
            raise RuntimeError("private key never leaked")
        if failure == "non-none":
            return False
        if failure == "catalog-race":
            (folder / multi.CATALOG).write_bytes(b"foreign-catalog")
        elif failure == "state-race":
            (folder / V2_STATE).write_bytes(b"foreign-state")
        elif failure == "manifest-race":
            (folder / multi.MANIFEST).write_bytes(b"foreign-manifest")
        elif failure == "journal-race":
            (folder / multi.JOURNAL).write_bytes(b"foreign-journal")
        return None

    with pytest.raises(multi.FixtureMultiResourceError,
                       match="FIXTURE_PREPUBLICATION_") as error:
        multi._commit_fixture_multi_resource_under_root(
            fd, candidate, owner_uid=uid, expected_generation=1,
            include_bytes=b"# next\n",
            catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
            verify_fixture_exposure_before_publish=prepublication,
        )
    assert "private key" not in str(error.value)
    assert (folder / multi.JOURNAL).is_file()
    if failure not in ("catalog-race", "journal-race"):
        assert (folder / multi.CATALOG).read_bytes() == old[multi.CATALOG]
    if failure == "journal-race":
        # Untrusted WAL must block recovery, never be silently discarded.
        with pytest.raises(multi.FixtureMultiResourceError):
            multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    elif failure in ("catalog-race", "state-race", "manifest-race"):
        # Foreign modification must not be erased by rollback.
        with pytest.raises(multi.FixtureMultiResourceError,
                           match="FOREIGN_RESOURCE_DRIFT"):
            multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    else:
        restored = multi._recover_fixture_multi_resource_under_root(
            fd, owner_uid=uid,
        )
        assert restored["status"] == "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE"
        assert {n: (folder / n).read_bytes() for n in multi.ORDER} == old


def test_multi_resource_prepublication_callback_type_refused_without_wal(
    fixture_root,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="FIXTURE_PREPUBLICATION_CALLBACK_INVALID"):
        multi._commit_fixture_multi_resource_under_root(
            fd, _multi_snapshot(1), owner_uid=uid, expected_generation=0,
            include_bytes=b"# candidate\n",
            catalog_bytes=_catalog_fixture([]),
            verify_fixture_exposure_before_publish=True,
        )
    assert not (folder / multi.JOURNAL).exists()
    assert not (folder / V2_STATE).exists()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Linux fork required")
def test_multi_resource_actual_pid_death_at_prepublication_is_recoverable(
    fixture_root,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    initial = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, initial, owner_uid=uid, expected_generation=0,
        include_bytes=b"# prior\n", catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    before = {name: (folder / name).read_bytes() for name in multi.ORDER}
    next_state = _multi_snapshot(
        2, generation=2, previous=initial, active=True,
    )
    pid = os.fork()
    if pid == 0:
        try:
            multi._commit_fixture_multi_resource_under_root(
                fd, next_state, owner_uid=uid, expected_generation=1,
                include_bytes=b"# next\n",
                catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
                verify_fixture_exposure_before_publish=lambda: os._exit(41),
            )
        except BaseException:
            os._exit(72)
        os._exit(73)
    ended, status = os.waitpid(pid, 0)
    assert ended == pid
    assert os.waitstatus_to_exitcode(status) == 41
    assert (folder / multi.CATALOG).read_bytes() == before[multi.CATALOG]
    assert (folder / multi.JOURNAL).is_file()
    restored = multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )
    assert restored["status"] == "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE"
    assert {name: (folder / name).read_bytes() for name in multi.ORDER} == before


def test_multi_resource_callback_failure_preserves_complete_undo_log(
    fixture_root,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root

    def fail():
        assert (folder / multi.JOURNAL).is_file()
        assert (folder / multi.MANIFEST).is_file()
        raise RuntimeError("private NGINX password should never leak")

    with pytest.raises(multi.FixtureMultiResourceError,
                       match="FIXTURE_EFFECTS_REFUSED") as caught:
        multi._commit_fixture_multi_resource_under_root(
            fd, _multi_snapshot(1, active=True),
            owner_uid=uid, expected_generation=0,
            include_bytes=b"# candidate\n",
            catalog_bytes=_catalog_fixture(["repo-0"]),
            verify_fixture_effects=fail,
        )
    assert "private NGINX" not in str(caught.value)
    assert (folder / multi.JOURNAL).is_file()
    assert multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )["status"] == "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE"
    assert not (folder / multi.MANIFEST).exists()
    assert not (folder / V2_STATE).exists()


def test_multi_resource_identical_generation_is_inert(fixture_root):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    old = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, old, owner_uid=uid, expected_generation=0,
        include_bytes=b"# nginx known-good\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    inode = (folder / V2_STATE).stat().st_ino
    next_state = _multi_snapshot(1, generation=2, previous=old, active=True)
    status = multi._commit_fixture_multi_resource_under_root(
        fd, next_state, owner_uid=uid, expected_generation=1,
        include_bytes=b"# nginx known-good\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    assert status["status"] == "NO_CHANGE_INERT_FIXTURE"
    assert (folder / V2_STATE).stat().st_ino == inode
    assert not (folder / multi.JOURNAL).exists()


def test_multi_resource_live_namespace_root_cannot_be_used_as_fixture():
    multi = _multi_resource_fixture()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ProposedV2PersistenceError,
                           match="CURRENT_NAMESPACE_ROOT_WRITES_REFUSED"):
            multi._commit_fixture_multi_resource_under_root(
                fd, _multi_snapshot(1), owner_uid=os.geteuid(),
                expected_generation=0, include_bytes=b"# inert\n",
                catalog_bytes=_catalog_fixture([]),
            )
        with pytest.raises(ProposedV2PersistenceError,
                           match="CURRENT_NAMESPACE_ROOT_WRITES_REFUSED"):
            multi._recover_fixture_multi_resource_under_root(
                fd, owner_uid=os.geteuid(),
            )
    finally:
        os.close(fd)


@pytest.mark.skipif(not hasattr(os, "fork"),
                    reason="requires Linux fork and disposable protected fixture")
@pytest.mark.parametrize("phase", [
    "journal_tmp_durable", "journal_durable", "include_durable",
    "state_durable", "catalog_durable", "manifest_durable",
])
def test_multi_resource_actual_process_death_replays_previous_bytes(
    fixture_root, phase,
):
    """Kill a separate writer process without running finally or compensation."""
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    initial = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, initial, owner_uid=uid, expected_generation=0,
        include_bytes=b"# previous exact nginx\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    old = {n: (folder / n).read_bytes() for n in multi.ORDER}
    next_state = _multi_snapshot(2, generation=2, previous=initial, active=True)

    pid = os.fork()
    if pid == 0:
        try:
            def die(point):
                if point == phase:
                    os._exit(41)

            multi._commit_fixture_multi_resource_under_root(
                fd, next_state, owner_uid=uid, expected_generation=1,
                include_bytes=b"# replacement exact nginx\n",
                catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
                inject_fault=die,
            )
        except BaseException:
            os._exit(71)
        os._exit(72)
    ended, status = os.waitpid(pid, 0)
    assert ended == pid
    assert os.waitstatus_to_exitcode(status) == 41
    assert (folder / (multi.JOURNAL_TMP if phase == "journal_tmp_durable"
                      else multi.JOURNAL)).is_file()
    assert multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )["status"] in (
        "DISCARDED_UNPUBLISHED_INERT_FIXTURE_JOURNAL",
        "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE",
    )
    assert {n: (folder / n).read_bytes() for n in multi.ORDER} == old
    assert all(not (folder / n).exists()
               for n in (multi.JOURNAL, multi.JOURNAL_TMP, multi.STAGE))


def test_multi_resource_second_crash_during_rollback_is_retryable(
    fixture_root, monkeypatch,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    old = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, old, owner_uid=uid, expected_generation=0,
        include_bytes=b"# original\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    original = {name: (folder / name).read_bytes() for name in multi.ORDER}
    next_state = _multi_snapshot(2, generation=2, previous=old, active=True)

    def crash(phase):
        if phase == "manifest_durable":
            raise RuntimeError("first crash")

    with pytest.raises(RuntimeError):
        multi._commit_fixture_multi_resource_under_root(
            fd, next_state, owner_uid=uid, expected_generation=1,
            include_bytes=b"# next\n",
            catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
            inject_fault=crash,
        )
    real_writer = multi._write_target
    counter = []

    def fail_after_first_restoration(*args, **kwargs):
        real_writer(*args, **kwargs)
        counter.append(True)
        if len(counter) == 1:
            raise RuntimeError("second synthetic crash")

    monkeypatch.setattr(multi, "_write_target", fail_after_first_restoration)
    with pytest.raises(RuntimeError, match="second synthetic crash"):
        multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    assert (folder / multi.JOURNAL).is_file()
    monkeypatch.setattr(multi, "_write_target", real_writer)
    assert multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )["status"] == "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE"
    assert {n: (folder / n).read_bytes() for n in multi.ORDER} == original
    assert not (folder / multi.JOURNAL).exists()


@pytest.mark.parametrize("damage", ["invalid-json", "wrong-digest", "oversize"])
def test_multi_resource_tampered_journal_refused_without_erasure(
    fixture_root, damage,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root

    def crash(phase):
        if phase == "manifest_durable":
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError):
        multi._commit_fixture_multi_resource_under_root(
            fd, _multi_snapshot(1), owner_uid=uid, expected_generation=0,
            include_bytes=b"# nginx\n", catalog_bytes=_catalog_fixture([]),
            inject_fault=crash,
        )
    journal = folder / multi.JOURNAL
    old = {n: (folder / n).read_bytes() for n in multi.ORDER}
    if damage == "invalid-json":
        journal.write_bytes(b'{"truncated":')
    elif damage == "wrong-digest":
        entry = json.loads(journal.read_bytes())
        entry["next_sha256"][multi.INCLUDE] = "a" * 64
        # Keep the tampered record canonical so the recovery tests the
        # expected next-digest refusal, not only generic JSON-format denial.
        journal.write_bytes(multi._canonical(
            entry, limit=multi.MAX_JOURNAL_BYTES,
        ))
        # Hash substitution is only detected once a resource diverges from
        # *both* the original and the forged next digest.
        with pytest.raises(multi.FixtureMultiResourceError,
                           match="FOREIGN_RESOURCE_DRIFT"):
            multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
        assert {n: (folder / n).read_bytes() for n in multi.ORDER} == old
        return
    else:
        journal.write_bytes(b"x" * (multi.MAX_JOURNAL_BYTES + 1))
    with pytest.raises((multi.FixtureMultiResourceError,
                       ProtectedStateStoreError, ValueError)):
        multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    assert {n: (folder / n).read_bytes() for n in multi.ORDER} == old
    assert journal.is_file()


def test_multi_resource_recovery_refuses_forged_next_hash_for_invalid_v2(
    fixture_root,
):
    """A journal digest cannot turn invalid next-generation state into authority."""
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root

    def crash(point):
        if point == "manifest_durable":
            raise RuntimeError("crash after new resources replaced")

    with pytest.raises(RuntimeError):
        multi._commit_fixture_multi_resource_under_root(
            fd, _multi_snapshot(1), owner_uid=uid, expected_generation=0,
            include_bytes=b"# candidate\n", catalog_bytes=_catalog_fixture([]),
            inject_fault=crash,
        )
    journal = folder / multi.JOURNAL
    state = folder / V2_STATE
    invalid = b'{"state_schema_version":999,"state_generation":1}'
    state.write_bytes(invalid)
    forged = json.loads(journal.read_bytes())
    forged["next_sha256"][V2_STATE] = hashlib.sha256(invalid).hexdigest()
    journal.write_bytes(multi._canonical(
        forged, limit=multi.MAX_JOURNAL_BYTES,
    ))
    old = {n: (folder / n).read_bytes() for n in multi.ORDER}
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="NEXT_STATE_INVALID"):
        multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    assert {n: (folder / n).read_bytes() for n in multi.ORDER} == old
    assert journal.is_file()


@pytest.mark.parametrize("resource", [
    "state", "include", "catalog", "manifest",
])
def test_multi_resource_clean_status_never_hides_foreign_owned_drift(
    fixture_root, resource,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    initial = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, initial, owner_uid=uid, expected_generation=0,
        include_bytes=b"# verified prior NGINX\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    chosen = {"state": V2_STATE, "include": multi.INCLUDE,
              "catalog": multi.CATALOG,
              "manifest": multi.MANIFEST}[resource]
    path = folder / chosen
    changed = path.read_bytes() + b"# foreign change"
    path.write_bytes(changed)
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="OWNER_MANIFEST_MISSING_OR_DRIFT"):
        multi._recover_fixture_multi_resource_under_root(
            fd, owner_uid=uid,
        )
    assert path.read_bytes() == changed
    assert not (folder / multi.JOURNAL).exists()


def test_multi_resource_committed_owner_blocks_all_state_only_operations(
    fixture_root,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    previous = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, previous, owner_uid=uid, expected_generation=0,
        include_bytes=b"# managed NGINX gen 1\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    assert multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )["status"] == "CLEAN_INERT_FIXTURE"
    before = {n: (folder / n).read_bytes() for n in multi.ORDER}
    next_snapshot = _multi_snapshot(
        2, generation=2, previous=previous, active=True,
    )
    with pytest.raises(ProposedV2PersistenceError,
                       match="RECOVERY_REQUIRED"):
        apply(fixture_root, next_snapshot)
    with pytest.raises(ProposedV2PersistenceError,
                       match="MULTI_RESOURCE_RECOVERY_REQUIRED"):
        rollback(fixture_root)
    with pytest.raises(ProposedV2PersistenceError,
                       match="MULTI_RESOURCE_RECOVERY_REQUIRED"):
        preview_v2_recovery(fd, owner_uid=uid)
    assert {n: (folder / n).read_bytes() for n in multi.ORDER} == before
    assert not (folder / multi.JOURNAL).exists()
    # The true multi-resource writer may still perform the next generation:
    # the cross-resource owner marker is not a pending WAL.
    written = multi._commit_fixture_multi_resource_under_root(
        fd, next_snapshot, owner_uid=uid, expected_generation=1,
        include_bytes=b"# managed NGINX gen 2\n",
        catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
    )
    assert written["status"] == "COMMITTED_INERT_FIXTURE_MULTI_RESOURCE"
    assert json.loads((folder / V2_STATE).read_bytes()) == next_snapshot
    assert json.loads((folder / multi.CATALOG).read_bytes())["active_ids"] == [
        "repo-0", "repo-1",
    ]
    assert not (folder / multi.JOURNAL).exists()


def test_multi_resource_clean_preview_refuses_legacy_state_without_manifest(
    fixture_root,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    assert multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )["status"] == "CLEAN_INERT_FIXTURE"
    legacy = _multi_snapshot(1)
    apply(fixture_root, legacy)
    prior = (folder / V2_STATE).read_bytes()
    with pytest.raises(multi.FixtureMultiResourceError,
                       match="OWNER_MANIFEST_MISSING_OR_DRIFT"):
        multi._recover_fixture_multi_resource_under_root(
            fd, owner_uid=uid,
        )
    assert (folder / V2_STATE).read_bytes() == prior


@pytest.mark.parametrize("marker", [
    ".native-nginx-v1.pending", ".native-nginx-v1.pending-tmp",
])
def test_v2_refuses_unreconciled_native_package_effects_before_any_write(
    fixture_root, marker,
):
    """APT/DNF is not an atomic rollback domain; keep its journal separate."""
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    marker_path = folder / marker
    marker_path.write_bytes(b'{"native_package_effects":"unknown"}')
    marker_path.chmod(0o600)
    before = {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}
    candidate = _multi_snapshot(1)

    with pytest.raises(ProposedV2PersistenceError,
                       match="NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED"):
        apply(fixture_root, candidate)
    with pytest.raises(ProposedV2PersistenceError,
                       match="NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED"):
        rollback(fixture_root)
    with pytest.raises(ProposedV2PersistenceError,
                       match="NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED"):
        preview_v2_recovery(fd, owner_uid=uid)
    with pytest.raises(ProposedV2PersistenceError,
                       match="NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED"):
        multi._commit_fixture_multi_resource_under_root(
            fd, candidate, owner_uid=uid, expected_generation=0,
            include_bytes=b"# noninstalled candidate\n",
            catalog_bytes=_catalog_fixture([]),
        )
    with pytest.raises(ProposedV2PersistenceError,
                       match="NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED"):
        multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    assert {p.name: p.read_bytes() for p in folder.iterdir()
            if p.is_file()} == before
    assert not (folder / V2_STATE).exists()
    assert not (folder / multi.JOURNAL).exists()


@pytest.mark.parametrize("marker", [
    ".native-nginx-v1.pending", ".native-nginx-v1.pending-tmp",
])
def test_pending_native_package_effects_block_multi_wal_recovery_without_erasure(
    fixture_root, marker,
):
    multi = _multi_resource_fixture()
    fd, folder, uid = fixture_root
    previous = _multi_snapshot(1, active=True)
    multi._commit_fixture_multi_resource_under_root(
        fd, previous, owner_uid=uid, expected_generation=0,
        include_bytes=b"# known-good NGINX fixture\n",
        catalog_bytes=_catalog_fixture(["repo-0"]),
    )
    known_good_state = (folder / V2_STATE).read_bytes()
    replacement = _multi_snapshot(
        2, generation=2, previous=previous, active=True,
    )

    def crash(point):
        if point == "catalog_durable":
            raise RuntimeError("synthetic unfinished composite transaction")

    with pytest.raises(RuntimeError):
        multi._commit_fixture_multi_resource_under_root(
            fd, replacement, owner_uid=uid, expected_generation=1,
            include_bytes=b"# replacement NGINX fixture\n",
            catalog_bytes=_catalog_fixture(["repo-0", "repo-1"]),
            inject_fault=crash,
        )
    before = {p.name: p.read_bytes() for p in folder.iterdir()
              if p.is_file()}
    marker_path = folder / marker
    marker_path.write_bytes(b'{"native_package_effects":"unverified"}')
    marker_path.chmod(0o600)

    with pytest.raises(ProposedV2PersistenceError,
                       match="NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED"):
        multi._recover_fixture_multi_resource_under_root(fd, owner_uid=uid)
    assert {p.name: p.read_bytes() for p in folder.iterdir()
            if p.is_file()} == {**before, marker: marker_path.read_bytes()}
    assert (folder / multi.JOURNAL).is_file()
    # A test-only operator reconciles the simulated package marker first.
    # No native package installation or automatic marker deletion occurs.
    marker_path.unlink()
    assert multi._recover_fixture_multi_resource_under_root(
        fd, owner_uid=uid,
    )["status"] == "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE"
    assert (folder / V2_STATE).read_bytes() == known_good_state
    assert not (folder / multi.JOURNAL).exists()
