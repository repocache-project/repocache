"""The authenticated candidate reads exact local evidence, never writes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
from recovery_journal_v1 import inspect_local_recovery_record, PairRefused, _check_observed_phase
import recoverable_fallback_pair_lab as pair
from scripts.smoke_client_recoverable_pair import build, IDENT


@pytest.mark.skipif(os.geteuid() != 0, reason="requires private root-owned fixture")
@pytest.mark.parametrize("manager", ["apt", "dnf"])
def test_exact_recovery_record_and_foreign_inode(tmp_path, manager):
    root = tmp_path / "fixture"
    root.mkdir(mode=0o700)
    source, mirror, _, state = build(root, manager)
    approval = state / ("candidate-" + IDENT + ".json")
    record = json.loads(approval.read_text())
    observed = pair.pre.inspect_source(record["source"], root=root)
    record["schema"] = 2
    record["source_identity"] = {
        key: observed[key] for key in pair.boundary.SOURCE_IDENTITY_FIELDS}
    approval.write_text(json.dumps(record))
    assert inspect_local_recovery_record(IDENT, _test_root=root)["status"] == "no-journal-read-only"
    apply = (pair.apply_retaining_apt_companion_sandbox if manager == "apt"
             else pair.apply_sandbox)
    if manager == "apt":
        apply(root, IDENT, current_catalog=False)
    else:
        apply(root, IDENT)
    def snapshot():
        return {str(p.relative_to(root)): (p.stat().st_ino, p.stat().st_mode,
                                          hashlib.sha256(p.read_bytes()).hexdigest())
                for p in root.rglob("*") if p.is_file()}
    before = snapshot()
    report = inspect_local_recovery_record(IDENT, _test_root=root)
    assert report["phase"] == "installed" and report["source_state"] == "proposed"
    assert report["companion_state"] == ("cache-bearing" if manager == "apt" else "not-applicable")
    assert not report["write_eligible"] and not report["route_revocation_verified"]
    assert snapshot() == before
    pair.restore_sandbox(root, IDENT)
    report = inspect_local_recovery_record(IDENT, _test_root=root)
    journal = json.loads((state / pair._journal_name(IDENT)).read_text())
    expected = ("original-or-restored" if journal["original_id"] == journal["restore_id"]
                else "restored")
    assert report["phase"] == "restored" and report["source_state"] == expected
    if manager == "apt":
        assert report["companion_state"] == "upstream-only"
    pending = state / pair._pending_journal_name(IDENT)
    pending.write_bytes(b"partial")
    before = snapshot()
    with pytest.raises(PairRefused, match="Pending journal"):
        inspect_local_recovery_record(IDENT, _test_root=root)
    assert snapshot() == before
    pending.unlink()
    target = mirror if manager == "apt" else source
    foreign = target.with_suffix(".foreign")
    foreign.write_bytes(target.read_bytes())
    foreign.chmod(0o644)
    os.replace(foreign, target)
    before = snapshot()
    with pytest.raises(PairRefused, match="recorded inode"):
        inspect_local_recovery_record(IDENT, _test_root=root)
    assert snapshot() == before


@pytest.mark.parametrize("phase,source,companion", [
    ("installed", "original", "cache-bearing"),
    ("installed", "proposed", "upstream-only"),
    ("armed", "proposed", "absent"),
    ("restore-armed", "restored", "cache-bearing"),
    ("restored", "restored", "cache-bearing"),
])
def test_inconsistent_recovery_phases_are_refused(phase, source, companion):
    record = {"phase": phase, "companion": "etc/apt/mirrors/repocache-example.list",
              "original_id": [1, 1], "proposed_id": [1, 2],
              "mirror_id": [1, 3],
              "restore_id": [1, 5] if phase in ("restore-armed", "restored") else None,
              "retained_id": [1, 4] if phase in ("restore-armed", "restored") else None}
    with pytest.raises(PairRefused):
        _check_observed_phase(record, source, companion)


def test_nonroot_readback_refused_before_inspection(monkeypatch):
    monkeypatch.setattr(os, "getresuid", lambda: (1000, 0, 0))
    with pytest.raises(PairRefused, match="requires root"):
        inspect_local_recovery_record(IDENT)


def test_recycled_original_inode_reports_ambiguity_not_new_authority():
    from recovery_journal_v1 import _classify_source
    record = {"original_id": [1, 2], "restore_id": [1, 2],
              "proposed_id": [1, 3], "phase": "restored", "companion": None}
    result = _classify_source(record, [1, 2], b"original", b"original", b"proposed")
    assert result == "original-or-restored"
    _check_observed_phase(record, result, "not-applicable")
    with pytest.raises(PairRefused):
        _check_observed_phase({**record, "phase": "armed"}, result, "not-applicable")
    with pytest.raises(PairRefused):
        _classify_source(record, [1, 4], b"original", b"original", b"proposed")


@pytest.mark.parametrize("apt,phase,source,companion,restore,retain,allowed", [
    (True, "armed", "original", "absent", None, None, True),
    (True, "armed", "proposed", "upstream-only", None, None, False),
    (True, "restore-armed", "original", "cache-bearing", None, [1, 4], True),
    (True, "restore-armed", "proposed", "upstream-only", None, [1, 4], True),
    (True, "restore-armed", "proposed", "cache-bearing", [1, 5], [1, 4], False),
    (True, "restore-armed", "restored", "upstream-only", [1, 5], [1, 4], True),
    (True, "restored", "original", "upstream-only", None, [1, 4], True),
    (True, "restored", "original", "upstream-only", [1, 5], [1, 4], False),
    (False, "restore-armed", "proposed", "not-applicable", None, None, False),
    (False, "restore-armed", "proposed", "not-applicable", [1, 5], None, True),
    (False, "restored", "original", "not-applicable", None, None, True),
    (False, "restored", "restored", "not-applicable", [1, 2], None, False),
    (False, "restored", "original-or-restored", "not-applicable", [1, 1], None, True),
    (False, "installed", "proposed", "not-applicable", [1, 5], None, False),
])
def test_readback_only_accepts_reachable_journal_states(
        apt, phase, source, companion, restore, retain, allowed):
    record = {"phase": phase, "companion": "private" if apt else None,
              "original_id": [1, 1], "proposed_id": [1, 2],
              "mirror_id": [1, 3] if apt else None,
              "restore_id": restore, "retained_id": retain}
    if allowed:
        _check_observed_phase(record, source, companion)
    else:
        with pytest.raises(PairRefused):
            _check_observed_phase(record, source, companion)


def _modern_pair(root, manager):
    root.mkdir(mode=0o700)
    source, mirror, _, state = build(root, manager)
    approval = state / ("candidate-" + IDENT + ".json")
    record = json.loads(approval.read_text())
    observed = pair.pre.inspect_source(record["source"], root=root)
    record["schema"] = 2
    record["source_identity"] = {
        key: observed[key] for key in pair.boundary.SOURCE_IDENTITY_FIELDS}
    approval.write_text(json.dumps(record))
    return source, mirror


def _apply_modern_pair(root, manager, crash=None):
    if manager == "apt":
        return pair.apply_retaining_apt_companion_sandbox(
            root, IDENT, current_catalog=False, crash=crash)
    return pair.apply_sandbox(root, IDENT, crash=crash)


@pytest.mark.skipif(os.geteuid() != 0, reason="requires private root-owned fixture")
@pytest.mark.parametrize("manager,crash,source_stage,companion_stage", [
    ("apt", "armed", "recorded", "recorded"),
    ("apt", "companion", "recorded", "absent"),
    ("apt", "source", "absent", "absent"),
    ("dnf", "armed", "recorded", "not-applicable"),
    ("dnf", "source", "absent", "not-applicable"),
])
def test_readback_pins_initial_stages(tmp_path, manager, crash, source_stage, companion_stage):
    root = tmp_path / "fixture"
    _modern_pair(root, manager)
    with pytest.raises(pair.InjectedCrash):
        _apply_modern_pair(root, manager, crash)
    report = inspect_local_recovery_record(IDENT, _test_root=root)
    assert report["phase"] == "armed"
    assert (report["source_stage_state"], report["companion_stage_state"]) == (
        source_stage, companion_stage)
    assert not report["write_eligible"]


@pytest.mark.skipif(os.geteuid() != 0, reason="requires private root-owned fixture")
@pytest.mark.parametrize("manager,crash,source_stage,companion_stage", [
    ("apt", "retention-armed", "absent", "recorded"),
    ("apt", "companion-neutralized", "absent", "absent"),
    ("apt", "restore-armed", "recorded", "absent"),
    ("apt", "source-restored", "absent", "absent"),
    ("dnf", "restore-armed", "recorded", "not-applicable"),
    ("dnf", "source-restored", "absent", "not-applicable"),
])
def test_readback_pins_rollback_stages(tmp_path, manager, crash, source_stage, companion_stage):
    root = tmp_path / "fixture"
    _modern_pair(root, manager)
    _apply_modern_pair(root, manager)
    with pytest.raises(pair.InjectedCrash):
        pair.restore_sandbox(root, IDENT, crash=crash)
    report = inspect_local_recovery_record(IDENT, _test_root=root)
    assert report["phase"] == "restore-armed"
    assert (report["source_stage_state"], report["companion_stage_state"]) == (
        source_stage, companion_stage)
    assert not report["write_eligible"]


@pytest.mark.skipif(os.geteuid() != 0, reason="requires private root-owned fixture")
@pytest.mark.parametrize("manager,crash,resource", [
    ("apt", "retention-armed", "companion"),
    ("apt", "restore-armed", "source"),
    ("dnf", "restore-armed", "source"),
])
def test_readback_refuses_missing_and_foreign_required_stage(tmp_path, manager, crash, resource):
    root = tmp_path / "fixture"
    source, mirror = _modern_pair(root, manager)
    _apply_modern_pair(root, manager)
    with pytest.raises(pair.InjectedCrash):
        pair.restore_sandbox(root, IDENT, crash=crash)
    path = (mirror if resource == "companion" else source).with_name(
        ".repocache-atomic-" + IDENT)
    saved = path.with_name(".fixture-owned-stage")
    raw = path.read_bytes()
    mode = path.stat().st_mode & 0o777
    path.rename(saved)
    with pytest.raises(PairRefused, match="Required recovery stage missing"):
        inspect_local_recovery_record(IDENT, _test_root=root)
    assert saved.read_bytes() == raw and not path.exists()
    before = _private_file_snapshot(root)
    with pytest.raises(PairRefused, match="Required recovery stage missing"):
        pair.recover_sandbox(root, IDENT)
    assert _private_file_snapshot(root) == before
    path.write_bytes(raw)
    path.chmod(mode)
    foreign = path.stat()
    with pytest.raises(PairRefused, match="not a recorded inode"):
        inspect_local_recovery_record(IDENT, _test_root=root)
    assert path.stat().st_ino == foreign.st_ino and path.read_bytes() == raw
    assert saved.read_bytes() == raw
    before = _private_file_snapshot(root)
    with pytest.raises(PairRefused, match="not a recorded inode"):
        pair.recover_sandbox(root, IDENT)
    assert _private_file_snapshot(root) == before
    path.unlink()
    saved.rename(path)
    assert inspect_local_recovery_record(IDENT, _test_root=root)["journal_record_verified"]


@pytest.mark.skipif(os.geteuid() != 0, reason="requires private root-owned fixture")
@pytest.mark.parametrize("manager,restore", [("apt", False), ("apt", True),
                                            ("dnf", False), ("dnf", True)])
def test_readback_refuses_unexpected_stage_without_following_symlink(tmp_path, manager, restore):
    root = tmp_path / "fixture"
    source, _ = _modern_pair(root, manager)
    _apply_modern_pair(root, manager)
    if restore:
        pair.restore_sandbox(root, IDENT)
    path = source.with_name(".repocache-atomic-" + IDENT)
    target = root / "fixture-foreign"
    path.symlink_to(target)
    with pytest.raises(PairRefused, match="Unexpected recovery stage"):
        inspect_local_recovery_record(IDENT, _test_root=root)
    assert path.is_symlink() and path.readlink() == target and not target.exists()


def _private_file_snapshot(root):
    import stat
    result = {}
    for path in root.rglob("*"):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            continue
        result[str(path.relative_to(root))] = (
            info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest())
    return result


@pytest.mark.skipif(os.geteuid() != 0, reason="requires private root-owned fixture")
@pytest.mark.parametrize("manager,resource", [
    ("apt", "source-stage"), ("apt", "companion-stage"),
    ("apt", "companion"), ("dnf", "source-stage"),
])
def test_modern_apply_refuses_foreign_resources_before_any_staging(tmp_path, manager, resource):
    root = tmp_path / "fixture"
    source, mirror = _modern_pair(root, manager)
    foreign = (source if resource == "source-stage" else mirror)
    if resource.endswith("-stage"):
        foreign = foreign.with_name(".repocache-atomic-" + IDENT)
    foreign.write_bytes(b"foreign")
    foreign.chmod(0o644)
    before = _private_file_snapshot(root)
    with pytest.raises(PairRefused, match="Unexpected (recovery stage|existing mirror companion)"):
        _apply_modern_pair(root, manager)
    assert _private_file_snapshot(root) == before


@pytest.mark.skipif(os.geteuid() != 0, reason="requires private root-owned fixture")
@pytest.mark.parametrize("manager,operation", [
    ("apt", "retry"), ("apt", "restore"), ("apt", "recover-armed"),
    ("apt", "recover-restored"), ("dnf", "retry"), ("dnf", "restore"),
    ("dnf", "recover-armed"), ("dnf", "recover-restored"),
])
def test_modern_writer_checks_all_stages_before_any_recovery_write(tmp_path, manager, operation):
    root = tmp_path / "fixture"
    source, mirror = _modern_pair(root, manager)
    if operation == "recover-armed":
        with pytest.raises(pair.InjectedCrash):
            _apply_modern_pair(root, manager, "source")
    else:
        _apply_modern_pair(root, manager)
        if operation == "recover-restored":
            pair.restore_sandbox(root, IDENT)
    foreign = source.with_name(".repocache-atomic-" + IDENT)
    foreign.write_bytes(b"foreign stage")
    foreign.chmod(0o644)
    before = _private_file_snapshot(root)
    with pytest.raises(PairRefused, match="Unexpected recovery stage"):
        if operation == "retry":
            _apply_modern_pair(root, manager)
        elif operation == "restore":
            pair.restore_sandbox(root, IDENT)
        else:
            pair.recover_sandbox(root, IDENT)
    assert _private_file_snapshot(root) == before
