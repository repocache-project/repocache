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
    assert report["phase"] == "restored" and report["source_state"] == "restored"
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
              "retained_id": [1, 2]}
    with pytest.raises(PairRefused):
        _check_observed_phase(record, source, companion)


def test_nonroot_readback_refused_before_inspection(monkeypatch):
    monkeypatch.setattr(os, "getresuid", lambda: (1000, 0, 0))
    with pytest.raises(PairRefused, match="requires root"):
        inspect_local_recovery_record(IDENT)
