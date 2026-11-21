"""End-to-end offline #95 proposals handed to native v2 fixed staging data.

No signed approval or installed worker is implied by these disposable tests.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from repocache.server_install_v1 import validate_install_document
from repocache.server_locked_manifest_reconcile_v1 import (
    preview_proposed_v2_state_transition,
)
from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_repository_reconcile_v1 import (
    render_fixed_native_repository_batch_envelope,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/prepare_server_repository_lifecycle.py"
EXAMPLE = ROOT / "docs/examples/server-install-v1.json"
DECISION = "a" * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def initial():
    document = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    document["expected_state_generation"] = 1
    document["repositories"][1]["id"] = "almalinux-baseos"
    document = validate_install_document(document, for_apply=True)
    encoded = canonical(document)
    digest = hashlib.sha256(encoded).hexdigest()
    records = [{
        "id": item["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(item).encode("utf-8"),
        ).hexdigest(),
        "desired_state": item["desired_state"],
        "observed_state": "not-activated",
    } for item in document["repositories"]]
    return {
        "state_schema_version": 2,
        "state_generation": 1,
        "configuration_base64": base64.b64encode(encoded).decode("ascii"),
        "configuration_sha256": digest,
        "repository_records": records,
        "id_reservations": [{
            "id": row["id"],
            "canonical_identity_sha256": row["canonical_identity_sha256"],
            "status": "allocated",
        } for row in records],
        "approval_reference": {
            "source": "operator",
            "decision_sha256": DECISION,
            "configuration_sha256": digest,
            "expected_generation": 0,
        },
    }


def private_file(path, data):
    if isinstance(data, (dict, list)):
        data = canonical(data)
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def invoke(previous, request, output, *, generation=1, digest=None,
           decision=DECISION):
    actual = previous.read_bytes()
    return subprocess.run(
        [sys.executable, str(SCRIPT),
         "--previous-v2-state", str(previous),
         "--request", str(request),
         "--proposal-output", str(output),
         "--expected-generation", str(generation),
         "--expected-state-sha256",
         hashlib.sha256(actual).hexdigest() if digest is None else digest,
         "--decision-sha256", decision],
        cwd=ROOT, text=True, capture_output=True, check=False, timeout=20,
    )


def prepared(tmp_path):
    previous = private_file(tmp_path / "prior.json", initial())
    assert stat.S_IMODE(tmp_path.stat().st_mode) & 0o022 == 0
    return previous, tmp_path / "request.json", tmp_path / "next.json"


def test_offline_enable_generates_exact_native_staging_state(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {
        "operation": "enable",
        "repository_ids": ["debian-trixie-main", "almalinux-baseos"],
    })
    before = previous.read_bytes()
    run = invoke(previous, request, output)
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["status"] == "OFFLINE_LIFECYCLE_PROPOSAL_PREPARED"
    assert report["authorizes_service_activation"] is False
    assert report["requires_operator_review"] is True
    assert report["state_generation"] == 2
    assert report["expected_state_sha256"] == hashlib.sha256(before).hexdigest()
    assert report["proposed_state_sha256"] == hashlib.sha256(
        output.read_bytes(),
    ).hexdigest()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert previous.read_bytes() == before
    assert not list(tmp_path.glob(".*.part-*"))
    snapshot = json.loads(output.read_bytes())
    preview_proposed_v2_state_transition(
        snapshot, expected_generation=1, previous_snapshot=initial(),
    )
    assert {item["desired_state"] for item in snapshot["repository_records"]} == {
        "active",
    }
    exact = render_fixed_native_repository_batch_envelope(
        before, expected_generation=1,
        expected_previous_state_sha256=hashlib.sha256(before).hexdigest(),
        operation="enable", repository_ids=(
            "debian-trixie-main", "almalinux-baseos",
        ), decision_sha256=DECISION,
    )
    wire = json.loads(exact["envelope_bytes"])
    assert output.read_bytes() == base64.b64decode(wire["next_state_base64"])
    # The same canonical snapshot is what the separate reviewed
    # native #237 authenticated stager accepts as its INPUT, not authority.


def test_offline_noop_never_creates_candidate(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {"operation": "disable",
                           "repository_ids": ["debian-trixie-main"]})
    old = previous.read_bytes()
    first = invoke(previous, request, output)
    second = invoke(previous, request, output)
    assert first.returncode == second.returncode == 0
    assert json.loads(first.stdout)["status"] == "OFFLINE_LIFECYCLE_NO_CHANGE"
    assert not output.exists()
    assert previous.read_bytes() == old


def test_offline_remove_retains_historical_reservations(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {"operation": "remove", "all_repositories": True})
    run = invoke(previous, request, output)
    assert run.returncode == 0
    snapshot = json.loads(output.read_bytes())
    assert snapshot["repository_records"] == []
    assert len(snapshot["id_reservations"]) == 2
    assert all(row["status"] == "retired" for row in snapshot["id_reservations"])
    assert initial()["id_reservations"][0]["id"] in {
        row["id"] for row in snapshot["id_reservations"]
    }


def test_offline_add_generates_durable_automatic_id_candidate(tmp_path):
    previous, request, output = prepared(tmp_path)
    repo = copy.deepcopy(json.loads(EXAMPLE.read_text())["repositories"][0])
    repo.pop("id")
    repo["upstream"]["base_url"] = "https://newmirror.example.invalid/debian/"
    repo["upstream"]["allowed_hosts"] = ["newmirror.example.invalid"]
    private_file(request, {"operation": "add", "proposed_repositories": [repo]})
    run = invoke(previous, request, output)
    assert run.returncode == 0, run.stderr
    next_state = json.loads(output.read_bytes())
    assert len(next_state["repository_records"]) == 3
    generated = set(row["id"] for row in next_state["repository_records"]) - {
        row["id"] for row in initial()["repository_records"]
    }
    assert len(generated) == 1
    assert next(iter(generated)).startswith("repo-")
    assert len(next_state["id_reservations"]) == 3


@pytest.mark.parametrize("bad", [
    {"operation": "enable", "repository_ids": ["../../etc/passwd"]},
    {"operation": "enable", "repository_ids": [
        "debian-trixie-main", "debian-trixie-main",
    ]},
    {"operation": "remove"},
    {"operation": "remove", "repository_ids": ["debian-trixie-main"],
     "all_repositories": True},
    {"operation": "add", "repository_ids": ["debian-trixie-main"]},
    {"operation": "disable", "repository_ids": ["debian-trixie-main"],
     "extra": "not-whitelisted"},
])
def test_offline_invalid_operation_never_creates_output(tmp_path, bad):
    previous, request, output = prepared(tmp_path)
    private_file(request, bad)
    run = invoke(previous, request, output)
    assert run.returncode == 1
    assert run.stdout.strip() == '{"status":"OFFLINE_LIFECYCLE_REFUSED"}'
    assert not output.exists()


def test_offline_refuses_forged_predecessor_and_does_not_touch_existing_output(
    tmp_path,
):
    previous, request, output = prepared(tmp_path)
    private_file(request, {"operation": "remove", "all_repositories": True})
    private_file(output, b"foreign-proposal")
    original = output.read_bytes()
    bad_hash = invoke(previous, request, output, digest="f" * 64)
    assert bad_hash.returncode == 1
    assert output.read_bytes() == original
    collision = invoke(previous, request, output)
    assert collision.returncode == 1
    assert output.read_bytes() == original
    assert not list(tmp_path.glob(".*.part-*"))


def test_offline_refuses_symlink_hardlink_and_world_readable_inputs(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {"operation": "remove", "all_repositories": True})
    surrogate = tmp_path / "link.json"
    surrogate.symlink_to(previous)
    assert invoke(surrogate, request, output).returncode == 1
    assert not output.exists()

    sibling = tmp_path / "hardlink.json"
    os.link(previous, sibling)
    assert invoke(previous, request, output).returncode == 1
    sibling.unlink()
    request.chmod(0o644)
    assert invoke(previous, request, output).returncode == 1
    assert not output.exists()


@pytest.mark.parametrize("invalid_json", [
    b'{"operation":"remove","operation":"enable","all_repositories":true}',
    b'{"operation":"remove","all_repositories":NaN}',
    b'{"operation":',
])
def test_offline_refuses_noncanonical_or_ambiguous_request(tmp_path, invalid_json):
    previous, request, output = prepared(tmp_path)
    private_file(request, invalid_json)
    run = invoke(previous, request, output)
    assert run.returncode == 1
    assert run.stdout.strip() == '{"status":"OFFLINE_LIFECYCLE_REFUSED"}'
    assert not output.exists()
