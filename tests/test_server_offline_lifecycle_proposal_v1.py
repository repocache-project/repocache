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
           decision=DECISION, dry_run=False, proposed_sha=None):
    actual = previous.read_bytes()
    args = [sys.executable, str(SCRIPT),
            "--previous-v2-state", str(previous),
            "--request", str(request),
            "--expected-generation", str(generation),
            "--expected-state-sha256",
            hashlib.sha256(actual).hexdigest() if digest is None else digest,
            "--decision-sha256", decision]
    if dry_run:
        args.append("--dry-run")
    else:
        args.extend(["--proposal-output", str(output)])
    if proposed_sha is not None:
        args.extend(["--expected-proposed-state-sha256", proposed_sha])
    return subprocess.run(
        args, cwd=ROOT, text=True, capture_output=True,
        check=False, timeout=20,
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


@pytest.mark.parametrize("operation,request_body", [
    ("enable", {"operation": "enable", "repository_ids": ["debian-trixie-main"]}),
    ("remove", {"operation": "remove", "all_repositories": True}),
])
def test_offline_dry_run_reviews_exact_proposal_without_writing(
    tmp_path, operation, request_body,
):
    previous, request, output = prepared(tmp_path)
    private_file(request, request_body)
    prior = previous.read_bytes()
    preview = invoke(previous, request, output, dry_run=True)
    assert preview.returncode == 0, preview.stderr
    report = json.loads(preview.stdout)
    assert report["status"] == "OFFLINE_LIFECYCLE_PREVIEW"
    assert report["changed"] is True
    assert report["proposal_written"] is False
    assert report["requires_operator_review"] is True
    assert report["authorizes_service_activation"] is False
    assert all(set(row) <= {"repository_id", "result", "id_assignment"}
               for row in report["per_repository"])
    assert report["per_repository"]
    assert not output.exists()
    assert previous.read_bytes() == prior
    assert not list(tmp_path.glob(".*.part-*"))

    prepare = invoke(previous, request, output)
    assert prepare.returncode == 0
    committed_report = json.loads(prepare.stdout)
    assert committed_report["proposal_written"] is True
    assert committed_report["per_repository"] == report["per_repository"]
    assert committed_report["proposed_state_sha256"] == report["proposed_state_sha256"]
    assert committed_report["proposed_state_sha256"] == hashlib.sha256(
        output.read_bytes()
    ).hexdigest()


def test_offline_dry_run_auto_id_is_stable_and_does_not_write(tmp_path):
    previous, request, output = prepared(tmp_path)
    repo = copy.deepcopy(json.loads(EXAMPLE.read_text())["repositories"][0])
    repo.pop("id")
    repo["upstream"]["base_url"] = "https://newmirror.example.invalid/debian/"
    repo["upstream"]["allowed_hosts"] = ["newmirror.example.invalid"]
    private_file(request, {"operation": "add", "proposed_repositories": [repo]})
    review = invoke(previous, request, output, dry_run=True)
    assert review.returncode == 0
    data = json.loads(review.stdout)
    assert data["per_repository"][0]["id_assignment"] == "AUTO_SUGGESTED"
    assert data["per_repository"][0]["repository_id"].startswith("repo-")
    assert not output.exists()
    next_run = invoke(previous, request, output)
    assert next_run.returncode == 0
    assert data["per_repository"] == json.loads(next_run.stdout)["per_repository"]
    assert data["proposed_state_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()


def test_offline_dry_run_noop_is_nonmutating_and_redacted(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {"operation": "disable",
                           "repository_ids": ["debian-trixie-main"]})
    preview = invoke(previous, request, output, dry_run=True)
    assert preview.returncode == 0
    report = json.loads(preview.stdout)
    assert report["status"] == "OFFLINE_LIFECYCLE_NO_CHANGE"
    assert report["proposal_written"] is False
    assert report["changed"] is False
    assert not output.exists()


def test_offline_refuses_ambiguous_preview_output_and_missing_output(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {"operation": "remove", "all_repositories": True})
    base_args = [sys.executable, str(SCRIPT),
                 "--previous-v2-state", str(previous),
                 "--request", str(request),
                 "--expected-generation", "1",
                 "--expected-state-sha256", hashlib.sha256(previous.read_bytes()).hexdigest(),
                 "--decision-sha256", DECISION]
    for args in (base_args, base_args + ["--dry-run", "--proposal-output", str(output)]):
        run = subprocess.run(args, cwd=ROOT, text=True, capture_output=True,
                             check=False, timeout=20)
        assert run.returncode == 1
        assert json.loads(run.stdout)["status"] == "OFFLINE_LIFECYCLE_REFUSED"
        assert not output.exists()


@pytest.mark.parametrize("reviewed_request", [
    {"operation": "enable", "repository_ids": ["debian-trixie-main"]},
    {"operation": "remove", "all_repositories": True},
])
def test_reviewed_sha_binds_preview_to_exact_created_state(
    tmp_path, reviewed_request,
):
    previous, request, output = prepared(tmp_path)
    private_file(request, reviewed_request)
    preview = invoke(previous, request, output, dry_run=True)
    assert preview.returncode == 0, preview.stderr
    approved_digest = json.loads(preview.stdout)["proposed_state_sha256"]
    assert not output.exists()

    run = invoke(previous, request, output, proposed_sha=approved_digest)
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["review_digest_precondition_checked"] is True
    assert report["proposed_state_sha256"] == approved_digest
    assert hashlib.sha256(output.read_bytes()).hexdigest() == approved_digest
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert report["authorizes_service_activation"] is False


def test_changed_request_after_review_cannot_write_unreviewed_proposal(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {
        "operation": "enable", "repository_ids": ["debian-trixie-main"],
    })
    preview = invoke(previous, request, output, dry_run=True)
    assert preview.returncode == 0
    pinned = json.loads(preview.stdout)["proposed_state_sha256"]
    before = previous.read_bytes()

    # Both operations are valid and would write a different next state if
    # the caller silently omitted the reviewed-digest condition.
    private_file(request, {"operation": "remove", "all_repositories": True})
    run = invoke(previous, request, output, proposed_sha=pinned)
    assert run.returncode == 1
    assert json.loads(run.stdout) == {"status": "OFFLINE_LIFECYCLE_REFUSED"}
    assert not output.exists()
    assert previous.read_bytes() == before
    assert not list(tmp_path.glob(".*.part-*"))

    private_file(request, {
        "operation": "enable", "repository_ids": ["debian-trixie-main"],
    })
    matching = invoke(previous, request, output, proposed_sha=pinned)
    assert matching.returncode == 0
    assert hashlib.sha256(output.read_bytes()).hexdigest() == pinned
    # A prior exact file is never overwritten by a subsequent bad pin.
    preserved = output.read_bytes()
    mismatch = invoke(previous, request, output, proposed_sha="f" * 64)
    assert mismatch.returncode == 1
    assert output.read_bytes() == preserved


@pytest.mark.parametrize("bad_sha", ["", "Z" * 64, "f" * 63, "0" * 65])
def test_invalid_expected_proposal_sha_refused_before_write(tmp_path, bad_sha):
    previous, request, output = prepared(tmp_path)
    private_file(request, {"operation": "remove", "all_repositories": True})
    run = invoke(previous, request, output, proposed_sha=bad_sha)
    assert run.returncode == 1
    assert json.loads(run.stdout) == {"status": "OFFLINE_LIFECYCLE_REFUSED"}
    assert not output.exists()


def test_review_sha_pin_refuses_noop_and_preview_combination(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {
        "operation": "disable", "repository_ids": ["debian-trixie-main"],
    })
    noop = invoke(previous, request, output, proposed_sha="a" * 64)
    assert noop.returncode == 1
    assert not output.exists()
    private_file(request, {"operation": "remove", "all_repositories": True})
    ambiguous = invoke(
        previous, request, output, proposed_sha="a" * 64, dry_run=True,
    )
    assert ambiguous.returncode == 1
    assert not output.exists()


def test_offline_mixed_states_one_reviewed_generation_exact_native_input(tmp_path):
    previous, request, output = prepared(tmp_path)
    initial_bytes = previous.read_bytes()
    initial_sha = hashlib.sha256(initial_bytes).hexdigest()
    enabled = render_fixed_native_repository_batch_envelope(
        initial_bytes, expected_generation=1,
        expected_previous_state_sha256=initial_sha, operation="enable",
        repository_ids=("debian-trixie-main",), decision_sha256=DECISION,
    )
    previous.write_bytes(base64.b64decode(
        json.loads(enabled["envelope_bytes"])["next_state_base64"],
        validate=True,
    ))
    original = previous.read_bytes()
    assert json.loads(original)["state_generation"] == 2
    changes = [
        {"repository_id": "debian-trixie-main", "desired_state": "disabled"},
        {"repository_id": "almalinux-baseos", "desired_state": "active"},
    ]
    private_file(request, {"operation": "set-states", "state_changes": changes})
    preview = invoke(previous, request, None, generation=2, dry_run=True)
    assert preview.returncode == 0, preview.stderr
    details = json.loads(preview.stdout)
    assert details["status"] == "OFFLINE_LIFECYCLE_PREVIEW"
    assert details["requires_operator_review"] is True
    assert details["authorizes_service_activation"] is False
    assert not output.exists()
    result = invoke(
        previous, request, output, generation=2,
        proposed_sha=details["proposed_state_sha256"],
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "OFFLINE_LIFECYCLE_PROPOSAL_PREPARED"
    assert report["review_digest_precondition_checked"] is True
    assert report["state_generation"] == 3
    assert report["per_repository"] == [
        {"repository_id": "debian-trixie-main",
         "result": "STATE_CHANGE_CANDIDATE"},
        {"repository_id": "almalinux-baseos",
         "result": "STATE_CHANGE_CANDIDATE"},
    ]
    assert report["proposed_state_sha256"] == hashlib.sha256(
        output.read_bytes(),
    ).hexdigest()
    assert previous.read_bytes() == original
    after = json.loads(output.read_bytes())
    assert after["state_generation"] == 3
    assert [(r["id"], r["desired_state"])
            for r in after["repository_records"]] == [
        ("debian-trixie-main", "disabled"), ("almalinux-baseos", "active"),
    ]
    assert after["id_reservations"] == initial()["id_reservations"]
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".*.part-*"))
    exact = render_fixed_native_repository_batch_envelope(
        original, expected_generation=2,
        expected_previous_state_sha256=hashlib.sha256(original).hexdigest(),
        operation="set-states",
        state_changes=(
            ("debian-trixie-main", "disabled"),
            ("almalinux-baseos", "active"),
        ),
        decision_sha256=DECISION,
    )
    assert output.read_bytes() == base64.b64decode(
        json.loads(exact["envelope_bytes"])["next_state_base64"],
        validate=True,
    )
    # The offline result is source-only data; only the installed worker
    # can independently authenticate, stage and actually apply these bytes.


def test_offline_mixed_states_idempotent_noop_has_no_candidate(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {
        "operation": "set-states",
        "state_changes": [
            {"repository_id": "debian-trixie-main", "desired_state": "disabled"},
            {"repository_id": "almalinux-baseos", "desired_state": "disabled"},
        ],
    })
    before = previous.read_bytes()
    for _ in range(2):
        completed = invoke(previous, request, output)
        assert completed.returncode == 0
        report = json.loads(completed.stdout)
        assert report["status"] == "OFFLINE_LIFECYCLE_NO_CHANGE"
        assert report["proposal_written"] is False
    assert previous.read_bytes() == before and not output.exists()


@pytest.mark.parametrize("bad", [
    {"operation": "set-states"},
    {"operation": "set-states", "state_changes": []},
    {"operation": "set-states", "state_changes": "malicious"},
    {"operation": "set-states", "repository_ids": ["debian-trixie-main"],
     "state_changes": [{"repository_id": "almalinux-baseos", "desired_state": "active"}]},
    {"operation": "set-states", "all_repositories": True,
     "state_changes": [{"repository_id": "almalinux-baseos", "desired_state": "active"}]},
    {"operation": "set-states", "proposed_repositories": [{"id": "x"}],
     "state_changes": [{"repository_id": "almalinux-baseos", "desired_state": "active"}]},
    {"operation": "set-states", "state_changes": [
        {"repository_id": "debian-trixie-main", "desired_state": "active"},
        {"repository_id": "debian-trixie-main", "desired_state": "disabled"},
    ]},
    {"operation": "set-states", "state_changes": [
        {"repository_id": "debian-trixie-main", "desired_state": "active"},
        {"repository_id": "nonexistent-repository", "desired_state": "disabled"},
    ]},
    {"operation": "set-states", "state_changes": [
        {"repository_id": "../etc/passwd", "desired_state": "active"},
    ]},
    {"operation": "set-states", "state_changes": [
        {"repository_id": "debian-trixie-main", "desired_state": True},
    ]},
    {"operation": "set-states", "state_changes": [
        {"repository_id": "debian-trixie-main", "desired_state": "approved"},
    ]},
    {"operation": "set-states", "state_changes": [
        {"repository_id": "debian-trixie-main", "desired_state": "active", "extra": True},
    ]},
    {"operation": "set-states", "state_changes": [
        {"repository_id": "debian-trixie-main", "desired_state": "active"},
    ] * 65},
    {"operation": "enable", "repository_ids": ["debian-trixie-main"],
     "state_changes": []},
])
def test_offline_mixed_state_invalid_request_refuses_without_output(tmp_path, bad):
    previous, request, output = prepared(tmp_path)
    private_file(request, bad)
    before = previous.read_bytes()
    refused = invoke(previous, request, output)
    assert refused.returncode == 1
    assert json.loads(refused.stdout) == {"status": "OFFLINE_LIFECYCLE_REFUSED"}
    assert not output.exists() and previous.read_bytes() == before
    assert not list(tmp_path.glob(".*.part-*"))


def test_offline_mixed_review_digest_pin_rejects_stale_candidate(tmp_path):
    previous, request, output = prepared(tmp_path)
    private_file(request, {
        "operation": "set-states",
        "state_changes": [
            {"repository_id": "debian-trixie-main", "desired_state": "active"},
            {"repository_id": "almalinux-baseos", "desired_state": "disabled"},
        ],
    })
    preview = invoke(previous, request, None, dry_run=True)
    assert preview.returncode == 0
    pinned = json.loads(preview.stdout)["proposed_state_sha256"]
    request.write_bytes(canonical({
        "operation": "set-states", "state_changes": [
            {"repository_id": "debian-trixie-main", "desired_state": "disabled"},
            {"repository_id": "almalinux-baseos", "desired_state": "active"},
        ],
    }))
    before = previous.read_bytes()
    refused = invoke(previous, request, output, proposed_sha=pinned)
    assert refused.returncode == 1
    assert json.loads(refused.stdout) == {"status": "OFFLINE_LIFECYCLE_REFUSED"}
    assert not output.exists() and previous.read_bytes() == before
