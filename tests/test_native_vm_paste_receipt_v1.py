"""Copy/paste VM identity receipt must never leak inputs or assert GO."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/format_native_vm_paste_receipt.py"


def sample():
    return {
        "schema_version": 1, "status": "NOT VERIFIED",
        "code": "DIGEST_MATCH_NATIVE_EVIDENCE_PENDING",
        "source_commit_sha": "a" * 40,
        "expected_artifact_sha256": "b" * 64,
        "observed_artifact_sha256": "b" * 64,
        "artifact_size_bytes": 42,
        "artifact_digest_matched": True,
        "native_prerequisites_observed": False,
        "native_probe_code": "CONTAINER_CONTEXT_REFUSED",
        "complete_server_acceptance_passed": False,
        "authorizes_host_write": False,
        "authorizes_publication": False,
    }


def run(blob):
    process = subprocess.run([sys.executable, "-B", str(SCRIPT)],
                             input=blob, capture_output=True, check=False)
    assert process.stderr == b""
    assert len(process.stdout.splitlines()) == 1
    prefix = b"REPOCACHE_VM_EVIDENCE_V1="
    assert process.stdout.startswith(prefix)
    return process.returncode, json.loads(process.stdout[len(prefix):])


def test_paste_line_is_compact_redacted_and_non_authorizing():
    value = sample()
    value["hidden_token"] = "PRIVATE_EXAMPLE_VALUE"
    code, result = run(json.dumps(value).encode())
    assert code == 2
    assert result == {
        "kind": "repocache.native.candidate.paste.v1",
        "status": "NOT VERIFIED",
        "code": "DIGEST_MATCH_NATIVE_EVIDENCE_PENDING",
        "source_sha": "a" * 40, "candidate_sha256": "b" * 64,
        "digest_matched": True, "native_prerequisites_reported_only": False,
        "complete_server_acceptance_passed": False,
        "authorizes_host_write": False, "authorizes_publication": False,
    }
    assert "PRIVATE_EXAMPLE_VALUE" not in str(result)


def test_readonly_prerequisite_report_is_not_release_pass():
    value = sample()
    value.update(code="DIGEST_MATCH_NATIVE_READONLY_OBSERVED",
                 native_probe_code="OBSERVATION_ONLY_NO_HOST_AUTHORITY",
                 native_prerequisites_observed=True)
    code, result = run(json.dumps(value).encode())
    assert code == 2
    assert result["native_prerequisites_reported_only"] is True
    assert result["status"] == "NOT VERIFIED"
    assert result["complete_server_acceptance_passed"] is False


def test_exact_digest_mismatch_remains_failure():
    value = sample()
    value.update(status="FAIL", code="CANDIDATE_DIGEST_MISMATCH",
                 observed_artifact_sha256="c" * 64,
                 artifact_digest_matched=False)
    code, result = run(json.dumps(value).encode())
    assert code == 1
    assert result["status"] == "FAIL"
    assert not result["digest_matched"]


@pytest.mark.parametrize("corruption", [
    "native-pass", "claimed-authority", "digest-contradiction",
    "unknown-code", "unknown-type", "oversized",
])
def test_untrusted_or_contradictory_receipts_fail_closed(corruption):
    value = sample()
    if corruption == "native-pass":
        value["status"] = "PASS"
    elif corruption == "claimed-authority":
        value["authorizes_host_write"] = True
    elif corruption == "digest-contradiction":
        value["observed_artifact_sha256"] = "c" * 64
    elif corruption == "unknown-code":
        value["native_probe_code"] = "PRIVATE_EXAMPLE_VALUE"
    elif corruption == "unknown-type":
        value["native_prerequisites_observed"] = 1
    else:
        payload = b"x" * (16 * 1024 + 1)
        code, result = run(payload)
        assert code == 2 and result["code"] == "INPUT_REFUSED"
        return
    code, result = run(json.dumps(value).encode())
    assert code == 2
    assert result["code"] == "INPUT_REFUSED"
    assert "PRIVATE_EXAMPLE_VALUE" not in str(result)


def test_duplicate_json_keys_and_malformed_utf8_are_refused():
    for data in (b'{"status":"FAIL","status":"NOT VERIFIED"}', b"\xff"):
        code, result = run(data)
        assert code == 2
        assert result["code"] == "INPUT_REFUSED"


@pytest.mark.parametrize("mutation", [
    {"code": "CANDIDATE_UNAVAILABLE"},
    {"code": "CANDIDATE_DIGEST_MISMATCH"},
    {"code": "DIGEST_MATCH_NATIVE_READONLY_OBSERVED"},
    {"code": "CANDIDATE_INODE_REFUSED", "artifact_digest_matched": False},
    {"native_prerequisites_observed": True},
    {"publisher_signature_verified": True},
    {"authorizes_nginx_reload": 1},
])
def test_forged_receipt_outcome_or_claim_cannot_look_like_evidence(mutation):
    value = sample()
    value.update(mutation)
    exit_code, output = run(json.dumps(value).encode())
    assert exit_code == 2
    assert output["code"] == "INPUT_REFUSED"
    assert output["complete_server_acceptance_passed"] is False


def test_unavailable_candidate_has_no_digest_or_native_claim():
    value = sample()
    value.update(
        code="CANDIDATE_UNAVAILABLE", expected_artifact_sha256="b" * 64,
        observed_artifact_sha256=None, artifact_size_bytes=None,
        artifact_digest_matched=False,
        native_probe_code="NATIVE_OBSERVATION_NOT_EXECUTED",
    )
    code, output = run(json.dumps(value).encode())
    assert code == 2
    assert output["code"] == "CANDIDATE_UNAVAILABLE"
    assert output["digest_matched"] is False
    assert output["candidate_sha256"] is None
