"""Read-only final VM candidate receipt tests: no false PASS/authority."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from repocache import native_acceptance_evidence_v1 as receipt

SOURCE_SHA = "a" * 40


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def candidate(tmp_path: Path, data: bytes = b"immutable candidate bytes"):
    path = tmp_path / "candidate.tar.gz"
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def test_exact_hash_match_never_certifies_native_vm(tmp_path):
    data = b"candidate bytes"
    path = candidate(tmp_path, data)
    output = receipt.collect_candidate_evidence(
        path, digest(data), SOURCE_SHA,
        native_probe=lambda: {
            "status": "NOT VERIFIED", "code": "CONTAINER_CONTEXT_REFUSED",
            "systemd_pid1_namespace_shape_observed": False,
            "effective_nginx_master_observed": False,
        })
    assert output["observed_artifact_sha256"] == digest(data)
    assert output["artifact_digest_matched"] is True
    assert output["artifact_size_bytes"] == len(data)
    assert output["status"] == "NOT VERIFIED"
    assert output["native_probe_code"] == "CONTAINER_CONTEXT_REFUSED"
    assert output["native_prerequisites_observed"] is False
    assert output["code"] == "DIGEST_MATCH_NATIVE_EVIDENCE_PENDING"
    assert all(output[k] is False for k in output
               if k.startswith("authorizes_") or k.endswith("_verified")
               or k == "complete_server_acceptance_passed")


def test_forged_positive_probe_cannot_grant_release_or_install(tmp_path):
    path = candidate(tmp_path)
    raw = path.read_bytes()
    proof = receipt.collect_candidate_evidence(
        path, digest(raw), SOURCE_SHA,
        native_probe=lambda: {
            "status": "READ_ONLY_PREREQUISITES_OBSERVED",
            "code": "OBSERVATION_ONLY_NO_HOST_AUTHORITY",
            "systemd_pid1_namespace_shape_observed": True,
            "effective_nginx_master_observed": True,
            "publisher_signature_verified": True,
            "complete_server_acceptance_passed": True,
            "authorizes_host_write": True, "authorizes_publication": True,
        })
    assert proof["native_prerequisites_observed"]
    assert proof["status"] == "NOT VERIFIED"
    assert proof["code"] == "DIGEST_MATCH_NATIVE_READONLY_OBSERVED"
    assert proof["publisher_signature_verified"] is False
    assert proof["complete_server_acceptance_passed"] is False
    assert proof["authorizes_host_write"] is False
    assert proof["authorizes_publication"] is False


def test_hash_mismatch_blocks_before_native_probe(tmp_path):
    path = candidate(tmp_path)
    def forbidden():
        pytest.fail("Never examine native host after wrong candidate")
    output = receipt.collect_candidate_evidence(
        path, "0" * 64, SOURCE_SHA, native_probe=forbidden)
    assert output["status"] == "FAIL"
    assert output["code"] == "CANDIDATE_DIGEST_MISMATCH"
    assert output["artifact_digest_matched"] is False
    assert not output["native_prerequisites_observed"]


def test_native_probe_exceptions_cannot_invent_positive(tmp_path):
    path = candidate(tmp_path)
    def broken():
        raise OSError("private information must not appear in JSON")
    output = receipt.collect_candidate_evidence(
        path, digest(path.read_bytes()), SOURCE_SHA, native_probe=broken)
    assert output["status"] == "NOT VERIFIED"
    assert output["native_probe_code"] == "NATIVE_OBSERVATION_NOT_EXECUTED"
    assert "private" not in str(output)


@pytest.mark.parametrize("bad_source,bad_hash", [
    ("A" * 40, "0" * 64),
    ("a" * 39, "0" * 64),
    (SOURCE_SHA, "a" * 63),
    (SOURCE_SHA, "G" * 64),
    ("../unsafe", "0" * 64),
    (SOURCE_SHA, None),
])
def test_invalid_revision_or_expected_hash_refused(tmp_path, bad_source, bad_hash):
    path = candidate(tmp_path)
    with pytest.raises(receipt.CandidateRefused):
        receipt.collect_candidate_evidence(path, bad_hash, bad_source)


def test_symlink_leaf_and_parent_refused(tmp_path):
    real = candidate(tmp_path)
    alias = tmp_path / "alias.tar.gz"
    alias.symlink_to(real)
    for path in (alias, tmp_path / "linkdir" / real.name):
        if path.parent != tmp_path:
            path.parent.symlink_to(tmp_path, target_is_directory=True)
        result = receipt.collect_candidate_evidence(
            path, digest(real.read_bytes()), SOURCE_SHA)
        assert result["status"] == "NOT VERIFIED"
        assert result["artifact_digest_matched"] is False
        assert result["code"] in ("CANDIDATE_UNAVAILABLE", "CANDIDATE_INODE_REFUSED")


def test_hardlink_and_group_writable_candidate_refused(tmp_path):
    path = candidate(tmp_path)
    alias = tmp_path / "alias"
    os.link(path, alias)
    proof = receipt.collect_candidate_evidence(
        path, digest(path.read_bytes()), SOURCE_SHA)
    assert proof["code"] == "CANDIDATE_INODE_REFUSED"
    alias.unlink()
    path.chmod(0o662)
    assert receipt.collect_candidate_evidence(
        path, digest(path.read_bytes()), SOURCE_SHA)["code"] == "CANDIDATE_INODE_REFUSED"


def test_empty_and_sparse_oversized_file_refused(tmp_path):
    path = candidate(tmp_path, b"")
    result = receipt.collect_candidate_evidence(path, digest(b""), SOURCE_SHA)
    assert result["code"] == "CANDIDATE_INODE_REFUSED"
    with path.open("wb") as stream:
        stream.truncate(receipt.MAX_CANDIDATE_BYTES + 1)
    result = receipt.collect_candidate_evidence(path, digest(b""), SOURCE_SHA)
    assert result["code"] == "CANDIDATE_INODE_REFUSED"


def test_negative_path_and_nonexistent_candidate_never_authorize(tmp_path):
    for path in (Path("/"), tmp_path / "missing", Path("../private")):
        data = receipt.collect_candidate_evidence(
            path, digest(b"x"), SOURCE_SHA)
        assert not data["artifact_digest_matched"]
        assert data["status"] == "NOT VERIFIED"
        assert not data["complete_server_acceptance_passed"]


def test_public_receipt_contains_no_untrusted_filename(tmp_path):
    path = tmp_path / "secret-token-would-be-untrusted.tar"
    path.write_bytes(b"x")
    path.chmod(0o600)
    proof = receipt.collect_candidate_evidence(
        path, digest(b"x"), SOURCE_SHA, native_probe=lambda: {
            "code": "evil/path/private", "status": "READ_ONLY_PREREQUISITES_OBSERVED",
        })
    assert "secret-token" not in str(proof)
    assert "evil" not in str(proof)
    assert proof["native_probe_code"] == "NATIVE_OBSERVATION_NOT_EXECUTED"


@pytest.mark.parametrize("code", [
    "CONTAINER_CONTEXT_REFUSED", "EFFECTIVE_NGINX_NOT_OBSERVED",
    "SYSTEMD_PID1_NOT_OBSERVED", "CANDIDATE_UNAVAILABLE",
])
def test_contradictory_native_probe_code_never_reports_observed_prerequisites(
    tmp_path, code,
):
    path = candidate(tmp_path)
    actual = digest(path.read_bytes())
    result = receipt.collect_candidate_evidence(
        path, actual, SOURCE_SHA, native_probe=lambda: {
            "status": "READ_ONLY_PREREQUISITES_OBSERVED",
            "code": code,
            "systemd_pid1_namespace_shape_observed": True,
            "effective_nginx_master_observed": True,
        },
    )
    assert result["artifact_digest_matched"] is True
    assert result["status"] == "NOT VERIFIED"
    assert result["native_probe_code"] == code
    assert result["native_prerequisites_observed"] is False
    assert result["code"] == "DIGEST_MATCH_NATIVE_EVIDENCE_PENDING"
    assert not result["complete_server_acceptance_passed"]
    assert not result["authorizes_host_write"]
