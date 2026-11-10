"""Root-owned, fixed-path candidate observation; NEVER operator authority."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

import repocache.server_root_control_fixed_candidate_v1 as candidate


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def snapshot(generation=1):
    return {
        "state_schema_version": 2, "state_generation": generation,
        "configuration_base64": "e30=", "configuration_sha256": "0"*64,
        "repository_records": [], "id_reservations": [],
        "approval_reference": {},
    }


def envelope(state=None, *, generation=0, digest=None):
    if state is None:
        state = snapshot(generation+1)
    raw = canonical(state)
    return {
        "request_schema_version": 1,
        "expected_generation": generation,
        "expected_state_sha256": digest,
        "next_state_base64": base64.b64encode(raw).decode("ascii"),
        "next_state_sha256": hashlib.sha256(raw).hexdigest(),
    }


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "owned-root"
    root.mkdir(mode=0o700)
    path = root
    for part in candidate._SEGMENTS:
        path = path / part
        path.mkdir(mode=0o700)
    file = path / candidate._NAME
    file.write_bytes(canonical(envelope()))
    file.chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd, file, root
    finally:
        os.close(fd)


def inspect(fd):
    return candidate._inspect_under_root(
        fd, owner_uid=os.getuid(), owner_gid=os.getgid(),
    )


def test_fixed_candidate_observation_inert_and_redacted(fixture):
    fd, file, _ = fixture
    report = inspect(fd)
    assert report["status"] == "FIXED_ROOT_OWNED_CANDIDATE_BYTES_ONLY"
    assert report["next_state_sha256"] == envelope()["next_state_sha256"]
    assert report["expected_generation"] == 0
    assert report["expected_state_sha256"] is None
    assert report["next_state_size_bytes"] > 0
    assert "next_state_base64" not in str(report)
    assert all(v is False for k, v in report.items()
               if k.startswith("authorizes_") or k.endswith("_verified")
               or k in ("state_lock_held", "preflight_remains_valid_after_return"))


def test_next_generation_and_digest_are_exact(fixture):
    fd, file, _ = fixture
    expected = "a"*64
    file.write_bytes(canonical(envelope(snapshot(9), generation=8,
                                        digest=expected)))
    report = inspect(fd)
    assert report["expected_generation"] == 8
    assert report["expected_state_sha256"] == expected


@pytest.mark.parametrize("change,reason", [
    (lambda obj: obj.update(expected_generation=True), "ENVELOPE_INVALID"),
    (lambda obj: obj.update(expected_generation=1), "ENVELOPE_INVALID"),
    (lambda obj: obj.update(expected_state_sha256="a"*64), "ENVELOPE_INVALID"),
    (lambda obj: obj.update(next_state_sha256="0"*64), "STATE_DIGEST_INVALID"),
    (lambda obj: obj.update(request_schema_version=2), "ENVELOPE_INVALID"),
    (lambda obj: obj.update(unexpected_path="/etc/shadow"), "ENVELOPE_INVALID"),
    (lambda obj: obj.update(next_state_base64="A*"), "STATE_BASE64_INVALID"),
])
def test_bad_candidate_envelope_denied(fixture, change, reason):
    fd, file, _ = fixture
    doc = envelope()
    change(doc)
    file.write_bytes(canonical(doc))
    with pytest.raises(candidate.FixedAdminCandidateError, match=reason):
        inspect(fd)


def test_canonical_format_and_duplicate_json_rejected(fixture):
    fd, file, _ = fixture
    raw = canonical(envelope())
    for broken in (b" "+raw, raw+b"\n",
                   b'{"request_schema_version":1,"request_schema_version":1}',
                   b"{}", b"not-json"):
        file.write_bytes(broken)
        with pytest.raises(candidate.FixedAdminCandidateError):
            inspect(fd)


def test_bad_state_snapshot_shape_denied(fixture):
    fd, file, _ = fixture
    for changed in (
        {"state_schema_version": 1},
        {"state_generation": 2},
        {"state_generation": True},
        {"extra_key": "/etc/shadow"},
    ):
        doc = snapshot()
        doc.update(changed)
        file.write_bytes(canonical(envelope(doc)))
        with pytest.raises(candidate.FixedAdminCandidateError,
                           match="STATE_VERSION_INVALID"):
            inspect(fd)


@pytest.mark.parametrize("kind", ["symlink", "mode", "hardlink", "writable_parent",
                                    "symlink_parent", "truncated"])
def test_untrusted_file_or_parent_denied(fixture, kind):
    fd, file, root = fixture
    if kind == "symlink":
        file.unlink()
        file.symlink_to("/etc/passwd")
    elif kind == "mode":
        file.chmod(0o666)
    elif kind == "hardlink":
        os.link(file, file.parent / "other")
    elif kind == "writable_parent":
        file.parent.chmod(0o777)
    elif kind == "symlink_parent":
        path = root / "var"
        path.rename(root / "hidden-var")
        path.symlink_to(root / "hidden-var")
    elif kind == "truncated":
        file.write_bytes(b"")
    with pytest.raises(candidate.FixedAdminCandidateError):
        inspect(fd)


def test_never_reads_current_root_for_nonroot(monkeypatch):
    monkeypatch.setattr(candidate.os, "getuid", lambda: 1000)
    monkeypatch.setattr(candidate.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(candidate.os, "getresuid", lambda: (1000, 1000, 1000))
    with pytest.raises(candidate.FixedAdminCandidateError, match="ROOT_REQUIRED"):
        candidate.inspect_fixed_current_namespace_admin_candidate()


def test_broker_has_no_candidate_dispatch_or_privileged_writer():
    import inspect as stdinspect
    from repocache.server_root_control_worker_v1 import serve_one_fixed_request
    assert "fixed_candidate" not in stdinspect.getsource(serve_one_fixed_request)
    assert "ROOT_TRANSACTION_NOT_IMPLEMENTED" in stdinspect.getsource(
        serve_one_fixed_request,
    )
