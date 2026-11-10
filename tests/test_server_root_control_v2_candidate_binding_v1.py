"""Exact same-lock fixed admin proposal vs canonical state-v2 CAS."""
from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest

import repocache.server_root_control_v2_candidate_binding_v1 as binding
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_proposed_state_v2_store import (
    V2_STATE, _commit_proposed_v2_under_root as commit,
)
from repocache.server_root_control_fixed_candidate_v1 import _NAME
from test_server_proposed_state_v2_store import snapshot


def canon(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


@pytest.fixture
def owned(tmp_path):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    directory = root
    for s in ("var", "lib", "repocache", "server"):
        directory /= s
        directory.mkdir(mode=0o700)
    (directory / LOCK_NAME).write_bytes(b"")
    (directory / LOCK_NAME).chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd, directory, os.getuid(), os.getgid()
    finally:
        os.close(fd)


def stage(layout, desired, *, expected=0, old_sha=None):
    _, directory, _, _ = layout
    raw = canon(desired)
    request = {
        "request_schema_version": 1,
        "expected_generation": expected,
        "expected_state_sha256": old_sha,
        "next_state_base64": base64.b64encode(raw).decode("ascii"),
        "next_state_sha256": hashlib.sha256(raw).hexdigest(),
    }
    file = directory / _NAME
    file.write_bytes(canon(request))
    file.chmod(0o600)
    return file


def inspect(layout):
    fd, _, uid, gid = layout
    return binding._bind_under_root(fd, owner_uid=uid, owner_gid=gid)


def test_bootstrap_locked_candidate_is_valid_preview_without_commit(owned):
    _, directory, _, _ = owned
    stage(owned, snapshot(count=1))
    before = (directory / _NAME).read_bytes()
    result = inspect(owned)
    assert result["status"] == "LOCKED_ROOT_CANDIDATE_V2_VALIDATED_PREVIEW_ONLY"
    assert result["current_generation"] == 0
    assert result["proposed_generation"] == 1
    assert result["proposed_repository_count"] == 1
    assert result["proposed_reserved_id_count"] == 1
    assert not (directory / V2_STATE).exists()
    assert (directory / _NAME).read_bytes() == before
    assert all(v is False for k, v in result.items()
               if k.startswith("authorizes_") or k.endswith("_verified")
               or k == "lock_still_held_after_return")


def test_existing_generation_requires_exact_predecessor(owned):
    fd, directory, uid, _ = owned
    first = snapshot(count=1)
    commit(fd, first, owner_uid=uid, expected_generation=0)
    old_digest = hashlib.sha256((directory / V2_STATE).read_bytes()).hexdigest()
    second = snapshot(count=1, generation=2, previous=first)
    stage(owned, second, expected=1, old_sha=old_digest)
    result = inspect(owned)
    assert result["whole_previous_state_sha256"] == old_digest
    assert result["proposed_generation"] == 2
    assert result["candidate_and_canonical_v2_transition_consistent"] is True


@pytest.mark.parametrize("kind,expected", [
    ("stale_generation", "STALE_GENERATION"),
    ("wrong_digest", "PREDECESSOR_DIGEST_MISMATCH"),
    ("missing_predecessor", "STALE_GENERATION"),
])
def test_replay_or_wrong_generation_fails_closed(owned, kind, expected):
    fd, directory, uid, _ = owned
    first = snapshot(count=1)
    commit(fd, first, owner_uid=uid, expected_generation=0)
    old_digest = hashlib.sha256((directory / V2_STATE).read_bytes()).hexdigest()
    second = snapshot(count=1, generation=2, previous=first)
    if kind == "stale_generation":
        stage(owned, snapshot(count=1), expected=0)
    elif kind == "wrong_digest":
        stage(owned, second, expected=1, old_sha="a"*64)
    else:
        stage(owned, snapshot(count=1), expected=0)
    with pytest.raises(binding.LockedRootCandidateBindingError, match=expected):
        inspect(owned)


def test_invalid_full_v2_config_refused_even_with_matching_candidate_digest(owned):
    bad = snapshot(count=1)
    bad["repository_records"][0]["desired_state"] = "disabled"
    stage(owned, bad)
    with pytest.raises(binding.LockedRootCandidateBindingError,
                       match="PROTECTED_CANDIDATE_UNVERIFIED"):
        inspect(owned)


def test_root_owned_candidate_replaced_during_lock_refused(owned, monkeypatch):
    file = stage(owned, snapshot(count=1))
    original = binding._load_private_under_root
    n = []

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        n.append(1)
        if len(n) == 1:
            file.write_bytes(canon({
                "request_schema_version": 1,
                "expected_generation": 0,
                "expected_state_sha256": None,
                "next_state_base64": "YQ==",
                "next_state_sha256": "0"*64,
            }))
        return result

    monkeypatch.setattr(binding, "_load_private_under_root", changed)
    with pytest.raises(binding.LockedRootCandidateBindingError,
                       match="PROTECTED_CANDIDATE_UNVERIFIED"):
        inspect(owned)


def test_nonroot_wrapper_never_opens_current_namespace_root(monkeypatch):
    monkeypatch.setattr(binding.os, "getuid", lambda: 1000)
    monkeypatch.setattr(binding.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(binding.os, "getresuid", lambda: (1000, 1000, 1000))
    with pytest.raises(binding.LockedRootCandidateBindingError,
                       match="ROOT_REQUIRED"):
        binding.inspect_current_namespace_fixed_root_v2_candidate()


def test_socket_worker_still_denies_real_apply():
    import inspect
    from repocache.server_root_control_worker_v1 import serve_one_fixed_request
    code = inspect.getsource(serve_one_fixed_request)
    assert "ROOT_TRANSACTION_NOT_IMPLEMENTED" in code
    assert "_bind_under_root" not in code
