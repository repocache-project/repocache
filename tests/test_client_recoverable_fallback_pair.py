"""Non-activating, sandbox-only APT/DNF transaction journal invariants."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
import recoverable_fallback_pair_lab as lab


@pytest.mark.parametrize("bad", [
    "", "../file", "/etc/passwd", "A" * 32,
    "a" * 31, "g" * 32, "a" * 33, None,
])
def test_pair_journal_refuses_untrusted_names(bad):
    with pytest.raises(lab.PairRefused):
        lab._journal_name(bad)


@pytest.mark.parametrize("bad", [
    "@", "not-base64", "a" * (2 * 1024 * 1024 + 1),
    42, None, "../",
])
def test_pair_journal_refuses_bad_payload_bytes(bad):
    with pytest.raises(lab.PairRefused):
        lab._decode(bad)


def test_duplicate_journal_keys_cannot_be_accepted():
    with pytest.raises(lab.PairRefused):
        lab._no_duplicates([("id", "a"), ("id", "b")])


@pytest.mark.parametrize("verb", [lab.apply_sandbox, lab.restore_sandbox,
                                  lab.recover_sandbox])
def test_no_transaction_may_target_real_root(verb):
    with pytest.raises(lab.PairRefused, match="Production root"):
        verb(Path("/"), "a" * 32)


def test_digest_and_identity_proofs_are_not_interchangeable():
    content = b"managed"
    first = (content, {"device": 25, "inode": 10})
    second = (content, {"device": 25, "inode": 11})
    assert lab._matches(first, content, [25, 10])
    assert not lab._matches(second, content, [25, 10])
    assert not lab._matches(first, b"foreign", [25, 10])
    assert not lab._matches(None, content, [25, 10])


def test_crash_fault_requires_explicit_accepted_label():
    lab._crash(None, "armed")
    lab._crash("source", "armed")
    with pytest.raises(lab.InjectedCrash):
        lab._crash("armed", "armed")


@pytest.mark.parametrize("payload", [b"", b"a\0b", os.urandom(32)])
def test_base64_protected_journal_round_trip(payload):
    assert lab._decode(lab._blob(payload)) == payload
