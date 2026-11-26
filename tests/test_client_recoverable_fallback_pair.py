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


@pytest.mark.parametrize("verb", [lab.apply_sandbox, lab.apply_retaining_apt_companion_sandbox, lab.restore_sandbox,
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


@pytest.mark.parametrize("missing_identity", ["original_id", "proposed_id"])
def test_corrupt_journal_missing_required_inode_identity_is_refused(
    tmp_path, monkeypatch, missing_identity,
):
    """A root-owned journal with a null mandatory inode must fail closed."""
    ident = "a" * 32
    current, proposed = b"upstream", b"compiled-fallback"
    journal = {
        "schema": 2, "id": ident, "phase": "armed",
        "approval": {}, "approval_sha256": "a" * 64,
        "source": "etc/yum.repos.d/approved.repo", "companion": None,
        "original": lab._blob(current), "proposed": lab._blob(proposed),
        "mirror": lab._blob(b""), "original_id": [8, 12],
        "proposed_id": [8, 13], "mirror_id": None, "restore_id": None,
        "mode": 0o644, "gid": 0,
        "original_digest": lab._hash(current),
        "proposed_digest": lab._hash(proposed),
        "mirror_digest": lab._hash(b""),
    }
    journal[missing_identity] = None
    # The test stubs only the root-required inode reader, not the schema:
    # the corrupted journal still has a real, existing stable leaf name.
    path = tmp_path / lab._journal_name(ident)
    path.write_bytes(b"fixture")
    import json
    wire = json.dumps(journal, separators=(",", ":")).encode("ascii")
    monkeypatch.setattr(lab.boundary, "_read_pinned",
                        lambda *_args, **_kwargs: wire)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(lab.PairRefused, match="journal schema"):
            lab._get_journal(fd, ident)
    finally:
        os.close(fd)


def test_journal_rejects_recomputed_digests_for_unapproved_proposal(tmp_path, monkeypatch):
    import json

    ident = "b" * 32
    source = "etc/yum.repos.d/approved.repo"
    original = (b"[approved]\nname=Approved\n"
                b"baseurl=https://mirror.example.org/alma/\nenabled=1\n"
                b"gpgcheck=1\nrepo_gpgcheck=1\n"
                b"gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10\n")
    cache = "https://cache.example.org/__repocache/repos/approved/"
    approval = {"schema": 1, "id": ident, "source": source,
                "source_sha256": lab._hash(original), "entry_sha256": lab._hash(original),
                "upstream": "https://mirror.example.org/alma/", "cache": cache,
                "route_sha256": lab._hash(cache.encode("ascii"))}
    proposal = lab.compiler.compile_fallback(
        source=source, original=original, expected_source_sha256=lab._hash(original),
        selected_entry_sha256=lab._hash(original), managed_id=ident,
        upstream=approval["upstream"], cache=cache)
    journal = {
        "schema": 2, "id": ident, "phase": "armed",
        "source": source, "companion": None,
        "approval": approval, "approval_sha256": lab._hash(lab._pack(approval)),
        "original": lab._blob(original), "proposed": lab._blob(proposal.proposed),
        "mirror": lab._blob(b""), "original_id": [8, 12],
        "proposed_id": [8, 13], "mirror_id": None, "restore_id": None,
        "mode": 0o644, "gid": 0,
        "original_digest": lab._hash(original),
        "proposed_digest": lab._hash(proposal.proposed),
        "mirror_digest": lab._hash(b""),
    }
    (tmp_path / lab._journal_name(ident)).write_bytes(b"fixture")
    monkeypatch.setattr(lab.boundary, "_read_pinned",
                        lambda *_args, **_kwargs: json.dumps(journal).encode("ascii"))
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert lab._get_journal(fd, ident) == journal
        modified = proposal.proposed.replace(cache.encode("ascii"),
                                             b"https://other.example.org/repo/")
        journal["proposed"] = lab._blob(modified)
        journal["proposed_digest"] = lab._hash(modified)
        with pytest.raises(lab.PairRefused, match="exact approved proposal"):
            lab._get_journal(fd, ident)
    finally:
        os.close(fd)


def test_retention_bytes_are_original_upstream_not_cache():
    assert lab._retained_bytes({"approval": {"upstream": "https://example.org/repo/",
                                            "cache": "https://cache.example.org/repo/"}}) == (
        b"https://example.org/repo/\tpriority:1\n")


def test_reserved_dnf4_pair_root_never_falls_back_to_dnf5(monkeypatch):
    root = Path("/var/tmp/repocache-booted-dnf4-fixture")

    def refused(_root):
        raise FileExistsError("stale PID")

    monkeypatch.setattr(lab, "_dnf4_private_claim", refused)
    monkeypatch.setattr(lab.locks, "hold_existing_native_package_locks",
                        lambda *_a, **_kw: pytest.fail("DNF5 fallback"))
    with pytest.raises(lab.locks.LockInspectionRefused, match="DNF4"):
        with lab._package_scope(root, "etc/yum.repos.d/base.repo"):
            pytest.fail("stale PID accepted")
    with pytest.raises(lab.locks.LockInspectionRefused, match="DNF4"):
        with lab._package_scope(root, "etc/apt/sources.list.d/base.list"):
            pytest.fail("APT accepted in DNF4 fixture")


def test_dnf4_guard_refuses_real_root_even_in_optimized_python():
    import subprocess

    client = Path(__file__).resolve().parents[1] / "client"
    code = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import recoverable_fallback_pair_lab as lab
try:
    lab._dnf4_fixture_guard(Path("/"))
except lab.locks.LockInspectionRefused:
    raise SystemExit(0)
raise SystemExit(91)
"""
    result = subprocess.run([sys.executable, "-I", "-O", "-c", code, str(client)],
                            capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("kind", ["file", "directory", "dangling", "fifo"])
def test_pending_journal_refuses_any_exact_leaf_without_following(tmp_path, kind):
    ident = "a" * 32
    path = tmp_path / lab._pending_journal_name(ident)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        lab._refuse_pending_journal(fd, ident)
        if kind == "file":
            path.write_bytes(b"partial")
        elif kind == "directory":
            path.mkdir()
        elif kind == "dangling":
            path.symlink_to(tmp_path / "absent")
        else:
            os.mkfifo(path)
        before = path.lstat()
        with pytest.raises(lab.PairRefused, match="Pending journal requires manual recovery"):
            lab._refuse_pending_journal(fd, ident)
        after = path.lstat()
        assert (before.st_dev, before.st_ino, before.st_mode) == (
            after.st_dev, after.st_ino, after.st_mode)
        # No unrelated transaction ID is blocked by this leaf.
        lab._refuse_pending_journal(fd, "b" * 32)
        if kind == "file":
            assert path.read_bytes() == b"partial"
        if kind == "dangling":
            assert not (tmp_path / "absent").exists()
    finally:
        os.close(fd)


def test_pending_journal_lookup_error_is_not_absence(monkeypatch):
    def denied(*args, **kwargs):
        assert kwargs == {"dir_fd": 123, "follow_symlinks": False}
        raise PermissionError("unavailable")
    monkeypatch.setattr(lab.os, "stat", denied)
    with pytest.raises(lab.PairRefused, match="Pending journal state cannot be verified"):
        lab._refuse_pending_journal(123, "a" * 32)


def test_pending_journal_name_uses_validated_id():
    assert lab._pending_journal_name("a" * 32) == ".pair-" + "a" * 32 + ".pending"
    with pytest.raises(lab.PairRefused, match="Invalid transaction identifier"):
        lab._pending_journal_name("../unsafe")
