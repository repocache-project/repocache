"""Managed NGINX include candidate promotion/restoration security regressions."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

import pytest

from repocache.server_native_nginx_managed_rehearsal_v1 import (
    ManagedIncludeRehearsalError,
    rehearse_managed_include_under_root,
)

NAME = "repocache-managed.conf"
STAGE = ".repocache-managed.stage"
BACKUP = ".repocache-managed.rollback"
OK = b"# candidate valid only inside disposable fixture\n"
OLD = b"# prior fixture managed include\n"


@pytest.fixture
def fixture_root(tmp_path):
    includedir = tmp_path / "etc" / "nginx" / "conf.d"
    includedir.mkdir(parents=True)
    root_fd = os.open(
        tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        yield root_fd, includedir
    finally:
        os.close(root_fd)


def exercise(root_fd, candidate=OK, previous_sha=None, checker=lambda: None):
    return rehearse_managed_include_under_root(
        root_fd, candidate, owner_uid=os.geteuid(),
        expected_previous_sha256=previous_sha, syntax_check=checker,
    )


def test_fresh_candidate_observed_then_absence_restored(fixture_root):
    root, includedir = fixture_root
    checked = []

    def check():
        checked.append((includedir / NAME).read_bytes())

    evidence = exercise(root, checker=check)
    assert checked == [OK]
    assert evidence["status"] == "FIXTURE_CANDIDATE_SYNTAX_REHEARSED_AND_RESTORED"
    assert evidence["previous_file_restored"] is True
    assert evidence["previous_file_was_present"] is False
    assert evidence["host_root_authenticated"] is False
    assert evidence["external_state_lock_authenticated"] is False
    assert evidence["authorizes_host_installation"] is False
    assert evidence["authorizes_nginx_reload"] is False
    assert evidence["authorizes_catalog_publication"] is False
    assert list(includedir.iterdir()) == []


def test_failed_syntax_restores_absence_and_redacts_untrusted_error(fixture_root):
    root, includedir = fixture_root

    def syntax():
        assert (includedir / NAME).read_bytes() == b"bad-directive;\n"
        raise RuntimeError("SECRET_CONFIG_REJECTED")

    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_SYNTAX_REJECTED_RESTORED$",
    ) as failure:
        exercise(root, candidate=b"bad-directive;\n", checker=syntax)
    assert "SECRET_CONFIG_REJECTED" not in str(failure.value)
    assert not list(includedir.iterdir())


def test_existing_owned_file_restored_as_original_inode(fixture_root):
    root, includedir = fixture_root
    target = includedir / NAME
    target.write_bytes(OLD)
    target.chmod(0o640)
    prior = os.stat(target)
    seen = []

    def syntax():
        seen.append((target.read_bytes(), os.stat(target).st_ino))

    for _ in range(2):
        report = exercise(
            root, previous_sha=hashlib.sha256(OLD).hexdigest(),
            checker=syntax,
        )
        assert report["previous_file_was_present"] is True
        assert target.read_bytes() == OLD
        assert os.stat(target).st_ino == prior.st_ino
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o640
        assert not (includedir / STAGE).exists()
        assert not (includedir / BACKUP).exists()
    assert len(seen) == 2
    assert all(data == OK and inode != prior.st_ino for data, inode in seen)


def test_existing_file_failed_syntax_restores_same_inode(fixture_root):
    root, includedir = fixture_root
    target = includedir / NAME
    target.write_bytes(OLD)
    target.chmod(0o640)
    inode = target.stat().st_ino
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_SYNTAX_REJECTED_RESTORED$",
    ):
        exercise(
            root, b"bad directive\n",
            previous_sha=hashlib.sha256(OLD).hexdigest(),
            checker=lambda: (_ for _ in ()).throw(ValueError("secret")),
        )
    assert target.read_bytes() == OLD
    assert target.stat().st_ino == inode
    assert set(x.name for x in includedir.iterdir()) == {NAME}


@pytest.mark.parametrize("conflict", [STAGE, BACKUP])
def test_leftover_transaction_stops_automatic_retry(fixture_root, conflict):
    root, includedir = fixture_root
    (includedir / conflict).write_bytes(b"unexpected previous transaction")
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_INTERRUPTED_TRANSACTION_REFUSED$",
    ):
        exercise(root, checker=lambda: pytest.fail("syntax called"))
    assert (includedir / conflict).read_bytes() == b"unexpected previous transaction"
    assert not (includedir / NAME).exists()


def test_foreign_include_refused_without_alteration(fixture_root):
    root, includedir = fixture_root
    target = includedir / NAME
    target.write_bytes(b"# foreign include\n")
    target.chmod(0o640)
    with pytest.raises(
        ManagedIncludeRehearsalError, match="^FOREIGN_MANAGED_INCLUDE_REFUSED$"
    ):
        exercise(root, checker=lambda: pytest.fail("syntax called"))
    assert target.read_bytes() == b"# foreign include\n"
    assert set(x.name for x in includedir.iterdir()) == {NAME}


def test_manifest_digest_mismatch_refused_without_staging(fixture_root):
    root, includedir = fixture_root
    target = includedir / NAME
    target.write_bytes(OLD)
    target.chmod(0o640)
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_PREVIOUS_DIGEST_MISMATCH$",
    ):
        exercise(root, previous_sha="0" * 64)
    assert target.read_bytes() == OLD
    assert set(x.name for x in includedir.iterdir()) == {NAME}


def test_symlink_target_not_adopted_even_with_digest(fixture_root):
    root, includedir = fixture_root
    foreign = includedir / "foreign-real"
    foreign.write_bytes(OLD)
    (includedir / NAME).symlink_to(foreign)
    with pytest.raises(ManagedIncludeRehearsalError):
        exercise(root, previous_sha=hashlib.sha256(OLD).hexdigest())
    assert foreign.read_bytes() == OLD
    assert (includedir / NAME).is_symlink()
    assert not (includedir / STAGE).exists()


def test_symlinked_parent_refused(fixture_root):
    root, includedir = fixture_root
    parent = includedir.parent
    includedir.rmdir()
    includedir.symlink_to(parent)
    with pytest.raises(ManagedIncludeRehearsalError):
        exercise(root, checker=lambda: pytest.fail("syntax called"))
    assert not (parent / NAME).exists()


def test_hardlinked_prior_target_refused(fixture_root):
    root, includedir = fixture_root
    target = includedir / NAME
    target.write_bytes(OLD)
    target.chmod(0o640)
    os.link(target, includedir / "foreign-link")
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_OWNER_OR_INODE_UNVERIFIED$",
    ):
        exercise(root, previous_sha=hashlib.sha256(OLD).hexdigest())
    assert target.read_bytes() == OLD


def test_world_writable_prior_target_refused(fixture_root):
    root, includedir = fixture_root
    target = includedir / NAME
    target.write_bytes(OLD)
    target.chmod(0o666)
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_OWNER_OR_INODE_UNVERIFIED$",
    ):
        exercise(root, previous_sha=hashlib.sha256(OLD).hexdigest())


@pytest.mark.parametrize("bad", [
    b"", b"missing newline", b"\x00malformed\n", b"\xff\n",
    b"\x1b\n", "string", b"x" * (256 * 1024 + 1),
])
def test_invalid_candidate_denied_without_io(fixture_root, bad):
    root, includedir = fixture_root
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_ARGUMENT_INVALID$",
    ):
        exercise(root, candidate=bad)
    assert not list(includedir.iterdir())


def test_non_none_syntax_return_is_not_success(fixture_root):
    root, includedir = fixture_root
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_SYNTAX_REJECTED_RESTORED$",
    ):
        exercise(root, checker=lambda: True)
    assert not list(includedir.iterdir())


def test_concurrent_replacement_of_promoted_target_never_overwritten(fixture_root):
    root, includedir = fixture_root

    def mutate():
        target = includedir / NAME
        target.write_bytes(b"# attacker altered candidate\n")

    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_ROLLBACK_TARGET_CHANGED$",
    ):
        exercise(root, checker=mutate)
    assert (includedir / NAME).read_bytes() == b"# attacker altered candidate\n"
    # This is NOT considered recovered; the foreign mutation blocks reentry.
    with pytest.raises(ManagedIncludeRehearsalError):
        exercise(root)


def test_exclusive_stage_name_protects_dangling_symlink(fixture_root):
    root, includedir = fixture_root
    (includedir / STAGE).symlink_to("unavailable-target")
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_INTERRUPTED_TRANSACTION_REFUSED$",
    ):
        exercise(root)
    assert (includedir / STAGE).is_symlink()


def test_failed_atomic_promotion_preserves_previous_and_refuses_retry(
    fixture_root, monkeypatch,
):
    import repocache.server_native_nginx_managed_rehearsal_v1 as native

    root, includedir = fixture_root
    target = includedir / NAME
    target.write_bytes(OLD)
    target.chmod(0o640)
    original_replace = native.os.replace

    def deny_promotion(source, destination, **kwargs):
        if source == STAGE:
            raise OSError("synthetic failed rename")
        return original_replace(source, destination, **kwargs)

    monkeypatch.setattr(native.os, "replace", deny_promotion)
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_TRANSACTION_UNVERIFIED$",
    ):
        exercise(root, previous_sha=hashlib.sha256(OLD).hexdigest())
    assert target.read_bytes() == OLD
    assert (includedir / STAGE).read_bytes() == OK
    assert (includedir / BACKUP).read_bytes() == OLD
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_INTERRUPTED_TRANSACTION_REFUSED$",
    ):
        exercise(root, previous_sha=hashlib.sha256(OLD).hexdigest())


def test_failed_restoration_is_never_reported_as_success(
    fixture_root, monkeypatch,
):
    import repocache.server_native_nginx_managed_rehearsal_v1 as native

    root, includedir = fixture_root
    target = includedir / NAME
    target.write_bytes(OLD)
    target.chmod(0o640)
    original_replace = native.os.replace

    def deny_restoration(source, destination, **kwargs):
        if source == BACKUP:
            raise OSError("synthetic disk failure")
        return original_replace(source, destination, **kwargs)

    monkeypatch.setattr(native.os, "replace", deny_restoration)
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_TRANSACTION_UNVERIFIED$",
    ):
        exercise(root, previous_sha=hashlib.sha256(OLD).hexdigest())
    # We cannot claim successful restoration when the filesystem prevents
    # it. The backed-up last-known-good bytes remain intact for recovery.
    assert target.read_bytes() == OK
    assert (includedir / BACKUP).read_bytes() == OLD
    with pytest.raises(
        ManagedIncludeRehearsalError,
        match="^MANAGED_INCLUDE_INTERRUPTED_TRANSACTION_REFUSED$",
    ):
        exercise(root, previous_sha=hashlib.sha256(OLD).hexdigest())


def test_actual_namespace_root_fd_refuses_fixture_mutation(monkeypatch):
    # This MUST fail before the function inspects or stages any host
    # NGINX include, even when the caller is root.
    monkeypatch.delenv("REPOCACHE_NATIVE_TEST_CONTAINER", raising=False)
    root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(
            ManagedIncludeRehearsalError,
            match="^MANAGED_INCLUDE_LIVE_HOST_ROOT_REFUSED$",
        ):
            rehearse_managed_include_under_root(
                root_fd, OK, owner_uid=os.geteuid(),
                expected_previous_sha256=None,
                syntax_check=lambda: pytest.fail("host root syntax invoked"),
            )
    finally:
        os.close(root_fd)
