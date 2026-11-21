#!/usr/bin/env python3
"""Real native NGINX include promote/syntax/restore, disposable Docker only (#27).

Run exclusively inside a fresh CI-only Debian 13 or AlmaLinux 10 container.
The checked out source is read-only; only fixed names in this container's
own native NGINX conf.d are exercised. No systemctl or service reload.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

from repocache.server_native_nginx_managed_rehearsal_v1 import (
    ManagedIncludeRehearsalError, rehearse_managed_include_under_root,
    recover_interrupted_owned_include_fixture_under_root,
)

_DIRECTORY = Path("/etc/nginx/conf.d")
_TARGET = _DIRECTORY / "repocache-managed.conf"
_STAGE = _DIRECTORY / ".repocache-managed.stage"
_ROLLBACK = _DIRECTORY / ".repocache-managed.rollback"
_PREVIOUS = b"# REPOCACHE disposable CI previous owned include\n"
_VALID = b"# REPOCACHE disposable CI valid candidate\n"
_INVALID = b"repocache_disposable_fixture_invalid_directive;\n"


class ManagedNativeSmokeError(ValueError):
    """Static redacted native test failure."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ManagedNativeSmokeError(code)


def _run_nginx() -> int:
    result = subprocess.run(
        ["/usr/sbin/nginx", "-t", "-q"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        cwd="/", check=False, timeout=20,
    )
    return result.returncode


def _guard() -> None:
    _require(
        os.environ.get("REPOCACHE_NATIVE_TEST_CONTAINER")
        == "CONFIRMED_DISPOSABLE_DOCKER_ONLY"
        and Path("/.dockerenv").is_file() and os.geteuid() == 0,
        "DISPOSABLE_ROOT_CONTAINER_REQUIRED",
    )
    pid1 = Path("/proc/1/comm").read_text("ascii").strip()
    _require(pid1 != "systemd", "BOOTED_SYSTEMD_HOST_REFUSED")
    _require(not os.path.ismount(_DIRECTORY), "NGINX_INCLUDE_MOUNT_REFUSED")
    _require(_DIRECTORY.is_dir() and Path("/usr/sbin/nginx").is_file(),
             "NATIVE_NGINX_INSTALL_UNVERIFIED")
    _require(
        not any(os.path.lexists(path) for path in (_TARGET, _STAGE, _ROLLBACK)),
        "EXISTING_MANAGED_INCLUDE_REFUSED",
    )
    _require(_run_nginx() == 0, "STOCK_NGINX_SYNTAX_UNVERIFIED")


def _rehearse(root_fd: int, candidate: bytes, previous: bytes | None,
              *, expect_invalid: bool) -> None:
    digest = None if previous is None else hashlib.sha256(previous).hexdigest()
    hits = []

    def native_checker() -> None:
        _require(_TARGET.read_bytes() == candidate,
                 "CANDIDATE_NOT_PUBLISHED_FOR_REAL_PARSER")
        status = _run_nginx()
        hits.append(status)
        if expect_invalid:
            _require(status != 0, "INVALID_NGINX_DIRECTIVE_ACCEPTED")
            raise ManagedNativeSmokeError("REAL_NGINX_SYNTAX_REJECTED")
        _require(status == 0, "VALID_NGINX_SYNTAX_REJECTED")

    try:
        result = rehearse_managed_include_under_root(
            root_fd, candidate, owner_uid=0,
            expected_previous_sha256=digest, syntax_check=native_checker,
        )
    except ManagedIncludeRehearsalError as exc:
        _require(
            expect_invalid
            and str(exc) == "MANAGED_INCLUDE_SYNTAX_REJECTED_RESTORED",
            "INCORRECT_NGINX_INCLUDE_REFUSAL",
        )
    else:
        _require(not expect_invalid and
                 result["status"] == "FIXTURE_CANDIDATE_SYNTAX_REHEARSED_AND_RESTORED"
                 and result["previous_file_restored"] is True
                 and result["host_root_authenticated"] is False
                 and result["authorizes_nginx_reload"] is False
                 and result["authorizes_host_installation"] is False,
                 "INVALID_RESTORATION_REPORT")
    _require(len(hits) == 1 and
             (hits[0] != 0 if expect_invalid else hits[0] == 0),
             "NATIVE_NGINX_PARSER_NOT_CALLED_OR_WRONG_STATUS")
    _require(not os.path.lexists(_STAGE) and not os.path.lexists(_ROLLBACK),
             "NGINX_TRANSACTION_ARTIFACT_LEFTOVER")
    _require(
        (_TARGET.read_bytes() if _TARGET.exists() else None) == previous,
        "PRIOR_NGINX_INCLUDE_NOT_RESTORED",
    )
    _require(_run_nginx() == 0, "RESTORED_STOCK_NGINX_SYNTAX_INVALID")


def run() -> dict[str, object]:
    _guard()
    fd = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        # Real NGINX parser reads the published candidate in its fixed
        # conf.d include. An invalid directive MUST be rejected by nginx -t.
        _rehearse(fd, _VALID, None, expect_invalid=False)
        _rehearse(fd, _INVALID, None, expect_invalid=True)

        # This fixture explicitly owns the previous file. An arbitrary
        # existing file would NOT be trusted merely because it has a digest.
        created = os.open(
            _TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o640,
        )
        try:
            os.write(created, _PREVIOUS)
            os.fsync(created)
        finally:
            os.close(created)
        inode = os.stat(_TARGET).st_ino
        for candidate, fail in ((_VALID, False), (_INVALID, True), (_VALID, False)):
            _rehearse(fd, candidate, _PREVIOUS, expect_invalid=fail)
            _require(os.stat(_TARGET).st_ino == inode,
                     "PREVIOUS_MANAGED_INODE_REPLACED")
        os.unlink(_TARGET)
        _require(_run_nginx() == 0, "STOCK_NGINX_POSTFIXTURE_SYNTAX_INVALID")

        # A pre-existing unmanaged name is NEVER silently adopted.
        foreign = b"# unmanaged NGINX include fixture\n"
        foreign_fd = os.open(
            _TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o640,
        )
        try:
            os.write(foreign_fd, foreign)
            os.fsync(foreign_fd)
        finally:
            os.close(foreign_fd)
        try:
            rehearse_managed_include_under_root(
                fd, _VALID, owner_uid=0, expected_previous_sha256=None,
                syntax_check=lambda: _require(False, "FOREIGN_SYNTAX_CALLBACK"),
            )
        except ManagedIncludeRehearsalError as exc:
            _require(str(exc) == "FOREIGN_MANAGED_INCLUDE_REFUSED",
                     "FOREIGN_INCLUDE_NOT_REFUSED")
        else:
            _require(False, "FOREIGN_INCLUDE_ADOPTED")
        _require(_TARGET.read_bytes() == foreign, "FOREIGN_INCLUDE_CHANGED")
        os.unlink(_TARGET)

        # Any residue from an interrupted transaction blocks reentry.
        interrupted = os.open(
            _STAGE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.write(interrupted, b"unreconciled fixture\n")
            os.fsync(interrupted)
        finally:
            os.close(interrupted)
        try:
            rehearse_managed_include_under_root(
                fd, _VALID, owner_uid=0, expected_previous_sha256=None,
                syntax_check=lambda: _require(False, "INTERRUPTED_SYNTAX_CALLBACK"),
            )
        except ManagedIncludeRehearsalError as exc:
            _require(str(exc) == "MANAGED_INCLUDE_INTERRUPTED_TRANSACTION_REFUSED",
                     "INTERRUPTED_TRANSACTION_NOT_REFUSED")
        else:
            _require(False, "INTERRUPTED_TRANSACTION_ADOPTED")
        _require(_STAGE.read_bytes() == b"unreconciled fixture\n",
                 "INTERRUPTED_STAGE_CHANGED")
        os.unlink(_STAGE)
        _require(not any(os.path.lexists(p) for p in (_TARGET, _STAGE, _ROLLBACK)),
                 "NGINX_INCLUDE_FIXTURE_DIRTY")

        # Simulate a *real separate-process death* after stage promotion
        # but before finally/rollback runs. The recovery below must require
        # both independently expected old/new digests and a single known
        # post-promotion phase. No live systemd/nginx reload occurs here.
        original_fd = os.open(
            _TARGET,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o640,
        )
        try:
            os.write(original_fd, _PREVIOUS)
            os.fsync(original_fd)
        finally:
            os.close(original_fd)
        original = os.stat(_TARGET)
        previous_digest = hashlib.sha256(_PREVIOUS).hexdigest()
        candidate_digest = hashlib.sha256(_VALID).hexdigest()

        child = os.fork()
        if child == 0:
            try:
                rehearse_managed_include_under_root(
                    fd, _VALID, owner_uid=0,
                    expected_previous_sha256=previous_digest,
                    syntax_check=lambda: os._exit(73),
                )
            except BaseException:
                os._exit(74)
            os._exit(75)
        _, code = os.waitpid(child, 0)
        _require(
            os.WIFEXITED(code) and os.WEXITSTATUS(code) == 73,
            "CRASH_DID_NOT_OCCUR_AFTER_INCLUDE_PROMOTION",
        )
        _require(
            not os.path.lexists(_STAGE)
            and _TARGET.read_bytes() == _VALID
            and _ROLLBACK.read_bytes() == _PREVIOUS
            and _ROLLBACK.stat().st_ino == original.st_ino,
            "CRASH_LEFT_UNKNOWN_INCLUDE_PHASE",
        )
        _require(
            _run_nginx() == 0,
            "CRASHED_CANDIDATE_IS_NOT_NATIVE_NGINX_SYNTAX_VALID",
        )
        recovered = recover_interrupted_owned_include_fixture_under_root(
            fd, owner_uid=0, expected_previous_sha256=previous_digest,
            expected_candidate_sha256=candidate_digest,
        )
        _require(
            recovered["status"] == "FIXTURE_INTERRUPTED_OWNED_INCLUDE_RESTORED"
            and recovered["previous_file_inode_and_bytes_restored"]
            and recovered["pending_package_effects_reconciled"] is False
            and recovered["authorizes_host_installation"] is False
            and recovered["authorizes_nginx_reload"] is False
            and _TARGET.read_bytes() == _PREVIOUS
            and _TARGET.stat().st_ino == original.st_ino
            and not os.path.lexists(_STAGE)
            and not os.path.lexists(_ROLLBACK)
            and _run_nginx() == 0,
            "CRASHED_NATIVE_NGINX_INCLUDE_NOT_RESTORED",
        )
        try:
            recover_interrupted_owned_include_fixture_under_root(
                fd, owner_uid=0, expected_previous_sha256=previous_digest,
                expected_candidate_sha256=candidate_digest,
            )
        except ManagedIncludeRehearsalError as exc:
            _require(
                str(exc) == "MANAGED_INCLUDE_RECOVERY_PHASE_UNVERIFIED",
                "REPEATED_RECOVERY_WRONG_REFUSAL",
            )
        else:
            _require(False, "REPEATED_RECOVERY_AUTO_ADOPTED")

        os.unlink(_TARGET)
        _require(
            not any(os.path.lexists(p) for p in (_TARGET, _STAGE, _ROLLBACK)),
            "POST_CRASH_FIXTURE_NOT_EMPTY",
        )
        _require(_run_nginx() == 0, "FINAL_STOCK_NGINX_SYNTAX_INVALID")
        return {
            "schema_version": 1,
            "status": "DISPOSABLE_NATIVE_MANAGED_INCLUDE_RESTORE_PASS",
            "real_nginx_parser_accepts_valid_include": True,
            "real_nginx_parser_rejects_invalid_include": True,
            "previous_owned_include_inode_preserved": True,
            "foreign_include_refused": True,
            "interrupted_transaction_refused": True,
            "crashed_child_exit_before_restore_detected": True,
            "digest_pinned_previous_inode_recovered_after_crash": True,
            "second_recovery_without_backup_refused": True,
            "original_nginx_syntax_restored": True,
            "booted_systemd_tested": False,
            "host_root_authorized": False,
            "nginx_service_reload_performed": False,
        }
    finally:
        os.close(fd)


def main() -> int:
    try:
        report = run()
    except Exception:
        report = {
            "schema_version": 1, "status": "FAIL",
            "code": "NATIVE_MANAGED_INCLUDE_REHEARSAL_UNVERIFIED",
            "host_root_authorized": False,
        }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return int(report["status"] != "DISPOSABLE_NATIVE_MANAGED_INCLUDE_RESTORE_PASS")


if __name__ == "__main__":
    raise SystemExit(main())
