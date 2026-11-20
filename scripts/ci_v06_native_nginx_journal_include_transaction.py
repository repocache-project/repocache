#!/usr/bin/env python3
"""End-to-end native package lock + managed NGINX include fixture (#27).

This is strictly a disposable Docker CI *rehearsal*. No host installer,
root-control broker, production transaction, systemd service or live reload
authority is created. We prove that an already-installed, distribution-native
NGINX include can be promoted and syntax-checked while the same durable
protected package-effects lock remains held, then restored safely.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

from ci_v06_journaled_native_server_install import (
    _require_disposable_context, _verify_pending_lock,
)
from repocache.server_native_nginx_local_boundary_v1 import (
    inspect_native_nginx_local_boundary,
)
from repocache.server_native_nginx_managed_rehearsal_v1 import (
    ManagedIncludeRehearsalError, rehearse_managed_include_under_root,
)
from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, NativePackageJournalError,
    _prepare_native_journal_under_root,
    _retain_native_package_journal_lock_under_root,
)
from repocache.server_native_package_effects_observe_v1 import (
    inspect_current_namespace_native_package_effects,
)
from repocache.server_protected_namespace_bootstrap_v1 import (
    bootstrap_protected_namespace_under_root,
)
from smoke_server_native_nginx_container_install import (
    run_rehearsal,
)

_ROOT = Path(__file__).resolve().parents[1]
_INCLUDE = Path("/etc/nginx/conf.d/repocache-managed.conf")
_STAGE = Path("/etc/nginx/conf.d/.repocache-managed.stage")
_BACKUP = Path("/etc/nginx/conf.d/.repocache-managed.rollback")
_MARKER = Path("/var/lib/repocache/server") / NATIVE_PENDING_NAME
_VALID = b"# REPOCACHE disposable locked transaction valid candidate\n"
_INVALID = b"repocache_locked_invalid_native_directive;\n"
_PRIOR = b"# REPOCACHE disposable known previous owned include\n"
_STATUS = "DISPOSABLE_NATIVE_JOURNAL_LOCKED_INCLUDE_RESTORE_PASS"


class LockedNativeIncludeTestError(ValueError):
    """Fixed redacted negative results, no output from package or NGINX."""


def _deny(code: str) -> None:
    raise LockedNativeIncludeTestError(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        _deny(code)


def _syntax_check(distribution: str, observations: list[str]) -> bool:
    """Use the real installed package binary while the state lock is held."""
    _verify_pending_lock(distribution, observations)
    completed = subprocess.run(
        ["/usr/sbin/nginx", "-t", "-q"], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        check=False, cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    return completed.returncode == 0


def _no_leftovers() -> None:
    _require(
        not os.path.lexists(_STAGE) and not os.path.lexists(_BACKUP),
        "INTERRUPTED_INCLUDE_STAGE_OR_BACKUP",
    )


def _check_include_rehearsal(
    root_fd: int, *, distribution: str, observations: list[str],
    candidate: bytes, previous: bytes | None, expected_syntax_ok: bool,
) -> None:
    _no_leftovers()
    previous_info = _INCLUDE.stat() if previous is not None else None
    if previous is None:
        _require(not os.path.lexists(_INCLUDE), "UNEXPECTED_MANAGED_INCLUDE")
    else:
        _require(_INCLUDE.read_bytes() == previous, "PREVIOUS_INCLUDE_CHANGED")

    callback_hits: list[bool] = []

    def parser() -> None:
        _require(_INCLUDE.read_bytes() == candidate,
                 "CANDIDATE_NOT_VISIBLE_TO_NATIVE_PARSER")
        valid = _syntax_check(distribution, observations)
        callback_hits.append(valid)
        if not valid:
            _deny("REAL_NATIVE_NGINX_SYNTAX_REFUSED")

    digest = None if previous is None else hashlib.sha256(previous).hexdigest()
    try:
        report = rehearse_managed_include_under_root(
            root_fd, candidate, owner_uid=0, expected_previous_sha256=digest,
            syntax_check=parser,
        )
    except ManagedIncludeRehearsalError as exc:
        _require(
            not expected_syntax_ok
            and str(exc) == "MANAGED_INCLUDE_SYNTAX_REJECTED_RESTORED",
            "UNEXPECTED_INCLUDE_TRANSACTION_FAILURE",
        )
    else:
        _require(
            expected_syntax_ok
            and report.get("status")
            == "FIXTURE_CANDIDATE_SYNTAX_REHEARSED_AND_RESTORED"
            and report.get("previous_file_restored") is True
            and report.get("authorizes_host_installation") is False
            and report.get("authorizes_nginx_reload") is False
            and report.get("protected_manifest_authenticated") is False,
            "MANAGED_INCLUDE_REHEARSAL_WRONG_AUTHORITY",
        )
    _require(
        callback_hits == [expected_syntax_ok],
        "NATIVE_NGINX_SYNTAX_RESULT_NOT_OBSERVED",
    )
    _no_leftovers()
    if previous is None:
        _require(not os.path.lexists(_INCLUDE), "ORIGINAL_ABSENCE_NOT_RESTORED")
    else:
        now = _INCLUDE.stat()
        _require(
            _INCLUDE.read_bytes() == previous
            and (now.st_dev, now.st_ino, now.st_mode, now.st_uid, now.st_gid)
                == (previous_info.st_dev, previous_info.st_ino,
                    previous_info.st_mode, previous_info.st_uid,
                    previous_info.st_gid),
            "ORIGINAL_OWNED_INCLUDE_INODE_NOT_RESTORED",
        )
    _require(
        _syntax_check(distribution, observations),
        "POST_RESTORE_NATIVE_NGINX_SYNTAX_INVALID",
    )


def _create_previous_owned_include() -> None:
    _require(not os.path.lexists(_INCLUDE), "PRIOR_INCLUDE_ALREADY_PRESENT")
    fd = os.open(
        _INCLUDE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0), 0o640,
    )
    try:
        _require(
            os.fstat(fd).st_uid == 0 and os.fstat(fd).st_nlink == 1,
            "PREVIOUS_FIXTURE_OWNERSHIP_UNVERIFIED",
        )
        view = memoryview(_PRIOR)
        while view:
            length = os.write(fd, view)
            if length <= 0:
                _deny("PREVIOUS_FIXTURE_WRITE_FAILED")
            view = view[length:]
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(
        "/etc/nginx/conf.d", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    _require(
        _INCLUDE.read_bytes() == _PRIOR
        and stat.S_IMODE(_INCLUDE.stat().st_mode) == 0o640,
        "PREVIOUS_FIXTURE_UNVERIFIED",
    )


def _foreign_include_refusal(root_fd: int) -> None:
    before = _INCLUDE.stat()
    try:
        rehearse_managed_include_under_root(
            root_fd, _VALID, owner_uid=0, expected_previous_sha256=None,
            syntax_check=lambda: _deny("FOREIGN_SYNTAX_CALLBACK_INVOKED"),
        )
    except ManagedIncludeRehearsalError as exc:
        _require(
            str(exc) == "FOREIGN_MANAGED_INCLUDE_REFUSED",
            "FOREIGN_INCLUDE_WRONG_REFUSAL",
        )
    else:
        _deny("FOREIGN_INCLUDE_ADOPTED")
    after = _INCLUDE.stat()
    _require(
        _INCLUDE.read_bytes() == _PRIOR
        and (after.st_dev, after.st_ino, after.st_mode)
            == (before.st_dev, before.st_ino, before.st_mode),
        "FOREIGN_REFUSAL_MODIFIED_OWNED_INCLUDE",
    )
    _no_leftovers()


def run() -> dict[str, Any]:
    # This guard rejects booted systemd hosts, preexisting NGINX, unsupported
    # OS/architecture and any protected namespace before touching packages.
    distribution, release = _require_disposable_context()
    document = json.loads(
        (_ROOT / "docs/examples/server-install-v1.json").read_text("utf-8")
    )
    root_fd = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        bootstrap = bootstrap_protected_namespace_under_root(root_fd, owner_uid=0)
        _require(bootstrap["status"] == "FRESH_PROTECTED_LOCK_DURABLE",
                 "PROTECTED_STATE_BOOTSTRAP_UNVERIFIED")
        preflight = inspect_native_nginx_local_boundary(
            os_release=release,
            python_version=(sys.version_info.major, sys.version_info.minor),
            document=document,
        ).to_dict()
        _require(
            preflight["code"] == "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED"
            and preflight["authorizes_package_transaction"] is False,
            "PREPACKAGE_OWNERSHIP_NOT_CLEAN",
        )
        observations: list[str] = []

        def guarded_runner(command: list[str], **kwargs: Any):
            _verify_pending_lock(distribution, observations)
            return subprocess.run(command, **kwargs)

        # Real fixed native APT/DNF transaction, plus real stock nginx -t,
        # all inside the single retained *fixture* protected journal lock.
        with _retain_native_package_journal_lock_under_root(
            root_fd, owner_uid=0, distribution=distribution,
            allow_native_package_parent_changes=True,
        ) as journal:
            _require(
                journal["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
                and journal["native_package_effects_reconciled"] is False
                and journal["authorizes_package_installation"] is False,
                "NATIVE_PACKAGE_JOURNAL_NOT_DURABLE",
            )
            native = run_rehearsal(
                distribution=distribution, runner=guarded_runner,
            )
            _require(
                native["native_transaction_executed_in_disposable_container"]
                and native["nginx_syntax_test_passed_in_container"],
                "NATIVE_NGINX_PACKAGE_INSTALL_UNVERIFIED",
            )
            _require(
                not os.path.lexists(_INCLUDE)
                and not os.path.lexists(_STAGE)
                and not os.path.lexists(_BACKUP),
                "FOREIGN_MANAGED_INCLUDE_AFTER_PACKAGE",
            )
            marker_before = _MARKER.read_bytes()

            # Rehearse only: every candidate is removed/restored BEFORE
            # returning to the lock owner. A syntax success never commits
            # any configured service on the host.
            _check_include_rehearsal(
                root_fd, distribution=distribution, observations=observations,
                candidate=_VALID, previous=None, expected_syntax_ok=True,
            )
            _check_include_rehearsal(
                root_fd, distribution=distribution, observations=observations,
                candidate=_INVALID, previous=None, expected_syntax_ok=False,
            )
            _create_previous_owned_include()
            for candidate, valid in (
                (_VALID, True), (_INVALID, False), (_VALID, True),
            ):
                _check_include_rehearsal(
                    root_fd, distribution=distribution,
                    observations=observations, candidate=candidate,
                    previous=_PRIOR, expected_syntax_ok=valid,
                )
            _foreign_include_refusal(root_fd)
            _require(
                _MARKER.read_bytes() == marker_before
                and len(observations) >= 10
                and all(item == "CONTENDED" for item in observations),
                "NATIVE_PACKAGE_LOCK_OR_JOURNAL_CHANGED_DURING_REHEARSAL",
            )
        # The package operation is deliberately still pending even after
        # the valid/invalid syntax and owned include restoration.
        _require(_MARKER.read_bytes() == marker_before, "NATIVE_JOURNAL_LOST")
        effects = inspect_current_namespace_native_package_effects(
            distribution=distribution,
        )
        _require(
            effects.get("status")
                == "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION"
            and effects.get("native_package_effects_reconciled") is False
            and effects.get("pending_native_effects_block_reentry") is True
            and effects.get("authorizes_native_marker_removal") is False,
            "NATIVE_PACKAGE_EFFECTS_RECONCILIATION_MISSING",
        )
        try:
            _prepare_native_journal_under_root(
                root_fd, owner_uid=0, distribution=distribution,
            )
        except NativePackageJournalError as exc:
            _require(
                str(exc) == "NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED",
                "PENDING_NATIVE_REENTRY_WRONG_REFUSAL",
            )
        else:
            _deny("PENDING_NATIVE_INSTALL_REENTRY_ALLOWED")
        _require(
            _MARKER.read_bytes() == marker_before and
            _INCLUDE.read_bytes() == _PRIOR and
            subprocess.run(
                ["/usr/sbin/nginx", "-t", "-q"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, cwd="/",
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                check=False,
            ).returncode == 0,
            "POST_LOCK_INCLUDE_OR_JOURNAL_UNVERIFIED",
        )
        return {
            "schema_version": 1,
            "status": _STATUS,
            "distribution": distribution,
            "real_native_apt_dnf_package_install_in_container": True,
            "durable_pending_package_journal_preserved": True,
            "single_exclusive_state_lock_through_native_and_include_checks": True,
            "real_nginx_parser_accepted_valid_owned_fragment": True,
            "real_nginx_parser_rejected_invalid_owned_fragment": True,
            "previous_owned_include_inode_restored": True,
            "foreign_include_refused_without_change": True,
            "second_native_package_transaction_refused": True,
            "host_root_authenticated": False,
            "booted_systemd_tested": False,
            "selinux_enforcing_tested": False,
            "nginx_reload_performed": False,
            "native_package_effects_reconciled": False,
            "authorizes_host_installation": False,
        }
    finally:
        os.close(root_fd)


def main() -> int:
    try:
        report = run()
    except Exception:
        report = {
            "schema_version": 1, "status": "FAIL",
            "code": "LOCKED_NATIVE_INCLUDE_REHEARSAL_UNVERIFIED",
            "authorizes_host_installation": False,
        }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return int(report.get("status") != _STATUS)


if __name__ == "__main__":
    raise SystemExit(main())
