"""Bounded read-only native-candidate identity receipt for the final VM gate.

Issue #19: capture exact candidate and source identity without pretending
the candidate is signed, installed, native-proven or release-authorized.
The caller must separately verify authentic owner signing, real installed
systemd/NGINX/SELinux, package integrity and the original issue criteria.
No host service, package manager, network or filesystem mutation occurs.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Callable, Mapping

from repocache.server_native_vm_readonly_v1 import (
    inspect_booted_vm_nginx_readonly,
)

MAX_CANDIDATE_BYTES = 2 * 1024 * 1024 * 1024
_SHA256 = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_SHA = re.compile(r"[a-f0-9]{40}\Z", re.ASCII)
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII)
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class CandidateRefused(ValueError):
    """Stable public status only; never report private path or source bytes."""


def _protected_read_digest(path: Path) -> tuple[str, int]:
    """Read only a pinned one-link file, no symlinked ancestors or aliases."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        raise CandidateRefused("CANDIDATE_PATH_REFUSED")
    fd = os.open("/", _DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            if component in ("", ".", ".."):
                raise CandidateRefused("CANDIDATE_PATH_REFUSED")
            nxt = os.open(component, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = nxt
        leaf = path.name
        if leaf in ("", ".", ".."):
            raise CandidateRefused("CANDIDATE_PATH_REFUSED")
        data_fd = os.open(leaf, _FILE, dir_fd=fd)
        try:
            before = os.fstat(data_fd)
            named = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size < 1 or before.st_size > MAX_CANDIDATE_BYTES
                    or stat.S_IMODE(before.st_mode) & 0o022
                    or (before.st_dev, before.st_ino) !=
                       (named.st_dev, named.st_ino)):
                raise CandidateRefused("CANDIDATE_INODE_REFUSED")
            h = hashlib.sha256()
            consumed = 0
            while consumed <= MAX_CANDIDATE_BYTES:
                chunk = os.read(data_fd, min(1024 * 1024,
                    MAX_CANDIDATE_BYTES + 1 - consumed))
                if not chunk:
                    break
                consumed += len(chunk)
                h.update(chunk)
            after = os.fstat(data_fd)
            named = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            identity = lambda x: (
                x.st_dev, x.st_ino, x.st_size, x.st_ctime_ns,
                x.st_mtime_ns, x.st_mode, x.st_uid, x.st_gid,
            )
            if (consumed > MAX_CANDIDATE_BYTES
                    or consumed != before.st_size
                    or identity(before) != identity(after)
                    or (after.st_dev, after.st_ino) !=
                       (named.st_dev, named.st_ino)):
                raise CandidateRefused("CANDIDATE_DRIFT_REFUSED")
            return h.hexdigest(), consumed
        finally:
            os.close(data_fd)
    except (OSError, UnicodeError) as exc:
        raise CandidateRefused("CANDIDATE_UNAVAILABLE") from exc
    finally:
        os.close(fd)


def collect_candidate_evidence(
    candidate: Path, expected_sha256: str, source_sha: str, *,
    native_probe: Callable[[], Mapping] = inspect_booted_vm_nginx_readonly,
) -> dict:
    """Produce a stable non-authorizing evidence receipt.

    Success *only* means byte identity matches the caller's expected hash.
    The supplied digest is not a publisher signature or a trusted root.
    """
    if (type(expected_sha256) is not str or
            not _SHA256.fullmatch(expected_sha256) or
            type(source_sha) is not str or not _SHA.fullmatch(source_sha) or
            not callable(native_probe)):
        raise CandidateRefused("CANDIDATE_IDENTITY_INPUT_REFUSED")
    report = {
        "schema_version": 1,
        "status": "NOT VERIFIED",
        "code": "CANDIDATE_UNAVAILABLE",
        "source_commit_sha": source_sha,
        "expected_artifact_sha256": expected_sha256,
        "observed_artifact_sha256": None,
        "artifact_size_bytes": None,
        "artifact_digest_matched": False,
        "native_prerequisites_observed": False,
        "native_probe_code": "NATIVE_OBSERVATION_NOT_EXECUTED",
        "publisher_signature_verified": False,
        "source_commit_authenticity_verified": False,
        "installed_artifact_verified": False,
        "installed_systemd_nginx_verified": False,
        "native_apt_dnf_fallback_verified": False,
        "selinux_enforcing_host_verified": False,
        "complete_server_acceptance_passed": False,
        "authorizes_host_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_publication": False,
    }
    try:
        observed, size = _protected_read_digest(Path(candidate))
    except (CandidateRefused, OSError, TypeError, ValueError) as exc:
        report["code"] = (
            str(exc) if type(exc) is CandidateRefused and
            _CODE.fullmatch(str(exc)) else "CANDIDATE_UNAVAILABLE"
        )
        return report
    report["observed_artifact_sha256"] = observed
    report["artifact_size_bytes"] = size
    report["artifact_digest_matched"] = observed == expected_sha256
    if observed != expected_sha256:
        report["status"] = "FAIL"
        report["code"] = "CANDIDATE_DIGEST_MISMATCH"
        return report
    try:
        native = native_probe()
    except Exception:
        native = None
    if (type(native) is dict and
            type(native.get("code")) is str and
            _CODE.fullmatch(native["code"])):
        report["native_probe_code"] = native["code"]
        report["native_prerequisites_observed"] = (
            native.get("status") == "READ_ONLY_PREREQUISITES_OBSERVED"
            and native.get("systemd_pid1_namespace_shape_observed") is True
            and native.get("effective_nginx_master_observed") is True
        )
    report["code"] = (
        "DIGEST_MATCH_NATIVE_READONLY_OBSERVED"
        if report["native_prerequisites_observed"] else
        "DIGEST_MATCH_NATIVE_EVIDENCE_PENDING"
    )
    # No host/issuer trust is inferred even from a successful native probe.
    return report
