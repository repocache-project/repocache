#!/usr/bin/env python3
"""Prepare one exact #95 state-v2 lifecycle proposal in a trusted checkout.

Offline only: this is not a public repocache CLI, release artifact, signed
operator approval, root-owned candidate installer or NGINX reload authority.
The separately reviewed native #31/#64 worker must authenticate/recheck
everything under its own protected lock before any state or route mutation.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any

if __name__ == "__main__":
    checkout = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(checkout / "src"), str(checkout)]

from repocache.server_repository_reconcile_v1 import (
    render_fixed_native_repository_batch_envelope,
)

_MAX_PREVIOUS = 4 * 1024 * 1024
_MAX_REQUEST = 1024 * 1024
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


class OfflineLifecycleError(ValueError):
    """Redacted errors: never return proposal, paths, URL or trusted keys."""


def _deny() -> None:
    raise OfflineLifecycleError("OFFLINE_LIFECYCLE_REFUSED")


def _sha(value: str) -> bool:
    return type(value) is str and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value
    )


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_ctime_ns, info.st_mtime_ns)


def _parent(path: Path, stack: ExitStack) -> int:
    if path.name in ("", ".", ".."):
        _deny()
    fd = os.open(path.parent, _DIR)
    stack.callback(os.close, fd)
    item = os.fstat(fd)
    if (not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) & 0o022):
        _deny()
    return fd


def _read_owned(path: Path, limit: int) -> bytes:
    """Require local owned single-link regular 0600 input before opening it."""
    with ExitStack() as stack:
        parent = _parent(path, stack)
        prior = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(prior.st_mode) or prior.st_nlink != 1
                or prior.st_uid != os.geteuid()
                or stat.S_IMODE(prior.st_mode) != 0o600
                or not 1 <= prior.st_size <= limit):
            _deny()
        fd = os.open(path.name, _READ, dir_fd=parent)
        stack.callback(os.close, fd)
        before = os.fstat(fd)
        if _identity(prior) != _identity(before):
            _deny()
        result = bytearray()
        while len(result) <= limit:
            data = os.read(fd, min(65536, limit + 1 - len(result)))
            if not data:
                break
            result.extend(data)
        after = os.fstat(fd)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (len(result) != prior.st_size
                or _identity(before) != _identity(after)
                or _identity(after) != _identity(named)):
            _deny()
        return bytes(result)


def _unique_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            _deny()
        result[key] = value
    return result


def _constant(_value: str) -> None:
    _deny()


def _request(raw: bytes) -> tuple[str, tuple[dict[str, Any], ...],
                                  tuple[str, ...], bool]:
    try:
        parsed = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs,
            parse_constant=_constant,
        )
        if type(parsed) is not dict or not set(parsed) <= {
            "operation", "proposed_repositories", "repository_ids",
            "all_repositories",
        } or "operation" not in parsed:
            _deny()
        operation = parsed["operation"]
        if operation not in ("add", "update", "enable", "disable", "remove"):
            _deny()
        proposed = parsed.get("proposed_repositories", [])
        identifiers = parsed.get("repository_ids", [])
        all_repositories = parsed.get("all_repositories", False)
        if (type(proposed) is not list
                or any(type(x) is not dict for x in proposed)
                or type(identifiers) is not list
                or any(type(x) is not str for x in identifiers)
                or type(all_repositories) is not bool):
            _deny()
        if operation in ("add", "update"):
            if not proposed or identifiers or all_repositories:
                _deny()
        elif operation in ("enable", "disable"):
            if proposed or not identifiers or all_repositories:
                _deny()
        elif proposed or (not identifiers and not all_repositories) or (
            all_repositories and identifiers
        ):
            _deny()
        return operation, tuple(proposed), tuple(identifiers), all_repositories
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        _deny()


def _atomic_create(path: Path, payload: bytes) -> None:
    """Durable create-if-absent; never replace a foreign or prior proposal."""
    with ExitStack() as stack:
        parent = _parent(path, stack)
        temporary = "." + path.name + ".part-" + secrets.token_hex(12)
        fd = os.open(temporary, _CREATE, 0o600, dir_fd=parent)
        temporary_stat = os.fstat(fd)
        stack.callback(os.close, fd)
        installed = False
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(os.dup(fd), "wb") as stream:
                stream.write(payload)
                stream.flush()
            os.fsync(fd)
            os.link(temporary, path.name, src_dir_fd=parent,
                    dst_dir_fd=parent, follow_symlinks=False)
            installed = True
            os.fsync(parent)
        finally:
            # Only clean up the inode that this process itself created.
            try:
                named = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                if (named.st_dev, named.st_ino) == (
                    temporary_stat.st_dev, temporary_stat.st_ino,
                ):
                    os.unlink(temporary, dir_fd=parent)
                    os.fsync(parent)
            except FileNotFoundError:
                pass
        if not installed:
            _deny()


def prepare_offline_lifecycle(
    previous: Path, request: Path, output: Path, *,
    expected_generation: int,
    expected_state_sha256: str,
    decision_sha256: str,
) -> dict[str, Any]:
    """Write a canonical exact next snapshot for separately approved staging."""
    if (type(expected_generation) is not int or expected_generation < 1
            or not _sha(expected_state_sha256)
            or not _sha(decision_sha256)):
        _deny()
    old = _read_owned(previous, _MAX_PREVIOUS)
    if hashlib.sha256(old).hexdigest() != expected_state_sha256:
        _deny()
    operation, proposed, ids, all_ids = _request(
        _read_owned(request, _MAX_REQUEST),
    )
    candidate = render_fixed_native_repository_batch_envelope(
        old, expected_generation=expected_generation,
        expected_previous_state_sha256=expected_state_sha256,
        decision_sha256=decision_sha256, operation=operation,
        proposed_repositories=proposed, repository_ids=ids,
        all_repositories=all_ids,
    )
    if (candidate["operator_approval_verified"] is not False
            or candidate["authorizes_state_write"] is not False
            or candidate["authorizes_nginx_reload"] is not False
            or candidate["authorizes_catalog_publication"] is not False
            or candidate["authorizes_cache_cleanup"] is not False):
        _deny()
    if candidate["changed"] is False:
        if candidate["envelope_bytes"] is not None:
            _deny()
        return {
            "status": "OFFLINE_LIFECYCLE_NO_CHANGE",
            "changed": False,
            "expected_generation": expected_generation,
            "requires_operator_review": True,
            "authorizes_service_activation": False,
        }
    if type(candidate["envelope_bytes"]) is not bytes:
        _deny()
    envelope = json.loads(candidate["envelope_bytes"].decode("ascii"))
    next_state = base64.b64decode(envelope["next_state_base64"], validate=True)
    if (envelope["expected_state_sha256"] != expected_state_sha256
            or envelope["expected_generation"] != expected_generation
            or hashlib.sha256(next_state).hexdigest()
               != envelope["next_state_sha256"]):
        _deny()
    _atomic_create(output, next_state)
    return {
        "status": "OFFLINE_LIFECYCLE_PROPOSAL_PREPARED",
        "changed": True,
        "state_generation": expected_generation + 1,
        "proposed_state_sha256": hashlib.sha256(next_state).hexdigest(),
        "expected_state_sha256": expected_state_sha256,
        "requires_operator_review": True,
        "authorizes_service_activation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-v2-state", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--proposal-output", required=True, type=Path)
    parser.add_argument("--expected-generation", required=True, type=int)
    parser.add_argument("--expected-state-sha256", required=True)
    parser.add_argument("--decision-sha256", required=True)
    args = parser.parse_args()
    try:
        result = prepare_offline_lifecycle(
            args.previous_v2_state, args.request, args.proposal_output,
            expected_generation=args.expected_generation,
            expected_state_sha256=args.expected_state_sha256,
            decision_sha256=args.decision_sha256,
        )
    except (OfflineLifecycleError, OSError, ValueError, TypeError,
            OverflowError, RecursionError, UnicodeError):
        print('{"status":"OFFLINE_LIFECYCLE_REFUSED"}')
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
