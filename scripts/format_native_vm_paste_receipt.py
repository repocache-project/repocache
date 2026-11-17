#!/usr/bin/env python3
"""Redacted paste-ready subset of a read-only #19 candidate receipt (#20).

This stdin/stdout-only formatter cannot certify native VM or release acceptance,
access a host, or add operator authority. It intentionally has no success exit.
"""
from __future__ import annotations

import json
import re
import sys

_MAX_INPUT = 16 * 1024
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_CODES = frozenset((
    "CANDIDATE_UNAVAILABLE", "CANDIDATE_PATH_REFUSED",
    "CANDIDATE_INODE_REFUSED", "CANDIDATE_DRIFT_REFUSED",
    "CANDIDATE_DIGEST_MISMATCH", "DIGEST_MATCH_NATIVE_READONLY_OBSERVED",
    "DIGEST_MATCH_NATIVE_EVIDENCE_PENDING",
))
_NATIVE_CODES = frozenset((
    "NATIVE_OBSERVATION_NOT_EXECUTED", "SUPPORTED_OS_NOT_OBSERVED",
    "ROOT_READ_ONLY_PROBE_REQUIRED", "CONTAINER_CONTEXT_REFUSED",
    "SYSTEMD_PID1_NOT_OBSERVED",
    "SYSTEMD_NAMESPACE_OR_RUNTIME_NOT_OBSERVED",
    "ALMALINUX_SELINUX_ENFORCING_NOT_OBSERVED",
    "EFFECTIVE_NGINX_NOT_OBSERVED", "OBSERVATION_ONLY_NO_HOST_AUTHORITY",
))
_IDENTITY_INPUT_REFUSED = "CANDIDATE_IDENTITY_INPUT_REFUSED"
_NO_AUTHORITY = {
    "complete_server_acceptance_passed": False,
    "authorizes_host_write": False,
    "authorizes_publication": False,
}


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _receipt(data: bytes) -> dict:
    if not 1 <= len(data) <= _MAX_INPUT:
        raise ValueError("invalid input size")
    try:
        item = json.loads(data.decode("utf-8", "strict"),
                          object_pairs_hook=_unique,
                          parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("invalid receipt JSON") from exc
    if type(item) is not dict or type(item.get("schema_version")) is not int or item["schema_version"] != 1:
        raise ValueError("invalid receipt shape")
    if item.get("code") == _IDENTITY_INPUT_REFUSED:
        # The collector has no valid identity to include in this outcome.
        if (set(item) != {"schema_version", "status", "code", *_NO_AUTHORITY}
                or item["status"] != "FAIL"
                or any(item[key] is not False for key in _NO_AUTHORITY)):
            raise ValueError("invalid identity refusal")
        return {
            "kind": "repocache.native.candidate.paste.v1",
            "status": "FAIL",
            "code": _IDENTITY_INPUT_REFUSED,
            **_NO_AUTHORITY,
        }
    sha, expected, observed = (item.get("source_commit_sha"),
                               item.get("expected_artifact_sha256"),
                               item.get("observed_artifact_sha256"))
    matched = item.get("artifact_digest_matched")
    native = item.get("native_prerequisites_observed")
    size = item.get("artifact_size_bytes")
    distribution = item.get("native_distribution")
    enforcing = item.get("native_selinux_enforcing_reported", False)
    if (type(sha) is not str or _SHA40.fullmatch(sha) is None
            or type(expected) is not str or _SHA64.fullmatch(expected) is None
            or (observed is not None and
                (type(observed) is not str or _SHA64.fullmatch(observed) is None))
            or type(matched) is not bool or type(native) is not bool
            or (size is not None and
                (type(size) is not int or not 1 <= size <= 2 * 1024**3))
            or matched is not (observed == expected)
            or (matched and size is None)
            or (not matched and native)
            or distribution not in (None, "debian", "almalinux")
            or type(enforcing) is not bool
            or (not matched and distribution is not None)
            or (enforcing and distribution != "almalinux")
            or (native and distribution == "almalinux" and not enforcing)
            or item.get("status") not in ("FAIL", "NOT VERIFIED")
            or type(item.get("status")) is not str
            or type(item.get("code")) is not str or item["code"] not in _CODES
            or type(item.get("native_probe_code")) is not str
            or item["native_probe_code"] not in _NATIVE_CODES
            or item.get("complete_server_acceptance_passed") is not False
            or item.get("authorizes_host_write") is not False
            or item.get("authorizes_publication") is not False):
        raise ValueError("contradictory or unsafe receipt")
    # Every collector outcome has a unique, non-authorizing evidence shape.
    # A forged positive digest must not be labelled as unreadable input,
    # and a mismatch must never be softened to NOT VERIFIED.
    code = item["code"]
    native_code = item["native_probe_code"]
    if (enforcing and native_code not in (
        "EFFECTIVE_NGINX_NOT_OBSERVED", "OBSERVATION_ONLY_NO_HOST_AUTHORITY",
    )) or (distribution is not None and native_code in (
        "NATIVE_OBSERVATION_NOT_EXECUTED", "SUPPORTED_OS_NOT_OBSERVED",
    )):
        raise ValueError("contradictory platform observation")
    if any(
        (key.startswith("authorizes_") or key.endswith("_verified"))
        and value is not False
        for key, value in item.items()
    ):
        raise ValueError("forged positive authorization")
    if code in {
        "CANDIDATE_UNAVAILABLE", "CANDIDATE_PATH_REFUSED",
        "CANDIDATE_INODE_REFUSED", "CANDIDATE_DRIFT_REFUSED",
    }:
        consistent = (
            item["status"] == "NOT VERIFIED" and observed is None
            and size is None and not matched and not native
            and native_code == "NATIVE_OBSERVATION_NOT_EXECUTED"
        )
    elif code == "CANDIDATE_DIGEST_MISMATCH":
        consistent = (
            item["status"] == "FAIL" and observed is not None
            and size is not None and not matched and not native
            and native_code == "NATIVE_OBSERVATION_NOT_EXECUTED"
        )
    elif code == "DIGEST_MATCH_NATIVE_READONLY_OBSERVED":
        consistent = (
            item["status"] == "NOT VERIFIED" and matched and native
            and native_code == "OBSERVATION_ONLY_NO_HOST_AUTHORITY"
        )
    else:  # DIGEST_MATCH_NATIVE_EVIDENCE_PENDING
        consistent = (
            item["status"] == "NOT VERIFIED" and matched and not native
        )
    if not consistent:
        raise ValueError("contradictory receipt outcome")
    return {
        "kind": "repocache.native.candidate.paste.v1",
        "status": item["status"],
        "code": item["code"],
        "source_sha": sha,
        "candidate_sha256": observed,
        "digest_matched": matched,
        "native_distribution": distribution,
        "native_probe_code": native_code,
        "native_selinux_enforcing_reported": enforcing,
        "native_prerequisites_reported_only": native,
        **_NO_AUTHORITY,
    }


def main() -> int:
    try:
        data = sys.stdin.buffer.read(_MAX_INPUT + 1)
        result = _receipt(data)
    except (OSError, ValueError):
        result = {
            "kind": "repocache.native.candidate.paste.v1",
            "status": "NOT VERIFIED",
            "code": "INPUT_REFUSED",
            **_NO_AUTHORITY,
        }
    print("REPOCACHE_VM_EVIDENCE_V1=" +
          json.dumps(result, sort_keys=True, separators=(",", ":")))
    # No successful exit: even a real SHA match is only a partial observation.
    return 1 if result["status"] == "FAIL" else 2


if __name__ == "__main__":
    raise SystemExit(main())
