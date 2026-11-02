"""Read-only managed NGINX include manifest/drift preview (#31, #18).

Snapshots supplied by the caller are NEVER proof of file ownership, safe path
traversal, trusted manifest provenance or administrator authorization. The
future fixed-purpose privileged engine must independently acquire its lock,
re-read protected state, verify inodes with dirfds/O_NOFOLLOW, stage candidate
files, run nginx -t, reload and recover before it can change any live state.

No filesystem, DNS, subprocess or service operations happen in this module.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from repocache.server_install_v1 import MAX_INT, validate_install_document

MAX_CANDIDATE_BYTES = 256 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MANIFEST_KEYS = frozenset({
    "schema_version", "generation", "path", "sha256",
    "uid", "gid", "mode", "dev", "ino",
})
_OBSERVED_KEYS = frozenset({
    "path", "kind", "sha256", "uid", "gid", "mode", "dev", "ino", "nlink",
})
_SAFE_MODES = frozenset({0o600, 0o640, 0o644})


class ManagedIncludePreviewError(ValueError):
    """Fail-closed preview refusal; diagnostics never include caller values."""


def _fail(code: str) -> None:
    raise ManagedIncludePreviewError(code)


def _integer(value: Any, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= MAX_INT


def _metadata(record: Any, *, manifest: bool, path: str) -> dict[str, Any]:
    keys = _MANIFEST_KEYS if manifest else _OBSERVED_KEYS
    if type(record) is not dict or record.keys() != keys:
        _fail("MANIFEST_OR_OBSERVATION_SCHEMA_INVALID")
    if record["path"] != path or type(record["path"]) is not str:
        _fail("MANAGED_INCLUDE_PATH_MISMATCH")
    if type(record["sha256"]) is not str or not _SHA256.fullmatch(record["sha256"]):
        _fail("MANAGED_INCLUDE_HASH_INVALID")
    if (not _integer(record["uid"]) or record["uid"] != 0
            or not _integer(record["gid"])
            or type(record["mode"]) is not int
            or record["mode"] not in _SAFE_MODES
            or not _integer(record["dev"], minimum=1)
            or not _integer(record["ino"], minimum=1)):
        _fail("MANAGED_INCLUDE_UNSAFE_METADATA")
    if manifest:
        if record["schema_version"] != 1 or type(record["schema_version"]) is not int:
            _fail("MANIFEST_SCHEMA_UNSUPPORTED")
        if not _integer(record["generation"], minimum=1):
            _fail("MANIFEST_GENERATION_INVALID")
    else:
        if record["kind"] != "regular" or type(record["kind"]) is not str:
            _fail("MANAGED_INCLUDE_NOT_REGULAR")
        if type(record["nlink"]) is not int or record["nlink"] != 1:
            _fail("MANAGED_INCLUDE_HARDLINK_OR_UNKNOWN")
    return record


def preview_managed_include(
    document: dict[str, Any],
    *,
    current_generation: int,
    candidate_bytes: bytes,
    previous_manifest: dict[str, Any] | None,
    observed_file: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare a candidate with strict caller snapshots, *never* authorizing a write.

    The candidate is untrusted, not parsed as NGINX syntax. A successful report
    cannot establish that the manifest came from protected state or that the
    observed file/inode or its parent directories were checked on the live host.
    No caller snapshot can become a privileged write token.
    """
    if not _integer(current_generation):
        _fail("CURRENT_GENERATION_INVALID")
    validated = validate_install_document(document, for_apply=True)
    if validated["expected_state_generation"] != current_generation:
        _fail("STALE_STATE_GENERATION")
    if (type(candidate_bytes) is not bytes
            or not 1 <= len(candidate_bytes) <= MAX_CANDIDATE_BYTES
            or b"\x00" in candidate_bytes):
        _fail("MANAGED_INCLUDE_CANDIDATE_INVALID")
    try:
        candidate_bytes.decode("utf-8", "strict")
    except UnicodeError:
        _fail("MANAGED_INCLUDE_CANDIDATE_NOT_UTF8")
    path = validated["deployment"]["paths"]["generated_include"]
    # Existing paths without a recorded managed manifest are foreign by
    # default. Likewise a manifest whose file disappeared is drift, not a
    # license to recreate/reclaim the name.
    if previous_manifest is None:
        if observed_file is not None:
            _fail("FOREIGN_INCLUDE_REFUSED")
        action = "WOULD_CREATE"
    else:
        previous = _metadata(previous_manifest, manifest=True, path=path)
        if previous["generation"] > current_generation:
            _fail("MANIFEST_GENERATION_AHEAD")
        if observed_file is None:
            _fail("MANAGED_INCLUDE_MISSING")
        observed = _metadata(observed_file, manifest=False, path=path)
        if any(previous[key] != observed[key] for key in
               ("sha256", "uid", "gid", "mode", "dev", "ino")):
            _fail("MANAGED_INCLUDE_DRIFT")
        digest = hashlib.sha256(candidate_bytes).hexdigest()
        action = ("UNCHANGED" if digest == previous["sha256"]
                  else "WOULD_REPLACE")
    return {
        "schema_version": 1,
        "status": "PREVIEW_ONLY",
        "action": action,
        "changed": action != "UNCHANGED",
        "current_generation": current_generation,
        "authorizes_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
        "protected_manifest_provenance_verified": False,
        "live_filesystem_ownership_verified": False,
        "nginx_syntax_verified": False,
    }
