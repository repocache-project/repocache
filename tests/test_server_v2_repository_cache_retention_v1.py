"""#95 Stage-A Linux fixture: persistent retired IDs outlive process/cache restarts.

All writes are to a newly made detached pytest temporary root. This is not
an installed or privileged host transaction; neither catalog nor NGINX is
activated. The actual kernel FD lock, state-v2 journal, and cache marker
functions are intentionally exercised together across a fresh Python process.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from repocache.server_locked_manifest_reconcile_v1 import (
    LockedManifestInspectionError,
)
from repocache.server_native_repository_cache_v1 import (
    bootstrap_repository_cache_under_root,
)
from repocache.server_native_storage_bootstrap_v1 import (
    bootstrap_native_nginx_storage_under_root,
)
from repocache.server_proposed_state_v2_store import (
    V2_JOURNAL, V2_STATE, ProposedV2PersistenceError,
    _commit_proposed_v2_under_root as commit,
    _recover_proposed_v2_under_root as recover,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_repository_plan_v1 import _canonical_identity

ROOT = Path(__file__).resolve().parents[1]
APT = "debian-trixie-main"
DNF = "almalinux-baseos"
DIGEST = "0123456789abcdef0123456789abcdef"


def document():
    data = json.loads(
        (ROOT / "docs/examples/server-install-v1.json").read_text("utf-8")
    )
    data["repositories"][1]["id"] = DNF
    for row in data["repositories"]:
        row["desired_state"] = "active"
    return data


def versioned(doc: dict, generation: int, previous: dict | None = None):
    source = copy.deepcopy(doc)
    source["expected_state_generation"] = generation
    raw = json.dumps(
        source, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")
    records = [{
        "id": row["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(row).encode("utf-8")
        ).hexdigest(),
        "desired_state": row["desired_state"],
        "observed_state": "not-activated",
    } for row in source["repositories"]]
    reservations = [{
        "id": row["id"],
        "canonical_identity_sha256": row["canonical_identity_sha256"],
        "status": "allocated",
    } for row in records]
    present = {row["id"] for row in records}
    if previous is not None:
        for row in previous["id_reservations"]:
            if row["id"] not in present:
                reservations.append({**row, "status": "retired"})
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "state_schema_version": 2,
        "state_generation": generation,
        "configuration_base64": base64.b64encode(raw).decode("ascii"),
        "configuration_sha256": digest,
        "repository_records": records,
        "id_reservations": reservations,
        "approval_reference": {
            "source": "operator",
            "decision_sha256": "d" * 64,
            "configuration_sha256": digest,
            "expected_generation": generation - 1,
        },
    }


@pytest.fixture
def detached(tmp_path):
    root = tmp_path / "detached-root"
    root.mkdir(mode=0o700)
    for path in ("var", "var/lib", "var/lib/repocache",
                 "var/lib/repocache/server", "var/cache",
                 "var/cache/nginx", "var/log", "var/log/nginx"):
        (root / path).mkdir(mode=0o700)
    state = root / "var/lib/repocache/server"
    (state / LOCK_NAME).write_bytes(b"")
    (state / LOCK_NAME).chmod(0o600)
    uid, gid = os.geteuid(), os.getegid()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        bootstrap_native_nginx_storage_under_root(
            fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        )
        for rid in (APT, DNF):
            bootstrap_repository_cache_under_root(
                fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
                repository_id=rid,
            )
        owned = root / "var/cache/nginx/repocache-managed" / DNF
        package = owned / "a" / "bc" / DIGEST
        package.parent.mkdir(mode=0o700, parents=True)
        package.write_bytes(b"retired-cache-content-must-survive")
        yield root, state, fd, uid, gid, package
    finally:
        os.close(fd)


def _save(fd, uid, value, expected):
    return commit(
        fd, value, owner_uid=uid, expected_generation=expected,
    )


def test_retirement_and_fresh_process_preserve_all_time_id_and_cache(detached):
    root, state, fd, uid, gid, package = detached
    original_doc = document()
    first = versioned(original_doc, 1)
    assert _save(fd, uid, first, 0)["status"] == "COMMITTED_INERT_V2"
    retired_doc = copy.deepcopy(original_doc)
    retired_doc["repositories"] = [
        r for r in retired_doc["repositories"] if r["id"] != DNF
    ]
    second = versioned(retired_doc, 2, first)
    assert _save(fd, uid, second, 1)["status"] == "COMMITTED_INERT_V2"
    saved = (state / V2_STATE).read_bytes()
    baseline = (package.stat().st_ino, hashlib.sha256(package.read_bytes()).hexdigest())
    assert {x["id"]: x["status"] for x in second["id_reservations"]} == {
        APT: "allocated", DNF: "retired",
    }
    assert not (state / V2_JOURNAL).exists()

    # This is a real new Python interpreter and reopened Linux root FD, not
    # reuse of the previous caller's in-memory v2 ledger or an NGINX mock.
    child = r"""
import json
import os
import sys
from pathlib import Path
from repocache.server_proposed_state_v2_store import (
    V2_STATE, _recover_proposed_v2_under_root,
)
from repocache.server_native_repository_cache_v1 import (
    bootstrap_repository_cache_under_root,
)
root = Path(sys.argv[1])
fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    report = _recover_proposed_v2_under_root(fd, owner_uid=os.geteuid())
    assert report["status"] == "CLEAN"
    record = json.loads((root / "var/lib/repocache/server" / V2_STATE).read_bytes())
    ids = {r["id"]: r["status"] for r in record["id_reservations"]}
    assert ids == {"debian-trixie-main": "allocated", "almalinux-baseos": "retired"}
    cache = bootstrap_repository_cache_under_root(
        fd, root_uid=os.geteuid(), cache_uid=os.geteuid(),
        cache_gid=os.getegid(), repository_id="almalinux-baseos",
    )
    assert cache["directory_created"] is False
    assert cache["existing_cache_contents_preserved"] is True
    assert cache["authorizes_cache_cleanup"] is False
    print("REOPENED_V2_LEDGER_AND_RETAINED_CACHE_PASS")
finally:
    os.close(fd)
"""
    child_run = subprocess.run(
        [sys.executable, "-c", child, str(root)],
        capture_output=True, text=True, check=False, timeout=15,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src"),
             "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert child_run.returncode == 0, child_run.stderr[-1600:]
    assert child_run.stdout.strip() == "REOPENED_V2_LEDGER_AND_RETAINED_CACHE_PASS"
    assert (state / V2_STATE).read_bytes() == saved
    assert (package.stat().st_ino, hashlib.sha256(package.read_bytes()).hexdigest()) == baseline

    # Even the original identical retired identifier must never be
    # resurrected. Rebinding it to a foreign upstream is also forbidden.
    for replace_origin in (False, True):
        unsafe = copy.deepcopy(original_doc)
        if replace_origin:
            unsafe["repositories"][1]["upstream"]["base_url"] = (
                "https://mirror.example.invalid/unrelated/"
            )
        rebound = versioned(unsafe, 3, second)
        with pytest.raises(
            (LockedManifestInspectionError, ProposedV2PersistenceError),
            match="RESERVATION_HISTORY_CHANGED|TRANSITION_INVALID",
        ):
            _save(fd, uid, rebound, 2)
        assert (state / V2_STATE).read_bytes() == saved
        assert not (state / V2_JOURNAL).exists()

    # A truly new independent source with a distinct ID can be adopted
    # only as an additional inert candidate. The old cache and tombstone
    # remain pinned; no hidden cleanup or retroactive ID reassignment.
    successor_doc = copy.deepcopy(retired_doc)
    new = copy.deepcopy(original_doc["repositories"][1])
    new["id"] = "fresh-dnf-repository"
    new["upstream"]["base_url"] = (
        "https://mirror.example.invalid/independent-repo/"
    )
    successor_doc["repositories"].append(new)
    third = versioned(successor_doc, 3, second)
    assert _save(fd, uid, third, 2)["status"] == "COMMITTED_INERT_V2"
    assert {r["id"]: r["status"] for r in third["id_reservations"]} == {
        APT: "allocated", "fresh-dnf-repository": "allocated", DNF: "retired",
    }
    new_cache = bootstrap_repository_cache_under_root(
        fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        repository_id="fresh-dnf-repository",
    )
    assert new_cache["directory_created"] is True
    assert (package.stat().st_ino, hashlib.sha256(package.read_bytes()).hexdigest()) == baseline
    assert recover(fd, owner_uid=uid)["status"] == "CLEAN"


def test_interrupted_retirement_requires_recovery_without_cache_purge(detached):
    _, state, fd, uid, _, package = detached
    original_doc = document()
    first = versioned(original_doc, 1)
    assert _save(fd, uid, first, 0)["status"] == "COMMITTED_INERT_V2"
    old_state = (state / V2_STATE).read_bytes()
    old_cache = package.read_bytes()
    reduced = copy.deepcopy(original_doc)
    reduced["repositories"] = [
        row for row in reduced["repositories"] if row["id"] != DNF
    ]
    retired = versioned(reduced, 2, first)

    def crash_at_durable_journal(phase):
        if phase == "journal_durable":
            raise RuntimeError("INJECTED_DETACHED_CRASH")

    with pytest.raises(RuntimeError, match="INJECTED_DETACHED_CRASH"):
        commit(
            fd, retired, owner_uid=uid, expected_generation=1,
            inject_fault=crash_at_durable_journal,
        )
    assert (state / V2_JOURNAL).is_file()
    assert package.read_bytes() == old_cache
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        _save(fd, uid, retired, 1)
    result = recover(fd, owner_uid=uid)
    assert result["status"] == "ROLLED_BACK_INERT_V2"
    assert (state / V2_STATE).read_bytes() == old_state
    assert not (state / V2_JOURNAL).exists()
    assert package.read_bytes() == old_cache
    assert _save(fd, uid, retired, 1)["status"] == "COMMITTED_INERT_V2"
    assert package.read_bytes() == old_cache
