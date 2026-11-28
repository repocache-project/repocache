#!/usr/bin/env python3
"""Booted #95/#28 native lifecycle smoke with an installed test-signed worker.

Runs only in pinned disposable Debian 13 / AlmaLinux 10 QEMU guests. The
operator requests, trust key, upstreams and TLS identity are test fixtures;
this is NOT publisher acceptance, real upstream APT/DNF integrity or cleanup
authority. No production host, CLI contract or client source is touched.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
import stat
import sys
import time

from ci_pr237_native_socket_guest import (
    accounts, assert_disabled, assert_static_socket, command, https_response,
    snapshot, synthetic_local_tls, unmanaged_nginx_snapshot,
)

FIXTURE = Path("/root/pr237-synthetic-fixture")
STATE = Path("/var/lib/repocache/server")
CATALOG = Path("/var/lib/repocache/public/catalog.json")
SOURCE = Path("/home/pr237ci/combined")
WAL = STATE / ".state-v2-native.pending"


def owned_file(path: Path, raw: bytes) -> Path:
    assert not path.exists() and not path.is_symlink()
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0
    assert stat.S_IMODE(info.st_mode) == 0o600 and path.read_bytes() == raw
    return path


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def active_catalog_is_empty(generation: int) -> bytes:
    raw = CATALOG.read_bytes()
    observed = json.loads(raw)
    assert observed["schema"] == 1 and observed["repositories"] == []
    assert https_response("/.well-known/repocache/catalog.json").endswith(raw)
    assert (
        ("x-repocache-generation: " + str(generation)).encode("ascii")
        in https_response("/__repocache/healthz").lower()
    )
    return raw


def main(distribution: str) -> None:
    assert distribution in ("debian", "almalinux")
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert command("/usr/bin/systemd-detect-virt", "--vm") in ("qemu", "kvm")
    if distribution == "almalinux":
        assert command("/usr/sbin/getenforce") == "Enforcing"
    assert not (STATE / "state-v2.json").exists()
    assert (STATE / ".admin-candidate-v2.json").is_file()
    assert not WAL.exists()

    sys.path[:0] = [str(SOURCE / "src"), str(SOURCE), str(SOURCE / "scripts")]
    from repocache.server_native_root_control_client_v1 import (
        NativeRootControlClientError, request_native_fixed_v2,
    )
    from scripts import install_native_root_worker
    from scripts.prepare_server_repository_lifecycle import (
        OfflineLifecycleError, prepare_offline_lifecycle,
    )

    pins = json.loads((FIXTURE / "pins.json").read_bytes())
    assert set(pins) == {"commit", "archive_sha256"}
    assets = FIXTURE / "assets"

    def fixed(operation: str) -> dict:
        # Installed root worker is a systemd one-shot with strict rate limits.
        time.sleep(3)
        try:
            return request_native_fixed_v2(operation)
        except NativeRootControlClientError:
            # Report only the worker's fixed redacted transaction vocabulary.
            logs = subprocess.run(
                ["/usr/bin/journalctl", "-u", "repocache-control.service",
                 "--no-pager", "--quiet", "-n", "50", "-o", "cat"],
                capture_output=True, text=True, timeout=12, check=False)
            for line in logs.stdout.splitlines()[-50:]:
                for code in re.findall(r"REPOCACHE_FIXED_TRANSACTION_REFUSAL: (NATIVE_V2_[A-Z0-9_]{2,100})", line):
                    print("NATIVE_LIFECYCLE_DIAGNOSTIC: " + code, flush=True)
            raise

    def prepare(operation: str, selectors: dict, generation: int, name: str):
        raw_prior = (STATE / "state-v2.json").read_bytes()
        digest = hashlib.sha256(raw_prior).hexdigest()
        previous = owned_file(FIXTURE / (name + "-previous.json"), raw_prior)
        request = owned_file(
            FIXTURE / (name + "-request.json"),
            canonical({"operation": operation, **selectors}),
        )
        output = FIXTURE / (name + "-candidate.json")
        planned = prepare_offline_lifecycle(
            previous, request, output,
            expected_generation=generation,
            expected_state_sha256=digest,
            decision_sha256=hashlib.sha256(name.encode("ascii")).hexdigest(),
        )
        assert planned["status"] == "OFFLINE_LIFECYCLE_PROPOSAL_PREPARED"
        assert planned["state_generation"] == generation + 1
        assert planned["authorizes_service_activation"] is False
        assert planned["requires_operator_review"] is True
        assert planned["proposed_state_sha256"] == hashlib.sha256(
            output.read_bytes(),
        ).hexdigest()
        return output, digest, planned

    accounts()
    synthetic_local_tls(distribution)
    vendor_before = unmanaged_nginx_snapshot()
    command("/usr/bin/systemctl", "daemon-reload")
    command("/usr/bin/systemctl", "start", "nginx.service", timeout=35)
    command("/usr/bin/systemctl", "start", "repocache-control.socket")
    assert_static_socket()
    assert_disabled("nginx.service")

    first = fixed("APPLY_V2")
    assert first["status"] == "APPLIED" and first["state_generation"] == 1
    assert first["nginx_reload_and_exposure_observed"] is True
    assert first["active_catalog_published"] is True
    initial_catalog = active_catalog_is_empty(1)
    initial_state = json.loads((STATE / "state-v2.json").read_bytes())
    assert initial_state["state_generation"] == 1
    assert len(initial_state["repository_records"]) == 2
    assert all(row["desired_state"] == "disabled"
               for row in initial_state["repository_records"])
    before = snapshot()
    print("PASS: real installed root worker activated empty-only generation one with matching HTTPS catalog", flush=True)

    doc = json.loads(
        base64.b64decode(initial_state["configuration_base64"], validate=True)
    )
    extra = copy.deepcopy(doc["repositories"][0])
    extra.pop("id", None)
    extra["desired_state"] = "disabled"
    extra["upstream"]["base_url"] = "https://native-extra.example.invalid/debian/"
    extra["upstream"]["allowed_hosts"] = ["native-extra.example.invalid"]
    candidate, prior_sha, planned = prepare(
        "add", {"proposed_repositories": [extra]}, 1, "pr95-add",
    )
    proposed = json.loads(candidate.read_bytes())
    previous_ids = {row["id"] for row in initial_state["repository_records"]}
    proposed_ids = {row["id"] for row in proposed["repository_records"]}
    added = proposed_ids - previous_ids
    assert len(added) == 1
    identifier = next(iter(added))
    assert identifier.startswith("repo-")
    assert {row["desired_state"] for row in proposed["repository_records"]} == {
        "disabled",
    }
    assert snapshot() == before
    assert active_catalog_is_empty(1) == initial_catalog

    # An untrusted invalid operation is refused before it can be staged.
    wrong = owned_file(FIXTURE / "pr95-invalid-request.json", canonical({
        "operation": "enable", "repository_ids": ["../../etc/passwd"],
    }))
    try:
        prepare_offline_lifecycle(
            FIXTURE / "pr95-add-previous.json", wrong, None,
            expected_generation=1, expected_state_sha256=prior_sha,
            decision_sha256="a" * 64, dry_run=True,
        )
    except ValueError:
        # Source planners may raise their own fixed-code ValueError rather
        # than the offline file-boundary wrapper exception.
        pass
    else:
        raise AssertionError("Unsafe repository ID generated a native candidate")
    assert snapshot() == before and not WAL.exists()

    staged = install_native_root_worker.stage_authenticated_proposal(
        assets, candidate, proposal_sha256=planned["proposed_state_sha256"],
        expected_state_sha256=prior_sha, **pins,
    )
    assert staged["status"] == "AUTHENTICATED_V2_PROPOSAL_STAGED"
    assert staged["expected_generation"] == 1
    assert snapshot() == before and active_catalog_is_empty(1) == initial_catalog
    added_live = fixed("APPLY_V2")
    assert (added_live["status"], added_live["state_generation"]) == ("APPLIED", 2)
    assert added_live["nginx_reload_and_exposure_observed"]
    assert added_live["active_catalog_published"]
    assert not WAL.exists()
    assert active_catalog_is_empty(2) == initial_catalog
    live = json.loads((STATE / "state-v2.json").read_bytes())
    assert {r["id"] for r in live["repository_records"]} == proposed_ids
    assert next(r for r in live["id_reservations"] if r["id"] == identifier)[
        "status"
    ] == "allocated"
    assert fixed("RECOVER_V2")["status"] == "CLEAN"
    print("PASS: booted native test-signed worker committed automatic-ID disabled repository and withheld all inactive routes from public HTTPS discovery", flush=True)

    # A genuine cache object is NOT claimed here: this is an independently
    # owned test marker proving the native normal-remove path does not purge
    # retained bytes. Cache-object attribution and force-cleanup remain open.
    retained = Path("/var/cache/nginx/repocache-managed") / (
        "pr95-preserved-" + identifier
    )
    retained.parent.mkdir(parents=True, exist_ok=True)
    raw_retained = b"REPOCACHE_DISPOSABLE_NORMAL_REMOVAL_RETENTION\n"
    owned_file(retained, raw_retained)
    retained_inode = retained.lstat().st_ino
    removed_candidate, old_sha, removal_plan = prepare(
        "remove", {"repository_ids": [identifier]}, 2, "pr95-remove",
    )
    assert snapshot() != before
    staged_remove = install_native_root_worker.stage_authenticated_proposal(
        assets, removed_candidate,
        proposal_sha256=removal_plan["proposed_state_sha256"],
        expected_state_sha256=old_sha, **pins,
    )
    assert staged_remove["expected_generation"] == 2
    assert active_catalog_is_empty(2) == initial_catalog
    withdrawn = fixed("APPLY_V2")
    assert (withdrawn["status"], withdrawn["state_generation"]) == ("APPLIED", 3)
    assert not WAL.exists()
    assert active_catalog_is_empty(3) == initial_catalog
    after = json.loads((STATE / "state-v2.json").read_bytes())
    assert {r["id"] for r in after["repository_records"]} == previous_ids
    reserved = next(r for r in after["id_reservations"] if r["id"] == identifier)
    assert reserved["status"] == "retired"
    assert {r["id"] for r in after["id_reservations"]} == proposed_ids
    assert retained.read_bytes() == raw_retained
    assert retained.lstat().st_ino == retained_inode
    assert fixed("RECOVER_V2")["status"] == "CLEAN"
    assert fixed("RELOAD_V2")["status"] == "RELOADED"
    assert unmanaged_nginx_snapshot() == vendor_before

    # Exact old reviewed candidate cannot be replayed after the protected
    # predecessor has advanced, even if its detached signature was valid.
    safe_before = snapshot()
    try:
        install_native_root_worker.stage_authenticated_proposal(
            assets, candidate, proposal_sha256=planned["proposed_state_sha256"],
            expected_state_sha256=prior_sha, **pins,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Stale previously signed proposal was restaged")
    assert snapshot() == safe_before and not WAL.exists()

    # An actual systemd service restart must preserve the committed ID
    # history and atomically visible inactive-only catalog, not resurrect
    # the retired route or weaken SELinux enforcement.
    command("/usr/bin/systemctl", "restart", "nginx.service", timeout=35)
    assert active_catalog_is_empty(3) == initial_catalog
    assert (STATE / "state-v2.json").read_bytes() == canonical(after)
    assert retained.read_bytes() == raw_retained
    assert retained.lstat().st_ino == retained_inode
    assert unmanaged_nginx_snapshot() == vendor_before
    if distribution == "almalinux":
        assert command("/usr/sbin/getenforce") == "Enforcing"
    command("/usr/bin/systemctl", "stop", "repocache-control.socket")
    command("/usr/bin/systemctl", "stop", "nginx.service")
    assert_static_socket()
    assert_disabled("nginx.service")
    print(
        "PASS: booted native test-signed repository add/remove and durable "
        "tombstone across NGINX restart; inactive HTTPS catalog stayed empty; "
        "synthetic retained bytes/inode survived; stale proposal refused",
        flush=True,
    )
    print("NOT VERIFIED: active approved upstream cache MISS/HIT, real APT/DNF signatures, force-cleanup, owner-signed release", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("debian", "almalinux"):
        raise SystemExit("Usage: ci_v06_native_repository_lifecycle_guest.py debian|almalinux")
    main(sys.argv[1])
