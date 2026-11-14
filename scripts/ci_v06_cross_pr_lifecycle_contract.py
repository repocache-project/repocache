"""Read-only CI integration of existing #95/#31/#28/#24 proposal contracts.

This script ONLY executes in the ephemeral five-PR merge rehearsal, not
in production or as an operator entrypoint. Root state path is always a
fresh descriptor-pinned temporary fake root; no real /etc/nginx, package
manager, public catalog or installed service is changed. Any pretend
approval-reference hash is TEST DATA, never operator authentication.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from repocache.server_repository_plan_v1 import (
    _canonical_identity, propose_automatic_repository_id,
)
from repocache.server_repository_reconcile_v1 import (
    ReconciliationPlanError,
    preview_repository_auto_add_nginx_from_untrusted_document,
    preview_repository_lifecycle_nginx_from_untrusted_document,
)
from repocache.server_proposed_state_v2_store import (
    V2_STATE, _commit_proposed_v2_under_root,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)
from repocache.server_derived_catalog_candidate_v1 import (
    preview_derived_catalog_from_nginx_dump,
)

_CA = (
    "/etc/ssl/certs/ca-certificates.crt"
    if Path("/etc/ssl/certs/ca-certificates.crt").exists()
    else "/etc/pki/tls/certs/ca-bundle.crt"
)


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("ascii")


def state(document: dict, *, generation: int, previous: dict | None) -> dict:
    config = copy.deepcopy(document)
    config["expected_state_generation"] = generation
    raw = canonical_bytes(config)
    records = [{
        "id": r["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(r).encode("utf-8")
        ).hexdigest(),
        "desired_state": r["desired_state"],
        "observed_state": "not-activated",
    } for r in config["repositories"]]
    reserved = [{
        "id": r["id"],
        "canonical_identity_sha256": r["canonical_identity_sha256"],
        "status": "allocated",
    } for r in records]
    if previous is not None:
        in_use = {r["id"] for r in records}
        for r in previous["id_reservations"]:
            if r["id"] not in in_use:
                reserved.append({**r, "status": "retired"})
    sha = hashlib.sha256(raw).hexdigest()
    return {
        "state_schema_version": 2,
        "state_generation": generation,
        "configuration_base64": base64.b64encode(raw).decode("ascii"),
        "configuration_sha256": sha,
        "repository_records": records,
        "id_reservations": reserved,
        "approval_reference": {
            "source": "operator",
            "decision_sha256": "d" * 64,
            "configuration_sha256": sha,
            "expected_generation": generation - 1,
        },
    }


def config_from_state(saved: dict) -> dict:
    raw = base64.b64decode(saved["configuration_base64"], validate=True)
    assert hashlib.sha256(raw).hexdigest() == saved["configuration_sha256"]
    return json.loads(raw)


def syntax_checked_candidate(doc: dict, pins: dict, root: Path) -> dict:
    candidate = render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=doc["expected_state_generation"],
        candidate_pins_by_repository=pins, ca_bundle_path=_CA,
    )
    config = root / "nginx-candidate.conf"
    config.write_text(
        f"pid {root / 'nginx.pid'};\n"
        f"error_log {root / 'nginx-error.log'} notice;\n"
        "events { worker_connections 32; }\nhttp {\n"
        + candidate["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19991;\n"
        + candidate["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    finished = subprocess.run(
        ["/usr/sbin/nginx", "-T", "-c", str(config), "-p", str(root)],
        shell=False, check=False, capture_output=True, text=True, timeout=10,
    )
    assert finished.returncode == 0, "fixed throwaway NGINX candidate rejected"
    result = preview_derived_catalog_from_nginx_dump(
        doc, candidate_pins_by_repository=pins, ca_bundle_path=_CA,
        nginx_dump_text=finished.stdout,
        nginx_t_exit_code=finished.returncode,
    )
    assert result["authorizes_catalog_publication"] is False
    assert result["actual_active_exposure_verified"] is False
    return result


def main() -> None:
    example = Path("docs/examples/server-install-v1.json")
    original = json.loads(example.read_text(encoding="utf-8"))
    original["repositories"][1]["id"] = "almalinux-baseos"
    for row in original["repositories"]:
        row["desired_state"] = "disabled"
    original["expected_state_generation"] = 1

    with tempfile.TemporaryDirectory(prefix="repocache-cross-lifecycle-") as dirname:
        root = Path(dirname) / "mock-root"
        root.mkdir(mode=0o700)
        state_dir = root
        for part in ("var", "lib", "repocache", "server"):
            state_dir = state_dir / part
            state_dir.mkdir(mode=0o700)
        lock = state_dir / LOCK_NAME
        lock.write_bytes(b"")
        lock.chmod(0o600)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        uid = os.geteuid()
        try:
            initial = state(original, generation=1, previous=None)
            assert _commit_proposed_v2_under_root(
                fd, initial, owner_uid=uid, expected_generation=0,
            )["state_generation"] == 1
            old = json.loads((state_dir / V2_STATE).read_bytes())
            assert old == initial
            history = frozenset(r["id"] for r in old["id_reservations"])
            assert history == frozenset(r["id"] for r in original["repositories"])

            new_repo = copy.deepcopy(original["repositories"][0])
            new_repo.pop("id")
            new_repo["upstream"]["base_url"] = (
                "https://added-mirror.example.invalid/debian/"
            )
            new_repo["upstream"]["allowed_hosts"] = [
                "added-mirror.example.invalid",
            ]
            new_repo["desired_state"] = "active"
            allocated = propose_automatic_repository_id(
                original, new_repo, current_generation=1,
                reserved_ids=history,
            )
            identifier = allocated["repository_id"]
            assert not allocated["existing"]
            pins = {
                identifier: {
                    "added-mirror.example.invalid": ["8.8.8.8"],
                },
            }
            addition = preview_repository_auto_add_nginx_from_untrusted_document(
                original, current_generation=1,
                proposed_repository=new_repo,
                reserved_ids=history,
                candidate_pins_by_repository=pins,
                ca_bundle_path=_CA,
            )
            assert addition["repository_id"] == identifier
            assert addition["desired_new_route_ids"] == [identifier]
            assert addition["automatic_id_provenance"] == "CALLER_SNAPSHOT_ONLY"
            next_doc = addition["next_generation_configuration_preview"]
            assert next_doc["expected_state_generation"] == 2
            assert next_doc != original
            next_state = state(next_doc, generation=2, previous=old)
            assert _commit_proposed_v2_under_root(
                fd, next_state, owner_uid=uid, expected_generation=1,
            )["state_generation"] == 2
            saved = json.loads((state_dir / V2_STATE).read_bytes())
            assert saved == next_state
            assert identifier in {r["id"] for r in saved["id_reservations"]}
            rendered = syntax_checked_candidate(
                config_from_state(saved), pins, Path(dirname),
            )
            assert rendered["desired_active_repository_ids"] == [identifier]
            assert len(rendered["candidate_catalog"]["repositories"]) == 1

            disable = preview_repository_lifecycle_nginx_from_untrusted_document(
                next_doc, current_generation=2,
                operation="disable", repository_id=identifier,
                candidate_pins_by_repository={}, ca_bundle_path=_CA,
            )
            assert disable["desired_withdraw_route_ids"] == [identifier]
            disabled_doc = disable["next_generation_configuration_preview"]
            assert disabled_doc["expected_state_generation"] == 3
            disabled = state(disabled_doc, generation=3, previous=saved)
            assert _commit_proposed_v2_under_root(
                fd, disabled, owner_uid=uid, expected_generation=2,
            )["state_generation"] == 3
            disabled_candidate = syntax_checked_candidate(
                config_from_state(disabled), {}, Path(dirname),
            )
            assert disabled_candidate["candidate_catalog"]["repositories"] == []
            assert identifier in {r["id"] for r in disabled["id_reservations"]}

            removal = preview_repository_lifecycle_nginx_from_untrusted_document(
                disabled_doc, current_generation=3, operation="remove",
                repository_id=identifier, candidate_pins_by_repository={},
                ca_bundle_path=_CA,
            )
            assert removal["tombstone_required_ids"] == [identifier]
            assert removal["cache_retention_required_ids"] == [identifier]
            removed_doc = removal["next_generation_configuration_preview"]
            assert removed_doc["expected_state_generation"] == 4
            removed = state(removed_doc, generation=4, previous=disabled)
            assert _commit_proposed_v2_under_root(
                fd, removed, owner_uid=uid, expected_generation=3,
            )["state_generation"] == 4
            retained = {r["id"]: r for r in removed["id_reservations"]}
            assert retained[identifier]["status"] == "retired"
            assert identifier not in {r["id"] for r in removed["repository_records"]}
            assert syntax_checked_candidate(
                config_from_state(removed), {}, Path(dirname),
            )["candidate_catalog"]["repositories"] == []

            # Historical IDs must not be silently reused, even when the
            # previous configuration was removed from desired deployment.
            previous_bytes = (state_dir / V2_STATE).read_bytes()
            with_id = {**new_repo, "id": identifier}
            try:
                preview_repository_lifecycle_nginx_from_untrusted_document(
                    removed_doc, current_generation=4, operation="add",
                    proposed_repository=with_id,
                    reserved_ids=frozenset(retained),
                    candidate_pins_by_repository=pins, ca_bundle_path=_CA,
                )
            except ReconciliationPlanError:
                pass
            else:
                raise AssertionError("retired repository id was silently reused")
            assert (state_dir / V2_STATE).read_bytes() == previous_bytes
            next_alloc = propose_automatic_repository_id(
                removed_doc, new_repo, current_generation=4,
                reserved_ids=frozenset(retained),
            )
            assert not next_alloc["existing"]
            assert next_alloc["repository_id"] != identifier
            print(
                "PASS: combined #95 automatic ID, #31 protected v2 CAS/"
                "tombstones, #28 real nginx -T and client-schema active-only"
                " preview on add/disable/remove; no native publication"
            )
        finally:
            os.close(fd)


if __name__ == "__main__":
    main()
