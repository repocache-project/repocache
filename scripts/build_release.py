#!/usr/bin/env python3
"""Build a reproducible tar.gz archive and SHA-256 checksum for releases."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "pyproject.toml", "install.sh", "platform_check.py", "release-policy.json",
    "docs/PRODUCTION_EXISTING_NGINX.md",
    "src/repocache/__init__.py", "src/repocache/cli.py",
    "src/repocache/core.py", "src/repocache/catalog.py", "src/repocache/rendering.py",
    "src/repocache/tui.py", "src/repocache/updater.py",
    "src/repocache/releases.py", "src/repocache/upgrade.py",
    "src/repocache/signatures.py", "src/repocache/recovery.py", "src/repocache/wheelhouse.py",
    "client/repocache_client.py", "client/install.sh",
    "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh",
)


# Reviewed candidate-only v0.6.0 source inventory. Historical v0.4.0
# source members remain immutable for archive compatibility checks.
V06_EXTRA_FILES = (
    "client/entry_approval_plan_sandbox.py",
    "client/entry_atomic_sandbox.py",
    "client/entry_candidate_sandbox.py",
    "client/entry_transaction_stage_sandbox.py",
    "client/managed_registry_sandbox.py",
    "client/native_fallback_plan.py",
    "client/native_package_lock_observation.py",
    "client/recoverable_fallback_pair_lab.py",
    "client/root_source_boundary.py",
    "client/source_entry_boundaries.py",
    "client/source_helper_preview.py",
    "client/source_metadata_lab.py",
    "client/source_preflight.py",
    "client/source_structure_subset.py",
    "client/transaction_atomic_lab.py",
    "client/transaction_metadata_sandbox.py",
    "client/transaction_stage.py",
    "docs/examples/server-install-v1.json",
    "scripts/collect_native_candidate_evidence.py",
    "scripts/format_native_vm_paste_receipt.py",
    "scripts/inspect_native_vm_nginx_prerequisites.py",
    "scripts/server_v06_preflight.py",
    "src/repocache/intake.py",
    "src/repocache/intake_service.py",
    "src/repocache/native_acceptance_evidence_v1.py",
    "src/repocache/server_bounded_dns_v1.py",
    "src/repocache/server_cache_bypass_decision_v1.py",
    "src/repocache/server_cache_pressure_alarm_observe_v1.py",
    "src/repocache/server_cache_pressure_alarm_v1.py",
    "src/repocache/server_cache_pressure_observe_v1.py",
    "src/repocache/server_cache_pressure_policy_v1.py",
    "src/repocache/server_derived_catalog_candidate_v1.py",
    "src/repocache/server_dns_refresh_schedule_v1.py",
    "src/repocache/server_fixture_activation_flow_v1.py",
    "src/repocache/server_fixture_multi_resource_wal_v1.py",
    "src/repocache/server_host_checks_v1.py",
    "src/repocache/server_install_v1.py",
    "src/repocache/server_locked_manifest_reconcile_v1.py",
    "src/repocache/server_managed_include_fd_v1.py",
    "src/repocache/server_managed_include_v1.py",
    "src/repocache/server_native_metrics_file_bootstrap_v1.py",
    "src/repocache/server_native_metrics_logrotate_candidate_v1.py",
    "src/repocache/server_native_min_free_syntax_probe_v1.py",
    "src/repocache/server_native_nginx_effective_unit_v1.py",
    "src/repocache/server_native_nginx_local_boundary_v1.py",
    "src/repocache/server_native_nginx_ownership_v1.py",
    "src/repocache/server_native_nginx_package_journal_v1.py",
    "src/repocache/server_native_nginx_prepackage_state_v1.py",
    "src/repocache/server_native_nginx_service_unit_v1.py",
    "src/repocache/server_native_package_effects_observe_v1.py",
    "src/repocache/server_native_package_payload_v1.py",
    "src/repocache/server_native_package_plan_v1.py",
    "src/repocache/server_native_package_trust_v1.py",
    "src/repocache/server_native_repository_cache_v1.py",
    "src/repocache/server_native_storage_bootstrap_v1.py",
    "src/repocache/server_native_tls_material_probe_v1.py",
    "src/repocache/server_native_vm_readonly_v1.py",
    "src/repocache/server_nginx_metrics_bundle_join_v1.py",
    "src/repocache/server_nginx_metrics_candidate_v1.py",
    "src/repocache/server_nginx_pin_render_v1.py",
    "src/repocache/server_nginx_repository_bundle_v1.py",
    "src/repocache/server_nginx_tls_listener_candidate_v1.py",
    "src/repocache/server_preflight_guidance_v1.py",
    "src/repocache/server_preflight_v1.py",
    "src/repocache/server_proposed_state_v2_store.py",
    "src/repocache/server_proposed_v2_locked_catalog_binding_v1.py",
    "src/repocache/server_proposed_v2_locked_digest_v1.py",
    "src/repocache/server_protected_namespace_bootstrap_v1.py",
    "src/repocache/server_protected_state_inspect_v1.py",
    "src/repocache/server_protected_state_store_v1.py",
    "src/repocache/server_repository_plan_v1.py",
    "src/repocache/server_repository_reconcile_v1.py",
    "src/repocache/server_stock_nginx_package_owner_v1.py",
    "src/repocache/server_upstream_address_preflight_v1.py",
    "src/repocache/server_upstream_rotation_v1.py",
    "src/repocache/submission_admin.py",
    "src/repocache/submission_db_worker.py",
    "src/repocache/submission_decisions.py",
    "src/repocache/submission_keys.py",
    "src/repocache/submission_recovery.py",
    "src/repocache/submissions.py",
)


def release_files_for_version(version: str) -> tuple[str, ...]:
    """Return a closed archive inventory; never glob unreviewed release files."""
    if version == "0.6.0":
        return (*FILES, *V06_EXTRA_FILES)
    return FILES


def build_release(output: Path, tag: str = "") -> tuple[Path, Path]:
    text = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"(\d+\.\d+\.\d+)"\s*$', text, re.MULTILINE)
    if not match:
        raise ValueError("Invalid project version in pyproject.toml")
    version = match.group(1)
    if tag and tag != "v" + version:
        raise ValueError("Tag does not match the project version")
    init = (ROOT / "src/repocache/__init__.py").read_text()
    if f'__version__ = "{version}"' not in init:
        raise ValueError("Project and package versions do not match")
    try:
        policy = json.loads((ROOT / "release-policy.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError("Incomplete release bundle: release-policy.json") from error
    if policy.get("version") != version or policy.get("schema") != 1:
        raise ValueError("Release compatibility policy version does not match the project")
    output.mkdir(parents=True, exist_ok=True)
    package = output / f"repocache-v{version}.tar.gz"
    with package.open("wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for name in release_files_for_version(version):
                    source = ROOT / name
                    if not source.is_file() or source.is_symlink():
                        raise ValueError(f"Incomplete release bundle: {name}")
                    data = source.read_bytes()
                    item = tarfile.TarInfo(f"repocache-v{version}/{name}")
                    item.size, item.mtime = len(data), 0
                    item.uid = item.gid = 0
                    item.uname = item.gname = "root"
                    item.mode = 0o755 if name in ("install.sh", "client/install.sh", "client/repocache_client.py",
                                                       "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh") else 0o644
                    tar.addfile(item, io.BytesIO(data))
    checksum = package.with_name(package.name + ".sha256")
    checksum.write_text(f"{hashlib.sha256(package.read_bytes()).hexdigest()}  {package.name}\n")
    return package, checksum


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--tag", default="")
    args = parser.parse_args()
    print("\n".join(map(str, build_release(args.output, args.tag))))
