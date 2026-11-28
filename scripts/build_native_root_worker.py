#!/usr/bin/env python3
"""Build the fixed root worker from an already authenticated v0.6 source tree.

The generated archive uses only first-party worker modules and the OS Python
standard library. It neither verifies publisher signatures nor installs or
starts a service. Obtain the input tree through the signed release verifier.
"""
from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import zipfile


INTERPRETER = b"#!/usr/bin/python3 -IS\n"
ENTRYPOINT = (
    b"from repocache.server_native_root_control_entrypoint_v1 import main\n"
    b"raise SystemExit(main())\n"
)
MODULES = (
    "__init__",
    "server_bounded_dns_v1",
    "server_derived_catalog_candidate_v1",
    "server_install_v1",
    "server_locked_manifest_reconcile_v1",
    "server_managed_include_fd_v1",
    "server_managed_include_v1",
    "server_native_egress_candidate_v1",
    "server_native_installed_storage_v1",
    "server_native_nginx_effective_unit_v1",
    "server_native_nginx_executable_v1",
    "server_native_nginx_package_journal_v1",
    "server_native_package_effects_observe_v1",
    "server_native_nginx_service_unit_v1",
    "server_native_root_control_entrypoint_v1",
    "server_native_v2_transaction_v1",
    "server_nginx_metrics_bundle_join_v1",
    "server_nginx_metrics_candidate_v1",
    "server_nginx_pin_render_v1",
    "server_nginx_repository_bundle_v1",
    "server_nginx_tls_listener_candidate_v1",
    "server_preflight_v1",
    "server_proposed_state_v2_store",
    "server_protected_namespace_bootstrap_v1",
    "server_protected_state_inspect_v1",
    "server_protected_state_store_v1",
    "server_repository_plan_v1",
    "server_root_control_fixed_candidate_v1",
    "server_root_control_full_context_v1",
    "server_root_control_host_preflight_v1",
    "server_root_control_native_syntax_v1",
    "server_root_control_pinned_tls_pair_v1",
    "server_root_control_protocol_v1",
    "server_root_control_worker_v1",
    "server_stock_nginx_package_owner_v1",
    "server_upstream_address_preflight_v1",
    "server_upstream_rotation_v1",
)


def build(source: Path) -> bytes:
    package = source / "src" / "repocache"
    if any(path.is_symlink() for path in (source, package.parent, package)):
        raise ValueError("Unexpected symlink in worker source tree")
    data = io.BytesIO(INTERPRETER)
    data.seek(0, io.SEEK_END)
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(zipfile.ZipInfo("__main__.py"), ENTRYPOINT)
        # Bind the exact dedicated unit from the authenticated source into
        # the deterministic worker. This is not a separate trust anchor.
        unit = source / "docs" / "examples" / "systemd" / "repocache-nginx.service"
        if any(parent.is_symlink() for parent in (
                unit, unit.parent, unit.parent.parent, unit.parent.parent.parent)):
            raise ValueError("Unexpected symlink in dedicated NGINX unit source")
        if not unit.is_file():
            raise ValueError("Missing dedicated NGINX unit source")
        unit_bytes = unit.read_bytes()
        if not 1 <= len(unit_bytes) <= 16384:
            raise ValueError("Invalid dedicated NGINX unit size")
        archive.writestr(zipfile.ZipInfo("repocache/_signed-owned-nginx.service"), unit_bytes)
        policy = source / "docs" / "examples" / "selinux" / "repocache-nginx.te"
        if (any(parent.is_symlink() for parent in (policy, policy.parent,
                policy.parent.parent, policy.parent.parent.parent)) or not policy.is_file()):
            raise ValueError("Missing or unsafe dedicated SELinux policy source")
        policy_bytes = policy.read_bytes()
        if not 1 <= len(policy_bytes) <= 16384:
            raise ValueError("Invalid dedicated SELinux policy size")
        archive.writestr(zipfile.ZipInfo("repocache/_signed-owned-nginx.te"), policy_bytes)
        for module in MODULES:
            filename = module + ".py"
            path = package / filename
            if not path.is_file() or path.is_symlink():
                raise ValueError("Missing or unexpected worker source file")
            archive.writestr(zipfile.ZipInfo("repocache/" + filename), path.read_bytes())
    return data.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    payload = build(arguments.source)
    # Never replace a different executable or follow an existing symlink.
    fd = os.open(arguments.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(payload)
        output.flush()
        os.fchmod(output.fileno(), 0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
