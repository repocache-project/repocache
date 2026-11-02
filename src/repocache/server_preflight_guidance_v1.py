"""Side-effect-free English guidance for partial server preflight (#26).

Only allowlisted check/status/code triples are accepted; the guidance never
contains host or deployment values and never grants installation authority.
"""
from __future__ import annotations

from types import MappingProxyType
from repocache.server_preflight_v1 import (
    NativePreflightReport, PreflightStatus, _REPORT_CHECK_CODES,
)

# Fixed remediation messages, not derived from untrusted input or host output.
_ACTIONS = MappingProxyType({
    "supported_os_and_python": "Use Debian 13 with OS Python 3.13 or AlmaLinux 10 with OS Python 3.12.",
    "architecture_identity": "Check the observed machine architecture; refuse malformed identities.",
    "architecture_supported": "Verify an explicitly approved machine architecture before installing.",
    "effective_uid": "Inspect without elevation; use a separately authorized native root helper for installation.",
    "native_package_manager_binary": "Check apt-get or dnf presence; issue #27 owns actual native package availability and repository trust.",
    "python_environment": "Verify the OS Python environment; an active virtual environment is not native provenance.",
    "python_package_origin": "Confirm distribution-managed Python provenance independently of executable presence.",
    "native_package_availability": "Issue #27 must verify native APT/DNF candidates, approved sources and signatures before an authorized transaction.",
    "storage_ownership_and_capacity": "Verify root ownership, safe mounts, sufficient bytes and free inodes before managing storage.",
    "listen_port_conflicts": "Check listener ownership and the requested HTTPS port; a free-port snapshot is not a reservation.",
    "nginx_ownership_and_features": "Verify native NGINX provenance, required modules and managed include ownership; do not adopt foreign files.",
    "tls_and_ca_trust": "Verify TLS certificate validity, hostname, CA trust, key match and protected file ownership before activation.",
    "systemd_native_runtime": "Verify intended systemd behaviour under the accepted native-test risk boundary.",
    "selinux_enforcing_native": "Keep AlmaLinux SELinux enforcing and verify required managed-path policy and labels.",
    "application_dependency_profile": "Verify the separately approved signed application dependency profile.",
    "managed_state_and_rollback": "Verify protected state ownership, generation, locking and recovery before any write.",
    "tls_reference_files": "Check TLS parent and file types, modes and ownership; do not read or display private key material.",
    "native_package_binaries": "Check fixed native executables; issue #27 handles missing packages with trusted APT/DNF.",
    "storage_path_safety": "Reject symlinks and unsafe parents; require verified ownership before using existing paths.",
    "storage_free_space": "Check free bytes, filesystem inodes, mounts and approved minimum storage thresholds.",
    "nginx_native_binary": "Check NGINX executable presence; issue #27 must verify its native package provenance.",
    "nginx_managed_include_collision": "Do not overwrite or adopt a foreign NGINX include without verified ownership.",
    "systemd_binary": "Check systemctl presence; a binary alone does not prove working native systemd.",
    "systemd_pid1_observation": "Inspect systemd PID 1 evidence; container observations do not certify a booted host.",
    "selinux_kernel_mode": "Verify AlmaLinux enforcing status; do not silently enable permissive mode.",
})

# When a new check is registered, require an explicit, reviewed English hint.
if set(_ACTIONS) != set(_REPORT_CHECK_CODES):
    raise RuntimeError("native preflight guidance mapping is incomplete")


def explain_native_preflight(report: NativePreflightReport) -> tuple[dict[str, str], ...]:
    """Provide static diagnostics for a partial report, without any host I/O.

    The return value is not wired to a public CLI and cannot authorize install.
    """
    if type(report) is not NativePreflightReport:
        raise TypeError("expected native preflight report")
    # Reject reports modified via object.__setattr__ after construction.
    NativePreflightReport(report.checks)
    return tuple({
        "check": item.name,
        "status": item.status.value,
        "code": item.code,
        "guidance": (
            "Local observation only; full installation readiness is not certified."
            if item.status is PreflightStatus.PASS else _ACTIONS[item.name]
        ),
    } for item in report.checks)
