"""Non-installed, read-only native NGINX pre-reload consistency check (#64).

This deliberately does NOT grant authority or reload a service. It composes
existing fixed native identity, syntax and bounded full-context observations
and refuses if the observed effective vendor unit changes during inspection.
No user-supplied path, unit, executable, environment or configuration is used.

Only a future independently signed/installed root transaction holding the
#31 exclusive state-v2 and multi-resource recovery lock may consume *private*
observations. This result cannot serve as a lease, approval or exposure proof.
"""
from __future__ import annotations

import os
from typing import Any

from repocache.server_native_nginx_effective_unit_v1 import (
    EffectiveNginxUnitError, inspect_effective_native_nginx_unit,
)
from repocache.server_root_control_host_preflight_v1 import (
    NativeHostPreflightError, require_native_host_preconditions,
)
from repocache.server_root_control_native_syntax_v1 import (
    FixedNginxSyntaxError, inspect_installed_default_nginx_syntax_only,
)
from repocache.server_root_control_full_context_v1 import (
    FixedNginxFullContextError, inspect_installed_default_nginx_full_context_only,
)


class FixedPreReloadObservationError(ValueError):
    """Only fixed redacted codes, never unit output or private dump text."""


def _deny(code: str) -> None:
    raise FixedPreReloadObservationError("NATIVE_PRE_RELOAD_" + code)


def _native_root() -> None:
    try:
        if (os.getuid() != 0 or os.geteuid() != 0
                or os.getresuid() != (0, 0, 0)):
            _deny("ROOT_REQUIRED")
    except AttributeError:
        _deny("ROOT_UNAVAILABLE")


def _host_preflight() -> None:
    try:
        report = require_native_host_preconditions()
    except NativeHostPreflightError:
        _deny("HOST_CONTEXT_REFUSED")
    if (type(report) is not dict
            or report.get("status") != "NATIVE_HOST_NECESSARY_PRECONDITIONS_ONLY"
            or report.get("host_root_provenance_verified") is not False
            or report.get("authorizes_nginx_reload") is not False):
        _deny("HOST_CONTEXT_UNVERIFIED")


def _unit_observation(distribution: str) -> tuple[int, str]:
    try:
        report = inspect_effective_native_nginx_unit(distribution)
    except EffectiveNginxUnitError:
        _deny("EFFECTIVE_UNIT_REFUSED")
    if (type(report) is not dict
            or report.get("status")
               != "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION"
            or report.get("unit_name") != "nginx.service"
            or report.get("authorizes_nginx_reload") is not False
            or type(report.get("main_pid_observed")) is not int
            or not 2 <= report["main_pid_observed"] <= 2**31 - 1
            or type(report.get("vendor_unit_sha256")) is not str
            or len(report["vendor_unit_sha256"]) != 64
            or any(c not in "0123456789abcdef"
                   for c in report["vendor_unit_sha256"])):
        _deny("EFFECTIVE_UNIT_UNVERIFIED")
    return report["main_pid_observed"], report["vendor_unit_sha256"]


def _syntax_observation() -> None:
    try:
        report = inspect_installed_default_nginx_syntax_only()
    except FixedNginxSyntaxError:
        _deny("SYNTAX_REFUSED")
    if (type(report) is not dict
            or report.get("status")
               != "NATIVE_INSTALLED_DEFAULT_NGINX_SYNTAX_ONLY"
            or report.get("default_config_syntax_observed") is not True
            or report.get("authorizes_nginx_reload") is not False):
        _deny("SYNTAX_UNVERIFIED")


def _context_observation() -> tuple[str, int]:
    try:
        report = inspect_installed_default_nginx_full_context_only()
    except FixedNginxFullContextError:
        _deny("FULL_CONTEXT_REFUSED")
    if (type(report) is not dict
            or report.get("status")
               != "NATIVE_DEFAULT_NGINX_FULL_CONTEXT_BYTES_ONLY"
            or report.get("full_context_bytes_observed") is not True
            or report.get("authorizes_nginx_reload") is not False
            or type(report.get("full_context_sha256")) is not str
            or len(report["full_context_sha256"]) != 64
            or any(c not in "0123456789abcdef"
                   for c in report["full_context_sha256"])
            or type(report.get("dump_size_bytes")) is not int
            or not 1 <= report["dump_size_bytes"] <= 4 * 1024 * 1024):
        _deny("FULL_CONTEXT_UNVERIFIED")
    return report["full_context_sha256"], report["dump_size_bytes"]


def inspect_native_nginx_pre_reload_consistency_only(
    distribution: str,
) -> dict[str, Any]:
    """Observe native root, fixed vendor systemd identity and default nginx.

    Both unit observations and host-context checks are repeated to catch
    simple concurrent changes, not to eliminate PID reuse or TOCTOU.
    Running nginx -t/-T can produce filesystem side effects. This private
    function is NOT installed, invoked by the worker, or safe to use on
    an untrusted native host. No action, lock, or publication is authorized.
    """
    if type(distribution) is not str or distribution not in ("debian", "almalinux"):
        _deny("DISTRIBUTION_REFUSED")
    _native_root()
    _host_preflight()
    before = _unit_observation(distribution)
    _syntax_observation()
    digest, size = _context_observation()
    after = _unit_observation(distribution)
    _host_preflight()
    if after != before:
        _deny("EFFECTIVE_UNIT_CHANGED")
    return {
        "schema_version": 1,
        "status": "NATIVE_NGINX_PRE_RELOAD_OBSERVATION_ONLY",
        "unit_name": "nginx.service",
        "vendor_unit_sha256": after[1],
        "full_context_sha256": digest,
        "dump_size_bytes": size,
        "effective_master_pid_observed": after[0],
        "native_root_preconditions_observed": True,
        "nginx_default_syntax_and_dump_observed": True,
        "effective_unit_rechecked": True,
        "all_nginx_includes_trusted": False,
        "signed_installed_worker_verified": False,
        "durable_v2_wal_and_lock_held_verified": False,
        "operator_approval_verified": False,
        "exposure_after_reload_verified": False,
        "host_selinux_acl_mount_verified": False,
        "authorizes_host_write": False,
        "authorizes_systemctl": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }
