#!/usr/bin/env python3
"""Redacted, copy/paste-ready read-only NGINX VM prerequisite receipt (#27).

Consumes one bounded JSON report from inspect_native_vm_nginx_prerequisites.py
via stdin. Prints exactly one fixed-shape line with no host paths, PIDs,
hostnames, shell commands, private state, certificate data or credentials.
Even a positive read-only prerequisite report is NEVER installation,
signed release, SELinux policy, native service or issue #27 acceptance.
"""
from __future__ import annotations

import json
import sys
from typing import Any

_MAX_BYTES = 4096
_PREFIX = "REPOCACHE_NGINX_VM_V1="
_KEYS = frozenset({
    "schema_version", "status", "code", "distribution",
    "supported_distro_python_observed",
    "systemd_pid1_namespace_shape_observed",
    "almalinux_selinux_enforcing_observed",
    "effective_nginx_master_observed", "host_root_attested",
    "installed_repocache_signature_verified",
    "complete_server_acceptance_passed", "live_repository_cache_verified",
    "durable_host_recovery_verified", "authorizes_package_installation",
    "authorizes_host_write", "authorizes_nginx_reload",
    "authorizes_catalog_publication",
})
_FALSE_AUTHORITY = (
    "host_root_attested", "installed_repocache_signature_verified",
    "complete_server_acceptance_passed", "live_repository_cache_verified",
    "durable_host_recovery_verified", "authorizes_package_installation",
    "authorizes_host_write", "authorizes_nginx_reload",
    "authorizes_catalog_publication",
)
_CODES_BEFORE_PID1 = frozenset({
    "UNSUPPORTED_NATIVE_ARCHITECTURE", "ROOT_READ_ONLY_PROBE_REQUIRED",
    "CONTAINER_CONTEXT_REFUSED", "SYSTEMD_PID1_NOT_OBSERVED",
    "SYSTEMD_NAMESPACE_OR_RUNTIME_NOT_OBSERVED",
})


def _unique(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in items:
        if name in result:
            raise ValueError("duplicate report key")
        result[name] = value
    return result


def _receipt(data: bytes) -> dict[str, Any]:
    """Reject impossible or privilege-claiming inputs, not just bad JSON."""
    if type(data) is not bytes or not 1 <= len(data) <= _MAX_BYTES:
        raise ValueError("report bounds")
    item = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_unique)
    if (type(item) is not dict or set(item) != _KEYS
            or type(item.get("schema_version")) is not int
            or item["schema_version"] != 1):
        raise ValueError("unexpected report keys or schema")
    for key in _FALSE_AUTHORITY:
        if item[key] is not False:
            raise ValueError("report claimed native authority")
    distro = item["distribution"]
    if distro is not None and (type(distro) is not str
                               or distro not in ("debian", "almalinux")):
        raise ValueError("unsupported distribution")
    for key in (
        "supported_distro_python_observed",
        "systemd_pid1_namespace_shape_observed",
        "almalinux_selinux_enforcing_observed",
        "effective_nginx_master_observed",
    ):
        if type(item[key]) is not bool:
            raise ValueError("invalid observation type")
    supported = item["supported_distro_python_observed"]
    booted = item["systemd_pid1_namespace_shape_observed"]
    selinux = item["almalinux_selinux_enforcing_observed"]
    nginx = item["effective_nginx_master_observed"]
    code = item["code"]
    status = item["status"]
    if type(code) is not str or type(status) is not str:
        raise ValueError("invalid report status")

    # Enumerate the exact report states actually emitted by the read-only
    # native inspector; a forged positive state cannot become a VM pass.
    if code == "SUPPORTED_OS_NOT_OBSERVED":
        valid = (distro is None and not supported and not booted
                 and not selinux and not nginx and status == "NOT VERIFIED")
    elif code in _CODES_BEFORE_PID1:
        valid = (distro is not None and supported and not booted
                 and not selinux and not nginx and status == "NOT VERIFIED")
    elif code == "ALMALINUX_SELINUX_ENFORCING_NOT_OBSERVED":
        valid = (distro == "almalinux" and supported and booted
                 and not selinux and not nginx and status == "NOT VERIFIED")
    elif code == "EFFECTIVE_NGINX_NOT_OBSERVED":
        valid = (distro is not None and supported and booted and not nginx
                 and selinux == (distro == "almalinux")
                 and status == "NOT VERIFIED")
    elif code == "OBSERVATION_ONLY_NO_HOST_AUTHORITY":
        valid = (distro is not None and supported and booted and nginx
                 and selinux == (distro == "almalinux")
                 and status == "READ_ONLY_PREREQUISITES_OBSERVED")
    else:
        valid = False
    if not valid:
        raise ValueError("contradictory native prerequisite report")

    return {
        "kind": "repocache.nginx.vm.prerequisites.v1",
        "status": "NOT VERIFIED",
        "code": code,
        "distribution": distro,
        "supported_distro_python_observed_only": supported,
        "systemd_pid1_namespace_shape_observed_only": booted,
        "almalinux_selinux_enforcing_observed_only": selinux,
        "effective_nginx_master_observed_only": nginx,
        "native_prerequisites_observed_only": nginx,
        "report_source_authenticated": False,
        "installed_host_and_release_authenticated": False,
        "issue_27_acceptance_passed": False,
        "authorizes_host_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_publication": False,
    }


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise ValueError("no arguments accepted")
        result = _receipt(sys.stdin.buffer.read(_MAX_BYTES + 1))
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        result = {
            "kind": "repocache.nginx.vm.prerequisites.v1",
            "status": "NOT VERIFIED",
            "code": "INPUT_REFUSED",
            "distribution": None,
            "supported_distro_python_observed_only": False,
            "systemd_pid1_namespace_shape_observed_only": False,
            "almalinux_selinux_enforcing_observed_only": False,
            "effective_nginx_master_observed_only": False,
            "native_prerequisites_observed_only": False,
            "report_source_authenticated": False,
            "installed_host_and_release_authenticated": False,
            "issue_27_acceptance_passed": False,
            "authorizes_host_write": False,
            "authorizes_nginx_reload": False,
            "authorizes_publication": False,
        }
    print(_PREFIX + json.dumps(result, sort_keys=True, separators=(",", ":")))
    # Deliberate nonzero return: passing prerequisites NEVER authorize
    # installation, report native host acceptance or enable merge/release.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
