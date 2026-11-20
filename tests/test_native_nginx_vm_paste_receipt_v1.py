"""Paste-only VM NGINX prerequisite reports never become host acceptance (#27)."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts/format_native_nginx_vm_paste_receipt.py"
)
_PREFIX = b"REPOCACHE_NGINX_VM_V1="


def report(distro="debian", code="CONTAINER_CONTEXT_REFUSED"):
    return {
        "schema_version": 1,
        "status": "NOT VERIFIED",
        "code": code,
        "distribution": distro,
        "supported_distro_python_observed": distro is not None,
        "systemd_pid1_namespace_shape_observed": False,
        "almalinux_selinux_enforcing_observed": False,
        "effective_nginx_master_observed": False,
        "host_root_attested": False,
        "installed_repocache_signature_verified": False,
        "complete_server_acceptance_passed": False,
        "live_repository_cache_verified": False,
        "durable_host_recovery_verified": False,
        "authorizes_package_installation": False,
        "authorizes_host_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }


def parse(data: bytes, *extra_args: str):
    proc = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), *extra_args],
        input=data, capture_output=True, check=False, timeout=10,
    )
    assert proc.stderr == b""
    assert proc.returncode == 2
    assert proc.stdout.startswith(_PREFIX)
    assert len(proc.stdout.splitlines()) == 1
    return json.loads(proc.stdout[len(_PREFIX):])


def encoded(item):
    return json.dumps(item, sort_keys=True, separators=(",", ":")).encode()


def test_container_refusal_is_one_line_and_does_not_claim_acceptance():
    actual = parse(encoded(report()))
    assert actual == {
        "kind": "repocache.nginx.vm.prerequisites.v1",
        "status": "NOT VERIFIED",
        "code": "CONTAINER_CONTEXT_REFUSED",
        "distribution": "debian",
        "supported_distro_python_observed_only": True,
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


@pytest.mark.parametrize("distro", ["debian", "almalinux"])
def test_synthetic_vm_prerequisites_remain_unverified(distro):
    item = report(distro, "OBSERVATION_ONLY_NO_HOST_AUTHORITY")
    item.update(
        status="READ_ONLY_PREREQUISITES_OBSERVED",
        systemd_pid1_namespace_shape_observed=True,
        almalinux_selinux_enforcing_observed=distro == "almalinux",
        effective_nginx_master_observed=True,
    )
    result = parse(encoded(item))
    assert result["distribution"] == distro
    assert result["native_prerequisites_observed_only"] is True
    assert result["effective_nginx_master_observed_only"] is True
    assert result["systemd_pid1_namespace_shape_observed_only"] is True
    assert result["status"] == "NOT VERIFIED"
    assert result["report_source_authenticated"] is False
    assert result["installed_host_and_release_authenticated"] is False
    assert result["issue_27_acceptance_passed"] is False
    assert all(
        value is False for name, value in result.items()
        if name.startswith("authorizes_")
    )


@pytest.mark.parametrize("code", [
    "UNSUPPORTED_NATIVE_ARCHITECTURE",
    "ROOT_READ_ONLY_PROBE_REQUIRED",
    "SYSTEMD_PID1_NOT_OBSERVED",
    "SYSTEMD_NAMESPACE_OR_RUNTIME_NOT_OBSERVED",
])
def test_pre_pid1_readonly_refusals_preserved_without_promotion(code):
    result = parse(encoded(report("debian", code)))
    assert result["code"] == code
    assert result["native_prerequisites_observed_only"] is False


def test_unsupported_os_has_no_claim_of_supported_distro():
    result = parse(encoded(report(None, "SUPPORTED_OS_NOT_OBSERVED")))
    assert result["code"] == "SUPPORTED_OS_NOT_OBSERVED"
    assert result["distribution"] is None
    assert result["supported_distro_python_observed_only"] is False


def test_selinux_enforcing_denial_remains_not_verified():
    item = report("almalinux", "ALMALINUX_SELINUX_ENFORCING_NOT_OBSERVED")
    item["systemd_pid1_namespace_shape_observed"] = True
    result = parse(encoded(item))
    assert result["code"] == "ALMALINUX_SELINUX_ENFORCING_NOT_OBSERVED"
    assert result["systemd_pid1_namespace_shape_observed_only"] is True
    assert result["almalinux_selinux_enforcing_observed_only"] is False
    assert result["issue_27_acceptance_passed"] is False


@pytest.mark.parametrize("distro", ["debian", "almalinux"])
def test_effective_nginx_not_observed_is_not_positive(distro):
    item = report(distro, "EFFECTIVE_NGINX_NOT_OBSERVED")
    item["systemd_pid1_namespace_shape_observed"] = True
    item["almalinux_selinux_enforcing_observed"] = distro == "almalinux"
    result = parse(encoded(item))
    assert result["code"] == "EFFECTIVE_NGINX_NOT_OBSERVED"
    assert result["effective_nginx_master_observed_only"] is False
    assert result["native_prerequisites_observed_only"] is False


@pytest.mark.parametrize("field,forged", [
    ("status", "READ_ONLY_PREREQUISITES_OBSERVED"),
    ("code", "ALL_ACCEPTANCE_PASSED"),
    ("schema_version", True),
    ("distribution", "Ubuntu 25.10 secret-host"),
    ("supported_distro_python_observed", False),
    ("systemd_pid1_namespace_shape_observed", True),
    ("effective_nginx_master_observed", True),
    ("almalinux_selinux_enforcing_observed", True),
    ("authorizes_nginx_reload", True),
    ("authorizes_package_installation", True),
    ("complete_server_acceptance_passed", True),
    ("host_root_attested", True),
    ("installed_repocache_signature_verified", True),
    ("live_repository_cache_verified", True),
    ("durable_host_recovery_verified", True),
    ("authorizes_host_write", 1),
    ("authorizes_catalog_publication", "yes"),
])
def test_forged_positive_or_privileged_input_rejected(field, forged):
    value = report()
    value[field] = forged
    result = parse(encoded(value))
    assert result["code"] == "INPUT_REFUSED"
    assert result["distribution"] is None
    assert result["native_prerequisites_observed_only"] is False
    assert result["issue_27_acceptance_passed"] is False


@pytest.mark.parametrize("corruption", [
    b"",
    b"not json",
    b"{}",
    b"[]",
    b'{"schema_version":1,"schema_version":1}',
    b"\xff\xfe\x00",
    b"a" * 5000,
])
def test_untrusted_or_oversized_input_never_leaks(corruption):
    result = parse(corruption)
    assert result["code"] == "INPUT_REFUSED"


def test_duplicate_input_and_unknown_secret_fields_are_rejected():
    value = encoded(report())
    duplicate = value[:-1] + b',"status":"NOT VERIFIED"}'
    assert parse(duplicate)["code"] == "INPUT_REFUSED"

    private = report()
    private["private_operator_host"] = "PRIVATE_HOSTNAME_AND_TOKEN"
    output = parse(encoded(private))
    assert output["code"] == "INPUT_REFUSED"
    assert "PRIVATE_HOSTNAME_AND_TOKEN" not in json.dumps(output)


def test_argument_injection_is_refused_before_reading_receipt():
    assert parse(encoded(report()), "--show-hostnames")["code"] == "INPUT_REFUSED"


def test_source_inspector_output_shape_is_explicit_and_without_authority():
    src = (
        Path(__file__).resolve().parents[1]
        / "src/repocache/server_native_vm_readonly_v1.py"
    ).read_text("utf-8")
    for required in (
        "READ_ONLY_PREREQUISITES_OBSERVED",
        "OBSERVATION_ONLY_NO_HOST_AUTHORITY",
        "ALMALINUX_SELINUX_ENFORCING_NOT_OBSERVED",
        "EFFECTIVE_NGINX_NOT_OBSERVED",
        "authorizes_nginx_reload",
        "installed_repocache_signature_verified",
    ):
        assert required in src
    assert "authorizes_nginx_reload\": True" not in src


def test_workflow_proves_real_distro_container_refusal_without_host_effects():
    source = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/server-v06-nginx-vm-paste-receipt.yml"
    ).read_text("utf-8")
    for required in (
        "debian:trixie-slim", "almalinux:10", "merge_group:",
        "target=/workspace,readonly",
        "REPOCACHE_NGINX_VM_V1=",
        "CONTAINER_CONTEXT_REFUSED",
        "issue_27_acceptance_passed",
    ):
        assert required in source
    assert "sudo " not in source
    assert "systemctl start" not in source
    assert "systemctl reload" not in source
