"""Defensive #26 tests for static non-authorizing preflight explanations."""
import json
import pytest

from repocache.server_preflight_guidance_v1 import (
    _ACTIONS, explain_native_preflight,
)
from repocache.server_preflight_v1 import (
    _REPORT_CHECK_CODES, NativeHostFacts, NativePreflightReport,
    PreflightCheck, PreflightStatus, assess_native_host,
)


def test_all_allowed_triples_have_safe_static_explanations():
    assert set(_ACTIONS) == set(_REPORT_CHECK_CODES)
    for name, codes in _REPORT_CHECK_CODES.items():
        for code, status in codes.items():
            report = NativePreflightReport((PreflightCheck(name, status, code),))
            output, = explain_native_preflight(report)
            assert (output["check"], output["code"], output["status"]) == (
                name, code, status.value,
            )
            assert output["guidance"].isascii() and output["guidance"].strip()
            if status is PreflightStatus.PASS:
                assert "not certified" in output["guidance"]
            else:
                assert output["guidance"] == _ACTIONS[name]


def test_host_secrets_cannot_enter_guidance_and_no_install_authorization():
    secret = "secret-supplied-by-unsupported-os-release"
    facts = NativeHostFacts(
        os_release=f"ID=debian\nVERSION_ID=13\nSECRET={secret}\n",
        python_version=(3, 13), machine="x86_64",
        euid=1000, native_manager_visible=False, running_in_venv=False,
    )
    report = assess_native_host(facts)
    result = explain_native_preflight(report)
    serialized = json.dumps(result)
    assert secret not in serialized
    assert "/etc/os-release" not in serialized
    assert "https://" not in serialized
    assert "issue #27" in serialized.lower()
    assert not report.all_verified and not report.authorizes_installation


def test_malformed_or_forged_reports_are_refused():
    with pytest.raises(TypeError):
        explain_native_preflight({"checks": []})
    report = NativePreflightReport((
        PreflightCheck(
            "native_package_manager_binary", PreflightStatus.FAIL,
            "NATIVE_PACKAGE_MANAGER_MISSING",
        ),
    ))
    object.__setattr__(report, "checks", (
        PreflightCheck(
            "native_package_manager_binary", PreflightStatus.PASS,
            "NATIVE_PACKAGE_MANAGER_MISSING",
        ),
    ))
    with pytest.raises(ValueError):
        explain_native_preflight(report)


def test_native_packages_are_not_conflated_with_online_python_profile():
    assert "APT/DNF" in _ACTIONS["native_package_availability"]
    assert "issue #27" in _ACTIONS["native_package_availability"].lower()
    assert "application dependency profile" in _ACTIONS["application_dependency_profile"]
