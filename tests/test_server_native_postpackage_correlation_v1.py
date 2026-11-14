"""Fail-closed native post-install NGINX evidence correlation (#27/#31).

The two observed package and journal probes run only read-only, never clear
the durable effects marker or authorize any host mutation.
"""
from __future__ import annotations

import copy

import pytest

from repocache import server_native_package_effects_observe_v1 as mod

SHA = "a" * 64


def inputs(distribution):
    return {
        "schema_version": 1,
        "status": "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION",
        "distribution": distribution,
        "journal_identity_verified": True,
        "pending_native_effects_block_reentry": True,
        "authorizes_native_marker_removal": False,
    }


def package(distribution):
    return {
        "schema_version": 1,
        "status": "READ_ONLY_STOCK_NGINX_PACKAGE_OWNER_OBSERVED",
        "platform": "debian13" if distribution == "debian" else "almalinux10",
        "package_name": "nginx" if distribution == "debian" else "nginx-core",
        "binary_path": "/usr/sbin/nginx",
        "native_package_db_owner_observed": True,
        "native_package_signature_verified": False,
        "authorizes_nginx_adoption": False,
    }


def unit():
    return {
        "schema_version": 1,
        "code": "VENDOR_NGINX_UNIT_OBSERVED",
        "unit_name": "nginx.service",
        "vendor_unit_sha256": SHA,
        "vendor_unit_bounded_and_owned": True,
        "native_package_file_ownership_verified": False,
        "authorizes_systemctl": False,
        "authorizes_nginx_reload": False,
    }


def observed(monkeypatch, distribution, *, before=None, after=None,
             pkg=None, vendor=None):
    events = []
    p = package(distribution) if pkg is None else pkg
    u = unit() if vendor is None else vendor
    first = inputs(distribution) if before is None else before
    last = first if after is None else after

    def pending(*, distribution):
        events.append("pending")
        return first if events.count("pending") == 1 else last

    def check_package():
        events.append("package")
        return p

    class FakeUnit:
        def to_dict(self):
            events.append("unit-fields")
            return u

    def check_unit(distribution):
        events.append("unit")
        return FakeUnit()

    monkeypatch.setattr(mod, "inspect_current_namespace_native_package_effects", pending)
    monkeypatch.setattr(mod, "inspect_stock_nginx_package_owner", check_package)
    monkeypatch.setattr(mod, "inspect_native_nginx_unit", check_unit)
    return events


@pytest.mark.parametrize("distribution,expected", [
    ("debian", "nginx"), ("almalinux", "nginx-core"),
])
def test_consistent_native_package_and_pending_journal_remain_non_authorizing(
    monkeypatch, distribution, expected,
):
    events = observed(monkeypatch, distribution)
    report = mod.inspect_current_namespace_native_postpackage_candidate(
        distribution=distribution
    )
    assert events == [
        "pending", "package", "unit", "unit-fields", "pending",
    ]
    assert report["status"] == "NATIVE_POSTPACKAGE_CORRELATION_CANDIDATE_ONLY"
    assert report["package"] == expected
    assert report["vendor_unit_sha256"] == SHA
    assert report["pending_journal_stable_across_observations"] is True
    assert report["native_package_db_owner_observed"] is True
    assert report["native_vendor_unit_shape_observed"] is True
    assert report["pending_native_effects_block_reentry"] is True
    assert all(report[key] is False for key in (
        "native_package_signature_verified",
        "installed_host_root_authenticated",
        "systemd_pid1_and_service_verified",
        "selinux_enforcing_verified",
        "operator_approval_verified",
        "package_effects_reconciled",
        "authorizes_native_marker_removal",
        "authorizes_package_installation",
        "authorizes_nginx_reload",
        "authorizes_host_mutation",
    ))


@pytest.mark.parametrize("bad", [
    True, None, "debian13", "almalinux10", 0, "ubuntu",
])
def test_invalid_distribution_never_enters_any_observer(monkeypatch, bad):
    monkeypatch.setattr(mod, "inspect_current_namespace_native_package_effects",
                        lambda **_: pytest.fail("invalid argument triggered I/O"))
    with pytest.raises(mod.NativeEffectsReconciliationError,
                       match="NATIVE_EFFECTS_ARGUMENT_INVALID"):
        mod.inspect_current_namespace_native_postpackage_candidate(
            distribution=bad
        )


@pytest.mark.parametrize("variation", [
    "changed-journal", "foreign-package", "foreign-platform",
    "unsigned-claim", "adoption-authority", "unit-foreign",
    "unit-shadow", "unit-authz", "invalid-unit-digest",
])
def test_any_mismatched_observation_fails_closed(monkeypatch, variation):
    before = inputs("debian")
    after = copy.deepcopy(before)
    pkg = package("debian")
    vendor = unit()
    if variation == "changed-journal":
        after["pending_native_effects_block_reentry"] = False
    elif variation == "foreign-package":
        pkg["package_name"] = "nginx-custom"
    elif variation == "foreign-platform":
        pkg["platform"] = "almalinux10"
    elif variation == "unsigned-claim":
        pkg["native_package_signature_verified"] = True
    elif variation == "adoption-authority":
        pkg["authorizes_nginx_adoption"] = True
    elif variation == "unit-foreign":
        vendor["unit_name"] = "foreign.service"
    elif variation == "unit-shadow":
        vendor["code"] = "VENDOR_NGINX_SHADOW_REFUSED"
    elif variation == "unit-authz":
        vendor["authorizes_systemctl"] = True
    else:
        vendor["vendor_unit_sha256"] = "Z" * 64
    observed(monkeypatch, "debian", before=before, after=after,
             pkg=pkg, vendor=vendor)
    with pytest.raises(mod.NativeEffectsReconciliationError,
                       match="^NATIVE_EFFECTS_"):
        mod.inspect_current_namespace_native_postpackage_candidate(
            distribution="debian"
        )


def test_readonly_probe_error_is_redacted(monkeypatch):
    observed(monkeypatch, "almalinux")
    def untrusted():
        raise OSError("secret /etc/pki/unsafe.key")
    monkeypatch.setattr(mod, "inspect_stock_nginx_package_owner", untrusted)
    with pytest.raises(mod.NativeEffectsReconciliationError) as exc:
        mod.inspect_current_namespace_native_postpackage_candidate(
            distribution="almalinux"
        )
    assert str(exc.value) == "NATIVE_EFFECTS_NATIVE_FACTS_UNVERIFIED"


def test_source_has_no_native_write_or_service_calls():
    import inspect
    code = inspect.getsource(mod.inspect_current_namespace_native_postpackage_candidate)
    for token in ("os.replace(", "os.unlink(", "subprocess.run(", "systemctl",
                  "apt-get", "dnf install", "os.chown("):
        assert token not in code
