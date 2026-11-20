"""Fail-closed native post-install NGINX evidence correlation (#27/#31).

The two observed package and journal probes run only read-only, never clear
the durable effects marker or authorize any host mutation.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import os
from pathlib import Path

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

    def collected(*, distribution):
        first_observation = pending(distribution=distribution)
        actual_package = check_package()
        actual_unit = check_unit(distribution).to_dict()
        last_observation = pending(distribution=distribution)
        return first_observation, actual_package, actual_unit, last_observation

    monkeypatch.setattr(mod, "_collect_current_namespace_postpackage_facts", collected)
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
    assert report["single_protected_lock_spanned_native_package_and_unit_reads"] is True
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


def test_readonly_probe_error_is_redacted(monkeypatch, tmp_path):
    from repocache.server_native_nginx_package_journal_v1 import (
        _prepare_native_journal_under_root,
    )
    from repocache.server_protected_state_store_v1 import LOCK_NAME, _locked

    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    folder = root
    for name in ("var", "lib", "repocache", "server"):
        folder = folder / name
        folder.mkdir(mode=0o700)
    (folder / LOCK_NAME).write_bytes(b"")
    (folder / LOCK_NAME).chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _prepare_native_journal_under_root(
            fd, owner_uid=os.geteuid(), distribution="almalinux",
        )
        with _locked(fd, os.geteuid()) as directory:
            monkeypatch.setattr(
                mod, "inspect_stock_nginx_package_owner",
                lambda: (_ for _ in ()).throw(
                    OSError("secret native RPM package path"),
                ),
            )
            with pytest.raises(mod.NativeEffectsReconciliationError) as exc:
                mod._collect_postpackage_facts_while_locked(
                    directory, owner_uid=os.geteuid(),
                    distribution="almalinux",
                )
            assert str(exc.value) == "NATIVE_EFFECTS_NATIVE_FACTS_UNVERIFIED"
    finally:
        os.close(fd)


def test_source_has_no_native_write_or_service_calls():
    import inspect
    code = inspect.getsource(mod.inspect_current_namespace_native_postpackage_candidate)
    for token in ("os.replace(", "os.unlink(", "subprocess.run(", '"systemctl"',
                  "apt-get", "dnf install", "os.chown("):
        assert token not in code


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_package_and_unit_are_observed_while_one_real_lock_is_held(
    tmp_path, monkeypatch, distribution,
):
    """A competing #31 state writer must not acquire the lock mid-probe."""
    from repocache.server_native_nginx_package_journal_v1 import (
        NATIVE_PENDING_NAME, _prepare_native_journal_under_root,
    )
    from repocache.server_protected_state_store_v1 import (
        LOCK_NAME, ProtectedStateStoreError, _locked,
    )

    root = tmp_path / "real-root"
    root.mkdir(mode=0o700)
    folder = root
    for name in ("var", "lib", "repocache", "server"):
        folder = folder / name
        folder.mkdir(mode=0o700)
    (folder / LOCK_NAME).write_bytes(b"")
    (folder / LOCK_NAME).chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _prepare_native_journal_under_root(
            fd, owner_uid=os.geteuid(), distribution=distribution,
        )
        marker = folder / NATIVE_PENDING_NAME
        marker_before = marker.read_bytes()
        identity = marker.stat().st_ino
        observed = []

        def check_pending_exclusive(operation):
            with pytest.raises(ProtectedStateStoreError,
                               match="^PROTECTED_LOCK_UNAVAILABLE$"):
                with _locked(fd, os.geteuid()):
                    pytest.fail("competing state writer acquired lock")
            assert marker.read_bytes() == marker_before
            observed.append(operation)

        def actual_package():
            check_pending_exclusive("package")
            return package(distribution)

        class FakeVendor:
            def to_dict(self):
                check_pending_exclusive("unit-data")
                return unit()

        def actual_unit(dist):
            assert dist == distribution
            check_pending_exclusive("unit")
            return FakeVendor()

        monkeypatch.setattr(mod, "inspect_stock_nginx_package_owner", actual_package)
        monkeypatch.setattr(mod, "inspect_native_nginx_unit", actual_unit)
        with _locked(fd, os.geteuid()) as directory:
            before, pkg, vendor, after = (
                mod._collect_postpackage_facts_while_locked(
                    directory, owner_uid=os.geteuid(),
                    distribution=distribution,
                )
            )
        assert before == after
        assert before["pending_native_effects_block_reentry"] is True
        assert pkg["package_name"] == (
            "nginx" if distribution == "debian" else "nginx-core"
        )
        assert vendor["vendor_unit_sha256"] == SHA
        assert observed == ["package", "unit", "unit-data"]
        assert marker.read_bytes() == marker_before
        assert marker.stat().st_ino == identity
        assert (folder / NATIVE_PENDING_NAME).is_file()
    finally:
        os.close(fd)


def test_current_host_probe_refuses_nonroot_before_any_lock_or_subprocess(
    monkeypatch,
):
    monkeypatch.setattr(mod.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(
        mod, "_locked",
        lambda *_a, **_kw: pytest.fail("unexpected protected lock attempt"),
    )
    with pytest.raises(
        mod.NativeEffectsReconciliationError,
        match="^NATIVE_EFFECTS_ROOT_READ_ONLY_OBSERVATION_REQUIRED$",
    ):
        mod._collect_current_namespace_postpackage_facts(distribution="debian")


def test_correlation_does_not_reconcile_irreversible_package_effects():
    import inspect
    code = inspect.getsource(mod._collect_postpackage_facts_while_locked)
    assert "os.unlink(" not in code
    assert "os.replace(" not in code
    assert "subprocess.run(" not in code
    assert "os.system(" not in code
    assert "systemctl" not in code
