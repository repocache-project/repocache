"""No-network, non-authorizing local boundary checks for NGINX (#27)."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from repocache import server_native_nginx_local_boundary_v1 as boundary
from repocache.server_native_nginx_prepackage_state_v1 import (
    PrepackageStateInspectionError,
)
from repocache.server_install_v1 import InstallInputError

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
DEBIAN = "ID=debian\nVERSION_ID=13\n"
ALMA = "ID=almalinux\nVERSION_ID=10\n"


def document():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def absent(path):
    raise FileNotFoundError(path)


def locked_snapshot():
    return {
        "schema_version": 1,
        "status": "LOCKED_PREPACKAGE_STATE_ABSENT",
        "nginx_include_directory_required": False,
        "nginx_live_manifest_verified": False,
        "native_transaction_journal_prepared": False,
        "state_generation": 0,
        "manifest_entry_present": False,
        "protected_state_directory_preprovisioned": True,
        "authorizes_package_installation": False,
        "exclusive_state_lock_held_during_inspection": True,
        "current_namespace_root_path_verified": True,
        "operator_authorization_verified": False,
        "authorizes_write": False,
        "authorizes_nginx_reload": False,
    }


def forbid(*args, **kwargs):
    pytest.fail("no privileged, package, network or state mutation allowed")


@pytest.mark.parametrize("release,python,distro", [
    (DEBIAN, (3, 13), "debian"),
    (ALMA, (3, 12), "almalinux"),
])
def test_positive_synthetic_locked_read_is_still_not_installer_authority(
    release, python, distro,
):
    calls = []
    def reader():
        calls.append("prepackage")
        return locked_snapshot()

    report = boundary.inspect_native_nginx_local_boundary(
        os_release=release, python_version=python, document=document(),
        lstat=absent, geteuid=lambda: 0, locked_inspector=reader,
    ).to_dict()
    assert calls == ["prepackage"]
    assert report["distribution"] == distro
    assert report["code"] == "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED"
    assert report["locked_prepackage_state_read_completed"]
    assert not report["locked_manifest_read_completed"]
    assert report["root_euid_observed"]
    assert report["status"] == "NOT VERIFIED"
    assert not report["host_root_namespace_authenticated"]
    assert not report["transaction_lock_held_across_mutation"]
    assert not report["native_package_authenticity_rechecked"]
    assert not report["operator_permission_authenticated"]
    assert not report["authorizes_package_transaction"]
    assert not report["authorizes_nginx_activation"]
    assert not report["can_install"]


@pytest.mark.parametrize("conflict", [
    "/etc/nginx", "/usr/sbin/nginx", "/var/log/nginx",
])
def test_foreign_footprint_refused_before_root_or_protected_inspection(conflict):
    def owned(path):
        if path == conflict:
            return SimpleNamespace(st_mode=0o40755)
        raise FileNotFoundError(path)

    report = boundary.inspect_native_nginx_local_boundary(
        os_release=DEBIAN, python_version=(3, 13), document=document(),
        lstat=owned, geteuid=forbid, locked_inspector=forbid,
    ).to_dict()
    assert report["code"] == "NGINX_FOOTPRINT_REFUSED"
    assert report["status"] == "FAIL"
    assert not report["authorizes_package_transaction"]
    assert conflict not in json.dumps(report)


@pytest.mark.parametrize("uid", [1000, -1, True, None])
def test_untrusted_effective_identity_stops_before_state_read(uid):
    report = boundary.inspect_native_nginx_local_boundary(
        os_release=ALMA, python_version=(3, 12), document=document(),
        lstat=absent, geteuid=lambda: uid, locked_inspector=forbid,
    ).to_dict()
    assert report["code"] == "NATIVE_ROOT_NOT_OBSERVED"
    assert not report["locked_manifest_read_completed"]
    assert not report["authorizes_package_transaction"]


def test_effective_identity_lookup_error_is_non_authorizing():
    def bad_euid():
        raise OSError("sensitive environment")

    report = boundary.inspect_native_nginx_local_boundary(
        os_release=DEBIAN, python_version=(3, 13), document=document(),
        lstat=absent, geteuid=bad_euid, locked_inspector=forbid,
    ).to_dict()
    assert report["code"] == "NATIVE_ROOT_NOT_OBSERVED"
    assert "sensitive" not in json.dumps(report)


@pytest.mark.parametrize("field,value", [
    ("state_generation", 1),
    ("state_generation", True),
    ("nginx_include_directory_required", True),
    ("nginx_live_manifest_verified", True),
    ("native_transaction_journal_prepared", True),
    ("manifest_entry_present", True),
    ("protected_state_directory_preprovisioned", False),
    ("authorizes_package_installation", True),
    ("exclusive_state_lock_held_during_inspection", False),
    ("current_namespace_root_path_verified", False),
    ("operator_authorization_verified", True),
    ("authorizes_write", True),
    ("authorizes_nginx_reload", True),
])
def test_mismatched_or_privileged_state_claim_refused(field, value):
    state = locked_snapshot()
    state[field] = value
    report = boundary.inspect_native_nginx_local_boundary(
        os_release=DEBIAN, python_version=(3, 13), document=document(),
        lstat=absent, geteuid=lambda: 0,
        locked_inspector=lambda **kwargs: state,
    ).to_dict()
    assert report["code"] == "PROTECTED_STATE_UNVERIFIED"
    assert not report["can_install"]


@pytest.mark.parametrize("error", [
    PrepackageStateInspectionError("PREPACKAGE_STATE_RECOVERY_REQUIRED"),
    PermissionError("private location"),
    ValueError("unsafe journal"),
])
def test_recovery_lock_or_access_errors_do_not_leak_or_recover(error):
    def reject(**kwargs):
        assert kwargs == {}
        raise error

    report = boundary.inspect_native_nginx_local_boundary(
        os_release=ALMA, python_version=(3, 12), document=document(),
        lstat=absent, geteuid=lambda: 0, locked_inspector=reject,
    ).to_dict()
    assert report["code"] == "PROTECTED_STATE_UNVERIFIED"
    assert str(error) not in json.dumps(report)
    assert not report["can_install"]


@pytest.mark.parametrize("release,version", [
    ("ID=debian\nVERSION_ID=12\n", (3, 13)),
    (ALMA, (3, 13)),
])
def test_unsupported_platform_never_observes_host(release, version):
    with pytest.raises(InstallInputError):
        boundary.inspect_native_nginx_local_boundary(
            os_release=release, python_version=version, document=document(),
            lstat=forbid, geteuid=forbid, locked_inspector=forbid,
        )


def test_noninitial_generation_rejected_before_root_or_state_inspection():
    d = document()
    d["expected_state_generation"] = 2
    report = boundary.inspect_native_nginx_local_boundary(
        os_release=DEBIAN, python_version=(3, 13), document=d,
        lstat=forbid, geteuid=forbid, locked_inspector=forbid,
    ).to_dict()
    assert report["code"] == "NGINX_FOOTPRINT_REFUSED"
    assert report["footprint_code"] == "NGINX_NONINITIAL_STATE_REFUSED"


def test_constructed_report_cannot_fake_inconsistent_footprint():
    with pytest.raises(ValueError):
        boundary.NativeNginxLocalBoundaryV1(
            "debian", "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED",
            "EXISTING_NGINX_OWNERSHIP_UNPROVEN",
        )


def test_inaccessible_nginx_marker_is_unknown_not_a_proven_conflict():
    def permission_error(path):
        if path == "/etc/nginx":
            raise PermissionError("private marker")
        raise FileNotFoundError(path)

    report = boundary.inspect_native_nginx_local_boundary(
        os_release=DEBIAN, python_version=(3, 13), document=document(),
        lstat=permission_error, geteuid=forbid, locked_inspector=forbid,
    ).to_dict()
    assert report["code"] == "NGINX_FOOTPRINT_REFUSED"
    assert report["footprint_code"] == "NGINX_FOOTPRINT_ACCESS_UNVERIFIED"
    assert report["status"] == "NOT VERIFIED"
    assert "private marker" not in json.dumps(report)
    assert not report["can_install"]


def test_preprovisioned_state_root_is_not_adopted_without_locked_proof():
    def state_only(path):
        if path == "/var/lib/repocache/server":
            return SimpleNamespace(st_mode=0o40700)
        raise FileNotFoundError(path)

    def reject():
        raise PrepackageStateInspectionError("PREPACKAGE_STATE_UNVERIFIED")

    report = boundary.inspect_native_nginx_local_boundary(
        os_release=DEBIAN, python_version=(3, 13), document=document(),
        lstat=state_only, geteuid=lambda: 0, locked_inspector=reject,
    ).to_dict()
    assert report["code"] == "PROTECTED_STATE_UNVERIFIED"
    assert not report["can_install"]


def test_preprovisioned_state_root_needs_locked_reader_even_when_other_paths_absent():
    def state_only(path):
        if path == "/var/lib/repocache/server":
            return SimpleNamespace(st_mode=0o40700)
        raise FileNotFoundError(path)

    report = boundary.inspect_native_nginx_local_boundary(
        os_release=ALMA, python_version=(3, 12), document=document(),
        lstat=state_only, geteuid=lambda: 0,
        locked_inspector=lambda: locked_snapshot(),
    ).to_dict()
    assert report["code"] == "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED"
    assert not report["authorizes_package_transaction"]
    assert not report["native_package_journal_prepared"]
