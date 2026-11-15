"""Fresh native NGINX ownership refusal and non-installing sequencing (#27)."""
from __future__ import annotations

import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from repocache.server_install_v1 import InstallInputError
from repocache import server_native_nginx_ownership_v1 as ownership


EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
DEBIAN = "ID=debian\nVERSION_ID=13\n"
ALMA = "ID=almalinux\nVERSION_ID=10\n"


def document():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def absent(path):
    raise FileNotFoundError(path)


@pytest.mark.parametrize("os_release,version,distro", [
    (DEBIAN, (3, 13), "debian"),
    (ALMA, (3, 12), "almalinux"),
])
def test_fresh_snapshot_is_not_install_authority(os_release, version, distro):
    seen = []
    def collect(path):
        seen.append(path)
        raise FileNotFoundError(path)

    report = ownership.inspect_fresh_nginx_footprint(
        os_release=os_release, python_version=version,
        document=document(), lstat=collect,
    )
    assert report.distribution == distro
    assert report.allows_metadata_probe
    assert report.code == "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED"
    assert len(seen) == len(ownership._NGINX_MARKERS)
    assert set(seen) == set(ownership._NGINX_MARKERS)
    values = report.to_dict()
    assert values["status"] == "NOT VERIFIED"
    assert not values["authorizes_package_transaction"]
    assert not values["systemd_and_listeners_verified"]
    assert not values["existing_instance_adoption_allowed"]
    assert not values["protected_ownership_manifest_verified"]


@pytest.mark.parametrize("conflict", ownership._NGINX_MARKERS)
def test_existing_nginx_artifact_always_refused_before_network(conflict, monkeypatch):
    def observe(path):
        if path == conflict:
            # A dangling link must be treated as present, not followed.
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)
        raise FileNotFoundError(path)

    def forbid(*a, **kw):
        raise AssertionError("native metadata must not run on a host conflict")

    monkeypatch.setattr(ownership, "inspect_native_nginx_metadata", forbid)
    report = ownership.prepare_fresh_native_nginx(
        os_release=DEBIAN, python_version=(3, 13),
        document=document(), lstat=observe, runner=forbid,
    )
    assert report.metadata is None
    assert report.footprint.code == "EXISTING_NGINX_OWNERSHIP_UNPROVEN"
    assert report.to_dict()["status"] == "FAIL"
    assert report.to_dict()["can_install"] is False
    assert report.to_dict()["authorizes_nginx_activation"] is False
    assert conflict not in json.dumps(report.to_dict())  # redact absolute path


def test_permission_failure_does_not_become_absent_or_trigger_network(monkeypatch):
    def observe(path):
        if path == "/etc/nginx":
            raise PermissionError("secret-operator-location")
        raise FileNotFoundError(path)

    def forbid(*a, **kw):
        raise AssertionError("network or package manager forbidden")

    monkeypatch.setattr(ownership, "inspect_native_nginx_metadata", forbid)
    report = ownership.prepare_fresh_native_nginx(
        os_release=ALMA, python_version=(3, 12),
        document=document(), lstat=observe, runner=forbid,
    )
    assert report.footprint.code == "NGINX_FOOTPRINT_ACCESS_UNVERIFIED"
    assert report.metadata is None
    assert report.to_dict()["status"] == "NOT VERIFIED"
    assert "secret-operator-location" not in json.dumps(report.to_dict())


def test_existing_artifact_dominates_incomplete_inventory(monkeypatch):
    def observe(path):
        if path == "/usr/sbin/nginx":
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o755)
        if path == "/etc/nginx":
            raise PermissionError("redacted")
        raise FileNotFoundError(path)

    monkeypatch.setattr(ownership, "inspect_native_nginx_metadata", lambda **kw:
                        pytest.fail("must not run native manager"))
    evidence = ownership.prepare_fresh_native_nginx(
        os_release=DEBIAN, python_version=(3, 13),
        document=document(), lstat=observe,
    )
    assert evidence.footprint.code == "EXISTING_NGINX_OWNERSHIP_UNPROVEN"


def test_noninitial_generation_refused_before_any_path_or_network(monkeypatch):
    requested = document()
    requested["expected_state_generation"] = 2

    def forbidden(*a, **kw):
        pytest.fail("no host operations after noninitial generation")

    monkeypatch.setattr(ownership, "inspect_native_nginx_metadata", forbidden)
    evidence = ownership.prepare_fresh_native_nginx(
        os_release=DEBIAN, python_version=(3, 13),
        document=requested, lstat=forbidden, runner=forbidden,
    )
    assert evidence.footprint.code == "NGINX_NONINITIAL_STATE_REFUSED"
    assert evidence.to_dict()["status"] == "FAIL"


@pytest.mark.parametrize("release,version", [
    ("ID=debian\nVERSION_ID=12\n", (3, 13)),
    (ALMA, (3, 13)),
    ("ID=ubuntu\nVERSION_ID=24.04\n", (3, 12)),
])
def test_unsupported_os_rejected_before_host_inspection(release, version):
    def forbidden(*a, **kw):
        pytest.fail("invalid OS must not touch host")

    with pytest.raises(InstallInputError):
        ownership.prepare_fresh_native_nginx(
            os_release=release, python_version=version,
            document=document(), lstat=forbidden, runner=forbidden,
        )


def test_policy_refusal_happens_before_host_inspection():
    value = document()
    value["deployment"]["nginx"]["ownership"] = "take-over"

    def forbidden(*a, **kw):
        pytest.fail("invalid ownership policy must not touch host")

    with pytest.raises(InstallInputError):
        ownership.inspect_fresh_nginx_footprint(
            os_release=DEBIAN, python_version=(3, 13),
            document=value, lstat=forbidden,
        )


@pytest.mark.parametrize("os_release,version,distro,output", [
    (DEBIAN, (3, 13), "debian", "nginx:\n  Candidate: 1.28-1\n"),
    (ALMA, (3, 12), "almalinux", "nginx\n"),
])
def test_no_known_footprint_allows_only_noninstalling_native_metadata(
    monkeypatch, os_release, version, distro, output,
):
    monkeypatch.setattr(
        __import__("repocache.server_native_package_trust_v1", fromlist=["_trusted_key"]),
        "_trusted_key", lambda path: True,
    )
    calls = []

    def runner(cmd, **kwargs):
        calls.append(list(cmd))
        assert "install" not in cmd and "upgrade" not in cmd
        assert kwargs["capture_output"] and kwargs["timeout"] == 120
        return SimpleNamespace(returncode=0, stdout=(
            output if len(calls) == 2 else ""), stderr="")

    evidence = ownership.prepare_fresh_native_nginx(
        os_release=os_release, python_version=version,
        document=document(), lstat=absent, runner=runner,
    )
    assert len(calls) == 2
    assert evidence.metadata is not None
    assert evidence.metadata.distribution == distro
    assert evidence.metadata.to_dict()["status"] == "PASS"
    assert evidence.to_dict()["status"] == "NOT VERIFIED"
    assert evidence.to_dict()["can_install"] is False
    assert evidence.to_dict()["authorizes_package_transaction"] is False
    assert not evidence.to_dict()["package_payload_authenticity_verified"]


def test_constructed_results_cannot_invent_authority():
    fresh = ownership.FreshNginxFootprintV1(
        "debian", "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED")
    refused = ownership.FreshNginxFootprintV1(
        "debian", "EXISTING_NGINX_OWNERSHIP_UNPROVEN")
    with pytest.raises(ValueError):
        ownership.NativeFreshNginxPreparationV1(fresh, None)
    from repocache.server_native_package_trust_v1 import NativeMetadataEvidenceV1
    with pytest.raises(ValueError):
        ownership.NativeFreshNginxPreparationV1(
            refused, NativeMetadataEvidenceV1(
                "debian", "NATIVE_CANDIDATE_OBSERVED", True, True))
    with pytest.raises(ValueError):
        ownership.FreshNginxFootprintV1("ubuntu", "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED")


@pytest.mark.parametrize("marker", [
    "/usr/local/lib/systemd/system/nginx.service",
    "/usr/local/lib/systemd/system/nginx.socket",
    "/usr/local/lib/systemd/system/nginx.service.d",
    "/etc/systemd/system/nginx.socket.d",
    "/run/systemd/system/nginx.service.d",
    "/run/systemd/system/nginx.socket",
    "/run/systemd/system/nginx.socket.d",
])
def test_custom_systemd_nginx_units_refuse_fresh_install_even_without_binary(
    marker, monkeypatch,
):
    def probe(path):
        if path == marker:
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)
        raise FileNotFoundError(path)

    monkeypatch.setattr(ownership, "inspect_native_nginx_metadata",
                        lambda **kw: pytest.fail("foreign systemd service touched network"))
    out = ownership.prepare_fresh_native_nginx(
        os_release=DEBIAN, python_version=(3, 13),
        document=document(), lstat=probe,
    )
    assert out.footprint.code == "EXISTING_NGINX_OWNERSHIP_UNPROVEN"
    assert out.metadata is None
    assert out.to_dict()["authorizes_package_transaction"] is False
    assert marker not in json.dumps(out.to_dict())
