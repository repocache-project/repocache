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


@pytest.mark.parametrize("value,expected", [
    (b"nginx\n", "PROCESS_NGINX_FOUND"),
    (b"nginx: master pr\n", "PROCESS_NGINX_FOUND"),
    (b"nginx: worker pr\n", "PROCESS_NGINX_FOUND"),
    (b"python3\n", "PROCESS_NGINX_NOT_OBSERVED"),
    (b"not-nginx\n", "PROCESS_NGINX_NOT_OBSERVED"),
    (b"nginxd\n", "PROCESS_NGINX_NOT_OBSERVED"),
])
def test_bounded_proc_process_comm_snapshot(tmp_path, value, expected):
    proc = tmp_path / "proc"
    proc.mkdir()
    task = proc / "123"
    task.mkdir()
    (task / "comm").write_bytes(value)
    (proc / "unrelated").mkdir()
    assert ownership._scan_nginx_process_footprint(
        proc_root=str(proc)
    ) == expected


def test_running_nginx_refuses_fresh_install_before_native_metadata(monkeypatch):
    def forbidden(*a, **kw):
        pytest.fail("native package manager must not run when nginx exists")

    monkeypatch.setattr(ownership, "inspect_native_nginx_metadata", forbidden)
    report = ownership.prepare_fresh_native_nginx(
        os_release=ALMA, python_version=(3, 12),
        document=document(), lstat=absent,
        process_probe=lambda: "PROCESS_NGINX_FOUND",
        runner=forbidden,
    )
    assert report.metadata is None
    assert report.footprint.code == "NGINX_RUNNING_PROCESS_REFUSED"
    assert report.footprint.to_dict()["status"] == "FAIL"
    assert report.to_dict()["can_install"] is False
    assert report.to_dict()["authorizes_nginx_activation"] is False


@pytest.mark.parametrize("process_result", [
    "PROCESS_SCAN_UNVERIFIED", None, True, "PROCESS_UNREVIEWED",
])
def test_uncertain_process_scan_refuses_native_metadata(
    monkeypatch, process_result,
):
    monkeypatch.setattr(ownership, "inspect_native_nginx_metadata",
                        lambda **kwargs: pytest.fail("native metadata invoked"))
    result = ownership.prepare_fresh_native_nginx(
        os_release=DEBIAN, python_version=(3, 13),
        document=document(), lstat=absent,
        process_probe=lambda: process_result,
    )
    assert result.footprint.code == "NGINX_PROCESS_SCAN_UNVERIFIED"
    assert result.metadata is None
    assert result.footprint.to_dict()["status"] == "NOT VERIFIED"


def test_process_scan_access_exception_is_redacted(monkeypatch):
    def protected_processes():
        raise PermissionError("SECRET_RUNNING_PROCESS_PATH")

    monkeypatch.setattr(ownership, "inspect_native_nginx_metadata",
                        lambda **kwargs: pytest.fail("network invoked"))
    report = ownership.prepare_fresh_native_nginx(
        os_release=ALMA, python_version=(3, 12),
        document=document(), lstat=absent,
        process_probe=protected_processes,
    )
    assert report.footprint.code == "NGINX_PROCESS_SCAN_UNVERIFIED"
    assert "SECRET_RUNNING_PROCESS_PATH" not in json.dumps(report.to_dict())


def test_filesystem_conflict_precedes_proc_scan_and_network(monkeypatch):
    monkeypatch.setattr(ownership, "inspect_native_nginx_metadata",
                        lambda **kw: pytest.fail("native manager invoked"))

    def marker(path):
        if path == "/etc/nginx":
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)
        raise FileNotFoundError(path)

    result = ownership.prepare_fresh_native_nginx(
        os_release=DEBIAN, python_version=(3, 13),
        document=document(), lstat=marker,
        process_probe=lambda: pytest.fail("process scan invoked"),
    )
    assert result.footprint.code == "EXISTING_NGINX_OWNERSHIP_UNPROVEN"


def test_proc_symlinked_comm_refuses_without_following(tmp_path):
    proc = tmp_path / "proc"
    task = proc / "123"
    task.mkdir(parents=True)
    target = tmp_path / "private-data"
    target.write_bytes(b"nginx\n")
    (task / "comm").symlink_to(target)
    assert ownership._scan_nginx_process_footprint(
        proc_root=str(proc)
    ) == "PROCESS_SCAN_UNVERIFIED"
    assert target.read_bytes() == b"nginx\n"


def test_proc_disappearing_pid_is_not_an_install_authority(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    (proc / "123").mkdir(parents=True)
    # A genuine /proc process can exit between directory listing and read.
    assert ownership._scan_nginx_process_footprint(
        proc_root=str(proc)
    ) == "PROCESS_NGINX_NOT_OBSERVED"
    # Even a successful snapshot is explicitly NOT VERIFIED.
    report = ownership.inspect_fresh_nginx_footprint(
        os_release=DEBIAN, python_version=(3, 13), document=document(),
        lstat=absent,
        process_probe=lambda: ownership._scan_nginx_process_footprint(
            proc_root=str(proc)
        ),
    ).to_dict()
    assert report["status"] == "NOT VERIFIED"
    assert report["all_nginx_instances_inventoried"] is False
    assert report["authorizes_package_transaction"] is False


def test_unreadable_proc_comm_and_excess_processes_are_refused(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    for pid in (123, 124):
        task = proc / str(pid)
        task.mkdir(parents=True)
        (task / "comm").write_bytes(b"python3\n")
    monkeypatch.setattr(ownership, "_MAX_PROC_PIDS", 1)
    assert ownership._scan_nginx_process_footprint(
        proc_root=str(proc)
    ) == "PROCESS_SCAN_UNVERIFIED"
    monkeypatch.setattr(ownership, "_MAX_PROC_PIDS", 65536)
    real_open = ownership.os.open

    def reject_comm(path, flags, *args, **kwargs):
        if str(path).endswith("/comm"):
            raise PermissionError("redacted")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(ownership.os, "open", reject_comm)
    assert ownership._scan_nginx_process_footprint(
        proc_root=str(proc)
    ) == "PROCESS_SCAN_UNVERIFIED"


def test_missing_proc_root_fails_closed():
    assert ownership._scan_nginx_process_footprint(
        proc_root="/nonexistent/repocache-ci-proc",
    ) == "PROCESS_SCAN_UNVERIFIED"
