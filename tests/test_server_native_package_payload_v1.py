"""Download-only NGINX payload staging, no actual native package transaction."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from repocache import server_native_package_trust_v1 as trust
from repocache import server_native_package_payload_v1 as stage

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
DEBIAN = "ID=debian\nVERSION_ID=13\n"
ALMA = "ID=almalinux\nVERSION_ID=10\n"


def document():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def absent(path):
    raise FileNotFoundError(path)


def scripted_runner(distro, *, problem=None):
    commands = []
    locations = []

    def run(args, **kwargs):
        assert isinstance(args, list) and all(isinstance(x, str) for x in args)
        assert kwargs["check"] is False and kwargs["capture_output"]
        assert kwargs["text"] and kwargs["timeout"] == 120
        assert not kwargs["env"].get("http_proxy")
        assert not kwargs["env"].get("https_proxy")
        assert not kwargs.get("shell")
        loc = Path(kwargs["cwd"])
        commands.append(args)
        locations.append(loc)
        if args[0] == "/usr/bin/apt-get":
            assert distro == "debian"
            assert "AllowUnauthenticated=false" in " ".join(args)
            assert "Acquire::AllowInsecureRepositories=false" in args
            if args[-1] == "nginx":
                assert "--download-only" in args
                assert "--no-install-recommends" in args
                assert "install" in args
                if problem == "download-failed":
                    return SimpleNamespace(returncode=100, stdout="", stderr="secret-url")
                archive = loc / "archives" / "nginx_1_amd64.deb"
                archive.write_bytes(b"synthetic-package")
                if problem == "symlink":
                    archive.unlink()
                    archive.symlink_to(loc / "not-a-package")
                if problem == "missing-nginx":
                    archive.rename(loc / "archives" / "other_1_amd64.deb")
                if problem == "no-files":
                    archive.unlink()
        if args[0] == "/usr/bin/apt-cache":
            return SimpleNamespace(returncode=0, stdout=(
                "nginx:\n  Candidate: 1.0\n"), stderr="")
        if args[0] == "/usr/bin/dnf":
            assert distro == "almalinux"
            assert "--noplugins" in args and "--no-plugins" not in args
            assert "--setopt=rc-baseos.repo_gpgcheck=1" in args
            assert "--setopt=rc-appstream.gpgcheck=1" in args
            assert "--setopt=sslverify=1" in args
            if "repoquery" in args:
                return SimpleNamespace(returncode=0, stdout="nginx\n", stderr="")
            if "install" in args:
                assert "--downloadonly" in args
                assert any(x.startswith("--downloaddir=") for x in args)
                assert any(x.startswith("--installroot=") for x in args)
                if problem == "download-failed":
                    return SimpleNamespace(returncode=2, stdout="", stderr="secret-url")
                folder = loc / "payloads"
                rpm = folder / "nginx-1.x86_64.rpm"
                rpm.write_bytes(b"synthetic-package")
                if problem == "symlink":
                    rpm.unlink()
                    rpm.symlink_to(loc / "not-a-package")
                if problem == "missing-nginx":
                    rpm.rename(folder / "other-1.x86_64.rpm")
                if problem == "no-files":
                    rpm.unlink()
        if args[0] == "/usr/bin/dpkg-deb":
            assert "--field" in args
            name = "other" if problem == "missing-nginx" else "nginx"
            return SimpleNamespace(returncode=0, stdout=name+"\n", stderr="")
        if args[0] == "/usr/bin/rpmkeys":
            assert "--checksig" in args
            assert any(x.startswith("--dbpath=") for x in args)
            return SimpleNamespace(returncode=0, stdout=(
                "nginx.rpm: digests OK\n" if problem == "bad-signature"
                else "nginx.rpm: digests signatures OK\n"), stderr="")
        if args[0] == "/usr/bin/rpm":
            assert any(x.startswith("--dbpath=") for x in args)
            if "-qp" in args:
                return SimpleNamespace(returncode=0, stdout=(
                    "other" if problem == "missing-nginx" else "nginx"), stderr="")
            assert "--initdb" in args or "--import" in args
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    return commands, locations, run


@pytest.mark.parametrize("distro,release,version", [
    ("debian", DEBIAN, (3, 13)),
    ("almalinux", ALMA, (3, 12)),
])
def test_full_download_only_with_scratch_authentication(
    monkeypatch, distro, release, version,
):
    monkeypatch.setattr(trust, "_trusted_key", lambda path: True)
    commands, locations, runner = scripted_runner(distro)
    report = stage.rehearse_native_nginx_downloads(
        os_release=release, python_version=version,
        document=document(), lstat=absent, runner=runner,
    ).to_dict()
    assert report["status"] == "PASS"
    assert report["code"] == "NATIVE_PAYLOADS_VERIFIED_IN_SCRATCH"
    assert report["payload_count"] == 1
    assert report["scratch_payload_integrity_verified"]
    assert report["individual_rpm_signatures_verified"] == (distro == "almalinux")
    assert not report["host_package_transaction_performed"]
    assert not report["payloads_persisted_for_installation"]
    assert not report["can_install"] and not report["authorizes_package_installation"]
    assert not report["authorizes_nginx_activation"]
    assert len(set(locations)) == 2  # separate metadata and payload scratch
    assert all(not x.exists() for x in locations)  # no host state retained
    if distro == "debian":
        assert len([x for x in commands if x[0] == "/usr/bin/apt-get"]) == 3
        assert any(x[0] == "/usr/bin/dpkg-deb" for x in commands)
        assert not any(x[0] in ("/usr/bin/dpkg", "/usr/bin/dpkg-query") for x in commands)
    else:
        assert any(x[0] == "/usr/bin/rpmkeys" for x in commands)
        assert not any(x[0] == "/usr/bin/rpm" and "-i" in x for x in commands)


@pytest.mark.parametrize("distro,release,version", [
    ("debian", DEBIAN, (3, 13)),
    ("almalinux", ALMA, (3, 12)),
])
@pytest.mark.parametrize("problem,code", [
    ("download-failed", "NATIVE_DOWNLOAD_FAILED"),
    ("symlink", "NATIVE_PAYLOAD_SET_UNSAFE"),
    ("no-files", "NATIVE_PAYLOAD_SET_UNSAFE"),
    ("missing-nginx", "NATIVE_NGINX_PAYLOAD_MISSING"),
])
def test_negative_native_download_never_promotes_to_install_authority(
    monkeypatch, distro, release, version, problem, code,
):
    monkeypatch.setattr(trust, "_trusted_key", lambda path: True)
    commands, locations, runner = scripted_runner(distro, problem=problem)
    report = stage.rehearse_native_nginx_downloads(
        os_release=release, python_version=version,
        document=document(), lstat=absent, runner=runner,
    ).to_dict()
    assert report["code"] == code
    assert report["status"] == "NOT VERIFIED"
    assert report["payload_count"] == 0
    assert not report["can_install"]
    assert "secret-url" not in json.dumps(report)
    assert all(not x.exists() for x in locations)


def test_rpm_digest_only_does_not_count_as_verified_signature(monkeypatch):
    monkeypatch.setattr(trust, "_trusted_key", lambda path: True)
    _, locations, runner = scripted_runner("almalinux", problem="bad-signature")
    result = stage.rehearse_native_nginx_downloads(
        os_release=ALMA, python_version=(3, 12),
        document=document(), lstat=absent, runner=runner,
    )
    assert result.code == "NATIVE_PAYLOAD_SIGNATURE_FAILED"
    assert result.payload_count == 0
    assert all(not x.exists() for x in locations)


@pytest.mark.parametrize("distro,release,version", [
    ("debian", DEBIAN, (3, 13)),
    ("almalinux", ALMA, (3, 12)),
])
def test_preexisting_nginx_never_downloads(monkeypatch, distro, release, version):
    def owned(path):
        if path == "/etc/nginx":
            return SimpleNamespace(st_mode=0o40755)
        raise FileNotFoundError(path)

    def forbid(*args, **kwargs):
        pytest.fail("external NGINX must block network/package commands")

    report = stage.rehearse_native_nginx_downloads(
        os_release=release, python_version=version,
        document=document(), lstat=owned, runner=forbid,
    ).to_dict()
    assert report["code"] == "NATIVE_PREPARATION_NOT_VERIFIED"
    assert report["status"] == "NOT VERIFIED"
    assert not report["can_install"]


def test_download_command_never_permits_native_package_install(tmp_path):
    apt = tmp_path / "debian"
    alma = tmp_path / "almalinux"
    apt.mkdir()
    alma.mkdir()
    a_refresh, a_command, _ = stage._download_command("debian", apt)
    d_refresh, d_command, _ = stage._download_command("almalinux", alma)
    assert a_refresh[-1] == "update"
    assert "--download-only" in a_command and "install" in a_command
    assert "--assume-yes" in a_command
    assert all("AllowUnauthenticated=false" not in x for x in [])  # no opt-out
    assert d_refresh[-2:] == ["makecache", "--refresh"]
    assert "--downloadonly" in d_command and "install" in d_command
    assert "--noplugins" in d_command
    assert "--setopt=rc-baseos.repo_gpgcheck=1" in d_command
    assert "--setopt=rc-baseos.gpgcheck=1" in d_command
    assert "--setopt=sslverify=1" in d_command
    assert not any("--nogpgcheck" in s for s in d_command)


@pytest.mark.parametrize("code,count", [
    ("NATIVE_PAYLOADS_VERIFIED_IN_SCRATCH", 0),
    ("NATIVE_DOWNLOAD_FAILED", 2),
    ("FORGED_SUCCESS", 1),
])
def test_synthetic_evidence_must_be_closed_and_coherent(code, count):
    with pytest.raises(ValueError):
        stage.NativePayloadRehearsalV1("debian", code, count)
