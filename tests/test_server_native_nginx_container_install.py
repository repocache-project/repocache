"""Synthetic negatives for the CI-only native NGINX package installation rehearsal."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import smoke_server_native_nginx_container_install as smoke


def test_debian_install_reuses_signed_sources_and_actual_container_dpkg_status(tmp_path):
    refresh, install = smoke._commands("debian", tmp_path)
    assert refresh[0] == "/usr/bin/apt-get"
    assert refresh[-1] == "update"
    assert install[-2:] == ["install", "nginx"]
    assert "--assume-yes" in install
    assert "--no-install-recommends" in install
    assert "Dir::State::status=/var/lib/dpkg/status" in install
    assert not any("absent-dpkg-status" in arg for arg in install)
    assert "Dir::Etc::sourceparts=-" in install
    assert "Acquire::AllowInsecureRepositories=false" in install
    assert "Acquire::AllowDowngradeToInsecureRepositories=false" in install
    source = (tmp_path / "sources.list").read_text(encoding="ascii")
    assert source.count("deb [signed-by=/usr/share/keyrings/debian-archive-keyring.pgp]") == 3
    assert "http://" not in source
    assert "/var/lib/repocache" not in " ".join(install)


def test_almalinux_install_uses_signed_fixed_repos_without_installroot(tmp_path):
    refresh, install = smoke._commands("almalinux", tmp_path)
    assert refresh[-2:] == ["makecache", "--refresh"]
    assert install[-2:] == ["install", "nginx"]
    assert install[0] == "/usr/bin/dnf"
    assert "--disablerepo=*" in install
    assert "--enablerepo=rc-baseos,rc-appstream" in install
    assert "--noplugins" in install
    assert "--setopt=rc-baseos.repo_gpgcheck=1" in install
    assert "--setopt=rc-appstream.repo_gpgcheck=1" in install
    assert "--setopt=rc-baseos.gpgcheck=1" in install
    assert "--setopt=rc-appstream.gpgcheck=1" in install
    assert not any(s.startswith("--installroot=") for s in install)
    source = (tmp_path / "repos/repocache.repo").read_text(encoding="ascii")
    assert "https://repo.almalinux.org/" in source
    assert "repo_gpgcheck=1" in source


def test_unknown_distro_fails_without_any_package_command(tmp_path):
    with pytest.raises(smoke.ContainerInstallRehearsalError,
                       match="^CONTAINER_DISTRIBUTION_UNSUPPORTED$"):
        smoke._commands("ubuntu", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_missing_explicit_docker_guard_prevents_install(monkeypatch):
    monkeypatch.delenv("REPOCACHE_NATIVE_TEST_CONTAINER", raising=False)
    monkeypatch.setattr(smoke, "_commands",
                        lambda *_: pytest.fail("must not reach package manager"))
    with pytest.raises(smoke.ContainerInstallRehearsalError,
                       match="^CONTAINER_ISOLATION_UNVERIFIED$"):
        smoke.run_rehearsal(distribution="debian")


def test_docker_guard_without_effective_root_denied(monkeypatch):
    monkeypatch.setenv("REPOCACHE_NATIVE_TEST_CONTAINER",
                       "CONFIRMED_DISPOSABLE_DOCKER_ONLY")
    monkeypatch.setattr(smoke.os, "geteuid", lambda: 1000)
    with pytest.raises(smoke.ContainerInstallRehearsalError,
                       match="^CONTAINER_ISOLATION_UNVERIFIED$"):
        smoke.run_rehearsal(distribution="debian")


def test_existing_container_nginx_prevents_any_package_mutation(monkeypatch):
    monkeypatch.setenv("REPOCACHE_NATIVE_TEST_CONTAINER",
                       "CONFIRMED_DISPOSABLE_DOCKER_ONLY")
    monkeypatch.setattr(smoke.os, "geteuid", lambda: 0)
    original_is_file = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda self:
                        True if str(self) == "/.dockerenv"
                        else original_is_file(self))
    monkeypatch.setattr(smoke, "validate_os_identity", lambda *_: "debian")
    monkeypatch.setattr(smoke.os.path, "lexists", lambda path: path == "/etc/nginx")
    monkeypatch.setattr(smoke, "_trusted_key",
                        lambda *_: pytest.fail("must not access signing key"))
    with pytest.raises(smoke.ContainerInstallRehearsalError,
                       match="^CONTAINER_EXISTING_NGINX_REFUSED$"):
        smoke.run_rehearsal(distribution="debian")


def test_failure_emits_only_static_error(monkeypatch, capsys):
    monkeypatch.setattr(smoke, "validate_os_identity", lambda *_: "debian")
    monkeypatch.setattr(smoke, "run_rehearsal",
                        lambda **_: (_ for _ in ()).throw(
                            smoke.ContainerInstallRehearsalError("CONTAINER_ISOLATION_UNVERIFIED")
                        ))
    assert smoke.main() == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "code": "CONTAINER_ISOLATION_UNVERIFIED", "status": "FAIL"
    }
