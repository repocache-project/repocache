"""Hosted VM runner preparation never disables APT authentication."""
import os
import stat
import subprocess
from types import SimpleNamespace

import pytest

from scripts import ci_prepare_qemu_runner as runner


def test_update_and_install_share_exact_source_and_security_options(monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "_trusted_runner_source", lambda: None)
    monkeypatch.setattr(runner.subprocess, "run", lambda argv, **kw: calls.append((argv, kw)))
    runner.prepare()
    assert len(calls) == 2
    update, install = (row[0] for row in calls)
    assert update[:2] == install[:2] == ["sudo", "-n"]
    assert update[2:update.index("update")] == install[3:install.index("install")]
    options = update[2:update.index("update")]
    for required in (
        "Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources",
        "Dir::Etc::sourceparts=-",
        "Acquire::AllowInsecureRepositories=false",
        "Acquire::AllowDowngradeToInsecureRepositories=false",
        "APT::Get::AllowUnauthenticated=false",
    ):
        assert required in options
    assert update[-2:] == ["update", "-qq"]
    assert install[-4:] == ["qemu-system-x86", "qemu-utils", "cloud-image-utils", "openssh-client"]
    assert all(kw == {"check": True, "stdin": subprocess.DEVNULL} for _, kw in calls)


def test_failed_archive_update_never_installs(monkeypatch):
    monkeypatch.setattr(runner, "_trusted_runner_source", lambda: None)
    calls = []
    def fail(argv, **kw):
        calls.append(argv)
        raise subprocess.CalledProcessError(100, argv)
    monkeypatch.setattr(runner.subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        runner.prepare()
    assert len(calls) == 1 and "update" in calls[0]


@pytest.mark.parametrize("fault", ["not-actions", "self-hosted", "wrong-os", "wrong-version",
                                  "source-symlink", "source-owner", "source-mode", "parent-mode",
                                  "empty-source", "missing-source"])
def test_runner_guard_refuses_before_sudo(monkeypatch, fault):
    monkeypatch.setenv("GITHUB_ACTIONS", "false" if fault == "not-actions" else "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted" if fault == "self-hosted" else "github-hosted")
    monkeypatch.setattr(runner.platform, "freedesktop_os_release", lambda: {
        "ID": "debian" if fault == "wrong-os" else "ubuntu",
        "VERSION_ID": "22.04" if fault == "wrong-version" else "24.04",
    })
    class Source:
        parents = [SimpleNamespace(lstat=lambda: SimpleNamespace(
            st_mode=stat.S_IFDIR | (0o777 if fault == "parent-mode" else 0o755),
            st_uid=0))]
        def lstat(self):
            if fault == "missing-source":
                raise FileNotFoundError()
            return SimpleNamespace(
                st_mode=(stat.S_IFLNK if fault == "source-symlink" else stat.S_IFREG)
                        | (0o666 if fault == "source-mode" else 0o644),
                st_uid=1000 if fault == "source-owner" else 0,
                st_size=0 if fault == "empty-source" else 300,
            )
    monkeypatch.setattr(runner, "_SOURCE", Source())
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **kw: pytest.fail("sudo before validation"))
    with pytest.raises((RuntimeError, FileNotFoundError)):
        runner.prepare()
