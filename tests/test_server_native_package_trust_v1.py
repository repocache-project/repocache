"""Native APT/DNF signed metadata probe negative/security tests (#27).

Fixtures and simulated process responses do not certify booted native hosts.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

from repocache.server_install_v1 import InstallInputError
from repocache import server_native_package_trust_v1 as native

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
DEBIAN = "ID=debian\nVERSION_ID=13\n"
ALMA = "ID=almalinux\nVERSION_ID=10\n"


def document():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def _run_success(output):
    calls = []

    def runner(args, **kwargs):
        assert isinstance(args, list) and args[0] in ("/usr/bin/apt-get",
                                                       "/usr/bin/apt-cache",
                                                       "/usr/bin/dnf")
        assert kwargs["timeout"] == 120 and kwargs["check"] is False
        assert kwargs["capture_output"] and kwargs["text"]
        assert kwargs["env"]["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
        assert kwargs["env"]["LC_ALL"] == "C"
        assert "http_proxy" not in kwargs["env"]
        assert "SECRET" not in kwargs["env"]
        assert not any(item in args for item in ("install", "upgrade", "remove",
                                                 "--allow-unauthenticated"))
        calls.append((list(args), kwargs))
        return SimpleNamespace(returncode=0, stdout=("" if len(calls) == 1
                                                       else output), stderr="")

    return calls, runner


@pytest.mark.parametrize("distro,release,python,output", [
    ("debian", DEBIAN, (3, 13), "nginx:\n Installed: (none)\n Candidate: 1.26.3-1\n"),
    ("almalinux", ALMA, (3, 12), "nginx\n"),
])
def test_fixed_native_sandbox_and_successfully_queried_candidate(
    monkeypatch, distro, release, python, output,
):
    monkeypatch.setattr(native, "_trusted_key", lambda path: True)
    input_doc = document()
    before = copy.deepcopy(input_doc)
    calls, runner = _run_success(output)
    evidence = native.inspect_native_nginx_metadata(
        os_release=release, python_version=python, document=input_doc,
        runner=runner,
    )
    assert input_doc == before
    assert evidence.distribution == distro
    assert evidence.metadata_signed is True
    assert evidence.candidate_available is True
    assert evidence.authorizes_installation is False
    report = evidence.to_dict()
    assert report["status"] == "PASS"
    assert report["can_install"] is False
    assert report["payload_signature_verified"] is False
    assert report["authorizes_installation"] is False
    assert len(calls) == 2
    update, query = (calls[0][0], calls[1][0])
    cwd = Path(calls[0][1]["cwd"])
    assert cwd == Path(calls[1][1]["cwd"])
    assert not cwd.exists()  # temporary state cleaned after probe
    assert not any("/var/lib/apt" in arg or "/var/cache/dnf" in arg
                   for arg in update + query)
    if distro == "debian":
        assert update[0] == "/usr/bin/apt-get"
        assert query[0] == "/usr/bin/apt-cache"
        assert "update" in update and "policy" in query
        assert "APT::Update::Error-Mode=any" in update
        assert "Acquire::AllowInsecureRepositories=false" in update
        assert any("Dir::Etc::sourceparts=-" == x for x in update)
        assert any("sourcelist=" in x for x in update)
    else:
        assert update[0] == query[0] == "/usr/bin/dnf"
        assert "makecache" in update and "--refresh" in update
        assert "repoquery" in query and "--available" in query
        assert "--setopt=rc-baseos.repo_gpgcheck=1" in update
        assert "--setopt=rc-appstream.repo_gpgcheck=1" in update
        assert "--setopt=skip_if_unavailable=0" in update
        assert "--assumeyes" in update
        assert "--noplugins" in update
        assert "--no-plugins" not in update
        assert "--disablerepo=*" in update
        assert "--enablerepo=rc-baseos,rc-appstream" in update
        assert "--setopt=rc-baseos.gpgcheck=1" in update
        assert "--setopt=rc-appstream.gpgcheck=1" in update
        assert not any(".pkg_gpgcheck=" in arg for arg in update)
        assert not any(arg.startswith("--repo=") for arg in update)


@pytest.mark.parametrize("distro,release,python,output", [
    ("debian", DEBIAN, (3, 13), "Candidate: (none)\n"),
    ("debian", DEBIAN, (3, 13), "Installed: 1.1\n"),
    ("debian", DEBIAN, (3, 13), "Candidate: 1.0\n Candidate: 2.0\n"),
    ("almalinux", ALMA, (3, 12), ""),
    ("almalinux", ALMA, (3, 12), "nginx\nuntrusted-package\n"),
])
def test_absent_or_ambiguous_candidate_never_claimed(
    monkeypatch, distro, release, python, output,
):
    monkeypatch.setattr(native, "_trusted_key", lambda path: True)
    _, runner = _run_success(output)
    result = native.inspect_native_nginx_metadata(
        os_release=release, python_version=python,
        document=document(), runner=runner,
    )
    assert result.to_dict()["code"] == "NATIVE_PACKAGE_NOT_AVAILABLE"
    assert not result.candidate_available
    assert not result.authorizes_installation


@pytest.mark.parametrize("mode", ["bad-exit", "exception", "timeout", "bad-stdout",
                                  "oversized", "unsigned-warning", "skipped-repo"])
def test_native_manager_failure_is_redacted_and_fails_closed(monkeypatch, mode):
    monkeypatch.setattr(native, "_trusted_key", lambda path: True)
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        if mode == "exception":
            raise OSError("secret-operator-repository-url")
        if mode == "timeout":
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        if mode == "bad-exit":
            return SimpleNamespace(returncode=1, stdout="", stderr="SecretToken: sensitive")
        if mode == "bad-stdout":
            return SimpleNamespace(returncode=0, stdout=None, stderr="")
        if mode == "oversized":
            return SimpleNamespace(returncode=0, stdout="x" * 65537, stderr="")
        if mode == "unsigned-warning":
            return SimpleNamespace(returncode=0, stdout="", stderr="repository not signed")
        return SimpleNamespace(returncode=0, stdout="",
                               stderr="Skipping repository due to invalid signature")

    result = native.inspect_native_nginx_metadata(
        os_release=DEBIAN, python_version=(3, 13),
        document=document(), runner=runner,
    )
    rendered = json.dumps(result.to_dict())
    assert not result.authorizes_installation
    assert result.to_dict()["status"] == "NOT VERIFIED"
    assert "SecretToken" not in rendered
    assert "secret-operator" not in rendered
    assert "sensitive" not in rendered
    assert len(calls) == 1


def test_invalid_os_or_policy_never_calls_native_manager(monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("unsupported platform must fail before native command")

    monkeypatch.setattr(native, "_trusted_key", forbidden)
    with pytest.raises(InstallInputError):
        native.inspect_native_nginx_metadata(
            os_release="ID=debian\nVERSION_ID=12\n",
            python_version=(3, 13), document=document(), runner=forbidden,
        )
    value = document()
    value["deployment"]["native_packages"]["policy"] = "auto"
    with pytest.raises(InstallInputError):
        native.inspect_native_nginx_metadata(
            os_release=DEBIAN, python_version=(3, 13),
            document=value, runner=forbidden,
        )


def test_bad_trust_anchor_fails_before_network_or_command(monkeypatch):
    calls = []
    def never_run(*args, **kwargs):
        calls.append(args)
        raise AssertionError("untrusted key may not result in a subprocess")

    monkeypatch.setattr(native, "_trusted_key", lambda path: False)
    evidence = native.inspect_native_nginx_metadata(
        os_release=ALMA, python_version=(3, 12),
        document=document(), runner=never_run,
    )
    assert not calls
    assert evidence.to_dict()["code"] == "NATIVE_TRUST_ANCHOR_UNSAFE"
    assert not evidence.authorizes_installation


def test_distro_sources_are_fixed_and_signature_checks_not_optional(tmp_path):
    # Deliberately only exercise exact, code-owned paths in a controlled root.
    root = tmp_path / "scratch"
    root.mkdir()
    update, query = native._apt_commands(root)
    source = (root / "sources.list").read_text(encoding="ascii")
    assert "signed-by=/usr/share/keyrings/debian-archive-keyring.pgp" in source
    assert source.count("deb [signed-by=") == 3
    assert "example.invalid" not in source
    assert "trusted=yes" not in source
    assert "AllowUnauthenticated=false" in " ".join(update)
    assert "policy" in query
    alma = tmp_path / "alma"
    alma.mkdir()
    refresh, repoquery = native._dnf_commands(alma)
    conf = (alma / "dnf.conf").read_text(encoding="ascii")
    repos = (alma / "repos" / "repocache.repo").read_text(encoding="ascii")
    assert "repo_gpgcheck=1" in conf
    assert "pkg_gpgcheck" not in conf
    assert repos.count("repo_gpgcheck=1") == 2
    assert "pkg_gpgcheck" not in repos
    assert repos.count("gpgcheck=1") == 4  # RPM and metadata GPG checks in both repos
    assert "skip_if_unavailable=0" in conf
    assert "https://repo.almalinux.org/almalinux/10/" in repos
    assert "repoquery" in repoquery
    assert "install" not in refresh


def test_trust_anchor_rejects_symlink_and_unprivileged_ancestors(
    tmp_path, monkeypatch,
):
    # Construct a safe synthetic root using mocked lstat so host /tmp modes
    # are not mistaken for actual trusted OS keyring provenance.
    good = SimpleNamespace(st_uid=0, st_mode=(stat.S_IFDIR | 0o755),
                           st_size=1024)
    leaf = SimpleNamespace(st_uid=0, st_mode=(stat.S_IFREG | 0o644),
                           st_size=128, st_nlink=1)

    def virtual_lstat(path):
        return leaf if str(path) == "/etc/pki/rpm-gpg/KEY" else good

    monkeypatch.setattr(native.os, "lstat", virtual_lstat)
    assert native._trusted_key("/etc/pki/rpm-gpg/KEY")
    monkeypatch.setattr(native.os, "lstat", lambda path:
        SimpleNamespace(st_uid=1000, st_mode=stat.S_IFREG | 0o644, st_size=42)
        if str(path) == "/etc/pki/rpm-gpg/KEY" else good)
    assert not native._trusted_key("/etc/pki/rpm-gpg/KEY")
    monkeypatch.setattr(native.os, "lstat", lambda path:
        SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777, st_size=42)
        if str(path) == "/etc/pki/rpm-gpg/KEY" else good)
    assert not native._trusted_key("/etc/pki/rpm-gpg/KEY")


def test_debian_key_path_must_be_real_root_owned_regular_file(monkeypatch):
    """A distro-supplied symlink is not an acceptable verified key path."""
    assert native._NATIVE["debian"][2] == (
        "/usr/share/keyrings/debian-archive-keyring.pgp"
    )
    key = native._NATIVE["debian"][2]
    root = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755, st_size=4096)
    proper = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644, st_size=128, st_nlink=1)
    link = SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777, st_size=128)
    monkeypatch.setattr(native.os, "lstat",
                        lambda name: proper if str(name) == key else root)
    assert native._trusted_key(key) is True
    monkeypatch.setattr(native.os, "lstat",
                        lambda name: link if str(name) == key else root)
    assert native._trusted_key(key) is False


@pytest.mark.parametrize("changes", [
    {"st_nlink": 2}, {"st_nlink": 0}, {"st_nlink": True},
    {"st_size": 0}, {"st_size": 1024 * 1024 + 1},
])
def test_native_signing_anchor_must_be_single_link_and_bounded(
    monkeypatch, changes,
):
    good_dir = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755,
                               st_size=4096)
    leaf = dict(st_uid=0, st_mode=stat.S_IFREG | 0o644,
                st_size=4096, st_nlink=1)
    leaf.update(changes)
    key = "/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10"
    monkeypatch.setattr(native.os, "lstat", lambda path: (
        SimpleNamespace(**leaf) if str(path) == key else good_dir
    ))
    assert native._trusted_key(key) is False


def test_normal_single_link_signed_distribution_anchor_still_eligible(monkeypatch):
    directory = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755,
                                st_size=4096)
    leaf = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644,
                           st_size=4096, st_nlink=1)
    key = "/usr/share/keyrings/debian-archive-keyring.pgp"
    monkeypatch.setattr(native.os, "lstat", lambda p: leaf if str(p) == key else directory)
    assert native._trusted_key(key) is True


@pytest.mark.parametrize("output", [
    "Candidate: 1.26.3-1\n",
    "foreign-package:\n Candidate: 1.26.3-1\n",
    "nginx:\n Candidate: /tmp/untrusted-package\n",
    "nginx:\n Candidate: not-a-version\n",
    "nginx:\n Candidate: 1.2;unexpected\n",
    "nginx:\n Candidate: 1.2\nnginx:\n",
    "nginx:\n Candidate: 1.2\n Candidate: 1.3\n",
])
def test_apt_policy_candidate_requires_exact_nginx_and_version(
    monkeypatch, output,
):
    monkeypatch.setattr(native, "_trusted_key", lambda path: True)
    _, runner = _run_success(output)
    evidence = native.inspect_native_nginx_metadata(
        os_release=DEBIAN, python_version=(3, 13),
        document=document(), runner=runner,
    )
    assert evidence.to_dict()["code"] == "NATIVE_PACKAGE_NOT_AVAILABLE"
    assert not evidence.candidate_available
    assert not evidence.authorizes_installation


@pytest.mark.parametrize("version", [
    "1.26.3-1", "2:1.26.3-1+deb13u1", "1.26.3~bpo13+1",
])
def test_legitimate_debian_versions_remain_valid_scratch_metadata(
    monkeypatch, version,
):
    monkeypatch.setattr(native, "_trusted_key", lambda path: True)
    _, runner = _run_success("nginx:\n Installed: (none)\n Candidate: " + version + "\n")
    evidence = native.inspect_native_nginx_metadata(
        os_release=DEBIAN, python_version=(3, 13),
        document=document(), runner=runner,
    )
    assert evidence.to_dict()["code"] == "NATIVE_CANDIDATE_OBSERVED"
    assert evidence.candidate_available and not evidence.authorizes_installation
