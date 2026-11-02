"""Non-installing native NGINX package metadata and provenance probe (#27).

Run native package-manager signature checks against a fresh, disposable,
explicitly allowlisted repository configuration. Never interpret this snapshot
as authorization to install, reload NGINX, change firewall rules or mutate
protected state. Package payload signatures require rechecking at installation.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any, Callable

from repocache.server_native_package_plan_v1 import preview_nginx_packages

# Fixed native binaries and OS-distributed trust anchors. Non-approved
# operator repository files, custom GPG keys and untrusted mirrors are unused.
_NATIVE = {
    "debian": ("/usr/bin/apt-get", "/usr/bin/apt-cache",
               "/usr/share/keyrings/debian-archive-keyring.pgp"),
    "almalinux": ("/usr/bin/dnf", "/usr/bin/dnf",
                  "/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10"),
}
_FAILURE_HINTS = {
    "NATIVE_TRUST_ANCHOR_UNSAFE": "Verify the OS-distributed root-owned signing key and its directory permissions.",
    "NATIVE_MANAGER_FAILED": "Inspect native APT/DNF trust, connectivity and repository availability in the operator console.",
    "NATIVE_MANAGER_TIMEOUT": "Restore connectivity to the distribution repositories and retry the native package probe.",
    "NATIVE_MANAGER_OUTPUT_INVALID": "Inspect the native package manager diagnostics; no trusted NGINX candidate was established.",
    "NATIVE_PACKAGE_NOT_AVAILABLE": "Check the distribution NGINX package availability in the authenticated native repository.",
}
_MAX_CAPTURE_BYTES = 64 * 1024
_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class NativeMetadataEvidenceV1:
    distribution: str
    code: str
    metadata_signed: bool
    candidate_available: bool

    def __post_init__(self) -> None:
        permitted = {
            "NATIVE_CANDIDATE_OBSERVED": (True, True),
            "NATIVE_PACKAGE_NOT_AVAILABLE": (True, False),
            **{code: (False, False) for code in _FAILURE_HINTS
               if code != "NATIVE_PACKAGE_NOT_AVAILABLE"},
        }
        if (type(self.distribution) is not str or self.distribution not in _NATIVE or
            type(self.code) is not str or self.code not in permitted or
            type(self.metadata_signed) is not bool or
            type(self.candidate_available) is not bool or
            (self.metadata_signed, self.candidate_available) != permitted[self.code]):
            raise ValueError("invalid native metadata evidence")

    @property
    def authorizes_installation(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_schema_version": 1,
            "distribution": self.distribution,
            "native_package": "nginx",
            "code": self.code,
            "status": ("PASS" if self.code == "NATIVE_CANDIDATE_OBSERVED"
                       else "NOT VERIFIED"),
            "metadata_signed": self.metadata_signed,
            "candidate_available": self.candidate_available,
            "payload_signature_verified": False,
            "authorizes_installation": False,
            "can_install": False,
            "guidance": (_FAILURE_HINTS.get(self.code)
                         or "Recheck signed metadata and package signatures at privileged installation."),
        }


def _trusted_key(path: str) -> bool:
    """Refuse symlinks and writable/unprivileged trust-anchor ancestry."""
    if type(path) is not str or not path.startswith("/"):
        return False
    current = Path("/")
    try:
        root = os.lstat(current)
    except OSError:
        return False
    if (root.st_uid != 0 or root.st_mode & 0o022 or
        not stat.S_ISDIR(root.st_mode)):
        return False
    for segment in Path(path).parts[1:]:
        current = current / segment
        try:
            info = os.lstat(current)
        except OSError:
            return False
        if info.st_uid != 0 or info.st_mode & 0o022:
            return False
        if segment == Path(path).parts[-1] and current == Path(path):
            if not stat.S_ISREG(info.st_mode) or not info.st_size:
                return False
        elif not stat.S_ISDIR(info.st_mode):
            return False
    return True


def _apt_commands(work: Path) -> tuple[list[str], list[str]]:
    """Isolated apt-secure signed metadata for Debian 13 official sources."""
    source = work / "sources.list"
    source.write_text(
        "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] "
        "https://deb.debian.org/debian trixie main\n"
        "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] "
        "https://deb.debian.org/debian trixie-updates main\n"
        "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] "
        "https://security.debian.org/debian-security trixie-security main\n",
        encoding="ascii",
    )
    for item in ("lists", "cache", "archives"):
        (work / item).mkdir(mode=0o700)
    # Absolute values override host state/cache, source configuration and
    # archive trust: user-controlled apt source lists are never consulted.
    opts = [
        "-o", f"Dir::State::lists={work / 'lists'}",
        "-o", f"Dir::State::status={work / 'absent-dpkg-status'}",
        "-o", f"Dir::Cache={work / 'cache'}",
        "-o", f"Dir::Cache::archives={work / 'archives'}",
        "-o", f"Dir::Etc::sourcelist={source}",
        "-o", "Dir::Etc::sourceparts=-",
        "-o", "Dir::Etc::main=-",
        "-o", "Dir::Etc::parts=-",
        "-o", "Dir::Etc::trusted=-",
        "-o", "Dir::Etc::trustedparts=-",
        "-o", "APT::Get::AllowUnauthenticated=false",
        "-o", "Acquire::AllowInsecureRepositories=false",
        "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
        "-o", "Acquire::Check-Valid-Until=true",
        "-o", "APT::Update::Error-Mode=any",
        "-o", "APT::Get::List-Cleanup=false",
        "-o", "APT::Sandbox::User=root",
    ]
    return ([_NATIVE["debian"][0], *opts, "update"],
            [_NATIVE["debian"][1], *opts, "policy", "nginx"])


def _dnf_commands(work: Path) -> tuple[list[str], list[str]]:
    """Isolated AlmaLinux 10 DNF4 metadata with mandatory OpenPGP checks."""
    repodir = work / "repos"
    repodir.mkdir(mode=0o700)
    (work / "root").mkdir(mode=0o700)
    (work / "cache").mkdir(mode=0o700)
    (work / "log").mkdir(mode=0o700)
    (work / "persist").mkdir(mode=0o700)
    (work / "vars").mkdir(mode=0o700)
    # AlmaLinux 10 ships DNF4: its '--noplugins', '--disablerepo' and
    # 'gpgcheck' syntax differs from DNF5. DNF4 does not support the DNF5
    # pkg_gpgcheck option, so require native DNF4 gpgcheck=1 instead.
    # Only distribution-selected HTTPS endpoints and root-owned OS signing
    # key; never reuse third-party enabled host repositories or host DNF cache.
    (repodir / "repocache.repo").write_text(
        "[rc-baseos]\nname=AlmaLinux 10 BaseOS\n"
        "baseurl=https://repo.almalinux.org/almalinux/10/BaseOS/$basearch/os/\n"
        "enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"
        "sslverify=1\nskip_if_unavailable=0\n"
        "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10\n"
        "[rc-appstream]\nname=AlmaLinux 10 AppStream\n"
        "baseurl=https://repo.almalinux.org/almalinux/10/AppStream/$basearch/os/\n"
        "enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"
        "sslverify=1\nskip_if_unavailable=0\n"
        "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10\n",
        encoding="ascii",
    )
    config = work / "dnf.conf"
    config.write_text(
        "[main]\n"
        f"reposdir={repodir}\n"
        f"cachedir={work / 'cache'}\n"
        f"system_cachedir={work / 'cache'}\n"
        f"logdir={work / 'log'}\n"
        f"persistdir={work / 'persist'}\n"
        f"varsdir={work / 'vars'}\n"
        "gpgcheck=1\nrepo_gpgcheck=1\n"
        "sslverify=1\nskip_if_unavailable=0\nbest=1\nplugins=0\n",
        encoding="ascii",
    )
    args = [
        _NATIVE["almalinux"][0], f"--config={config}",
        f"--installroot={work / 'root'}", "--releasever=10",
        f"--setopt=reposdir={repodir}",
        f"--setopt=cachedir={work / 'cache'}",
        f"--setopt=system_cachedir={work / 'cache'}",
        f"--setopt=logdir={work / 'log'}",
        f"--setopt=persistdir={work / 'persist'}",
        f"--setopt=varsdir={work / 'vars'}",
        "--disablerepo=*",
        "--enablerepo=rc-baseos,rc-appstream",
        "--noplugins",
        "--setopt=skip_if_unavailable=0",
        "--setopt=sslverify=1",
        "--setopt=plugins=0",
        "--setopt=rc-baseos.repo_gpgcheck=1",
        "--setopt=rc-appstream.repo_gpgcheck=1",
        "--setopt=rc-baseos.gpgcheck=1",
        "--setopt=rc-appstream.gpgcheck=1",
        "--assumeyes",
    ]
    return ([*args, "makecache", "--refresh"],
            [*args, "repoquery", "--available", "--queryformat=%{name}", "nginx"])


def _run(command: list[str], *, work: Path,
         runner: Callable[..., Any]) -> tuple[str, str]:
    """Execute with sanitized environment. Never expose raw subprocess output."""
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(work),
        "TMPDIR": str(work),
        "LC_ALL": "C",
        "LANG": "C",
        "DEBIAN_FRONTEND": "noninteractive",
        "APT_CONFIG": "/dev/null",
    }
    try:
        proc = runner(command, env=env, cwd=str(work), text=True,
                      capture_output=True, check=False, timeout=_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return "", "NATIVE_MANAGER_TIMEOUT"
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return "", "NATIVE_MANAGER_FAILED"
    if (type(proc.returncode) is not int or proc.returncode != 0 or
        type(proc.stdout) is not str or type(proc.stderr) is not str):
        return "", "NATIVE_MANAGER_FAILED"
    if (len(proc.stdout) > _MAX_CAPTURE_BYTES or
        len(proc.stderr) > _MAX_CAPTURE_BYTES):
        return "", "NATIVE_MANAGER_OUTPUT_INVALID"
    # A zero exit code alone is insufficient if DNF skipped a broken repo.
    lowered = (proc.stdout + proc.stderr).lower()
    if any(token in lowered for token in (
        "skipping repository", "ignoring repository", "failed to download",
        "gpg check failed", "signature verification failed", "not signed",
        "signature error", "gpg error", "cannot be authenticated",
        "repository unavailable", "no matching packages",
    )):
        return "", "NATIVE_MANAGER_FAILED"
    return proc.stdout, ""


def inspect_native_nginx_metadata(
    *, os_release: str, python_version: tuple[int, int],
    document: dict[str, Any],
    runner: Callable[..., Any] = subprocess.run,
) -> NativeMetadataEvidenceV1:
    """Refresh signed native metadata in scratch and query candidate, no install.

    Intended for an explicitly initiated #27 package verification stage,
    NOT for the no-network read-only #26 preflight. Always revalidate again
    in the separately authorized privileged transaction; no token/approval.
    """
    plan = preview_nginx_packages(
        os_release=os_release, python_version=python_version, document=document,
    )
    distro = plan.distribution
    if not _trusted_key(_NATIVE[distro][2]):
        return NativeMetadataEvidenceV1(distro, "NATIVE_TRUST_ANCHOR_UNSAFE", False, False)
    with tempfile.TemporaryDirectory(prefix="repocache-native-metadata-") as tmp:
        work = Path(tmp)
        update, query = (_apt_commands(work) if distro == "debian"
                         else _dnf_commands(work))
        _output, error = _run(update, work=work, runner=runner)
        if error:
            return NativeMetadataEvidenceV1(distro, error, False, False)
        output, error = _run(query, work=work, runner=runner)
        if error:
            return NativeMetadataEvidenceV1(distro, error, False, False)
        if distro == "debian":
            # Locale C apt-cache policy output: only accept an explicit
            # nonempty candidate, never an installed-package-only result.
            candidates = [line.strip().split(":", 1)[1].strip()
                          for line in output.splitlines()
                          if line.strip().startswith("Candidate:")]
            available = (len(candidates) == 1 and
                         candidates[0] not in ("(none)", "", "none") and
                         len(candidates[0]) <= 128)
        else:
            # Force --available and fixed repository list. Reject ambiguous
            # or untrusted output rather than assuming rc=0 means available.
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            available = bool(lines) and len(lines) <= 128 and all(
                line == "nginx" for line in lines
            )
        if not available:
            return NativeMetadataEvidenceV1(
                distro, "NATIVE_PACKAGE_NOT_AVAILABLE", True, False
            )
        return NativeMetadataEvidenceV1(
            distro, "NATIVE_CANDIDATE_OBSERVED", True, True
        )
