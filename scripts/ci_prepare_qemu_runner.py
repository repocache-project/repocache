#!/usr/bin/env python3
"""Install VM tooling from the hosted Ubuntu runner's existing archive only.

Unrelated preconfigured third-party repositories are not QEMU dependencies.
Keep all repository authentication, required packages and guest tests intact.
No changes to source files, keyrings, or guest package configuration.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import stat
import subprocess

_SOURCE = Path("/etc/apt/sources.list.d/ubuntu.sources")
_PACKAGES = ("qemu-system-x86", "qemu-utils", "cloud-image-utils", "openssh-client")


def _trusted_runner_source() -> None:
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("Expected disposable GitHub-hosted runner")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise RuntimeError("Expected Ubuntu 24.04 runner")
    for parent in _SOURCE.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise RuntimeError("Unsafe runner APT source parent")
    info = _SOURCE.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or not 0 < info.st_size <= 65536):
        raise RuntimeError("Expected root-owned Ubuntu archive source")


def prepare() -> None:
    _trusted_runner_source()
    # Use the runner's existing Ubuntu source (and its Signed-By policy),
    # rather than rewriting APT configuration or installing a new key.
    # Both operations must select exactly the same source set.
    apt = [
        "apt-get", "-o", f"Dir::Etc::sourcelist={_SOURCE}",
        "-o", "Dir::Etc::sourceparts=-",
        "-o", "Acquire::AllowInsecureRepositories=false",
        "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
        "-o", "APT::Get::AllowUnauthenticated=false",
    ]
    subprocess.run(["sudo", "-n", *apt, "update", "-qq"],
                   check=True, stdin=subprocess.DEVNULL)
    subprocess.run(["sudo", "-n", "DEBIAN_FRONTEND=noninteractive",
                    *apt, "install", "-y", "-qq", "--no-install-recommends", *_PACKAGES],
                   check=True, stdin=subprocess.DEVNULL)


if __name__ == "__main__":
    prepare()
