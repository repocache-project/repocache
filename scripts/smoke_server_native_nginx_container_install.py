"""CI-only native NGINX installation rehearsal in an ephemeral Docker image.

This script intentionally performs an actual APT/DNF package transaction
INSIDE an explicitly marked disposable test container. It is not an installer,
root helper, unit/service manager, or privilege delegation API. It must never
be run on a real host. No systemd, SELinux or production acceptance is claimed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from repocache.server_install_v1 import validate_os_identity
from repocache.server_native_package_trust_v1 import (
    _NATIVE, _apt_commands, _dnf_commands, _run, _trusted_key,
)


class ContainerInstallRehearsalError(ValueError):
    """Static, redacted CI failure codes; do not print package-manager output."""


def _deny(code: str) -> None:
    raise ContainerInstallRehearsalError(code)


def _commands(distribution: str, work: Path) -> tuple[list[str], list[str]]:
    """Generate a tightly bounded command pair from signed source profiles.

    Debian uses the same freshly authenticated APT lists and trusted sources
    as the download-only stage, but must use the *container* dpkg status file
    rather than the deliberately empty download rehearsal status database.

    AlmaLinux uses the identical signed DNF4 official repo configuration and
    disables all other repositories/plugins, but intentionally drops only
    --installroot: this disposable Docker image itself is the install target.
    """
    if distribution == "debian":
        update, _ = _apt_commands(work)
        actual_status = "-o"
        opts = list(update[:-1])
        # Reject future unreviewed command layout changes instead of silently
        # installing against unknown package-manager state.
        expected = "Dir::State::status=" + str(work / "absent-dpkg-status")
        positions = [i for i, x in enumerate(opts) if x == expected]
        if (len(positions) != 1 or positions[0] == 0
                or opts[positions[0] - 1] != actual_status):
            _deny("CONTAINER_APT_PROFILE_CHANGED")
        opts[positions[0]] = "Dir::State::status=/var/lib/dpkg/status"
        return [*opts, "update"], [
            *opts, "--assume-yes", "--no-install-recommends", "install", "nginx"
        ]
    if distribution == "almalinux":
        update, _ = _dnf_commands(work)
        if update[-2:] != ["makecache", "--refresh"]:
            _deny("CONTAINER_DNF_PROFILE_CHANGED")
        prefix = update[:-2]
        roots = [x for x in prefix if x.startswith("--installroot=")]
        if len(roots) != 1 or roots[0] != "--installroot=" + str(work / "root"):
            _deny("CONTAINER_DNF_PROFILE_CHANGED")
        opts = [x for x in prefix if x != roots[0]]
        return [*opts, "makecache", "--refresh"], [*opts, "install", "nginx"]
    _deny("CONTAINER_DISTRIBUTION_UNSUPPORTED")


def run_rehearsal(
    *,
    distribution: str,
    runner=subprocess.run,
) -> dict[str, object]:
    """Verify all fixed guards, install only in the disposable image."""
    if (os.environ.get("REPOCACHE_NATIVE_TEST_CONTAINER") !=
            "CONFIRMED_DISPOSABLE_DOCKER_ONLY"
            or not Path("/.dockerenv").is_file()
            or os.geteuid() != 0):
        _deny("CONTAINER_ISOLATION_UNVERIFIED")
    release = Path("/etc/os-release").read_text(encoding="ascii")
    observed = validate_os_identity(
        release, (sys.version_info.major, sys.version_info.minor)
    )
    if observed != distribution:
        _deny("CONTAINER_DISTRIBUTION_MISMATCH")
    # First refuse any NGINX already installed or configured. This test must
    # never adopt or overwrite a pre-existing instance in the container.
    if any(os.path.lexists(path) for path in (
        "/etc/nginx", "/usr/sbin/nginx", "/usr/bin/nginx",
        "/usr/lib/systemd/system/nginx.service", "/lib/systemd/system/nginx.service",
    )):
        _deny("CONTAINER_EXISTING_NGINX_REFUSED")
    if not _trusted_key(_NATIVE[distribution][2]):
        _deny("CONTAINER_TRUST_ANCHOR_UNVERIFIED")
    with tempfile.TemporaryDirectory(prefix="repocache-container-nginx-") as tmp:
        work = Path(tmp)
        refresh, install = _commands(distribution, work)
        _, failure = _run(refresh, work=work, runner=runner)
        if failure:
            _deny("CONTAINER_AUTHENTICATED_REFRESH_FAILED")
        _, failure = _run(install, work=work, runner=runner)
        if failure:
            _deny("CONTAINER_NATIVE_PACKAGE_INSTALL_FAILED")
        if distribution == "debian":
            native_check = [
                "/usr/bin/dpkg-query", "-W", "-f=${Status}", "nginx"
            ]
        else:
            native_check = ["/usr/bin/rpm", "-q", "nginx"]
        output, failure = _run(native_check, work=work, runner=runner)
        if failure or (distribution == "debian" and
                       output.strip() != "install ok installed"):
            _deny("CONTAINER_NATIVE_PACKAGE_POSTCHECK_FAILED")
        if not Path("/usr/sbin/nginx").is_file():
            _deny("CONTAINER_NGINX_BINARY_MISSING")
        _, failure = _run(
            ["/usr/sbin/nginx", "-t", "-q"], work=work, runner=runner
        )
        if failure:
            _deny("CONTAINER_NGINX_CONFIG_VALIDATION_FAILED")
    return {
        "schema_version": 1,
        "status": "CONTAINER_NATIVE_NGINX_INSTALLED_SYNTAX_OK",
        "distribution": distribution,
        "authenticated_native_source_used": True,
        "native_transaction_executed_in_disposable_container": True,
        "nginx_syntax_test_passed_in_container": True,
        "native_systemd_tested": False,
        "selinux_enforcing_host_tested": False,
        "service_start_or_reload_explicitly_requested_by_test_driver": False,
        "host_package_transaction_authorized": False,
        "production_installation_verified": False,
    }


def main() -> int:
    try:
        distro = validate_os_identity(
            Path("/etc/os-release").read_text(encoding="ascii"),
            (sys.version_info.major, sys.version_info.minor),
        )
        evidence = run_rehearsal(distribution=distro)
    except Exception as exc:
        # Never emit package-manager stdout/stderr or environment paths.
        code = (str(exc) if type(exc) is ContainerInstallRehearsalError
                else "CONTAINER_REHEARSAL_UNVERIFIED")
        print(json.dumps({"status": "FAIL", "code": code}, sort_keys=True))
        return 1
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
