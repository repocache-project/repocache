"""Native NGINX download-only payload rehearsal, never a package installer (#27).

The signed metadata probe already proves repository metadata trust in a private
scratch tree. This second, explicitly initiated phase downloads into another
private tree using freshly checked native metadata; it never runs an RPM/DPKG
transaction, writes a host package cache, or authorizes service activation.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any, Callable

from repocache.server_native_nginx_ownership_v1 import (
    prepare_fresh_native_nginx,
)
from repocache.server_native_package_trust_v1 import (
    _NATIVE, _apt_commands, _dnf_commands, _run,
)

_MAX_ARTIFACTS = 96
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_CODES = frozenset({
    "NATIVE_PAYLOADS_VERIFIED_IN_SCRATCH",
    "NATIVE_PREPARATION_NOT_VERIFIED",
    "NATIVE_DOWNLOAD_METADATA_FAILED",
    "NATIVE_DOWNLOAD_FAILED",
    "NATIVE_PAYLOAD_SET_UNSAFE",
    "NATIVE_PAYLOAD_SIGNATURE_FAILED",
    "NATIVE_NGINX_PAYLOAD_MISSING",
})


@dataclass(frozen=True)
class NativePayloadRehearsalV1:
    distribution: str
    code: str
    payload_count: int

    def __post_init__(self) -> None:
        if (type(self.distribution) is not str
                or self.distribution not in _NATIVE
                or type(self.code) is not str or self.code not in _CODES
                or type(self.payload_count) is not int
                or not 0 <= self.payload_count <= _MAX_ARTIFACTS
                or (self.code == "NATIVE_PAYLOADS_VERIFIED_IN_SCRATCH")
                != (self.payload_count > 0)):
            raise ValueError("invalid download-only evidence")

    def to_dict(self) -> dict[str, Any]:
        ok = self.code == "NATIVE_PAYLOADS_VERIFIED_IN_SCRATCH"
        return {
            "schema_version": 1,
            "distribution": self.distribution,
            "code": self.code,
            "status": "PASS" if ok else "NOT VERIFIED",
            "payload_count": self.payload_count,
            "native_download_only": True,
            "scratch_payload_integrity_verified": ok,
            # Debian .deb authenticity is bound to signed apt Release/Packages
            # hashes; unlike RPM, individual .deb files are not GPG-signed.
            "individual_rpm_signatures_verified": ok and self.distribution == "almalinux",
            "host_package_transaction_performed": False,
            "payloads_persisted_for_installation": False,
            "authorizes_package_installation": False,
            "authorizes_nginx_activation": False,
            "can_install": False,
        }


def _download_command(distro: str, work: Path) -> tuple[list[str], list[str], Path]:
    """Use the identical fixed APT/DNF4 source and trust configuration."""
    if distro == "debian":
        refresh, _ = _apt_commands(work)
        # -d/--download-only is essential: apt-get install never invokes dpkg.
        # The empty isolated dpkg status prevents host-state installation
        # decisions; cache and sources are strictly private/fixed.
        return (refresh, [*refresh[:-1], "--assume-yes", "--download-only",
                          "--no-install-recommends", "install", "nginx"],
                work / "archives")
    refresh, _ = _dnf_commands(work)
    output = work / "payloads"
    output.mkdir(mode=0o700)
    # DNF4 --downloadonly does not execute an RPM transaction. DNF is confined
    # to the private installroot/cache and the fixed signed distro sources.
    return (refresh, [*refresh[:-2], "--downloadonly", f"--downloaddir={output}",
                     "--setopt=install_weak_deps=False", "install", "nginx"], output)


def _artifacts(directory: Path, extension: str) -> tuple[Path, ...] | None:
    """Reject unexpected special files, links, partials and oversized sets."""
    try:
        if not directory.is_dir() or directory.is_symlink():
            return None
        root = os.stat(directory)
        # The extraction/download root itself must be private and owned by
        # the executing user. Checking only the children left a writable
        # root able to acquire injected new payloads during inventory.
        if (not stat.S_ISDIR(root.st_mode)
                or root.st_uid != os.geteuid()
                or root.st_mode & 0o022):
            return None
        found: list[Path] = []
        total = 0
        for item in directory.rglob("*"):
            info = item.lstat()
            if (info.st_dev != root.st_dev or info.st_uid != os.geteuid()
                    or info.st_mode & 0o022):
                return None
            if stat.S_ISDIR(info.st_mode):
                continue
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                return None
            if item.name == "lock" and item.parent == directory and extension == ".deb":
                continue
            # Files left in APT's /partial are not committed downloads.
            if "partial" in item.relative_to(directory).parts:
                return None
            if item.suffix != extension or info.st_size <= 0:
                return None
            total += info.st_size
            found.append(item)
            if len(found) > _MAX_ARTIFACTS or total > _MAX_TOTAL_BYTES:
                return None
        if not found:
            return None
        return tuple(sorted(found))
    except (OSError, ValueError, RuntimeError):
        return None


def _verify_deb(
    files: tuple[Path, ...], *, work: Path, runner: Callable[..., Any],
) -> str:
    names: set[str] = set()
    for item in files:
        # Metadata read only; NEVER evaluate maintainer scripts inside .debs.
        output, error = _run(
            ["/usr/bin/dpkg-deb", "--field", str(item), "Package"],
            work=work, runner=runner,
        )
        if error:
            return "NATIVE_PAYLOAD_SIGNATURE_FAILED"
        name = output.strip()
        if not name or len(name) > 128 or not all(
            c.isascii() and (c.isalnum() or c in "+-.") for c in name
        ):
            return "NATIVE_PAYLOAD_SET_UNSAFE"
        names.add(name)
    return ("NATIVE_PAYLOADS_VERIFIED_IN_SCRATCH" if "nginx" in names
            else "NATIVE_NGINX_PAYLOAD_MISSING")


def _verify_rpm(
    files: tuple[Path, ...], *, work: Path, runner: Callable[..., Any],
) -> str:
    db = work / "rpmdb"
    db.mkdir(mode=0o700)
    for command in (
        ["/usr/bin/rpm", f"--dbpath={db}", "--initdb"],
        ["/usr/bin/rpm", f"--dbpath={db}", "--import", _NATIVE["almalinux"][2]],
    ):
        _, error = _run(command, work=work, runner=runner)
        if error:
            return "NATIVE_PAYLOAD_SIGNATURE_FAILED"
    names: set[str] = set()
    for item in files:
        out, error = _run(
            ["/usr/bin/rpmkeys", f"--dbpath={db}", "--checksig", str(item)],
            work=work, runner=runner,
        )
        # rpmkeys may report digest-only OK. Require an actual validated
        # OpenPGP signature class and reject all failure/unknown-key results.
        # Parse the result after the filename delimiter: 'signatures' in
        # a maliciously named RPM file is never verification evidence.
        lines = out.strip().splitlines()
        if (error or len(lines) != 1 or ": " not in lines[0]
                or lines[0].rsplit(": ", 1)[1] != "digests signatures OK"):
            return "NATIVE_PAYLOAD_SIGNATURE_FAILED"
        name, error = _run(
            ["/usr/bin/rpm", f"--dbpath={db}", "-qp",
             "--queryformat=%{NAME}", str(item)],
            work=work, runner=runner,
        )
        if error:
            return "NATIVE_PAYLOAD_SIGNATURE_FAILED"
        name = name.strip()
        if not name or len(name) > 128 or not all(
            c.isascii() and (c.isalnum() or c in "+-.") for c in name
        ):
            return "NATIVE_PAYLOAD_SET_UNSAFE"
        names.add(name)
    return ("NATIVE_PAYLOADS_VERIFIED_IN_SCRATCH" if "nginx" in names
            else "NATIVE_NGINX_PAYLOAD_MISSING")


def rehearse_native_nginx_downloads(
    *, os_release: str, python_version: tuple[int, int],
    document: dict[str, Any],
    lstat: Callable[[str], os.stat_result] = os.lstat,
    runner: Callable[..., Any] = subprocess.run,
) -> NativePayloadRehearsalV1:
    """Repeat signed-metadata trust and fetch packages only in disposable scratch.

    No reuse of the returned evidence as an install approval is permitted.
    On an actual host, pre-existing ownership and state may change between
    observations; the privileged transaction needs fresh locked rechecks.
    """
    prepared = prepare_fresh_native_nginx(
        os_release=os_release, python_version=python_version,
        document=document, lstat=lstat, runner=runner,
    )
    distro = prepared.footprint.distribution
    if (not prepared.footprint.allows_metadata_probe
            or prepared.metadata is None
            or prepared.metadata.code != "NATIVE_CANDIDATE_OBSERVED"):
        return NativePayloadRehearsalV1(
            distro, "NATIVE_PREPARATION_NOT_VERIFIED", 0)
    with tempfile.TemporaryDirectory(prefix="repocache-native-payload-") as tmp:
        work = Path(tmp)
        refresh, command, output_dir = _download_command(distro, work)
        _, error = _run(refresh, work=work, runner=runner)
        if error:
            return NativePayloadRehearsalV1(
                distro, "NATIVE_DOWNLOAD_METADATA_FAILED", 0)
        _, error = _run(command, work=work, runner=runner)
        if error:
            return NativePayloadRehearsalV1(distro, "NATIVE_DOWNLOAD_FAILED", 0)
        files = _artifacts(output_dir, ".deb" if distro == "debian" else ".rpm")
        if files is None:
            return NativePayloadRehearsalV1(
                distro, "NATIVE_PAYLOAD_SET_UNSAFE", 0)
        code = (_verify_deb(files, work=work, runner=runner)
                if distro == "debian" else
                _verify_rpm(files, work=work, runner=runner))
        return NativePayloadRehearsalV1(
            distro, code, len(files) if code == "NATIVE_PAYLOADS_VERIFIED_IN_SCRATCH"
            else 0)
