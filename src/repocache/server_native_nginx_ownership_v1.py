"""Conservative native NGINX fresh-host ownership gate (#27).

Read-only and non-authorizing. It rejects existing NGINX artifacts before
opt-in repository metadata traffic. This is not a comprehensive service,
listener, SELinux, package-transaction or protected-manifest ownership proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import subprocess
from typing import Any, Callable

from repocache.server_native_package_plan_v1 import preview_nginx_packages
from repocache.server_native_package_trust_v1 import (
    NativeMetadataEvidenceV1, inspect_native_nginx_metadata,
)

# Fixed, non-operator-controlled initial-install conflict markers. Presence of
# ANY entry, including a dangling symlink, refuses a fresh install. Absence
# is only a snapshot; nonstandard NGINX services still need independent checks.
_NGINX_MARKERS = (
    "/etc/nginx",
    "/usr/sbin/nginx",
    "/usr/bin/nginx",
    "/usr/local/sbin/nginx",
    "/usr/local/bin/nginx",
    "/usr/local/nginx",
    "/usr/local/etc/nginx",
    "/usr/lib/systemd/system/nginx.service",
    "/lib/systemd/system/nginx.service",
    "/etc/systemd/system/nginx.service",
    "/etc/systemd/system/nginx.service.d",
    "/etc/systemd/system/nginx.socket",
    # Non-packaged host units and runtime drop-ins can exist even after an
    # operator removes /etc/nginx and the distribution-owned binary.
    "/usr/local/lib/systemd/system/nginx.service",
    "/usr/local/lib/systemd/system/nginx.socket",
    "/usr/local/lib/systemd/system/nginx.service.d",
    "/etc/systemd/system/nginx.socket.d",
    "/run/systemd/system/nginx.service",
    "/run/systemd/system/nginx.service.d",
    "/run/systemd/system/nginx.socket",
    "/run/systemd/system/nginx.socket.d",
    "/etc/init.d/nginx",
    "/run/nginx.pid",
    "/var/run/nginx.pid",
    "/var/lib/nginx",
    "/var/lib/repocache/server",
    "/var/log/nginx",
)

_CODES = {
    "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED": "NOT VERIFIED",
    "EXISTING_NGINX_OWNERSHIP_UNPROVEN": "FAIL",
    "NGINX_FOOTPRINT_ACCESS_UNVERIFIED": "NOT VERIFIED",
    "NGINX_NONINITIAL_STATE_REFUSED": "FAIL",
    "NGINX_RUNNING_PROCESS_REFUSED": "FAIL",
    "NGINX_PROCESS_SCAN_UNVERIFIED": "NOT VERIFIED",
}


# /proc/<pid>/comm is a kernel-bounded process name, not an ownership
# attestation. A prior executable can stay active after its file is removed;
# checking only filesystem markers would permit an unsafe fresh install.
# Even a clean result is an expiring snapshot, never installation authority.
_MAX_PROC_PIDS = 65536
_PROC_FLAGS = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
               getattr(os, "O_CLOEXEC", 0))


def _scan_nginx_process_footprint(*, proc_root: str = "/proc") -> str:
    """Read bounded Linux process names without following /proc comm symlinks.

    The root override is private and used only by synthetic tests. Unknown,
    inaccessible or excessively large enumerations fail closed. An exited
    process may disappear between enumeration and its comm read; this is
    still a non-authorizing snapshot and must be repeated under a real
    privileged transaction. No command line, environment, PID or host path
    is returned to the caller or logged.
    """
    if (type(proc_root) is not str or not proc_root.startswith("/")
            or len(proc_root) > 4096 or "\x00" in proc_root):
        return "PROCESS_SCAN_UNVERIFIED"
    observed = 0
    try:
        with os.scandir(proc_root) as entries:
            for entry in entries:
                name = entry.name
                if (type(name) is not str or not name.isascii()
                        or not name.isdecimal() or name.startswith("0")
                        or len(name) > 10):
                    continue
                observed += 1
                if observed > _MAX_PROC_PIDS:
                    return "PROCESS_SCAN_UNVERIFIED"
                try:
                    fd = os.open(
                        proc_root + "/" + name + "/comm", _PROC_FLAGS,
                    )
                except FileNotFoundError:
                    # The process exited. Never promote this into an
                    # authoritative assertion that it cannot restart.
                    continue
                except OSError:
                    return "PROCESS_SCAN_UNVERIFIED"
                try:
                    value = os.read(fd, 64)
                    overflow = os.read(fd, 1)
                except FileNotFoundError:
                    continue
                except OSError:
                    return "PROCESS_SCAN_UNVERIFIED"
                finally:
                    os.close(fd)
                if overflow or not value or len(value) > 32:
                    return "PROCESS_SCAN_UNVERIFIED"
                name_bytes = value.removesuffix(b"\n")
                if name_bytes == b"nginx" or name_bytes.startswith(b"nginx:"):
                    return "PROCESS_NGINX_FOUND"
        return "PROCESS_NGINX_NOT_OBSERVED"
    except (OSError, TypeError, ValueError):
        return "PROCESS_SCAN_UNVERIFIED"


@dataclass(frozen=True)
class FreshNginxFootprintV1:
    distribution: str
    code: str

    def __post_init__(self) -> None:
        if (type(self.distribution) is not str
                or self.distribution not in ("debian", "almalinux")
                or type(self.code) is not str or self.code not in _CODES):
            raise ValueError("invalid fresh NGINX ownership evidence")

    @property
    def allows_metadata_probe(self) -> bool:
        return self.code == "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "distribution": self.distribution,
            "code": self.code,
            "status": _CODES[self.code],
            "no_known_conflict_observed": self.allows_metadata_probe,
            "all_nginx_instances_inventoried": False,
            "existing_instance_adoption_allowed": False,
            "protected_ownership_manifest_verified": False,
            "systemd_and_listeners_verified": False,
            "authorizes_package_transaction": False,
            "authorizes_nginx_activation": False,
            "guidance": (
                "Inspect and independently approve migration of existing NGINX; "
                "never take over its service or configuration."
                if self.code in (
                    "EXISTING_NGINX_OWNERSHIP_UNPROVEN",
                    "NGINX_RUNNING_PROCESS_REFUSED",
                ) else
                "Inspect unexpected host artifacts, access rights and ownership "
                "before any native package transaction."
                if self.code != "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED" else
                "Recheck service, listeners, protected state, ownership and "
                "package trust under an authorized privileged transaction."
            ),
        }


def inspect_fresh_nginx_footprint(
    *, os_release: str, python_version: tuple[int, int],
    document: dict[str, Any],
    lstat: Callable[[str], os.stat_result] = os.lstat,
    process_probe: Callable[[], str] | None = None,
) -> FreshNginxFootprintV1:
    """Validate input first; inspect fixed paths without following leaf links.

    A positive outcome is deliberately NOT VERIFIED for transaction approval:
    it does not observe all processes, mount namespaces, service aliases,
    firewall policy, alternate namespaces/binaries or a trusted manifest
    under lock. /proc comm is conservative early conflict evidence only.
    """
    plan = preview_nginx_packages(
        os_release=os_release, python_version=python_version, document=document
    )
    if document.get("expected_state_generation") != 0:
        return FreshNginxFootprintV1(
            plan.distribution, "NGINX_NONINITIAL_STATE_REFUSED"
        )
    present = False
    incomplete = False
    for path in _NGINX_MARKERS:
        try:
            lstat(path)
        except FileNotFoundError:
            pass
        except OSError:
            incomplete = True
        else:
            present = True
    if present:
        code = "EXISTING_NGINX_OWNERSHIP_UNPROVEN"
    elif incomplete:
        code = "NGINX_FOOTPRINT_ACCESS_UNVERIFIED"
    else:
        try:
            # Late binding keeps the real /proc probe as the production
            # default while synthetic tests can inject a separate simulated
            # process snapshot alongside their simulated lstat results.
            probe = (_scan_nginx_process_footprint
                     if process_probe is None else process_probe)
            observed_processes = probe()
        except (OSError, ValueError, TypeError):
            observed_processes = "PROCESS_SCAN_UNVERIFIED"
        if observed_processes == "PROCESS_NGINX_FOUND":
            code = "NGINX_RUNNING_PROCESS_REFUSED"
        elif observed_processes == "PROCESS_NGINX_NOT_OBSERVED":
            code = "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED"
        else:
            code = "NGINX_PROCESS_SCAN_UNVERIFIED"
    return FreshNginxFootprintV1(plan.distribution, code)


@dataclass(frozen=True)
class NativeFreshNginxPreparationV1:
    footprint: FreshNginxFootprintV1
    metadata: NativeMetadataEvidenceV1 | None

    def __post_init__(self) -> None:
        if type(self.footprint) is not FreshNginxFootprintV1:
            raise ValueError("invalid NGINX footprint")
        if (self.footprint.allows_metadata_probe
                and (type(self.metadata) is not NativeMetadataEvidenceV1
                     or self.metadata.distribution != self.footprint.distribution)):
            raise ValueError("missing or invalid native package evidence")
        if not self.footprint.allows_metadata_probe and self.metadata is not None:
            raise ValueError("native metadata may not bypass ownership refusal")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": "NOT VERIFIED" if self.footprint.allows_metadata_probe
                      else _CODES[self.footprint.code],
            "footprint": self.footprint.to_dict(),
            "metadata": None if self.metadata is None else self.metadata.to_dict(),
            "package_payload_authenticity_verified": False,
            "native_transaction_rechecked": False,
            "protected_transaction_lock_held": False,
            "systemd_and_selinux_verified": False,
            "authorizes_package_transaction": False,
            "can_install": False,
            "authorizes_nginx_activation": False,
        }


def prepare_fresh_native_nginx(
    *, os_release: str, python_version: tuple[int, int],
    document: dict[str, Any],
    lstat: Callable[[str], os.stat_result] = os.lstat,
    process_probe: Callable[[], str] | None = None,
    runner: Callable[..., Any] = subprocess.run,
) -> NativeFreshNginxPreparationV1:
    """Optional network metadata check only after conservative path refusal.

    Never reuse this preparation report as privileged authority. An actual
    installer must independently verify complete native host state, ownership,
    trust, RPM/DEB payloads and journal immediately before package mutation.
    """
    footprint = inspect_fresh_nginx_footprint(
        os_release=os_release, python_version=python_version,
        document=document, lstat=lstat, process_probe=process_probe,
    )
    if not footprint.allows_metadata_probe:
        return NativeFreshNginxPreparationV1(footprint, None)
    metadata = inspect_native_nginx_metadata(
        os_release=os_release, python_version=python_version,
        document=document, runner=runner,
    )
    return NativeFreshNginxPreparationV1(footprint, metadata)
