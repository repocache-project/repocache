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
    "/run/systemd/system/nginx.service",
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
}


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
                if self.code == "EXISTING_NGINX_OWNERSHIP_UNPROVEN" else
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
) -> FreshNginxFootprintV1:
    """Validate input first; inspect fixed paths without following leaf links.

    A positive outcome is deliberately NOT VERIFIED for transaction approval:
    it does not observe all processes, mount namespaces, service aliases,
    firewall policy, alternate binaries, or a trusted manifest under lock.
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
        code = "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED"
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
    runner: Callable[..., Any] = subprocess.run,
) -> NativeFreshNginxPreparationV1:
    """Optional network metadata check only after conservative path refusal.

    Never reuse this preparation report as privileged authority. An actual
    installer must independently verify complete native host state, ownership,
    trust, RPM/DEB payloads and journal immediately before package mutation.
    """
    footprint = inspect_fresh_nginx_footprint(
        os_release=os_release, python_version=python_version,
        document=document, lstat=lstat,
    )
    if not footprint.allows_metadata_probe:
        return NativeFreshNginxPreparationV1(footprint, None)
    metadata = inspect_native_nginx_metadata(
        os_release=os_release, python_version=python_version,
        document=document, runner=runner,
    )
    return NativeFreshNginxPreparationV1(footprint, metadata)
