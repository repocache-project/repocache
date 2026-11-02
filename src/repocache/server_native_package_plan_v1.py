"""Inert, reviewable distribution NGINX package plan for server provisioning (#27).

This module does not consult APT/DNF, inspect trusted sources, run native
commands, install packages or authorize privileged operations. In particular,
a package name in this plan is *not* package availability or provenance proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from repocache.server_install_v1 import (
    validate_install_document,
    validate_os_identity,
)

# The allowlist is implementation-owned, never read from an operator document.
# Native distro packages only; do not use upstream NGINX repositories or PyPI.
_NATIVE_NGINX = {
    "debian": ("apt", ("nginx",)),
    "almalinux": ("dnf", ("nginx",)),
}

# Each unresolved gate is a mandatory fail-closed prerequisite for *future*
# authorized package installation. Do not reinterpret this static inventory
# as evidence that any of these checks has actually been performed.
_PENDING_GATES = (
    (
        "approved_signed_sources", "NATIVE_SOURCE_TRUST_UNVERIFIED",
        "Check distribution-approved APT/DNF sources, enabled signature "
        "verification and trusted keys; reject unsigned or unapproved sources.",
    ),
    (
        "authenticated_metadata", "NATIVE_METADATA_TRUST_UNVERIFIED",
        "Use native APT/DNF authentication and verify usable current metadata; "
        "reject stale, offline or unverifiable metadata.",
    ),
    (
        "package_availability", "NATIVE_PACKAGE_AVAILABILITY_UNVERIFIED",
        "Verify NGINX is available from an approved authenticated native source; "
        "report missing or untrusted packages before provisioning.",
    ),
    (
        "existing_nginx_ownership", "NGINX_OWNERSHIP_UNVERIFIED",
        "Reject unmanaged or conflicting NGINX installations before package "
        "or service changes.",
    ),
    (
        "privileged_transaction", "NATIVE_TRANSACTION_NOT_AUTHORIZED",
        "Require a separate privileged install authorization and repeat native "
        "source, metadata and package checks at execution time.",
    ),
)


@dataclass(frozen=True)
class NativePackagePlanV1:
    """Non-authorizing plan. All security gates intentionally remain pending."""

    distribution: str

    def __post_init__(self) -> None:
        if type(self.distribution) is not str or self.distribution not in _NATIVE_NGINX:
            raise ValueError("unsupported native package plan distribution")

    @property
    def manager(self) -> str:
        return _NATIVE_NGINX[self.distribution][0]

    @property
    def packages(self) -> tuple[str, ...]:
        return _NATIVE_NGINX[self.distribution][1]

    @property
    def authorizes_installation(self) -> bool:
        return False

    @property
    def all_verified(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        """Bounded, deterministic and free of host paths or input secrets."""
        return {
            "plan_schema_version": 1,
            "distribution": self.distribution,
            "manager": self.manager,
            "packages": list(self.packages),
            "native_packages_policy": "explicit-review",
            "checks": [
                {
                    "check": name,
                    "status": "NOT VERIFIED",
                    "code": code,
                    "guidance": guidance,
                }
                for name, code, guidance in _PENDING_GATES
            ],
            "all_verified": False,
            "can_install": False,
            "authorizes_installation": False,
        }


def preview_nginx_packages(
    *, os_release: str, python_version: tuple[int, int], document: dict[str, Any],
) -> NativePackagePlanV1:
    """Validate native OS and closed v1 input before constructing a fixed plan.

    No external call or host filesystem access occurs here. ``document`` is
    revalidated; a caller's earlier parser validation is not an authority.
    Raises InstallInputError on unsupported OS, Python or configuration.
    """
    distribution = validate_os_identity(os_release, python_version)
    validated = validate_install_document(document, for_apply=False)
    if validated["deployment"]["native_packages"]["policy"] != "explicit-review":
        # The strict v1 validator already rejects this; keep a defensive guard
        # if its contract changes in the future.
        raise ValueError("unsupported native package policy")
    return NativePackagePlanV1(distribution=distribution)
