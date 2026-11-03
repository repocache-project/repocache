"""Non-authorizing local NGINX transaction boundary observation (#27).

This ties the conservative fresh-host refusal to #31's read-only locked
pre-package state reader (which does not require an installed NGINX include). It does NOT hold a lock across a native package
transaction, authorize an operator, inspect all processes/listeners, download
packages, install NGINX, or activate any service.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Callable

from repocache.server_native_nginx_ownership_v1 import (
    inspect_fresh_nginx_footprint,
)
from repocache.server_native_package_plan_v1 import preview_nginx_packages
from repocache.server_native_nginx_prepackage_state_v1 import (
    PrepackageStateInspectionError,
    inspect_current_namespace_prepackage_state,
)
from repocache.server_protected_state_inspect_v1 import _FIXED_STATE_ROOT

_CODES = frozenset({
    "NGINX_FOOTPRINT_REFUSED",
    "NATIVE_ROOT_NOT_OBSERVED",
    "PROTECTED_STATE_UNVERIFIED",
    "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED",
})
_FRESH = "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED"


@dataclass(frozen=True)
class NativeNginxLocalBoundaryV1:
    distribution: str
    code: str
    footprint_code: str

    def __post_init__(self) -> None:
        if (type(self.distribution) is not str
                or self.distribution not in ("debian", "almalinux")
                or type(self.code) is not str or self.code not in _CODES
                or type(self.footprint_code) is not str
                or (self.code == "NGINX_FOOTPRINT_REFUSED")
                   != (self.footprint_code != _FRESH)):
            raise ValueError("invalid local native transaction boundary")

    def to_dict(self) -> dict[str, Any]:
        observed = self.code == "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED"
        return {
            "schema_version": 1,
            "distribution": self.distribution,
            "code": self.code,
            "status": ("FAIL" if self.code == "NGINX_FOOTPRINT_REFUSED"
                       and self.footprint_code in (
                           "EXISTING_NGINX_OWNERSHIP_UNPROVEN",
                           "NGINX_NONINITIAL_STATE_REFUSED",
                       ) else "NOT VERIFIED"),
            "footprint_code": self.footprint_code,
            "locked_manifest_read_completed": observed,
            "current_namespace_root_observed": observed,
            "root_euid_observed": self.code in (
                "PROTECTED_STATE_UNVERIFIED", "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED"
            ),
            "existing_nginx_adoption_allowed": False,
            "host_root_namespace_authenticated": False,
            "operator_permission_authenticated": False,
            "native_package_authenticity_rechecked": False,
            "transaction_lock_held_across_mutation": False,
            "native_package_journal_prepared": False,
            "systemd_listeners_selinux_verified": False,
            "authorizes_package_transaction": False,
            "authorizes_nginx_activation": False,
            "can_install": False,
        }


def inspect_native_nginx_local_boundary(
    *, os_release: str, python_version: tuple[int, int],
    document: dict[str, Any],
    lstat: Callable[[str], os.stat_result] = os.lstat,
    geteuid: Callable[[], int] = os.geteuid,
    locked_inspector: Callable[..., dict[str, Any]] = (
        inspect_current_namespace_prepackage_state
    ),
) -> NativeNginxLocalBoundaryV1:
    """Observe known conflicts and #31 state, without network or mutations.

    The #31 lock is released before returning. Even a positive observation
    cannot be reused for an actual transaction. A future trusted root helper
    must verify operator authority, host namespace, live processes/listeners,
    package signatures and journaling while holding the correct live lock.
    Injected readers are only useful for synthetic test fixtures.
    """
    plan = preview_nginx_packages(
        os_release=os_release, python_version=python_version, document=document
    )
    # The #31 state directory/lock MUST be preprovisioned before a real
    # package transaction, yet the legacy fresh-footprint scan treated its
    # very existence as foreign NGINX. Ignore exactly that one code-owned
    # marker here; the pinned #31 lock reader below verifies it strictly.
    # The standalone metadata/download probe retains the conservative
    # unconditional refusal of a pre-existing state directory.
    def nginx_marker(path: str) -> os.stat_result:
        if path == _FIXED_STATE_ROOT:
            raise FileNotFoundError(path)
        return lstat(path)

    footprint = inspect_fresh_nginx_footprint(
        os_release=os_release, python_version=python_version,
        document=document, lstat=nginx_marker,
    )
    if not footprint.allows_metadata_probe:
        return NativeNginxLocalBoundaryV1(
            plan.distribution, "NGINX_FOOTPRINT_REFUSED", footprint.code
        )
    try:
        uid = geteuid()
    except (OSError, ValueError, TypeError):
        uid = None
    if type(uid) is not int or uid != 0:
        return NativeNginxLocalBoundaryV1(
            plan.distribution, "NATIVE_ROOT_NOT_OBSERVED", footprint.code
        )
    try:
        # Only a generation-0 fresh install is within this boundary.
        # Never try a recovery operation automatically on journal conflicts.
        state = locked_inspector()
    except (PrepackageStateInspectionError, OSError, ValueError, TypeError):
        return NativeNginxLocalBoundaryV1(
            plan.distribution, "PROTECTED_STATE_UNVERIFIED", footprint.code
        )
    if (type(state) is not dict
            or state.get("status") != "LOCKED_PREPACKAGE_STATE_ABSENT"
            or state.get("nginx_include_directory_required") is not False
            or state.get("nginx_live_manifest_verified") is not False
            or state.get("native_transaction_journal_prepared") is not False
            or type(state.get("state_generation")) is not int
            or state["state_generation"] != 0
            or state.get("manifest_entry_present") is not False
            or state.get("protected_state_directory_preprovisioned") is not True
            or state.get("exclusive_state_lock_held_during_inspection") is not True
            or state.get("current_namespace_root_path_verified") is not True
            or state.get("operator_authorization_verified") is not False
            or state.get("authorizes_write") is not False
            or state.get("authorizes_package_installation") is not False
            or state.get("authorizes_nginx_reload") is not False):
        return NativeNginxLocalBoundaryV1(
            plan.distribution, "PROTECTED_STATE_UNVERIFIED", footprint.code
        )
    return NativeNginxLocalBoundaryV1(
        plan.distribution, "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED", footprint.code
    )
