"""Locked repository inventory from the committed fixture v2 ownership domain.

A bounded, read-only #95 operator-inspection primitive for detached Linux test
roots. It is not an administrator CLI, a native root worker, or a public
discovery endpoint. A shadow fixture catalog cannot prove NGINX exposure.
"""
from __future__ import annotations

import hashlib
from typing import Any

from repocache.server_fixture_multi_resource_wal_v1 import (
    CATALOG, V2_STATE, _check_no_auxiliary_pending, _read_all, _validate_old,
)
from repocache.server_proposed_state_v2_store import (
    _legacy_refusal, _read_v2, _refuse_actual_root_fixture_write,
)
from repocache.server_proposed_v2_locked_digest_v1 import _state_inode
from repocache.server_protected_state_store_v1 import (
    _json, _locked,
)


class FixtureRepositoryInventoryError(ValueError):
    """Redacted refusal; never include upstream, key references or paths."""


def _deny(reason: str) -> None:
    raise FixtureRepositoryInventoryError("FIXTURE_REPOSITORY_INVENTORY_" + reason)


def inspect_locked_fixture_repository_inventory_under_root(
    root_fd: int, *, owner_uid: int, expected_generation: int,
    expected_state_sha256: str,
) -> dict[str, Any]:
    """Inspect committed v2 ID history and shadow catalog under ONE FD lock.

    The user-facing distinction is essential: desired active state, a shadow
    catalog entry and real NGINX exposure are *different evidence*. No
    approval or authorization may be inferred from any inventory field.
    """
    try:
        _refuse_actual_root_fixture_write(root_fd)
    except (ValueError, OSError):
        _deny("FIXTURE_ROOT_REFUSED")
    if (type(owner_uid) is not int or not 0 <= owner_uid <= 2**32 - 2
            or type(expected_generation) is not int
            or not 1 <= expected_generation < 2**63
            or type(expected_state_sha256) is not str
            or len(expected_state_sha256) != 64
            or any(c not in "0123456789abcdef"
                   for c in expected_state_sha256)):
        _deny("ARGUMENT_INVALID")
    try:
        with _locked(root_fd, owner_uid) as directory:
            _legacy_refusal(directory, owner_uid)
            _check_no_auxiliary_pending(directory, owner_uid)
            state, raw = _read_v2(directory, owner_uid)
            if state is None or raw is None:
                _deny("COMMITTED_STATE_REQUIRED")
            first_inode = _state_inode(directory)
            owned = _read_all(directory, owner_uid)
            if raw != owned[V2_STATE]:
                _deny("STATE_READ_DRIFT")
            # Requires the COMPLETE previous commit: no caller-supplied
            # catalog or independent allowlist may override owner manifest.
            _validate_old(owned)
            digest = hashlib.sha256(raw).hexdigest()
            if (state["state_generation"] != expected_generation
                    or digest != expected_state_sha256):
                _deny("STALE_OR_SUBSTITUTED_STATE")
            catalog = _json(owned[CATALOG], limit=512 * 1024)
            included = frozenset(catalog["active_ids"])
            present = [
                {
                    "id": row["id"],
                    "desired_state": row["desired_state"],
                    "observed_state": "not-activated",
                    "shadow_catalog_intent": (
                        "fixture-included" if row["id"] in included
                        else "withdrawn"
                    ),
                    "real_nginx_exposure_verified": False,
                }
                for row in sorted(
                    state["repository_records"], key=lambda x: x["id"],
                )
            ]
            retired = sorted(
                row["id"] for row in state["id_reservations"]
                if row["status"] == "retired"
            )
            _legacy_refusal(directory, owner_uid)
            _check_no_auxiliary_pending(directory, owner_uid)
            later, later_raw = _read_v2(directory, owner_uid)
            if (later != state or later_raw != raw
                    or _state_inode(directory) != first_inode
                    or _read_all(directory, owner_uid) != owned):
                _deny("RESOURCE_CHANGED_DURING_READ")
            return {
                "schema_version": 1,
                "status": "FIXTURE_LOCKED_REPOSITORY_INVENTORY_ONLY",
                "state_generation": expected_generation,
                "whole_state_sha256": digest,
                "repositories": present,
                "retired_repository_ids": retired,
                "present_repository_count": len(present),
                "retired_repository_count": len(retired),
                "shadow_catalog_entry_count": len(included),
                "fixture_owner_manifest_and_ledger_verified": True,
                "operator_authorization_verified": False,
                "native_root_provenance_verified": False,
                "real_nginx_exposure_verified": False,
                "published_client_catalog_verified": False,
                "preflight_remains_valid_after_return": False,
                "authorizes_state_write": False,
                "authorizes_nginx_reload": False,
                "authorizes_catalog_publication": False,
                "authorizes_cache_cleanup": False,
            }
    except FixtureRepositoryInventoryError:
        raise
    except (ValueError, TypeError, OSError, OverflowError, RecursionError):
        _deny("PROTECTED_RESOURCES_UNVERIFIED")
