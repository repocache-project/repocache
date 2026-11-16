"""Private same-lock state-v2 / NGINX-render / client-catalog binding (#31).

This is a necessary *read-only*, fixture-FD consistency assertion. The
NGINX dump and exit status are untrusted caller claims, not native-systemd
or live-routing evidence. They MUST NOT be accepted as a publication token.
No CLI, privileged worker, actual host writer or installed entrypoint uses
this module. Never let a socket peer select its root FD, owner or pins.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from repocache.server_derived_catalog_candidate_v1 import (
    DerivedCatalogCandidateError, preview_derived_catalog_from_nginx_dump,
)
from repocache.server_install_v1 import MAX_INT, parse_install_bytes
from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError, render_repository_nginx_bundle_candidate,
)
from repocache.server_proposed_v2_locked_digest_v1 import _state_inode
from repocache.server_protected_state_store_v1 import (
    ProtectedStateStoreError, _canonical, _json, _locked,
)
from repocache.server_proposed_state_v2_store import (
    ProposedV2PersistenceError, _legacy_refusal, _pending, _read_v2,
    _refuse_actual_root_fixture_write,
)


class LockedV2CatalogBindingError(ValueError):
    """Stable, redacted refusal codes; no NGINX dump, path or source data."""


def _deny(code: str) -> None:
    raise LockedV2CatalogBindingError("LOCKED_V2_CATALOG_" + code)


def _valid_digest(value: Any) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _preview_locked_v2_catalog_binding_under_root(
    root_fd: int, *, owner_uid: int, expected_generation: int,
    expected_state_sha256: str, candidate_pins_by_repository: Any,
    ca_bundle_path: str, untrusted_nginx_dump: str,
    untrusted_nginx_t_exit_code: int,
) -> dict[str, Any]:
    """Observe all three candidate domains within ONE protected fixture lock.

    Caller-supplied nginx output/status is NEVER evidence that NGINX
    actually executed or that a managed route is live. This helper cannot
    implement authorization, syntax checking, state write, reload, catalog
    publication or an authority lease after returning.
    """
    # Do not allow test-only caller-controlled root FDs to be used against
    # the actual namespace root: a positive fixture report is not host trust.
    _refuse_actual_root_fixture_write(root_fd)
    if (type(owner_uid) is not int or owner_uid < 0
            or type(expected_generation) is not int
            or not 1 <= expected_generation <= MAX_INT
            or not _valid_digest(expected_state_sha256)
            or type(ca_bundle_path) is not str
            or type(untrusted_nginx_dump) is not str
            or type(untrusted_nginx_t_exit_code) is not int):
        _deny("ARGUMENT_INVALID")
    try:
        # Clone untrusted caller-owned nested structures into a bounded,
        # canonical copy BEFORE taking the FD lock, never trust them again.
        raw_pins = _canonical(candidate_pins_by_repository, limit=1024 * 1024)
        pinned = _json(raw_pins, limit=1024 * 1024)
    except (ValueError, TypeError, OverflowError, RecursionError):
        _deny("PINS_INVALID")
    try:
        with _locked(root_fd, owner_uid) as directory:
            _legacy_refusal(directory, owner_uid)
            if _pending(directory, owner_uid):
                _deny("RECOVERY_REQUIRED")
            state, state_raw = _read_v2(directory, owner_uid)
            if state is None or state_raw is None:
                _deny("STATE_ABSENT")
            initial_inode = _state_inode(directory)
            if state["state_generation"] != expected_generation:
                _deny("STALE_GENERATION")
            if hashlib.sha256(state_raw).hexdigest() != expected_state_sha256:
                _deny("STATE_DIGEST_MISMATCH")
            document = parse_install_bytes(
                base64.b64decode(state["configuration_base64"], validate=True),
                for_apply=True,
            )
            render = render_repository_nginx_bundle_candidate(
                document, expected_state_generation=expected_generation,
                candidate_pins_by_repository=pinned,
                ca_bundle_path=ca_bundle_path,
            )
            derived = preview_derived_catalog_from_nginx_dump(
                document, candidate_pins_by_repository=pinned,
                ca_bundle_path=ca_bundle_path,
                nginx_dump_text=untrusted_nginx_dump,
                nginx_t_exit_code=untrusted_nginx_t_exit_code,
            )
            if (render["status"] != "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY"
                    or derived["status"] != "INERT_DERIVED_CATALOG_CANDIDATE_ONLY"
                    or render["authorizes_catalog_publication"] is not False
                    or derived["authorizes_catalog_publication"] is not False
                    or render["authorizes_nginx_activation"] is not False
                    or derived["desired_active_repository_ids"]
                       != render["proposed_repository_ids"]):
                _deny("DOMAIN_BINDING_INVALID")
            # Canonical, bounded potential client-schema bytes. These are
            # deliberately NOT written, nor treated as observed exposure.
            catalog_bytes = _canonical(
                derived["candidate_catalog"], limit=512000,
            )
            upstream_bytes = render["http_upstream_fragment"].encode("utf-8")
            location_bytes = render["server_location_fragment"].encode("utf-8")
            # Independent root writers can ignore an advisory flock:
            # recheck state, inode/ctime, legacy and WAL before returning.
            _legacy_refusal(directory, owner_uid)
            if _pending(directory, owner_uid):
                _deny("RECOVERY_REQUIRED")
            later, later_raw = _read_v2(directory, owner_uid)
            if (later != state or later_raw != state_raw
                    or _state_inode(directory) != initial_inode):
                _deny("STATE_CHANGED_DURING_PREVIEW")
            return {
                "schema_version": 1,
                "status": "LOCKED_V2_INERT_CATALOG_BINDING_ONLY",
                "state_generation": expected_generation,
                "whole_state_bytes_sha256": expected_state_sha256,
                "generated_upstream_sha256": hashlib.sha256(
                    upstream_bytes,
                ).hexdigest(),
                "generated_location_sha256": hashlib.sha256(
                    location_bytes,
                ).hexdigest(),
                "candidate_catalog_sha256": hashlib.sha256(
                    catalog_bytes,
                ).hexdigest(),
                "proposed_active_ids": render["proposed_repository_ids"],
                "candidate_catalog": derived["candidate_catalog"],
                "canonical_state_and_render_consistent_under_one_lock": True,
                "untrusted_dump_matches_inert_render_structure_only": True,
                "catalog_candidate_generated_not_published": True,
                "operator_authorization_verified": False,
                "signed_installed_binary_verified": False,
                "native_host_root_verified": False,
                "native_nginx_execution_verified": False,
                "actual_active_exposure_verified": False,
                "preflight_remains_valid_after_lock_release": False,
                "authorizes_state_write": False,
                "authorizes_nginx_reload": False,
                "authorizes_catalog_publication": False,
            }
    except LockedV2CatalogBindingError:
        raise
    except DerivedCatalogCandidateError:
        _deny("NGINX_DUMP_MISMATCH")
    except NginxRepositoryBundleError:
        _deny("NGINX_RENDER_INVALID")
    except (ProtectedStateStoreError, ProposedV2PersistenceError,
            OSError, ValueError, TypeError, OverflowError,
            UnicodeError, RecursionError):
        _deny("PROTECTED_STATE_UNVERIFIED")
