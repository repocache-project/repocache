"""Fixture-only #95 lifecycle transaction joining the protected v2 ledger to NGINX.

The reusable pure v2 lifecycle builder, persisted protected state,
generated NGINX include and derived catalog are bound through a durable
multi-resource WAL. This is an executable
integration seam for a future fixed-identity native worker, NOT that worker:
the root FD and approval digest are test inputs, a callback cannot prove
installed NGINX exposure, and the real '/' is categorically refused.

Do not call from CLI, server socket handlers or privileged installers.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Any, Callable

from repocache.server_fixture_multi_resource_wal_v1 import (
    _check_no_auxiliary_pending,
    _commit_fixture_multi_resource_under_root,
    _read_all,
    _validate_old,
    V2_STATE,
)
from repocache.server_install_v1 import (
    MAX_INT, parse_install_bytes,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)
from repocache.server_proposed_state_v2_store import (
    _legacy_refusal, _read_v2, _refuse_actual_root_fixture_write,
)
from repocache.server_protected_state_store_v1 import (
    _canonical, _locked,
)
from repocache.server_repository_v2_transition_v1 import (
    plan_repository_v2_transition, plan_repository_v2_batch_transition,
)


class FixtureRepositoryTransactionError(ValueError):
    """Stable failure codes; never include configuration or sensitive paths."""


def _deny(code: str) -> None:
    raise FixtureRepositoryTransactionError("FIXTURE_REPOSITORY_TRANSACTION_" + code)


def commit_fixture_repository_change_under_root(
    root_fd: int, *,
    owner_uid: int,
    expected_generation: int,
    operation: str,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
    fixture_decision_sha256: str,
    verify_fixture_exposure_before_publish: Callable[[], None],
    repository_id: str | None = None,
    proposed_repository: dict[str, Any] | None = None,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Persist an actual add/update/enable/disable/remove *fixture* transition.

    The first lock reads canonical, owned protected state and its all-time ID
    reservations, then constructs a complete immutable candidate. The WAL
    takes a second lock and performs a compare-and-swap recheck before
    durable NGINX/state writes; any intervening writer must fail closed.
    The old discovery bytes stay published during the test-only barrier.

    There is deliberately no force-cleanup, installed-file mutation, systemd,
    real NGINX reload, operator authentication or publisher authority here.
    A future native worker cannot use this fixture entrypoint.
    """
    _refuse_actual_root_fixture_write(root_fd)
    if (type(owner_uid) is not int or owner_uid < 0
            or type(expected_generation) is not int
            or not 1 <= expected_generation < MAX_INT
            or type(fixture_decision_sha256) is not str
            or len(fixture_decision_sha256) != 64
            or any(c not in "0123456789abcdef" for c in fixture_decision_sha256)
            or not callable(verify_fixture_exposure_before_publish)
            or (inject_fault is not None and not callable(inject_fault))):
        _deny("ARGUMENT_INVALID")
    try:
        with _locked(root_fd, owner_uid) as directory:
            _legacy_refusal(directory, owner_uid)
            _check_no_auxiliary_pending(directory, owner_uid)
            old, raw = _read_v2(directory, owner_uid)
            if old is None or raw is None:
                _deny("EXISTING_V2_REQUIRED")
            _validate_old(_read_all(directory, owner_uid))
            if old["state_generation"] != expected_generation:
                _deny("STALE_GENERATION")
            # This general builder is reusable by the eventual installed
            # native candidate-staging workflow. It has no filesystem power.
            # Our source predecessor is read under the actual protected
            # fixture lock; the WAL rechecks the CAS on a second lock.
            plan = plan_repository_v2_transition(
                old, expected_generation=expected_generation,
                expected_previous_state_sha256=hashlib.sha256(
                    raw,
                ).hexdigest(),
                operation=operation,
                repository_id=repository_id,
                proposed_repository=proposed_repository,
                decision_sha256=fixture_decision_sha256,
            )
            if not plan["changed"]:
                return {
                    "status": "NO_CHANGE_INERT_FIXTURE_REPOSITORY",
                    "state_generation": expected_generation,
                    "repository_id": plan["repository_id"],
                    "fixture_only": True,
                    "host_activation_verified": False,
                    "operator_authorization_verified": False,
                    "authorizes_nginx_reload": False,
                    "authorizes_catalog_publication": False,
                    "authorizes_cache_cleanup": False,
                }
            next_snapshot = plan["proposed_snapshot"]
            next_document = parse_install_bytes(
                base64.b64decode(
                    next_snapshot["configuration_base64"], validate=True,
                ),
                for_apply=True,
            )
            bundle = render_repository_nginx_bundle_candidate(
                next_document,
                expected_state_generation=expected_generation + 1,
                candidate_pins_by_repository=candidate_pins_by_repository,
                ca_bundle_path=ca_bundle_path,
            )
            if (bundle["status"] != "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY"
                    or bundle["authorizes_nginx_activation"] is not False
                    or bundle["authorizes_catalog_publication"] is not False):
                _deny("BUNDLE_UNSAFE")
            # Shadow include and catalog, not /etc/nginx or a public endpoint.
            include_bytes = (
                bundle["http_upstream_fragment"]
                + "server {\n"
                + bundle["server_location_fragment"]
                + "}\n"
            ).encode("utf-8")
            catalog_bytes = _canonical({
                "schema_version": 1,
                "status": "fixture-only-observed-candidate",
                "active_ids": bundle["proposed_repository_ids"],
            }, limit=512000)
    except FixtureRepositoryTransactionError:
        raise
    except (ValueError, TypeError, OverflowError, OSError, RecursionError):
        _deny("PREPARE_REFUSED")

    # Never rely on the earlier read after releasing the lock. The WAL's
    # second protected read and exact generation/ledger transition is the
    # final authority *within this disposable fixture only*.
    try:
        result = _commit_fixture_multi_resource_under_root(
            root_fd, next_snapshot,
            owner_uid=owner_uid,
            expected_generation=expected_generation,
            include_bytes=include_bytes,
            catalog_bytes=catalog_bytes,
            expected_previous_state_sha256=hashlib.sha256(raw).hexdigest(),
            inject_fault=inject_fault,
            verify_fixture_exposure_before_publish=(
                verify_fixture_exposure_before_publish
            ),
        )
    except ValueError:
        _deny("COMMIT_REFUSED")
    return {
        "status": result["status"],
        "state_generation": result["state_generation"],
        "repository_id": plan["repository_id"],
        "fixture_only": True,
        "durable_shadow_wal_exercised": result["durable_shadow_wal_exercised"],
        "host_activation_verified": False,
        "operator_authorization_verified": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
    }


def commit_fixture_repository_batch_under_root(
    root_fd: int, *,
    owner_uid: int,
    expected_generation: int,
    operation: str,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
    fixture_decision_sha256: str,
    verify_fixture_exposure_before_publish: Callable[[], None],
    proposed_repositories: tuple[dict[str, Any], ...] = (),
    repository_ids: tuple[str, ...] = (),
    all_repositories: bool = False,
    inject_fault: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Commit one whole #95 batch through the disposable four-resource WAL.

    The fixed v2 ledger and generation are read under the first fixture lock;
    the existing WAL reacquires its independent lock and compare-and-swaps
    the *same* previous state hash before writing any staged resources.
    Even a multi-repository removal does not touch repository cache bytes.
    No callback or result here attests live NGINX exposure or host authority.
    """
    _refuse_actual_root_fixture_write(root_fd)
    if (type(owner_uid) is not int or owner_uid < 0
            or type(expected_generation) is not int
            or not 1 <= expected_generation < MAX_INT
            or type(fixture_decision_sha256) is not str
            or len(fixture_decision_sha256) != 64
            or any(c not in "0123456789abcdef" for c in fixture_decision_sha256)
            or not callable(verify_fixture_exposure_before_publish)
            or (inject_fault is not None and not callable(inject_fault))
            or type(proposed_repositories) is not tuple
            or type(repository_ids) is not tuple
            or type(all_repositories) is not bool):
        _deny("BATCH_ARGUMENT_INVALID")
    try:
        with _locked(root_fd, owner_uid) as directory:
            _legacy_refusal(directory, owner_uid)
            _check_no_auxiliary_pending(directory, owner_uid)
            previous, raw = _read_v2(directory, owner_uid)
            if previous is None or raw is None:
                _deny("EXISTING_V2_REQUIRED")
            owned = _read_all(directory, owner_uid)
            _validate_old(owned)
            if owned[V2_STATE] != raw:
                _deny("PREDECESSOR_READ_DRIFT")
            if previous["state_generation"] != expected_generation:
                _deny("STALE_GENERATION")
            old_digest = hashlib.sha256(raw).hexdigest()
            batch = plan_repository_v2_batch_transition(
                previous,
                expected_generation=expected_generation,
                expected_previous_state_sha256=old_digest,
                operation=operation,
                decision_sha256=fixture_decision_sha256,
                proposed_repositories=proposed_repositories,
                repository_ids=repository_ids,
                all_repositories=all_repositories,
            )
            if batch["changed"] is False:
                return {
                    "status": "NO_CHANGE_INERT_FIXTURE_REPOSITORY_BATCH",
                    "state_generation": expected_generation,
                    "per_repository": batch["per_repository"],
                    "retired_ids": [],
                    "fixture_only": True,
                    "host_activation_verified": False,
                    "operator_authorization_verified": False,
                    "authorizes_nginx_reload": False,
                    "authorizes_catalog_publication": False,
                    "authorizes_cache_cleanup": False,
                }
            candidate = batch["proposed_snapshot"]
            next_document = parse_install_bytes(
                base64.b64decode(candidate["configuration_base64"], validate=True),
                for_apply=True,
            )
            bundle = render_repository_nginx_bundle_candidate(
                next_document,
                expected_state_generation=expected_generation + 1,
                candidate_pins_by_repository=candidate_pins_by_repository,
                ca_bundle_path=ca_bundle_path,
            )
            expected_active = sorted(
                item["id"] for item in candidate["repository_records"]
                if item["desired_state"] == "active"
            )
            if (bundle["status"] != "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY"
                    or bundle["proposed_repository_ids"] != expected_active
                    or bundle["authorizes_nginx_activation"] is not False
                    or bundle["authorizes_catalog_publication"] is not False):
                _deny("BATCH_BUNDLE_UNSAFE")
            include_bytes = (
                bundle["http_upstream_fragment"] + "server {\n"
                + bundle["server_location_fragment"] + "}\n"
            ).encode("utf-8")
            catalog_bytes = _canonical({
                "schema_version": 1,
                "status": "fixture-only-observed-candidate",
                "active_ids": expected_active,
            }, limit=512000)
    except FixtureRepositoryTransactionError:
        raise
    except (ValueError, TypeError, OverflowError, OSError,
            UnicodeError, RecursionError):
        _deny("BATCH_PREPARE_REFUSED")

    try:
        committed = _commit_fixture_multi_resource_under_root(
            root_fd, candidate,
            owner_uid=owner_uid,
            expected_generation=expected_generation,
            include_bytes=include_bytes,
            catalog_bytes=catalog_bytes,
            expected_previous_state_sha256=old_digest,
            inject_fault=inject_fault,
            verify_fixture_exposure_before_publish=(
                verify_fixture_exposure_before_publish
            ),
        )
    except ValueError:
        _deny("BATCH_COMMIT_REFUSED")
    return {
        "status": committed["status"],
        "state_generation": committed["state_generation"],
        "per_repository": batch["per_repository"],
        "retired_ids": batch["retired_ids_proposed"],
        "fixture_only": True,
        "durable_shadow_wal_exercised": committed["durable_shadow_wal_exercised"],
        "host_activation_verified": False,
        "operator_authorization_verified": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
    }
