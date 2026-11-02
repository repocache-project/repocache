"""Fail-closed refresh scheduling for approved upstream pin candidates (#28).

A future unprivileged systemd timer can call refresh_due repeatedly. This
does not install such a timer and NEVER commits protected state, mutates
NGINX, reloads a daemon, or publishes a catalog. The proposed pins cannot
substitute for a root-verified ownership manifest or transaction journal.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import socket
from typing import Any, Callable

from repocache.server_bounded_dns_v1 import bounded_getaddrinfo
from repocache.server_install_v1 import ID, MAX_INT, validate_install_document
from repocache.server_upstream_rotation_v1 import (
    MIN_REFRESH_INTERVAL_SECONDS,
    UpstreamRotationError,
    propose_automatic_upstream_refresh,
)

MAX_FAILURE_BACKOFF_SECONDS = 3600
INITIAL_FAILURE_BACKOFF_SECONDS = 60
MAX_JITTER_SECONDS = 60


class UpstreamScheduleError(ValueError):
    """Fixed redacted error that never includes a DNS or repository value."""


@dataclass(frozen=True)
class RefreshSlot:
    """Ephemeral scheduling hint, NOT an authenticated persisted generation."""

    repository_id: str
    generation: int
    next_due: float
    failures: int


def _valid_clock(value: Any) -> bool:
    return (builtins_type(value) in (int, float)
            and math.isfinite(value) and 0 <= value <= 1e15)


# Avoid accepting bool, which otherwise behaves as an integer.
builtins_type = type


def _jitter(repository_id: str) -> int:
    return hashlib.sha256(repository_id.encode("ascii")).digest()[0] % (
        MAX_JITTER_SECONDS + 1
    )


def refresh_due(
    document: dict[str, Any],
    *,
    repository_id: str,
    current_generation: int,
    previous_pins_by_host: dict[str, list[str]] | None,
    now_monotonic: float,
    prior_slot: RefreshSlot | None = None,
    resolver: Callable[..., list[tuple[Any, ...]]] | None = None,
) -> dict[str, Any]:
    """Run at most one bounded candidate refresh if the repository is due.

    Results and slots are hints only. Caller MUST obtain and verify protected
    state/approval/generation under its exclusive lock before activation.
    Never infer approval from a prior slot, DNS response or this output.
    """
    if (not _valid_clock(now_monotonic)
            or builtins_type(repository_id) is not str
            or len(repository_id) > 48 or ID.fullmatch(repository_id) is None
            or builtins_type(current_generation) is not int
            or not 0 <= current_generation <= MAX_INT):
        raise UpstreamScheduleError("SCHEDULE_INPUT_INVALID")
    try:
        doc = validate_install_document(document, for_apply=True)
    except (ValueError, TypeError):
        raise UpstreamScheduleError("SCHEDULE_DOCUMENT_INVALID") from None
    if doc["expected_state_generation"] != current_generation:
        raise UpstreamScheduleError("SCHEDULE_STALE_GENERATION")
    active = [r for r in doc["repositories"]
              if r.get("id") == repository_id and r["desired_state"] == "active"]
    if len(active) != 1:
        raise UpstreamScheduleError("SCHEDULE_REPOSITORY_NOT_ACTIVE")

    if prior_slot is not None:
        if (builtins_type(prior_slot) is not RefreshSlot
                or builtins_type(prior_slot.repository_id) is not str
                or prior_slot.repository_id != repository_id
                or builtins_type(prior_slot.generation) is not int
                or not 0 <= prior_slot.generation <= MAX_INT
                or not _valid_clock(prior_slot.next_due)
                or builtins_type(prior_slot.failures) is not int
                or not 0 <= prior_slot.failures <= 12):
            raise UpstreamScheduleError("SCHEDULE_SLOT_INVALID")
    if (prior_slot is not None
            and prior_slot.generation == current_generation
            and now_monotonic < prior_slot.next_due):
        return {
            "status": "NOT_DUE",
            "slot": prior_slot,
            "candidate": None,
            "authorizes_nginx_activation": False,
            "authorizes_catalog_publication": False,
            "automatic_scheduler_installed": False,
        }

    failures = (prior_slot.failures
                if prior_slot is not None
                and prior_slot.generation == current_generation else 0)
    try:
        candidate = propose_automatic_upstream_refresh(
            doc,
            repository_id=repository_id,
            current_generation=current_generation,
            previous_pins_by_host=previous_pins_by_host,
            resolver=bounded_getaddrinfo if resolver is None else resolver,
        )
    except (UpstreamRotationError, socket.gaierror):
        failures = min(failures + 1, 12)
        delay = min(
            MAX_FAILURE_BACKOFF_SECONDS,
            INITIAL_FAILURE_BACKOFF_SECONDS * (2 ** min(failures - 1, 6))
            + _jitter(repository_id),
        )
        return {
            "status": "DNS_RETRY_SCHEDULED",
            "slot": RefreshSlot(repository_id, current_generation,
                                now_monotonic + delay, failures),
            "candidate": None,
            "authorizes_nginx_activation": False,
            "authorizes_catalog_publication": False,
            "automatic_scheduler_installed": False,
        }

    return {
        "status": "PIN_CHANGE_CANDIDATE" if candidate["changed"] else "PINS_UNCHANGED",
        "slot": RefreshSlot(
            repository_id, current_generation,
            now_monotonic + MIN_REFRESH_INTERVAL_SECONDS + _jitter(repository_id),
            0,
        ),
        "candidate": candidate,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "automatic_scheduler_installed": False,
    }
