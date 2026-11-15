"""PRIVATE fixture-only #31 NGINX/catalog compensation sequence.

This is a deterministic rehearsal seam for disposable NGINX and state tests.
The injected callbacks are **arbitrary test code**, not privileged operations
or an administrator authorization API. No public CLI/daemon may invoke this.
The v2 fixture state journal remains pending across all callbacks until the
caller explicitly completes its same-lock post-replace barrier.

A Python callback cannot repair power loss. This sequence is not the durable
multi-resource host journal required before real NGINX activation.
"""
from __future__ import annotations

from typing import Any, Callable


class FixtureActivationFlowError(ValueError):
    """Only fixed non-secret error codes may escape fixture callbacks."""


_PHASES = (
    "stage_managed_candidate",
    "syntax_check",
    "reload_candidate",
    "verify_live_exposure",
    "publish_derived_catalog",
    "verify_derived_catalog",
)


def _deny(code: str) -> None:
    raise FixtureActivationFlowError("FIXTURE_ACTIVATION_" + code)


def run_fixture_activation_flow(
    candidate: dict[str, Any], *,
    stage_managed_candidate: Callable[[dict[str, Any]], None],
    syntax_check: Callable[[], None],
    reload_candidate: Callable[[], None],
    verify_live_exposure: Callable[[], None],
    publish_derived_catalog: Callable[[], None],
    verify_derived_catalog: Callable[[], None],
    compensate: Callable[[], None],
) -> None:
    """Strict stage->syntax->reload->observe->publish->verify->compensate.

    Caller must already hold the same v2 fixture lock and a pending v2 journal.
    Every step must return *exactly* None. For any failure after staging starts,
    attempt compensation exactly once. Even successful compensation causes
    an exception: the caller must still recover the pending v2 state journal.
    Compensation failure stays an explicit refusal and never falls through
    to a fabricated successful activation.
    """
    if (type(candidate) is not dict
            or candidate.get("status") != "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY"
            or candidate.get("authorizes_nginx_activation") is not False
            or candidate.get("authorizes_catalog_publication") is not False
            or type(candidate.get("proposed_repository_ids")) is not list
            or any(type(r) is not str for r in candidate["proposed_repository_ids"])
            or candidate["proposed_repository_ids"] != sorted(
                set(candidate["proposed_repository_ids"])
            )):
        _deny("CANDIDATE_INVALID")
    callbacks = {
        "stage_managed_candidate": stage_managed_candidate,
        "syntax_check": syntax_check,
        "reload_candidate": reload_candidate,
        "verify_live_exposure": verify_live_exposure,
        "publish_derived_catalog": publish_derived_catalog,
        "verify_derived_catalog": verify_derived_catalog,
    }
    if any(not callable(step) for step in (*callbacks.values(), compensate)):
        _deny("CALLBACK_INVALID")

    phase = _PHASES[0]
    try:
        for phase in _PHASES:
            step = callbacks[phase]
            if phase == "stage_managed_candidate":
                result = step(candidate)
            else:
                result = step()
            if result is not None:
                _deny("STEP_RESULT_INVALID")
    except Exception:
        # The stage callback may have already changed bytes before raising,
        # so compensation MUST also run when that first step fails.
        try:
            if compensate() is not None:
                _deny("COMPENSATION_RESULT_INVALID")
        except Exception:
            _deny("COMPENSATION_FAILED")
        _deny("STEP_FAILED")
    return None
