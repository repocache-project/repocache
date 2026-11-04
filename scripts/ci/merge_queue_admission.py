"""Fail-closed queue admission evidence checks; NOT an active GitHub admission gate.

Only a separately deployed, trusted controller may assemble these inputs from
authenticated GitHub APIs and protected acceptance records. Input JSON and a
passing local test never grant queue admission or merge authorization.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REQUIRED_APP_ID = 15368  # GitHub Actions; verify the integration ID live on rollout.
REQUIRED_CONTEXTS = (
    "Unit tests (Python 3.12)",
    "Unit tests (Python 3.13)",
    "Bundle integrity and unsigned-source refusal (almalinux10)",
    "Bundle integrity and unsigned-source refusal (debian13)",
    "Offline wheels (almalinux:10)",
    "Offline wheels (debian:trixie-slim)",
    "Signed release and native offline dependency artifact",
    "Synthetic rootless update and rollback (almalinux:10)",
    "Synthetic rootless update and rollback (debian:trixie-slim)",
)
_SHA = re.compile(r"^[a-f0-9]{40}$")
_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _integration_ref(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("integration/"):
        return False
    components = value.split("/")[1:]
    return bool(components) and all(
        component not in (".", "..") and _COMPONENT.fullmatch(component)
        for component in components
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _required_checks(
    provided: Any, *, expected_sha: str, errors: list[str], prefix: str
) -> None:
    if not isinstance(provided, list):
        errors.append(f"{prefix}: missing check-run collection")
        return
    contexts: dict[str, list[Mapping[str, Any]]] = {}
    for check in provided:
        if not isinstance(check, Mapping) or not isinstance(check.get("name"), str):
            errors.append(f"{prefix}: malformed check-run")
            continue
        contexts.setdefault(check["name"], []).append(check)
    for name in REQUIRED_CONTEXTS:
        items = contexts.get(name, [])
        if len(items) != 1:
            errors.append(f"{prefix}: expected exactly one check-run for {name}")
            continue
        check = items[0]
        if (
            check.get("head_sha") != expected_sha
            or check.get("app_id") != REQUIRED_APP_ID
            or check.get("status") != "completed"
            or check.get("conclusion") != "success"
        ):
            errors.append(f"{prefix}: untrusted, stale or non-success check-run: {name}")


def evaluate_verified_evidence(snapshot: Mapping[str, Any]) -> list[str]:
    """Report failures only; the caller MUST authenticate all input provenance.

    No positive return value is authoritative until a separate privileged
    controller securely gathers records and publishes a source-bound verdict.
    """
    errors: list[str] = []
    if snapshot.get("repository") != "repocache-project/repocache":
        errors.append("unexpected repository")
    pr = _mapping(snapshot.get("pull_request"))
    number = pr.get("number")
    head = pr.get("head_sha")
    target = pr.get("base_ref")
    base_sha = pr.get("base_sha")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        errors.append("invalid PR number")
    if not _integration_ref(target):
        errors.append("target is not an integration branch")
    if not _sha(head) or not _sha(base_sha):
        errors.append("invalid PR head or base SHA")
    if pr.get("state") != "open" or pr.get("draft") is not False:
        errors.append("PR is closed or draft")
    if pr.get("mergeable") is not True:
        errors.append("mergeability is not confirmed")

    source = _mapping(snapshot.get("protected_acceptance"))
    source_sha = source.get("source_sha")
    required_ids = source.get("required_criteria")
    if not _sha(source_sha):
        errors.append("missing protected acceptance source SHA")
    if (
        not isinstance(required_ids, list)
        or not required_ids
        or not all(isinstance(item, str) and item.strip() for item in required_ids)
        or len(set(required_ids)) != len(required_ids)
    ):
        errors.append("missing or malformed original criteria inventory")
        required_ids = []

    evidence = snapshot.get("criteria_evidence")
    if not isinstance(evidence, list):
        errors.append("missing criteria evidence")
        evidence = []
    found: dict[str, list[Mapping[str, Any]]] = {}
    for item in evidence:
        if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
            errors.append("malformed criterion evidence")
            continue
        found.setdefault(item["id"], []).append(item)
    if set(found) != set(required_ids):
        errors.append("criterion inventory differs from protected specification")
    for ident in required_ids:
        matches = found.get(ident, [])
        if len(matches) != 1:
            errors.append(f"criterion {ident}: missing or duplicate")
        elif (
            matches[0].get("status") != "PASS"
            or matches[0].get("tested_sha") != head
            or not isinstance(matches[0].get("evidence_ref"), str)
            or not matches[0]["evidence_ref"].strip()
        ):
            errors.append(f"criterion {ident}: not PASS on exact PR head with evidence")

    if not isinstance(snapshot.get("milestone"), str) or not snapshot["milestone"].strip():
        errors.append("missing release milestone")
    if snapshot.get("unresolved_review_threads") != 0:
        errors.append("review thread resolution not verified")
    if snapshot.get("blocking_reviews") != 0:
        errors.append("blocking reviews remain or are unverified")
    if snapshot.get("material_security_findings") != 0:
        errors.append("security findings remain or are unverified")
    if snapshot.get("pending_dependencies") != 0:
        errors.append("dependencies remain or are unverified")

    approval = _mapping(snapshot.get("maintainer_decision"))
    if not (
        approval.get("verified_provenance") is True
        and approval.get("decision") == "admit-to-merge-queue"
        and approval.get("pr_number") == number
        and approval.get("head_sha") == head
        and approval.get("base_sha") == base_sha
        and approval.get("base_ref") == target
        and approval.get("acceptance_source_sha") == source_sha
    ):
        errors.append("missing or stale authenticated maintainer admission decision")

    _required_checks(
        snapshot.get("pull_request_checks"),
        expected_sha=head,
        errors=errors,
        prefix="pull request",
    )
    stage = snapshot.get("stage")
    if stage == "merge_group":
        group = _mapping(snapshot.get("merge_group"))
        group_sha = group.get("head_sha")
        if (
            not _sha(group_sha)
            or group.get("base_ref") != target
            or group.get("pr_numbers") != [number]
            or group.get("base_sha") != base_sha
        ):
            errors.append("merge-group identity and target not verified")
        _required_checks(
            group.get("checks"),
            expected_sha=group_sha,
            errors=errors,
            prefix="merge group",
        )
    elif stage != "admission":
        errors.append("unsupported admission stage")
    return errors
