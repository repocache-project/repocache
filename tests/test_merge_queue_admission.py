"""Pure-policy negative tests; not GitHub API or live Merge Queue evidence."""
from __future__ import annotations

from copy import deepcopy
import re

import pytest

from scripts.ci.merge_queue_admission import (
    REQUIRED_APP_ID,
    REQUIRED_CONTEXTS,
    evaluate_verified_evidence,
)

HEAD, BASE, SOURCE, GROUP = ("a" * 40, "b" * 40, "c" * 40, "d" * 40)


def checks(sha: str) -> list[dict]:
    return [
        dict(name=name, status="completed", conclusion="success",
             head_sha=sha, app_id=REQUIRED_APP_ID)
        for name in REQUIRED_CONTEXTS
    ]


def valid_snapshot(stage: str = "admission") -> dict:
    result = {
        "repository": "repocache-project/repocache",
        "stage": stage,
        "pull_request": {
            "number": 242, "state": "open", "draft": False, "mergeable": True,
            "head_sha": HEAD, "base_sha": BASE, "base_ref": "integration/v0.6.0",
        },
        "protected_acceptance": {
            "source_sha": SOURCE, "required_criteria": ["ci-contract", "security"],
        },
        "criteria_evidence": [
            {"id": "ci-contract", "status": "PASS", "tested_sha": HEAD,
             "evidence_ref": "workflow-run:123"},
            {"id": "security", "status": "PASS", "tested_sha": HEAD,
             "evidence_ref": "review:456"},
        ],
        "milestone": "v0.6.0",
        "unresolved_review_threads": 0,
        "blocking_reviews": 0,
        "material_security_findings": 0,
        "pending_dependencies": 0,
        "maintainer_decision": {
            "verified_provenance": True,
            "decision": "admit-to-merge-queue",
            "pr_number": 242, "head_sha": HEAD,
            "base_sha": BASE, "base_ref": "integration/v0.6.0",
            "acceptance_source_sha": SOURCE,
        },
        "pull_request_checks": checks(HEAD),
    }
    if stage == "merge_group":
        result["merge_group"] = {
            "head_sha": GROUP,
            "base_sha": BASE,
            "base_ref": "integration/v0.6.0",
            "pr_numbers": [242],
            "checks": checks(GROUP),
        }
    return result


@pytest.mark.parametrize("stage", ["admission", "merge_group"])
def test_complete_mock_evidence(stage):
    assert evaluate_verified_evidence(valid_snapshot(stage)) == []


@pytest.mark.parametrize(("path", "value"), [
    (("repository",), "untrusted/repo"),
    (("pull_request", "base_ref"), "main"),
    (("pull_request", "base_ref"), "release/v0.6.0"),
    (("pull_request", "head_sha"), "f" * 40),
    (("pull_request", "draft"), True),
    (("pull_request", "mergeable"), None),
    (("protected_acceptance", "required_criteria"), []),
    (("criteria_evidence", 0, "status"), "NOT VERIFIED"),
    (("criteria_evidence", 0, "status"), "FAIL"),
    (("criteria_evidence", 0, "tested_sha"), "f" * 40),
    (("criteria_evidence", 0, "evidence_ref"), ""),
    (("milestone",), ""),
    (("milestone",), "v0.7.0"),
    (("unresolved_review_threads",), 1),
    (("blocking_reviews",), 1),
    (("material_security_findings",), 1),
    (("pending_dependencies",), 1),
    (("maintainer_decision", "verified_provenance"), False),
    (("maintainer_decision", "base_sha"), "f" * 40),
    (("maintainer_decision", "head_sha"), "f" * 40),
    (("maintainer_decision", "decision"), "auto-merge"),
    (("pull_request_checks", 0, "conclusion"), "skipped"),
    (("pull_request_checks", 0, "conclusion"), "neutral"),
    (("pull_request_checks", 0, "status"), "queued"),
    (("pull_request_checks", 0, "app_id"), 7),
    (("pull_request_checks", 0, "head_sha"), "f" * 40),
])
def test_reject_untrusted_stale_or_nonpassing_evidence(path, value):
    snapshot = deepcopy(valid_snapshot())
    element = snapshot
    for key in path[:-1]:
        element = element[key]
    element[path[-1]] = value
    assert evaluate_verified_evidence(snapshot), path


def test_missing_required_context_is_denied():
    snapshot = valid_snapshot()
    snapshot["pull_request_checks"].pop()
    assert evaluate_verified_evidence(snapshot)


def test_duplicate_required_context_is_denied():
    snapshot = valid_snapshot()
    snapshot["pull_request_checks"].append(snapshot["pull_request_checks"][0].copy())
    assert evaluate_verified_evidence(snapshot)


@pytest.mark.parametrize(("field", "value"), [
    ("head_sha", "f" * 40),
    ("base_sha", "f" * 40),
    ("base_ref", "integration/v0.7.0"),
    ("pr_numbers", [242, 243]),
])
def test_merge_group_must_match_exact_source(field, value):
    snapshot = valid_snapshot("merge_group")
    snapshot["merge_group"][field] = value
    assert evaluate_verified_evidence(snapshot)


def test_merge_group_requires_all_nine_checks_again():
    snapshot = valid_snapshot("merge_group")
    snapshot["merge_group"]["checks"][0]["conclusion"] = "failure"
    assert evaluate_verified_evidence(snapshot)


def test_missing_group_record_fails_closed():
    snapshot = valid_snapshot("merge_group")
    del snapshot["merge_group"]
    assert evaluate_verified_evidence(snapshot)


def test_future_versioned_lanes_allowed_in_pure_policy():
    for target in ("integration/v0.6.0", "integration/v0.7.0",
                   "integration/v0.8.0", "integration/v1.12.30",
                   "integration/client-foundations-clean-24"):
        snapshot = valid_snapshot()
        snapshot["pull_request"]["base_ref"] = target
        snapshot["maintainer_decision"]["base_ref"] = target
        if re.fullmatch(r"integration/v[0-9]+\.[0-9]+\.[0-9]+", target):
            snapshot["milestone"] = target.removeprefix("integration/")
        assert evaluate_verified_evidence(snapshot) == []
