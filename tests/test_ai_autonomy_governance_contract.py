"""Guard adopted AI autonomy without relaxing protected acceptance.

These tests check repository guidance, not live GitHub permissions or CI results.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_autonomy_is_not_an_intermediate_approval_gate():
    guide = read("AGENTS.md")
    workflow = read("docs/DEVELOPMENT_WORKFLOW.md")
    for token in ("Autonomous execution by default", "independent approved work"):
        assert token.lower() in (guide + workflow).lower()
    assert "A completed plan, test, PR, CI run or checkpoint is not itself a stopping condition" in guide
    assert "all original applicable criteria PASS" in workflow
    assert "NOT VERIFIED" in workflow


def test_adopted_delegation_and_protected_boundaries_agree():
    documents = (
        read("AGENTS.md"), read("CONTRIBUTING.md"),
        read("docs/DEVELOPMENT_WORKFLOW.md"),
        read("docs/PR_REVIEW_GOVERNANCE.md"),
        read(".github/pull_request_template.md"),
        read("docs/PR_MILESTONE_GOVERNANCE.md"),
    )
    for document in documents:
        assert "PR #245" in document
        assert "integration/vMAJOR.MINOR.PATCH" in document or "versioned-integration" in document
    policy = read("docs/PR_REVIEW_GOVERNANCE.md")
    assert "all nine strict required" in policy
    assert "every original applicable acceptance criterion PASS" in policy
    assert "main" in policy and "release/*" in policy
    assert "distinct explicit maintainer permission" in policy
    assert "The explicit maintainer merge decision" not in policy
    template = read(".github/pull_request_template.md")
    assert "Standing conditional authorization is not active" not in template


def test_live_queue_configuration_is_not_implicit_pilot_authorization():
    queue = read("docs/INTEGRATION_MERGE_QUEUE_PROPOSAL.md")
    assert "ruleset #26753319" in queue
    assert "active" in queue and "NOT VERIFIED" in queue
    assert "separately authorized" in queue
    assert "maintainer-controlled action" not in queue
    lifecycle = read("docs/RELEASE_LIFECYCLE.md")
    assert "historical migration" in lifecycle
    assert "## Before allowing parallel AI sessions to resume" not in lifecycle
