"""Static generic release lifecycle boundaries (issue #76).

These tests cannot substitute for native or real owner-signed acceptance.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_lifecycle_is_generic_and_respects_main_linear_history():
    doc = (ROOT / "docs/RELEASE_LIFECYCLE.md").read_text("utf-8")
    for token in (
        "integration/vX.Y.Z", "release/vX.Y.Z", "`main`",
        "squash", "rebase", "source commit SHA", "alpha", "beta",
        "Debian 13", "AlmaLinux 10", "NOT VERIFIED", "#76", "#88",
        "postpublication", "hotfix",
    ):
        assert token in doc
    assert "Do not reuse production" in doc


def test_adopted_routing_does_not_block_parallel_sessions():
    doc = (ROOT / "docs/RELEASE_LIFECYCLE.md").read_text("utf-8")
    for token in (
        "PRs #230, #183 and #231", "historical migration",
        "protected `main`", "integration/v0.6.0",
        "integration/v0.7.0", "NOT VERIFIED",
        "independent approved work",
    ):
        assert token in doc


def test_official_release_build_is_still_manually_tagged_from_main():
    workflow = (WORKFLOWS / "release.yml").read_text("utf-8")
    assert "on:\n  workflow_dispatch:\n" in workflow
    assert "\n  push:" not in workflow.split("permissions:", 1)[0]
    assert "if: startsWith(github.ref, 'refs/tags/v') && github.actor == 'teixemf'" in workflow
    assert 'compare/${GITHUB_SHA}...main' in workflow
    assert "Release commit is not an ancestor of main" in workflow
    assert "name: unsigned-release-candidate" in workflow
    assert "offline_sign_release.py" not in workflow
    assert "permissions:\n  contents: read" in workflow


def test_final_candidate_acceptance_stays_manual_and_version_reviewed():
    signed = (WORKFLOWS / "signed-candidate-acceptance.yml").read_text("utf-8")
    verifier = (ROOT / "scripts/draft_release_gate.py").read_text("utf-8")
    assert "workflow_dispatch:" in signed
    assert "refs/heads/main" in signed
    assert 'require(tag == "v0.5.0"' in verifier
    assert '"0.4.0" in policy["compatible_from"]' in verifier
    assert '"/compare/" + commit + "...main"' in verifier
    assert "signed-candidate-acceptance.yml" in signed or "draft_release_gate.py" in signed
