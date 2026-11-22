"""Repository-wide CI/native/publisher staging source contract.

These tests prove policy references and the existence of distinct evidence
owners. They do not approve a PR, replace original issue criteria, or
certify any native/publisher acceptance.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGES = ROOT / "docs/ACCEPTANCE_STAGES.md"
LINKED = (
    ROOT / "AGENTS.md",
    ROOT / "docs/DEVELOPMENT_WORKFLOW.md",
    ROOT / "docs/PR_REVIEW_GOVERNANCE.md",
    ROOT / "docs/RELEASE_LIFECYCLE.md",
    ROOT / "docs/TESTING.md",
    ROOT / ".github/pull_request_template.md",
)


def test_every_milestone_uses_one_shared_acceptance_policy():
    doc = STAGES.read_text(encoding="utf-8")
    assert "every maintainer-selected milestone and release" in doc
    assert "vMAJOR.MINOR.PATCH" in doc
    assert "Stage A — implementation acceptance in CI" in doc
    assert "Stage B — system-level/native acceptance" in doc
    assert "Stage C — security and publisher acceptance" in doc
    assert "commissioned human review is optional for all issues" in doc
    assert "pinned-image VM harness is a reusable starting point" in doc
    assert "NOT VERIFIED" in doc
    assert "An original issue may remain NOT VERIFIED" in doc


def test_shared_policy_is_referenced_from_all_operational_entrypoints():
    for path in LINKED:
        assert path.is_file()
        content = path.read_text(encoding="utf-8")
        assert "ACCEPTANCE_STAGES.md" in content, path


def test_stages_do_not_erase_native_or_owner_gate():
    doc = STAGES.read_text(encoding="utf-8")
    for obligation in (
        "booted", "SELinux enforcing", "APT/DNF", "Ed25519",
        "issue-specific", "scope amendment", "approval",
        "Stage A", "Stage B", "Stage C", "PASS", "FAIL", "NOT VERIFIED",
    ):
        # Stage A can be independently complete without granting B/C PASS.
        if obligation == "scope amendment":
            assert "scope amendment" in doc
        else:
            assert obligation in doc
    governance = (ROOT / "docs/PR_REVIEW_GOVERNANCE.md").read_text(
        encoding="utf-8"
    )
    assert "issue-specific" in governance
    assert "protected" in governance
    assert "all applicable" in governance


def test_option_c_separates_functional_proof_from_real_publisher_signature():
    """Static policy guard, not a substitute for booted VMs or real signatures."""
    stages = STAGES.read_text(encoding="utf-8")
    fast = (ROOT / "docs/DEVELOPMENT_FAST_PATH.md").read_text(encoding="utf-8")
    workflow = (ROOT / "docs/DEVELOPMENT_WORKFLOW.md").read_text(encoding="utf-8")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    signature_verifier = (ROOT / "src/repocache/signatures.py").read_text(encoding="utf-8")
    release_acceptance = (ROOT / "docs/RELEASE_ACCEPTANCE_POLICY.md").read_text(encoding="utf-8")
    for text in (stages, fast, workflow, agents):
        assert "option c" in text.lower(), "missing approved development signing boundary"
        assert "Stage" in text
    assert "Ed25519" in stages and "Ed25519" in agents
    assert "sign" in fast and "sign" in workflow
    assert "#31" in stages and "#31" in fast and "#31" in workflow
    assert "#76/#88" in stages and "#76/#88" in fast and "#76/#88" in workflow
    for expected in (
        "no unsigned-install escape hatch",
        "guest-local trust anchors",
        "after the final reviewed source",
        "full applicable Stage-A/B acceptance",
        "Stage C",
    ):
        assert expected in stages, expected
    # The production publication policy must still demand authentic final bytes.
    assert "genuine offline publisher" in release_acceptance
    assert "independently provisioned trust anchor" in release_acceptance
    assert "Before extracting or running candidate code" in release_acceptance
    for expected in (
        "Publisher release signature is invalid",
        "Publisher trust anchor is not provisioned",
        "Missing or invalid Ed25519 signature",
        "if result.returncode != 0:",
    ):
        assert expected in signature_verifier, expected
