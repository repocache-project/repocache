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
    assert "Stage C — independent security and publisher acceptance" in doc
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
