"""Source-only guardrails for the preparatory integration merge queue change.

These tests do not establish live GitHub merge queue eligibility or acceptance.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
REQUIRED = ("tests.yml", "offline-wheelhouse.yml", "upgrade-distros.yml")


def test_all_nine_required_contexts_are_merge_group_eligible():
    expected = {
        "tests.yml": (
            "Unit tests (Python",
            "Bundle integrity and unsigned-source refusal",
        ),
        "offline-wheelhouse.yml": (
            "Offline wheels (",
            "Signed release and native offline dependency artifact",
        ),
        "upgrade-distros.yml": ("Synthetic rootless update and rollback",),
    }
    for name in REQUIRED:
        source = (WORKFLOWS / name).read_text(encoding="utf-8")
        trigger = source.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        assert "  pull_request:" in ("\n" + trigger), name
        assert "  merge_group:" in ("\n" + trigger), name
        assert "paths:" not in trigger and "paths-ignore:" not in trigger, name
        assert "permissions:\n  contents: read" in source, name
        assert "persist-credentials: false" in source, name
        for context in expected[name]:
            assert context in source, (name, context)


def test_queue_preparation_does_not_enable_release_automation():
    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "\n  merge_group:" not in release
    assert "\n  push:" not in release
    proposal = (ROOT / "docs/INTEGRATION_MERGE_QUEUE_PROPOSAL.md").read_text(
        encoding="utf-8"
    )
    assert "active" in proposal
    assert "ruleset #26753319" in proposal
    assert "NOT VERIFIED" in proposal
    assert "integration/v*" in proposal
