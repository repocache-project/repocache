"""Keep supplementary client CI opt-in for Markdown-only pull requests.

This is a source-contract guard, not proof of GitHub webhook delivery.
Mandatory branch-protection contexts remain unconditional and are tested
separately by the protected release integration contract suite.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
OPTIONAL_CLIENT_WORKFLOWS = (
    "client-atomic-sandbox.yml",
    "client-entry-approval-plan.yml",
    "client-entry-candidates.yml",
    "client-helper-preview.yml",
    "client-managed-registry.yml",
    "client-metadata-sandbox.yml",
    "client-native-fallback.yml",
    "client-shared-entry-atomic.yml",
    "client-source-preflight.yml",
    "client-transaction-metadata.yml",
)
TRIGGER = (
    "on:\n"
    "  pull_request:\n"
    "    paths-ignore:\n"
    "      - '*.md'\n"
    "      - '**/*.md'\n"
    "  workflow_dispatch:\n"
)
MARKDOWN_GLOBS = ("*.md", "**/*.md")
REQUIRED_WORKFLOWS = ("tests.yml", "offline-wheelhouse.yml", "upgrade-distros.yml")


def _read_trigger(name: str) -> str:
    source = (WORKFLOWS / name).read_text(encoding="utf-8")
    assert source.startswith("name:")
    before_jobs = source.split("\npermissions:\n", 1)
    assert len(before_jobs) == 2
    return before_jobs[0]


def _matches_markdown_glob(pattern: str, path: str) -> bool:
    # Only the two explicitly reviewed GitHub glob shapes are supported.
    # A slash in a GitHub glob is not matched by a single '*'.
    expressions = {
        "*.md": r"[^/]+\.md",
        "**/*.md": r"(?:[^/]+/)*[^/]+\.md",
    }
    return re.fullmatch(expressions[pattern], path) is not None


def _should_run_pull_request(changed_paths: tuple[str, ...]) -> bool:
    assert changed_paths, "GitHub supplies at least one changed path"
    return any(
        not any(_matches_markdown_glob(pattern, path) for pattern in MARKDOWN_GLOBS)
        for path in changed_paths
    )


@pytest.mark.parametrize("name", OPTIONAL_CLIENT_WORKFLOWS)
def test_supplementary_client_workflows_only_ignore_markdown_on_pr(name: str) -> None:
    header = _read_trigger(name)
    assert header.endswith("\n" + TRIGGER.rstrip("\n"))
    assert header.count("  pull_request:") == 1
    assert header.count("  workflow_dispatch:") == 1
    assert "\n  push:" not in header
    assert "pull_request_target:" not in header
    source = (WORKFLOWS / name).read_text(encoding="utf-8")
    assert "\npermissions:\n  contents: read\n" in source
    assert "persist-credentials: false" in source


@pytest.mark.parametrize(("changed", "expected_run"), [
    (("README.md",), False),
    (("SECURITY.md",), False),
    (("docs/DEVELOPMENT_WORKFLOW.md",), False),
    (("docs/releases/NOTES.md", "SECURITY.md"), False),
    (("client/repocache_client.py",), True),
    (("SECURITY.md", "client/repocache_client.py"), True),
    (("docs/README.md", ".github/workflows/client-native-fallback.yml"), True),
    (("docs/CONFIG.yaml",), True),
    (("tests/test_client.py",), True),
])
def test_representative_github_path_filter_cases(
    changed: tuple[str, ...], expected_run: bool
) -> None:
    assert _should_run_pull_request(changed) is expected_run


@pytest.mark.parametrize("name", REQUIRED_WORKFLOWS)
def test_protected_required_workflows_still_unfiltered(name: str) -> None:
    header = _read_trigger(name)
    assert "  pull_request:\n" in header
    assert "    paths-ignore:" not in header
    assert "    paths:" not in header
