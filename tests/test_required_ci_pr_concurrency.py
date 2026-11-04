"""Source, mutation and scenario tests for required-CI PR supersession.

These are static tests, not proof of GitHub scheduler/event delivery.
"""
from __future__ import annotations

from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
REQUIRED = ("tests.yml", "offline-wheelhouse.yml", "upgrade-distros.yml")
GROUP = "group: ${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.run_attempt == 1 && format('pr-{0}', github.event.pull_request.number) || format('isolated-{0}-{1}-{2}', github.event_name, github.sha, github.run_id) }}"
CANCEL = "cancel-in-progress: ${{ github.event_name == 'pull_request' && github.run_attempt == 1 }}"


def _contract(name: str, source: str) -> None:
    assert source.startswith("name: ")
    assert source.count("\nconcurrency:\n") == 1
    assert "permissions:\n  contents: read\n\nconcurrency:\n" in source
    assert "\n\njobs:\n" in source
    section = source.split("\nconcurrency:\n", 1)[1].split("\njobs:\n", 1)[0]
    statements = [line.strip() for line in section.splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
    assert statements == [GROUP, CANCEL]
    events = source.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
    for event in ("pull_request:", "push:", "merge_group:"):
        assert events.count("  " + event + "\n") == 1
    assert "pull_request_target:" not in events
    assert "paths-ignore:" not in events and "\n    paths:" not in events
    assert "branches: [main, 'release/**', 'integration/**']" in events
    if name != "tests.yml":
        assert events.count("  workflow_dispatch:\n") == 1
    assert "persist-credentials: false" in source


@pytest.mark.parametrize("name", REQUIRED)
def test_required_workflows_preserve_safely_isolated_concurrency(name: str) -> None:
    _contract(name, (WORKFLOWS / name).read_text("utf-8"))


def _model(workflow: str, event: str, attempt: int, pr: int | None,
           sha: str, run_id: int) -> tuple[str, bool]:
    """Model the intended expression, not GitHub's scheduler."""
    supersedes = event == "pull_request" and attempt == 1
    if supersedes:
        assert pr is not None and pr > 0
        suffix = f"pr-{pr}"
    else:
        suffix = f"isolated-{event}-{sha}-{run_id}"
    return f"{workflow}-{suffix}", supersedes


def test_new_pr_head_supersedes_old_head_but_not_other_pr_or_workflow() -> None:
    old = _model("Tests", "pull_request", 1, 244, "sha-old", 100)
    new = _model("Tests", "pull_request", 1, 244, "sha-new", 101)
    other = _model("Tests", "pull_request", 1, 245, "sha-new", 102)
    separate = _model("Offline wheelchain validation", "pull_request", 1, 244, "sha-new", 103)
    assert old == new and new[1] is True
    assert len({old[0], other[0], separate[0]}) == 3


def test_stale_manual_rerun_cannot_cancel_new_pr_head() -> None:
    latest = _model("Tests", "pull_request", 1, 244, "new", 102)
    manual_retry = _model("Tests", "pull_request", 2, 244, "old", 101)
    assert latest[1] and not manual_retry[1]
    assert latest[0] != manual_retry[0]


@pytest.mark.parametrize("event", ("push", "merge_group", "workflow_dispatch"))
def test_non_pr_events_have_unique_uncancellable_sha_run_groups(event: str) -> None:
    a = _model("Tests", event, 1, None, "sha-a", 100)
    b = _model("Tests", event, 1, None, "sha-a", 101)
    c = _model("Tests", event, 1, None, "sha-b", 100)
    assert not any(x[1] for x in (a, b, c))
    assert len({a[0], b[0], c[0]}) == 3


@pytest.mark.parametrize(("before", "after"), [
    (GROUP, GROUP.replace("github.run_attempt == 1 && ", "")),
    (GROUP, GROUP.replace("github.event.pull_request.number", "github.head_ref")),
    (GROUP, GROUP.replace("github.sha", "github.ref")),
    (GROUP, GROUP.replace("github.run_id", "github.ref")),
    (CANCEL, "cancel-in-progress: true"),
    (CANCEL, "cancel-in-progress: ${{ github.event_name != 'merge_group' }}"),
    ("  merge_group:\n", ""),
    ("  pull_request:\n", "  pull_request_target:\n"),
    ("  push:\n", ""),
    ("permissions:\n  contents: read", "permissions:\n  contents: write"),
])
def test_mutations_refuse_broken_isolation(before: str, after: str) -> None:
    source = (WORKFLOWS / "offline-wheelhouse.yml").read_text("utf-8")
    assert before in source
    with pytest.raises(AssertionError):
        _contract("offline-wheelhouse.yml", source.replace(before, after, 1))
