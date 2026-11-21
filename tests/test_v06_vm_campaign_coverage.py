"""Coverage-index regression: evidence is never equivalent to issue acceptance."""
from pathlib import Path

import pytest

from scripts.collect_v06_vm_campaign_coverage import SCENARIOS, collect


HEAD = "1" * 40


def test_missing_evidence_fails_closed(tmp_path: Path) -> None:
    observed = collect(tmp_path, "debian13", "smoke", HEAD)
    assert observed["scenario_status"] == "NOT_VERIFIED"
    assert all(item["acceptance"] == "NOT_VERIFIED" for item in observed["criteria"])


@pytest.mark.parametrize("platform", ["debian13", "almalinux10"])
@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_complete_guest_scenario_never_implies_original_acceptance(
    tmp_path: Path, platform: str, scenario: str,
) -> None:
    for item in SCENARIOS[scenario]["files"]:
        (tmp_path / item).write_text("test fixture", encoding="utf-8")
    (tmp_path / "sha.txt").write_text(HEAD, encoding="utf-8")
    (tmp_path / "summary.md").write_text(
        f"## PR #237 — {platform} {scenario} experimental booted VM\n"
        f"Source HEAD: {HEAD}\n"
        "Last phase: complete\nVM exercise: PASS\n",
        encoding="utf-8",
    )
    distro = "debian" if platform == "debian13" else "almalinux"
    (tmp_path / "facts.txt").write_text(
        f"ID={distro}\nsystemd\nEnforcing\n", encoding="utf-8",
    )
    observed = collect(tmp_path, platform, scenario, HEAD)
    assert observed["scenario_status"] == "EXECUTED"
    assert observed["full_original_issue_acceptance"] == "NOT_VERIFIED"
    assert observed["signed_publisher_candidate"] == "NOT_VERIFIED"
    assert all(item["coverage"] == "EXERCISED_PARTIAL" for item in observed["criteria"])
    assert all(item["acceptance"] == "NOT_VERIFIED" for item in observed["criteria"])


def test_wrong_head_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "sha.txt").write_text("2" * 40, encoding="utf-8")
    assert collect(tmp_path, "debian13", "smoke", HEAD)["scenario_status"] == "NOT_VERIFIED"


@pytest.mark.parametrize("platform,scenario,head", [
    ("unknown", "smoke", HEAD),
    ("debian13", "other", HEAD),
    ("debian13", "smoke", "bad"),
])
def test_unexpected_inputs_rejected(tmp_path: Path, platform: str, scenario: str, head: str) -> None:
    with pytest.raises(ValueError):
        collect(tmp_path, platform, scenario, head)
