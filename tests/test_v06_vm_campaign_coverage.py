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
    if scenario == "native-lifecycle":
        (tmp_path / "native-v2-repository-lifecycle.txt").write_text(
            "PASS: booted native test-signed repository add/remove and durable\n"
            "NOT VERIFIED: active approved upstream cache MISS/HIT\n",
            encoding="utf-8",
        )
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
    if scenario == "smoke":
        assert observed["other_campaigns"]["P0-2"] == "NOT_VERIFIED"
        assert observed["other_campaigns"]["P0-3"] == "NOT_VERIFIED"


def test_p02_partial_coverage_requires_exact_log_and_completed_guest(tmp_path: Path) -> None:
    for name in SCENARIOS["smoke"]["files"]:
        (tmp_path / name).write_text("fixture", encoding="utf-8")
    (tmp_path / "sha.txt").write_text(HEAD, encoding="utf-8")
    (tmp_path / "summary.md").write_text(
        f"## PR #237 — debian13 smoke experimental booted VM\n"
        f"Source HEAD: {HEAD}\nLast phase: complete\nVM exercise: PASS\n",
        encoding="utf-8",
    )
    (tmp_path / "facts.txt").write_text("ID=debian\nsystemd\n", encoding="utf-8")
    log = tmp_path / "native-cache-data-plane.txt"
    log.write_text("PASS: booted native VM stock NGINX disposable HTTPS APT/DNF MISS/HIT",
                   encoding="utf-8")
    cli = tmp_path / "native-client-cli-source-guard.txt"
    cli.write_text(
        "PASS: booted native VM client CLI --apply refusal and APT/DNF source integrity",
        encoding="utf-8",
    )
    observed = collect(tmp_path, "debian13", "smoke", HEAD)
    assert observed["other_campaigns"]["P0-2"] == "EXERCISED_PARTIAL"
    assert observed["other_campaigns"]["P0-3"] == "EXERCISED_PARTIAL"
    assert {row["issue_criterion"] for row in observed["criteria"]} >= {
        "28.01", "28.02", "28.03", "30.01", "24.04", "107.03", "107.04",
    }
    assert all(row["acceptance"] == "NOT_VERIFIED" for row in observed["criteria"])
    (tmp_path / "sha.txt").write_text("2" * 40, encoding="utf-8")
    failed = collect(tmp_path, "debian13", "smoke", HEAD)
    assert failed["other_campaigns"]["P0-2"] == "NOT_VERIFIED"
    assert failed["other_campaigns"]["P0-3"] == "NOT_VERIFIED"


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


def test_native_lifecycle_evidence_requires_final_guest_markers(tmp_path: Path) -> None:
    for name in SCENARIOS["native-lifecycle"]["files"]:
        (tmp_path / name).write_text("fixture", encoding="utf-8")
    (tmp_path / "sha.txt").write_text(HEAD, encoding="utf-8")
    (tmp_path / "summary.md").write_text(
        "## PR #237 — almalinux10 native-lifecycle experimental booted VM\n"
        f"Source HEAD: {HEAD}\nLast phase: complete\nVM exercise: PASS\n",
        encoding="utf-8",
    )
    (tmp_path / "facts.txt").write_text(
        "ID=almalinux\nsystemd\nEnforcing\n", encoding="utf-8",
    )
    result = collect(tmp_path, "almalinux10", "native-lifecycle", HEAD)
    assert result["scenario_status"] == "NOT_VERIFIED"
    assert result["other_campaigns"]["P0-2"] == "NOT_VERIFIED"
    log = tmp_path / "native-v2-repository-lifecycle.txt"
    log.write_text(
        "PASS: booted native test-signed repository add/remove and durable\n"
        "NOT VERIFIED: active approved upstream cache MISS/HIT\n",
        encoding="utf-8",
    )
    result = collect(tmp_path, "almalinux10", "native-lifecycle", HEAD)
    assert result["scenario_status"] == "EXECUTED"
    assert result["other_campaigns"]["P0-2"] == "EXERCISED_PARTIAL"
    assert {row["issue_criterion"] for row in result["criteria"]} >= {
        "95.02", "95.03", "95.04", "28.05",
    }
    assert all(row["acceptance"] == "NOT_VERIFIED" for row in result["criteria"])
