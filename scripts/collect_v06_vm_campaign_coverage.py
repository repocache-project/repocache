#!/usr/bin/env python3
"""Conservative per-job coverage inventory for PR237 QEMU experiments.

Only records which original issue criteria were *exercised partially* by a
completed booted VM scenario. Never reports acceptance PASS, including when
the entire guest scenario succeeds. Does not contact GitHub or modify guests.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CAMPAIGNS = {
    "P0-1": "Installation, systemd and recovery",
    "P0-2": "NGINX, TLS, cache and storage",
    "P0-3": "Client APT/DNF and CLI",
    "P0-4": "Owner-signed candidate and release",
    "P1-1": "Advanced security/isolation (v0.7.0)",
    "P1-2": "Dependency, migration and regression (v0.7.0)",
}
SCENARIOS = {
    "smoke": {
        "files": (
            "before-reboot.txt", "after-reboot.txt", "reboot-ids.txt",
            "synthetic-installed-worker.txt", "pending-journal-before-reboot.txt",
            "pending-journal-after-reboot.txt", "second-reboot-ids.txt",
            "native-cache-data-plane.txt",
            "native-client-cli-source-guard.txt",
        ),
        "criteria": ("19.06", "19.10", "26.01", "27.05", "31.03", "64.04"),
    },
    "native-installer": {
        "files": (
            "installer-prerequisites.txt", "native-install.txt",
            "native-install-after-reboot.txt", "installer-reboot-ids.txt",
            "synthetic-installed-worker.txt", "native-socket-v2.txt",
        ),
        "criteria": (
            "19.03", "19.06", "19.07", "19.10", "27.04",
            "31.01", "31.03", "31.05", "64.01", "64.02", "64.03",
        ),
    },
    "native-lifecycle": {
        "files": (
            "installer-prerequisites.txt", "native-install.txt",
            "native-install-after-reboot.txt", "installer-reboot-ids.txt",
            "synthetic-installed-worker.txt", "native-v2-repository-lifecycle.txt",
        ),
        "criteria": ("95.02", "95.03", "95.04", "95.05", "95.06", "28.04", "28.05"),
    },
    "native-package-interruption": {
        "files": (
            "installer-prerequisites.txt",
            "native-package-manager-interruption.txt",
            "native-package-manager-after-reboot.txt",
            "interrupted-manager-reboot-ids.txt",
            "synthetic-installed-worker.txt",
        ),
        "criteria": ("19.10", "19.16", "31.05"),
    },
}


def collect(path: Path, platform: str, scenario: str, expected_head: str) -> dict:
    if platform not in ("debian13", "almalinux10"):
        raise ValueError("unsupported platform")
    if scenario not in SCENARIOS:
        raise ValueError("unsupported scenario")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise ValueError("expected HEAD must be 40 lowercase hexadecimal characters")
    files = SCENARIOS[scenario]["files"]
    required = ("sha.txt", "summary.md", "facts.txt") + files
    missing = [name for name in required if not (path / name).is_file() or not (path / name).stat().st_size]
    observed_head = (path / "sha.txt").read_text(encoding="utf-8").strip() if "sha.txt" not in missing else None
    summary = (path / "summary.md").read_text(encoding="utf-8") if "summary.md" not in missing else ""
    facts = (path / "facts.txt").read_text(encoding="utf-8") if "facts.txt" not in missing else ""
    expected_image = "debian" if platform == "debian13" else "almalinux"
    facts_valid = (f"ID={expected_image}" in facts or f'ID="{expected_image}"' in facts) and (
        re.search(r"(?m)^systemd\s*$", facts) is not None
    )
    if platform == "almalinux10":
        facts_valid = facts_valid and re.search(r"(?m)^Enforcing\s*$", facts) is not None
    completed = (
        not missing
        and observed_head == expected_head
        and f"## PR #237 — {platform} {scenario} experimental booted VM" in summary
        and f"Source HEAD: {expected_head}" in summary
        and "Last phase: complete" in summary
        and "VM exercise: PASS" in summary
        and facts_valid
    )
    if scenario == "native-lifecycle" and completed:
        log = (path / "native-v2-repository-lifecycle.txt").read_text(encoding="utf-8")
        completed = (
            "PASS: booted native test-signed repository add/remove and durable" in log
            and "NOT VERIFIED: active approved upstream cache MISS/HIT" in log
        )
    secondary = ()
    if scenario == "smoke":
        native_log = (path / "native-cache-data-plane.txt")
        if completed and native_log.is_file():
            native_text = native_log.read_text(encoding="utf-8")
            if "PASS: booted native VM stock NGINX disposable HTTPS APT/DNF MISS/HIT" in native_text:
                secondary = ("28.01", "28.02", "28.03", "30.01")
    client_criteria = ()
    if scenario == "smoke":
        client_log = path / "native-client-cli-source-guard.txt"
        if completed and client_log.is_file():
            client_text = client_log.read_text(encoding="utf-8")
            if "PASS: booted native VM client CLI --apply refusal and APT/DNF source integrity" in client_text:
                client_criteria = ("24.04", "107.03", "107.04")
    campaigns = {k: "NOT_RUN" for k in CAMPAIGNS if k != "P0-1"}
    if scenario == "native-lifecycle":
        campaigns["P0-2"] = "EXERCISED_PARTIAL" if completed else "NOT_VERIFIED"
    if scenario == "smoke":
        campaigns["P0-2"] = "EXERCISED_PARTIAL" if secondary else "NOT_VERIFIED"
        campaigns["P0-3"] = "EXERCISED_PARTIAL" if client_criteria else "NOT_VERIFIED"
    return {
        "campaign": "P0-1",
        "platform": platform,
        "scenario": scenario,
        "expected_source_sha": expected_head,
        "observed_source_sha": observed_head,
        "scenario_status": "EXECUTED" if completed else "NOT_VERIFIED",
        "full_original_issue_acceptance": "NOT_VERIFIED",
        "signed_publisher_candidate": "NOT_VERIFIED",
        "required_evidence_files_missing": missing,
        "guest_identity_verified": bool(facts_valid),
        "criteria": [
            {"issue_criterion": c, "coverage": "EXERCISED_PARTIAL" if completed else "NOT_VERIFIED",
             "acceptance": "NOT_VERIFIED"}
            for c in SCENARIOS[scenario]["criteria"]
        ] + [
            {"issue_criterion": c, "coverage": "EXERCISED_PARTIAL",
             "acceptance": "NOT_VERIFIED"}
            for c in secondary
        ] + [
            {"issue_criterion": c, "coverage": "EXERCISED_PARTIAL",
             "acceptance": "NOT_VERIFIED"}
            for c in client_criteria
        ],
        "other_campaigns": campaigns,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--platform", choices=("debian13", "almalinux10"), required=True)
    parser.add_argument("--scenario", choices=tuple(SCENARIOS), required=True)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args(argv)
    try:
        report = collect(args.evidence_dir, args.platform, args.scenario, args.expected_head)
        args.evidence_dir.mkdir(parents=True, exist_ok=True)
        target = args.evidence_dir / "v06-campaign-coverage.json"
        target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"P0-1 {args.platform}/{args.scenario}: {report['scenario_status']}; original issue acceptance NOT_VERIFIED")
        if report["required_evidence_files_missing"]:
            print("Missing evidence: " + ", ".join(report["required_evidence_files_missing"]))
        return 0  # Existing guest job remains the source of overall success/failure.
    except (OSError, UnicodeError, ValueError) as exc:
        print("Coverage inventory NOT_VERIFIED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
