#!/usr/bin/env python3
"""Emit a read-only source/candidate identity receipt for final VM runbooks.

Use PYTHONPATH=src. Nonzero exit means evidence is incomplete/invalid; no
successful exit can grant installation, signing, staging or publication.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from repocache.native_acceptance_evidence_v1 import (
    CandidateRefused, collect_candidate_evidence,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="repocache-native-candidate-evidence",
        description="Read-only exact-byte candidate receipt; NOT a VM acceptance or signer",
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    try:
        receipt = collect_candidate_evidence(
            Path(args.candidate), args.sha256, args.source_sha)
    except (CandidateRefused, ValueError, OSError):
        receipt = {
            "schema_version": 1, "status": "FAIL",
            "code": "CANDIDATE_IDENTITY_INPUT_REFUSED",
            "complete_server_acceptance_passed": False,
            "authorizes_host_write": False,
            "authorizes_publication": False,
        }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    # This is a readiness diagnostic, not a release gate. A digest match with
    # genuine read-only native prerequisites is still NOT VERIFIED overall.
    if receipt["status"] == "FAIL":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
