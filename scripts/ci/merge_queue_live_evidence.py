"""Read-only, live GitHub preflight. NEVER admits or merges a PR.

This collects GitHub API evidence from the canonical repository, pins exact
source and base SHAs and deliberately leaves authority-sensitive fields UNKNOWN.
The policy evaluator must therefore fail closed until an independently trusted
admission controller is implemented and deployed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from scripts.ci.merge_queue_admission import (
    REQUIRED_APP_ID,
    REQUIRED_CONTEXTS,
    evaluate_verified_evidence,
)

REPOSITORY = "repocache-project/repocache"
REPOSITORY_ID = 1425889415
API_ROOT = "https://api.github.com/repos/" + REPOSITORY + "/"
_SHA = re.compile(r"^[a-f0-9]{40}$")


class EvidenceError(ValueError):
    """The live snapshot is inaccessible, malformed, incomplete or stale."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise EvidenceError("GitHub REST redirect refused")


class GitHubReader:
    """Unprivileged GET-only GitHub REST client, fixed host and repository."""

    def __init__(self, token: str | None = None):
        self._token = token
        self._opener = urllib.request.build_opener(_NoRedirect())

    def get(self, path: str) -> Any:
        if not isinstance(path, str) or path.startswith(("/", ".")):
            raise EvidenceError("invalid GitHub API path")
        if "://" in path or "//" in path or ".." in path:
            raise EvidenceError("unsafe GitHub API path")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "repocache-admission-preflight",
        }
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        request = urllib.request.Request(
            API_ROOT + path if path else API_ROOT.rstrip("/"),
            headers=headers, method="GET",
        )
        try:
            with self._opener.open(request, timeout=15) as response:
                payload = response.read(2_000_001)
        except (OSError, urllib.error.URLError) as exc:
            raise EvidenceError("GitHub API request failed") from exc
        if len(payload) > 2_000_000:
            raise EvidenceError("GitHub API response exceeded size limit")
        try:
            return json.loads(payload)
        except (ValueError, UnicodeError) as exc:
            raise EvidenceError("malformed GitHub API response") from exc


def _obj(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceError("malformed " + context)
    return value


def _sha(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise EvidenceError("invalid " + context)
    return value


def _pr_identity(pr: Mapping[str, Any]) -> tuple[str, str, str]:
    head = _sha(_obj(pr.get("head"), "head").get("sha"), "PR head")
    base = _obj(pr.get("base"), "base")
    ref = base.get("ref")
    if not isinstance(ref, str) or not ref.startswith("integration/"):
        raise EvidenceError("not an integration PR")
    if _obj(base.get("repo"), "base repo").get("full_name") != REPOSITORY:
        raise EvidenceError("PR targets an unexpected repository")
    return (head, _sha(base.get("sha"), "PR base"), ref)


def _blocking_reviews(reviews: Any) -> int | None:
    if not isinstance(reviews, list) or len(reviews) >= 100:
        return None
    latest: dict[str, str] = {}
    for raw in reviews:
        review = _obj(raw, "review")
        actor = _obj(review.get("user"), "reviewer").get("login")
        state = review.get("state")
        if not isinstance(actor, str) or not isinstance(state, str):
            raise EvidenceError("review author or state missing")
        if state in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[actor] = state
    return sum(value == "CHANGES_REQUESTED" for value in latest.values())


def collect_live_preflight(
    api: Any, *, number: int, expected_head: str, expected_base: str
) -> dict[str, Any]:
    """Return a partial snapshot with security-sensitive fields unverified.

    The first and final PR/base reads reject drift during collection. This
    does not make the snapshot atomic or authorize a merge: before any future
    action an enforcing controller must perform its own fresh trusted checks.
    """
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise EvidenceError("invalid PR number")
    expected_head = _sha(expected_head, "expected head")
    expected_base = _sha(expected_base, "expected base")

    repository = _obj(api.get(""), "repository")
    if (repository.get("full_name") != REPOSITORY
            or repository.get("id") != REPOSITORY_ID
            or _obj(repository.get("owner"), "owner").get("type") != "Organization"):
        raise EvidenceError("canonical repository identity mismatch")

    pr = _obj(api.get(f"pulls/{number}"), "pull request")
    if pr.get("number") != number:
        raise EvidenceError("PR number mismatch")
    head, base, target = _pr_identity(pr)
    if head != expected_head or base != expected_base:
        raise EvidenceError("PR identity drift since operator preflight")
    branch_name = quote(target, safe="/")
    branch = _obj(api.get(f"branches/{branch_name}"), "target branch")
    actual_base = _sha(_obj(branch.get("commit"), "branch commit").get("sha"), "protected base")
    if actual_base != base or branch.get("protected") is not True:
        raise EvidenceError("target branch moved or is unprotected")

    check_data = _obj(
        api.get(f"commits/{head}/check-runs?per_page=100&filter=latest"),
        "check-run collection",
    )
    checks = check_data.get("check_runs")
    if (not isinstance(checks, list)
            or type(check_data.get("total_count")) is not int
            or check_data["total_count"] != len(checks)
            or len(checks) >= 100):
        raise EvidenceError("incomplete or malformed check-run pagination")

    normalized = []
    for item in checks:
        check = _obj(item, "check-run")
        normalized.append({
            "name": check.get("name"),
            "status": check.get("status"),
            "conclusion": check.get("conclusion"),
            "head_sha": check.get("head_sha"),
            "app_id": _obj(check.get("app"), "check-run source").get("id"),
        })
    reviews = api.get(f"pulls/{number}/reviews?per_page=100")
    blocking = _blocking_reviews(reviews)

    end_pr = _obj(api.get(f"pulls/{number}"), "final pull request")
    end_branch = _obj(api.get(f"branches/{branch_name}"), "final branch")
    if _pr_identity(end_pr) != (head, base, target) or end_pr.get("state") != pr.get("state") \
            or end_pr.get("draft") != pr.get("draft") or \
            _obj(end_branch.get("commit"), "final branch commit").get("sha") != base:
        raise EvidenceError("PR or target branch moved during evidence collection")

    milestone = pr.get("milestone")
    snapshot = {
        "repository": REPOSITORY,
        "stage": "admission",
        "pull_request": {
            "number": number,
            "state": pr.get("state"),
            "draft": pr.get("draft"),
            "mergeable": pr.get("mergeable"),
            "head_sha": head,
            "base_sha": base,
            "base_ref": target,
        },
        "milestone": milestone.get("title") if isinstance(milestone, Mapping) else None,
        "pull_request_checks": normalized,
        "blocking_reviews": blocking,
        # The below require authoritative protected evidence, GitHub review
        # thread inspection and verified maintainer authorization. NEVER infer
        # a passing result from a PR body, ordinary label or public comment.
        "unresolved_review_threads": None,
        "material_security_findings": None,
        "pending_dependencies": None,
        "protected_acceptance": {},
        "criteria_evidence": [],
        "maintainer_decision": {},
    }
    return snapshot


def evaluate_live_preflight(api: Any, *, number: int, expected_head: str,
                            expected_base: str) -> list[str]:
    snapshot = collect_live_preflight(
        api, number=number, expected_head=expected_head, expected_base=expected_base
    )
    errors = evaluate_verified_evidence(snapshot)
    # Guard against reusing this read-only collector as an authorization gate.
    if not errors:
        raise EvidenceError("unsafe: read-only preflight unexpectedly approved")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-base", required=True)
    args = parser.parse_args()
    try:
        errors = evaluate_live_preflight(
            GitHubReader(token=os.environ.get("GITHUB_TOKEN")),
            number=args.pr, expected_head=args.expected_head,
            expected_base=args.expected_base,
        )
    except EvidenceError as exc:
        print(json.dumps({"result": "NOT VERIFIED", "errors": [str(exc)]}))
        return 2
    print(json.dumps({"result": "NOT VERIFIED", "errors": errors}, indent=2))
    return 2  # Intentionally never signals admission permission.


if __name__ == "__main__":
    sys.exit(main())
