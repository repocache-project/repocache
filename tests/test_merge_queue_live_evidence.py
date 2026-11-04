"""Mocked REST evidence tests. No network and no real admission permission."""
from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.ci.merge_queue_live_evidence import (
    REPOSITORY,
    REPOSITORY_ID,
    EvidenceError,
    collect_live_preflight,
    evaluate_live_preflight,
)
from scripts.ci.merge_queue_admission import REQUIRED_APP_ID, REQUIRED_CONTEXTS

HEAD = "a" * 40
BASE = "b" * 40


def records():
    return {
        "": {
            "id": REPOSITORY_ID, "full_name": REPOSITORY,
            "owner": {"type": "Organization"},
        },
        "pulls/17": {
            "number": 17, "state": "open", "draft": False, "mergeable": True,
            "head": {"sha": HEAD},
            "base": {
                "sha": BASE, "ref": "integration/v0.8.0",
                "repo": {"full_name": REPOSITORY},
            },
            "milestone": {"title": "v0.8.0"},
        },
        "branches/integration/v0.8.0": {
            "commit": {"sha": BASE}, "protected": True,
        },
        f"commits/{HEAD}/check-runs?per_page=100&filter=latest": {
            "total_count": len(REQUIRED_CONTEXTS),
            "check_runs": [
                {"name": name, "head_sha": HEAD, "status": "completed",
                 "conclusion": "success", "app": {"id": REQUIRED_APP_ID}}
                for name in REQUIRED_CONTEXTS
            ],
        },
        "pulls/17/reviews?per_page=100": [],
    }


class FakeAPI:
    def __init__(self, values):
        self.values = values
        self.requested = []

    def get(self, path):
        self.requested.append(path)
        return deepcopy(self.values[path])


def collect(api):
    return collect_live_preflight(api, number=17, expected_head=HEAD,
                                  expected_base=BASE)


def test_successful_mocked_github_reads_still_cannot_admit():
    api = FakeAPI(records())
    snapshot = collect(api)
    assert len(snapshot["pull_request_checks"]) == 9
    assert snapshot["pull_request"]["base_ref"] == "integration/v0.8.0"
    assert snapshot["blocking_reviews"] == 0
    assert snapshot["unresolved_review_threads"] is None
    errors = evaluate_live_preflight(api, number=17, expected_head=HEAD,
                                     expected_base=BASE)
    assert errors
    assert any("authenticated maintainer" in error for error in errors)
    assert any("criteria" in error for error in errors)
    assert api.requested.count("pulls/17") == 4


@pytest.mark.parametrize(("path", "change"), [
    ("", lambda item: item.update(id=0)),
    ("", lambda item: item.update(owner={"type": "User"})),
    ("pulls/17", lambda item: item["head"].update(sha="c" * 40)),
    ("pulls/17", lambda item: item["base"].update(sha="c" * 40)),
    ("pulls/17", lambda item: item["base"].update(ref="main")),
    ("pulls/17", lambda item: item["base"]["repo"].update(full_name="other/repo")),
    ("branches/integration/v0.8.0", lambda item: item.update(protected=False)),
    ("branches/integration/v0.8.0",
     lambda item: item["commit"].update(sha="c" * 40)),
    (f"commits/{HEAD}/check-runs?per_page=100&filter=latest",
     lambda item: item.update(total_count=101)),
    (f"commits/{HEAD}/check-runs?per_page=100&filter=latest",
     lambda item: item.update(total_count=8)),
])
def test_live_identity_and_incomplete_pagination_denied(path, change):
    data = records()
    change(data[path])
    with pytest.raises(EvidenceError):
        collect(FakeAPI(data))


def test_missing_github_api_data_denied():
    data = records()
    del data["pulls/17"]
    with pytest.raises(KeyError):
        collect(FakeAPI(data))


def test_check_from_wrong_app_denied_by_policy():
    data = records()
    item = data[f"commits/{HEAD}/check-runs?per_page=100&filter=latest"]["check_runs"][0]
    item["app"]["id"] = 101
    snapshot = collect(FakeAPI(data))
    from scripts.ci.merge_queue_admission import evaluate_verified_evidence
    assert any("untrusted" in error for error in evaluate_verified_evidence(snapshot))


def test_changes_requested_review_not_silently_ignored():
    data = records()
    data["pulls/17/reviews?per_page=100"] = [
        {"user": {"login": "reviewer"}, "state": "CHANGES_REQUESTED"}
    ]
    assert collect(FakeAPI(data))["blocking_reviews"] == 1


def test_review_pagination_unverified():
    data = records()
    data["pulls/17/reviews?per_page=100"] = [
        {"user": {"login": f"user{i}"}, "state": "APPROVED"}
        for i in range(100)
    ]
    assert collect(FakeAPI(data))["blocking_reviews"] is None


def test_wrong_expected_sha_rejected():
    with pytest.raises(EvidenceError):
        collect_live_preflight(FakeAPI(records()), number=17,
                               expected_head="c" * 40, expected_base=BASE)


def test_future_main_is_not_eligible():
    data = records()
    data["pulls/17"]["base"]["ref"] = "main"
    with pytest.raises(EvidenceError):
        collect(FakeAPI(data))


class FakeHTTPResponse:
    def __init__(self, data: bytes):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        assert limit == 2_000_001
        return self.data


class FakeHTTP:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeHTTPResponse(b'{"ok": true}')


def test_http_reader_is_restricted_to_canonical_get_and_no_redirects():
    from scripts.ci.merge_queue_live_evidence import GitHubReader
    client = GitHubReader()
    fake = FakeHTTP()
    client._opener = fake
    assert client.get("") == {"ok": True}
    assert client.get("pulls/245") == {"ok": True}
    assert [request.full_url for request, _ in fake.requests] == [
        "https://api.github.com/repos/repocache-project/repocache",
        "https://api.github.com/repos/repocache-project/repocache/pulls/245",
    ]
    assert all(request.get_method() == "GET" for request, _ in fake.requests)
    assert all(timeout == 15 for _, timeout in fake.requests)


@pytest.mark.parametrize("path", [
    "//attacker.invalid", "/another/repo", "../other", ".git",
    "https://attacker.invalid", "pulls/../1", "foo//bar",
])
def test_http_reader_rejects_noncanonical_request_paths(path):
    from scripts.ci.merge_queue_live_evidence import GitHubReader
    with pytest.raises(EvidenceError):
        GitHubReader().get(path)
