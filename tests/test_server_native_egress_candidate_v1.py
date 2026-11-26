"""Pure candidate egress: exact canonical render, no privileged effects."""
from __future__ import annotations

import hashlib
import pytest

from repocache.server_native_egress_candidate_v1 import (
    NativeEgressCandidateError, derive_pinned_egress_candidate,
    render_namespace_egress_candidate,
)
from repocache.server_nginx_repository_bundle_v1 import render_repository_nginx_bundle_candidate
from test_server_proposed_state_v2_store import document


def fixture(*, both=True):
    doc = document(count=2, generation=1)
    doc["repositories"][0]["desired_state"] = "active"
    doc["repositories"][1]["desired_state"] = "active" if both else "disabled"
    doc["repositories"][0]["upstream"]["allowed_hosts"].append("alternate.example.invalid")
    doc["repositories"][1]["upstream"]["base_url"] = (
        "https://mirror1.example.invalid:8008/repo/"
    )
    pins = {"repo-0": {"mirror0.example.invalid": ["2001:4860:4860::8888", "8.8.8.8"],
                       "alternate.example.invalid": ["9.9.9.9"]}}
    if both:
        pins["repo-1"] = {"mirror1.example.invalid": ["1.1.1.1"]}
    fragment = render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=1, candidate_pins_by_repository=pins,
        ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
    )["http_upstream_fragment"].encode("ascii")
    return doc, fragment


def test_exact_tuple_candidate_and_disabled_withdrawal():
    doc, raw = fixture()
    plan = render_namespace_egress_candidate(doc, generation=1, http_fragment=raw, worker_uid=987)
    assert plan["http_sha256"] == hashlib.sha256(raw).hexdigest()
    assert plan["destinations"] == (("1.1.1.1", 8008), ("8.8.8.8", 443),
                                    ("2001:4860:4860::8888", 443))
    rules = plan["nft_candidate"]
    assert "policy drop;" in rules and "ct state related" not in rules
    assert "meta skuid 987 ip daddr 1.1.1.1 tcp dport 8008 ct state new accept" in rules
    assert "meta skuid 987 ip6 daddr 2001:4860:4860::8888 tcp dport 443" in rules
    assert "meta skuid 987 ip daddr 1.1.1.1 tcp dport 443" not in rules
    assert "meta skuid 987 ip daddr 8.8.8.8 tcp dport 8008" not in rules
    assert "9.9.9.9" not in rules
    assert 'meta skuid 0 oifname "lo"' in rules
    assert not plan["authorizes_firewall_change"] and not plan["runtime_egress_verified"]
    doc, raw = fixture(both=False)
    next_plan = render_namespace_egress_candidate(
        doc, generation=1, http_fragment=raw, worker_uid=987)
    assert "1.1.1.1" not in next_plan["nft_candidate"]


@pytest.mark.parametrize("fault", [
    "wrong-port", "private", "duplicate", "extra-directive", "missing",
    "foreign-group", "wrong-family", "noncanonical", "extra-group", "stale",
])
def test_refuse_noncanonical_or_unapproved_egress(fault):
    doc, raw = fixture()
    generation = 1
    if fault == "wrong-port":
        raw = raw.replace(b"8.8.8.8:443;", b"8.8.8.8:8008;")
    elif fault == "private":
        raw = raw.replace(b"8.8.8.8:443;", b"127.0.0.1:443;")
    elif fault == "duplicate":
        raw = raw.replace(b"    server 8.8.8.8:443;\n",
                          b"    server 8.8.8.8:443;\n    server 8.8.8.8:443;\n")
    elif fault == "extra-directive":
        raw += b"resolver 8.8.8.8;\n"
    elif fault == "missing":
        raw = b""
    elif fault == "foreign-group":
        raw = raw.replace(b"repocache_pin_repo_0", b"repocache_pin_foreign")
    elif fault == "wrong-family":
        raw = raw.replace(b"8.8.8.8:443;", b"[8.8.8.8]:443;")
    elif fault == "noncanonical":
        raw = raw.replace(b":443;", b":00443;")
    elif fault == "extra-group":
        raw += raw
    else:
        generation = 2
    with pytest.raises(NativeEgressCandidateError, match="NATIVE_EGRESS_CANDIDATE_INVALID"):
        derive_pinned_egress_candidate(doc, generation=generation, http_fragment=raw)


@pytest.mark.parametrize("uid", [0, -1, 2**31, True, "987"])
def test_invalid_worker_identity(uid):
    doc, raw = fixture()
    with pytest.raises(NativeEgressCandidateError, match="NATIVE_EGRESS_WORKER_UID_INVALID"):
        render_namespace_egress_candidate(doc, generation=1, http_fragment=raw, worker_uid=uid)


def test_inactive_generation_has_no_worker_connections():
    doc = document(count=1, generation=1)
    doc["repositories"][0]["desired_state"] = "disabled"
    plan = render_namespace_egress_candidate(doc, generation=1, http_fragment=b"", worker_uid=987)
    assert plan["destinations"] == ()
    assert "meta skuid 987" not in plan["nft_candidate"]
