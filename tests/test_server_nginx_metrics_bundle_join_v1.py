"""Integration between canonical pinned NGINX routes and opt-in metrics."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from repocache.server_nginx_metrics_bundle_join_v1 import (
    JoinedNginxCandidateError, render_repository_nginx_metrics_join,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
CA = "/etc/ssl/certs/ca-certificates.crt"


def fixture(opt_in=True, apt=True, dnf=True):
    doc = json.loads(EXAMPLE.read_text())
    doc["deployment"]["logging"]["metrics_opt_in"] = opt_in
    for r in doc["repositories"]:
        r["desired_state"] = "active" if ((r["kind"] == "apt" and apt)
                                           or (r["kind"] == "dnf" and dnf)) else "disabled"
        if r["kind"] == "dnf":
            r["id"] = "almalinux-baseos"
    pins = {r["id"]: {"mirror.example.invalid": ["8.8.8.8"]}
            for r in doc["repositories"] if r["desired_state"] == "active"}
    return doc, pins


def joined(doc, pins, **kw):
    return render_repository_nginx_metrics_join(
        doc, expected_state_generation=0,
        candidate_pins_by_repository=pins, ca_bundle_path=CA, **kw,
    )


def test_real_route_location_join_and_no_independent_locations():
    doc, pins = fixture()
    before = deepcopy(doc), deepcopy(pins)
    a = joined(doc, pins)
    b = joined(doc, pins)
    assert a == b
    assert (doc, pins) == before
    assert a["metrics_repository_ids"] == a["proposed_repository_ids"]
    assert a["http_fragment"].count("log_format repocache_metrics") == 1
    assert a["server_fragment"].count("location ^~ /__repocache/repos/") == 2
    assert a["server_fragment"].count('set $repocache_metric_repo "') == 2
    assert a["server_fragment"].count("access_log /var/log/nginx/repocache-managed/metrics.jsonl") == 2
    assert not a["authorizes_nginx_activation"]
    assert not a["authorizes_catalog_publication"]
    assert not a["trusted_active_state_verified"]
    assert not a["audited_existing_access_log_inheritance"]


def test_disabled_routes_absent_even_with_logging_opt_in():
    d,p = fixture(apt=False)
    a=joined(d,p)
    assert a["metrics_repository_ids"] == ["almalinux-baseos"]
    assert "debian-trixie-main" not in a["server_fragment"]
    d,p = fixture(apt=False,dnf=False)
    b=joined(d,p)
    assert b["server_fragment"] == ""
    assert b["http_fragment"] == ""


def test_opt_out_retains_only_routes_no_logging():
    d,p=fixture(opt_in=False)
    a=joined(d,p)
    assert a["metrics_repository_ids"] == []
    assert "access_log " not in a["server_fragment"]
    assert "log_format repocache_metrics" not in a["http_fragment"]
    assert a["server_fragment"].count("location ^~ /__repocache/repos/") == 2


@pytest.mark.parametrize("bad",[
    {"debian-trixie-main":{"mirror.example.invalid":["127.0.0.1"]}},
    {}, None, [], {"unexpected":{"mirror.example.invalid":["8.8.8.8"]}},
])
def test_missing_untrusted_or_unapproved_pin_refused(bad):
    d,_=fixture()
    with pytest.raises(JoinedNginxCandidateError,match="JOINED_NGINX_INPUT_INVALID"):
        joined(d,bad)


def test_generation_changed_refused():
    d,p=fixture()
    d["expected_state_generation"]=2
    with pytest.raises(JoinedNginxCandidateError,match="JOINED_NGINX_INPUT_INVALID"):
        joined(d,p)


def test_no_arbitrary_nginx_network_or_host_mutation():
    import inspect
    from repocache import server_nginx_metrics_bundle_join_v1 as mod
    text=inspect.getsource(mod)
    for banned in ("subprocess", "os.open(", "socket.", "nginx -s", "systemctl"):
        assert banned not in text
