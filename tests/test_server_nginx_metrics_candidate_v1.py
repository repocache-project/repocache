"""Opt-in NGINX metrics candidates tied to validated repository state (#29)."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from repocache.server_nginx_metrics_candidate_v1 import (
    METRICS_LOG, NginxMetricsCandidateError,
    render_nginx_metrics_candidate,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document(*, enabled=True, apt_active=True, dnf_active=True):
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc["deployment"]["logging"]["metrics_opt_in"] = enabled
    doc["repositories"][0]["desired_state"] = (
        "active" if apt_active else "disabled"
    )
    doc["repositories"][1]["id"] = "almalinux-baseos"
    doc["repositories"][1]["desired_state"] = (
        "active" if dnf_active else "disabled"
    )
    return doc


def test_explicit_opt_in_only_for_active_repositories_and_no_credentials():
    doc = document()
    before = deepcopy(doc)
    output = render_nginx_metrics_candidate(doc)
    assert doc == before
    assert output["opt_in_requested"]
    assert output["metrics_path_candidate"] == METRICS_LOG
    assert list(output["location_directives_by_repository"]) == [
        "almalinux-baseos", "debian-trixie-main"
    ]
    assert output["http_log_format_fragment"].count("log_format repocache_metrics") == 1
    assert "escape=json" in output["http_log_format_fragment"]
    for repo_id, lines in output["location_directives_by_repository"].items():
        assert lines == (
            f'set $repocache_metric_repo "/__repocache/repos/{repo_id}/";\n'
            f"access_log {METRICS_LOG} repocache_metrics;\n"
        )
    combined = output["http_log_format_fragment"] + "".join(
        output["location_directives_by_repository"].values()
    )
    for forbidden in ("$request_uri", "$uri", "$remote_addr", "$http_cookie",
                      "$http_authorization", "$args", "$query_string",
                      "$http_user_agent", "$request", "Authorization"):
        assert forbidden not in combined
    for name in ("audit_logging_inheritance_verified", "nginx_syntax_verified",
                 "active_exposure_verified", "managed_log_ownership_verified",
                 "authorizes_nginx_activation", "authorizes_catalog_publication"):
        assert output[name] is False


@pytest.mark.parametrize("apt,dnf", [
    (False, True), (True, False), (False, False)
])
def test_disabled_repositories_not_logged_or_advertised(apt, dnf):
    out = render_nginx_metrics_candidate(
        document(apt_active=apt, dnf_active=dnf)
    )
    assert len(out["location_directives_by_repository"]) == int(apt)+int(dnf)
    assert ("debian-trixie-main" in out["location_directives_by_repository"]) == apt
    assert ("almalinux-baseos" in out["location_directives_by_repository"]) == dnf
    assert not out["authorizes_catalog_publication"]
    if not apt and not dnf:
        assert out["http_log_format_fragment"] == ""
        assert out["metrics_path_candidate"] is None


def test_default_opt_out_emits_no_format_no_directives():
    out = render_nginx_metrics_candidate(document(enabled=False))
    assert not out["opt_in_requested"]
    assert not out["location_directives_by_repository"]
    assert out["http_log_format_fragment"] == ""
    assert out["metrics_path_candidate"] is None
    assert not out["authorizes_nginx_activation"]


@pytest.mark.parametrize("bad", [None, 1, 0, "true", {}, []])
def test_non_boolean_opt_in_rejected_before_fragment_emission(bad):
    with pytest.raises(NginxMetricsCandidateError,
                       match="NGINX_METRICS_DOCUMENT_INVALID"):
        render_nginx_metrics_candidate(document(enabled=bad))


def test_unauthenticated_unallocated_active_repository_refused():
    doc = document()
    del doc["repositories"][1]["id"]
    with pytest.raises(NginxMetricsCandidateError, match="NGINX_METRICS_"):
        render_nginx_metrics_candidate(doc)


def test_static_test_does_not_install_logging_or_read_files():
    src = (EXAMPLE.parents[2] / "src/repocache/server_nginx_metrics_candidate_v1.py")
    text = src.read_text()
    for banned in ("subprocess", "os.open(", "os.unlink(", "os.chmod(",
                   "systemctl", "nginx -s", "shell=True"):
        assert banned not in text
    assert 'METRICS_LOG = "/var/log/nginx/repocache-managed/metrics.jsonl"' in text
