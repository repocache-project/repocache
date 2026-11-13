"""Closed NGINX managed metrics logrotate candidate policy and refusals."""
import json
from copy import deepcopy
from pathlib import Path

import pytest

from repocache.server_native_metrics_logrotate_candidate_v1 import (
    NativeMetricsRotationCandidateError,
    render_native_metrics_rotation_candidate,
)

EXAMPLE=Path(__file__).resolve().parents[1]/"docs/examples/server-install-v1.json"


def doc(enabled=True,days=7):
    x=json.loads(EXAMPLE.read_text())
    x["deployment"]["logging"]["metrics_opt_in"]=enabled
    x["deployment"]["logging"]["retention_days"]=days
    return x


def test_fixed_root_only_non_authorizing_rotation():
    x=doc()
    before=deepcopy(x)
    out=render_native_metrics_rotation_candidate(x)
    assert x==before
    assert out["enabled"] is True
    assert out["retention_days"] == 7
    assert out["rotation_candidate"].startswith(
        "/var/log/nginx/repocache-managed/metrics.jsonl {\n"
    )
    for expected in (
        "    daily\n", "    rotate 7\n", "    create 0600 root root\n",
        "    compress\n", "    delaycompress\n", "    notifempty\n",
        "    postrotate\n",
        "/usr/bin/systemctl kill --kill-who=main --signal=USR1 nginx.service",
    ):
        assert expected in out["rotation_candidate"]
    for field in ("authorizes_logrotate_installation","authorizes_nginx_signal",
                  "actual_nginx_reopen_verified","live_log_retention_verified"):
        assert out[field] is False


def test_logging_optout_has_no_rotation_profile():
    out=render_native_metrics_rotation_candidate(doc(enabled=False))
    assert out["rotation_candidate"] == ""
    assert out["retention_days"] is None
    assert not out["requires_authenticated_root_install"]


@pytest.mark.parametrize("days",[0,-1,3651,True,1.0,"7",None])
def test_bad_retention_rejected_by_install_v1_schema(days):
    with pytest.raises(NativeMetricsRotationCandidateError,
                       match="METRICS_ROTATION_DOCUMENT_INVALID"):
        render_native_metrics_rotation_candidate(doc(days=days))


@pytest.mark.parametrize("enabled",[None,1,0,"true",{},[]])
def test_bad_optin_refused(enabled):
    with pytest.raises(NativeMetricsRotationCandidateError):
        render_native_metrics_rotation_candidate(doc(enabled=enabled))


def test_alternate_operator_path_never_enters_generated_logrotate_text():
    x=doc()
    x["deployment"]["paths"]["log_root"]="/tmp/foreign"
    with pytest.raises(NativeMetricsRotationCandidateError):
        render_native_metrics_rotation_candidate(x)


def test_no_invocations_or_root_worker_in_source():
    from repocache import server_native_metrics_logrotate_candidate_v1 as mod
    import inspect
    text=inspect.getsource(mod)
    for bad in ("subprocess", "os.open(", "os.unlink(", "shell=True", "os.system"):
        assert bad not in text
