#!/usr/bin/env python3
"""Stock distro logrotate end-to-end on *disposable* root-only files (#29).

Only the candidate's fixed file token and the systemd reopen hook are
replaced in this test harness: no NGINX signal, host log or source is touched.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile

from repocache.core import Settings, metrics
from repocache.server_native_metrics_logrotate_candidate_v1 import (
    render_native_metrics_rotation_candidate,
)

_MANAGED="/var/log/nginx/repocache-managed/metrics.jsonl"
_REOPEN="/usr/bin/systemctl kill --kill-who=main --signal=USR1 nginx.service"
_ROUTE="/__repocache/repos/debian-trixie-main/"


def main() -> None:
    assert os.geteuid() == 0 and Path("/.dockerenv").is_file()
    assert os.environ.get("REPOCACHE_DISPOSABLE_NATIVE_CI") == "1"
    doc=json.loads(Path("/repo/docs/examples/server-install-v1.json").read_text())
    doc["deployment"]["logging"]["metrics_opt_in"]=True
    doc["deployment"]["logging"]["retention_days"]=3
    candidate=render_native_metrics_rotation_candidate(doc)
    assert candidate["requires_exact_vendor_nginx_unit"]
    assert not candidate["authorizes_logrotate_installation"]
    with tempfile.TemporaryDirectory(prefix="repocache-logrotate-v06-") as tmp:
        root=Path(tmp)
        log=root/"metrics.jsonl"
        conf=root/"logrotate.conf"
        state=root/"logrotate.state"
        source=candidate["rotation_candidate"]
        assert source.count(_MANAGED)==1 and source.count(_REOPEN)==1
        # Explicitly *test-only* substitutions; never deploy or invoke
        # production systemd from a disposable CI rotation exercise.
        private=source.replace(_MANAGED,str(log)).replace(_REOPEN,"/bin/true")
        conf.write_text(private)
        def write_one(status):
            record={
                "time_iso8601":datetime.now(timezone.utc).isoformat(),
                "repocache_repository":_ROUTE,
                "status":str(status),
                "upstream_cache_status":"HIT",
                "body_bytes_sent":"12",
                "request_time":"0.001",
            }
            with log.open("a",encoding="utf-8") as out:
                out.write(json.dumps(record)+"\n")
        def rotate():
            run=subprocess.run(
                ["logrotate","--force","--state",str(state),str(conf)],
                capture_output=True,check=False,timeout=20,
            )
            assert run.returncode == 0, "PRIVATE_NATIVE_LOGROTATE_FAILED"
        write_one(200)
        rotate()
        assert log.exists() and log.stat().st_size == 0
        assert (log.stat().st_mode & 0o777)==0o600
        assert (root/"metrics.jsonl.1").exists()
        write_one(201)
        rotate()
        assert (root/"metrics.jsonl.2.gz").is_file()
        write_one(202)
        observed=metrics(Settings(metrics_log=log),hours=1,
                         repo=_ROUTE,now=datetime.now(timezone.utc))
        assert observed["available"] and observed["requests"]==3
        assert observed["history_files_read"]==3
        assert observed["bytes_sent"]==36
        assert observed["cache_observed"]==3 and observed["hit"]==3
        assert observed["rotation_incomplete"] is False
        print("PASS: native logrotate preserved two archived plus current "
              "privacy-limited NGINX metric records",flush=True)
    print("PASS: no installed host logging, systemctl signal or deletion",flush=True)


if __name__ == "__main__":
    main()
