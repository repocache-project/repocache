#!/usr/bin/env python3
"""Actual native nginx -T for #97 observed pressure -> cache bypass recovery.

Uses approved pure policy and NGINX bundle renderers, no installed reload.
Only rootless disposable Debian13/AlmaLinux10 distro containers.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from repocache.server_cache_bypass_decision_v1 import (
    CachePressureBypassError, preview_cache_pressure_nginx_recovery_candidate,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)

ROOT = Path(__file__).resolve().parents[1]
HOST = "mirror.example.invalid"


def syntax(nginx: str, prefix: Path, result: dict) -> str:
    bundle = result["nginx_candidate"]
    for part in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        (prefix / part).mkdir(mode=0o700, exist_ok=True)
    config = (
        f"pid {prefix / 'nginx.pid'};\n"
        f"error_log {prefix / 'nginx.log'} notice;\n"
        "worker_processes 1;\nevents { worker_connections 64; }\n"
        "http {\naccess_log off;\n"
        + "".join(f"{part}_temp_path {prefix / part};\n"
                  for part in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        + bundle["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19217;\n"
        + bundle["server_location_fragment"]
        + "}\n}\n"
    )
    conf = prefix / "nginx.conf"
    conf.write_text(config, encoding="ascii")
    command = [nginx, "-T", "-p", str(prefix), "-c", str(conf)]
    check = subprocess.run(command, text=True, capture_output=True,
                           check=False, timeout=12)
    assert check.returncode == 0, "STOCK_NGINX_PRESSURE_CONFIG_REFUSED"
    assert not result["authorizes_nginx_reload"]
    assert not result["authorizes_catalog_publication"]
    return check.stdout


def main() -> None:
    if (os.geteuid() == 0 or not Path("/.dockerenv").is_file()
            or os.environ.get("REPOCACHE_DISPOSABLE_NGINX_SMOKE") != "1"):
        raise RuntimeError("DISPOSABLE_NONROOT_ONLY")
    nginx = shutil.which("nginx")
    assert nginx == "/usr/sbin/nginx"
    ca = next((x for x in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(x).is_file()), None)
    assert ca
    doc = json.loads((ROOT / "docs/examples/server-install-v1.json").read_text())
    for item in doc["repositories"]:
        item["desired_state"] = "active"
        if item["kind"] == "dnf":
            item["id"] = "almalinux-baseos"
    ids = sorted(item["id"] for item in doc["repositories"])
    assert len(ids) == 2
    pins = {rid: {HOST: ["8.8.8.8"]} for rid in ids}
    policy = doc["deployment"]["cache_policy"]["disk_pressure"]
    warning = policy["warning_free_bytes"]
    critical = policy["critical_free_bytes"]
    margin = 4096
    with tempfile.TemporaryDirectory(prefix="repocache-pressure-native-") as tmp:
        root = Path(tmp)
        cache = root / "cache"
        cache.mkdir(mode=0o700)
        doc["deployment"]["paths"]["cache_root"] = str(cache)
        for rid in ids:
            (cache / rid).mkdir(mode=0o700)
        raw_normal = render_repository_nginx_bundle_candidate(
            doc, expected_state_generation=0, candidate_pins_by_repository=pins,
            ca_bundle_path=ca,
        )
        def decide(free, *, old=None, bypass=(), complete=True):
            return preview_cache_pressure_nginx_recovery_candidate(
                doc, expected_state_generation=0,
                candidate_pins_by_repository=pins, ca_bundle_path=ca,
                free_bytes=free, free_inodes=256 if complete else None,
                disk_writable=True if complete else None,
                measurements_complete=complete, recovery_margin_bytes=margin,
                previous_alarm=old, previously_bypassed_ids=bypass,
            )
        healthy = decide(warning + margin + 1)
        assert healthy["bypass_repository_ids"] == []
        assert healthy["nginx_candidate"] == raw_normal
        syntax(nginx, root, healthy)
        critical_case = decide(critical)
        assert critical_case["decision_code"] == "PROPOSE_BYPASS_ON_OBSERVED_CRITICAL"
        assert critical_case["bypass_repository_ids"] == ids
        assert critical_case["nginx_candidate"]["http_upstream_fragment"] == raw_normal[
            "http_upstream_fragment"
        ]
        assert critical_case["nginx_candidate"]["server_location_fragment"].count(
            "    proxy_cache off;"
        ) == len(ids)
        syntax(nginx, root, critical_case)

        stale = decide(None, complete=False,
                       old=critical_case["alarm_candidate"]["next_state"],
                       bypass=tuple(ids))
        assert stale["decision_code"] == "HOLD_LAST_BYPASS_WHILE_NOT_RECOVERED"
        assert stale["bypass_repository_ids"] == ids
        assert stale["nginx_candidate"]["server_location_fragment"] == critical_case[
            "nginx_candidate"
        ]["server_location_fragment"]
        syntax(nginx, root, stale)

        warning_case = decide(warning,
                              old=stale["alarm_candidate"]["next_state"],
                              bypass=tuple(ids))
        assert warning_case["bypass_repository_ids"] == ids
        syntax(nginx, root, warning_case)
        recovered = decide(warning + margin + 1,
                           old=warning_case["alarm_candidate"]["next_state"],
                           bypass=tuple(ids))
        assert recovered["decision_code"] == "PROPOSE_RESTORE_AFTER_VERIFIED_RECOVERY"
        assert recovered["bypass_repository_ids"] == []
        assert recovered["nginx_candidate"] == raw_normal
        syntax(nginx, root, recovered)
        try:
            decide(-1)
        except CachePressureBypassError:
            pass
        else:
            raise AssertionError("UNTRUSTED_NEGATIVE_FREE_SPACE_ACCEPTED")
        for result in (healthy, critical_case, stale, warning_case, recovered):
            for field in ("authorizes_nginx_policy_apply",
                          "authorizes_nginx_reload",
                          "authorizes_cache_cleanup",
                          "authorizes_catalog_publication",
                          "authorizes_client_fallback_apply"):
                assert result[field] is False
        print("PASS: stock nginx -T accepts actual alarm-derived normal, "
              "critical bypass, stale hold, warning hold and recovered candidates")
        print("NOT VERIFIED: authenticated telemetry, actual cache manager, "
              "host reload/systemd/SELinux or signed APT/DNF fallback")


if __name__ == "__main__":
    main()
