#!/usr/bin/env python3
"""Test stock NGINX cache-policy inheritance and min_free syntax (#97).

For disposable, unprivileged Debian 13 / AlmaLinux 10 Docker userspace only.
Only validates generated candidate bytes with native 'nginx -t'; it does not
reload any host NGINX, enforce live quotas, delete cache files or grant
server authorization. A real booted SELinux/systemd campaign remains #19.
"""
from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)

ROOT = Path(__file__).resolve().parents[1]
CACHE_LINE = re.compile(r"^proxy_cache_path (\S+) levels=1:2 "
    r"keys_zone=(repocache_cache_[a-z0-9_]+):1m "
    r"inactive=([0-9]+)s max_size=([0-9]+) use_temp_path=off;$")


def require_disposable() -> None:
    if (os.geteuid() == 0 or not Path("/.dockerenv").exists()
            or os.environ.get("REPOCACHE_DISPOSABLE_NGINX_SMOKE") != "1"):
        raise RuntimeError("Refuse to execute outside unprivileged disposable CI")


def checked_syntax(nginx: str, root: Path, http_fragment: str,
                   server_fragment: str) -> bool:
    conf = root / "policy.conf"
    # File is local temporary fixture material, not an installed NGINX path.
    conf.write_text(
        f"pid {root / 'nginx.pid'};\n"
        f"error_log {root / 'nginx-error.log'} notice;\n"
        "worker_processes 1;\n"
        "events { worker_connections 64; }\nhttp {\n"
        "access_log off;\n"
        + "".join(
            f"{name}_temp_path {root / name};\n"
            for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
        )
        + http_fragment
        + "\nserver { listen 127.0.0.1:18371;\n"
        + server_fragment
        + "\n}\n}\n",
        encoding="ascii",
    )
    result = subprocess.run(
        [nginx, "-t", "-p", str(root), "-c", str(conf)],
        check=False, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=20,
    )
    return result.returncode == 0


def main() -> None:
    require_disposable()
    nginx = shutil.which("nginx")
    if not nginx:
        raise AssertionError("Distribution-packaged nginx is required")
    ca = next((p for p in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(p).is_file()), None)
    if ca is None:
        raise AssertionError("Distribution CA bundle unavailable")

    with tempfile.TemporaryDirectory(prefix="repocache-nginx-policy-") as tmp:
        root = Path(tmp)
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (root / name).mkdir(mode=0o700)
        original = json.loads(
            (ROOT / "docs/examples/server-install-v1.json").read_text(
                encoding="utf-8"))
        original_snapshot = copy.deepcopy(original)
        items = original["repositories"]
        if len(items) != 2:
            raise AssertionError("Expected only two supported test repositories")
        for item in items:
            item["desired_state"] = "active"
            if item["kind"] == "dnf":
                item["id"] = "almalinux-baseos"
        # Exercise live override precedence using exactly the accepted v1
        # document format, not an independent cache-policy generator.
        apt = next(i for i in items if i["kind"] == "apt")
        dnf = next(i for i in items if i["kind"] == "dnf")
        apt["cache_overrides"] = {
            "inactive_seconds": 120,
            "max_size_bytes": 4 * 1024 * 1024,
        }
        assert dnf["cache_overrides"] == {}
        cache_root = root / "candidate_cache"
        original["deployment"]["paths"]["cache_root"] = str(cache_root)
        for item in items:
            (cache_root / item["id"]).mkdir(parents=True, mode=0o700)
        pins = {
            item["id"]: {"mirror.example.invalid": ["8.8.8.8"]}
            for item in items
        }
        bundle = render_repository_nginx_bundle_candidate(
            original, expected_state_generation=0,
            candidate_pins_by_repository=pins, ca_bundle_path=ca)
        assert bundle["authorizes_nginx_activation"] is False
        assert bundle["authorizes_catalog_publication"] is False

        fragment = bundle["http_upstream_fragment"]
        rules = [x.strip() for x in fragment.splitlines()
                 if x.strip().startswith("proxy_cache_path ")]
        if len(rules) != 2:
            raise AssertionError("Each active repository needs an isolated cache zone")
        observed = {}
        for item in rules:
            match = CACHE_LINE.fullmatch(item)
            if match is None:
                raise AssertionError("Unrecognized native stock cache policy")
            path, zone, inactive, capacity = match.groups()
            if not path.startswith(str(cache_root) + "/"):
                raise AssertionError("Cache path escaped disposable fixture")
            if zone in observed:
                raise AssertionError("Duplicate cache namespace")
            observed[zone] = (int(inactive), int(capacity))
        assert observed == {
            "repocache_cache_debian_trixie_main": (120, 4 * 1024 * 1024),
            "repocache_cache_almalinux_baseos": (
                original["deployment"]["cache_policy"]["global"]["inactive_seconds"],
                original["deployment"]["cache_policy"]["global"]["max_size_bytes"],
            ),
        }
        assert checked_syntax(
            nginx, root, fragment, bundle["server_location_fragment"])
        print("PASS: stock nginx -t validates independent inherited/overridden "
              "inactive and max_size directives", flush=True)

        # The *actual production renderer*, not a test-only string patch,
        # proposes min_free using the contract's validated critical threshold.
        # Positive nginx -t is still a disposable-binary observation, not a
        # trust assertion about an installed or subsequently upgraded host.
        min_free_bundle = render_repository_nginx_bundle_candidate(
            original, expected_state_generation=0,
            candidate_pins_by_repository=pins, ca_bundle_path=ca,
            native_min_free_supported=True,
        )
        critical = original["deployment"]["cache_policy"]["disk_pressure"][
            "critical_free_bytes"]
        enhanced = min_free_bundle["http_upstream_fragment"]
        assert enhanced.count(f" min_free={critical} ") == 2
        assert min_free_bundle["native_min_free_candidate_emitted"] is True
        assert min_free_bundle["native_min_free_supported_verified"] is False
        assert min_free_bundle["authorizes_nginx_activation"] is False
        assert " min_free=" not in fragment
        supported = checked_syntax(
            nginx, root, enhanced,
            min_free_bundle["server_location_fragment"],
        )
        if supported:
            print("PASS: stock nginx -t accepts strictly rendered critical "
                  "min_free threshold on this actual binary", flush=True)
        else:
            # Exact binary capability unsupported. Never silently promote the
            # enhanced candidate or claim pressure enforcement; the unchanged
            # legacy baseline is still a distinct syntactically valid fallback.
            assert checked_syntax(
                nginx, root, fragment, bundle["server_location_fragment"])
            print("NOT VERIFIED: min_free unsupported on this binary; "
                  "fallback candidate unchanged; no activation", flush=True)

        # An invalid native value must never be accepted or deployed.
        poisoned = fragment.replace(
            " use_temp_path=off;",
            " min_free=not_a_size use_temp_path=off;")
        assert poisoned != fragment
        assert not checked_syntax(
            nginx, root, poisoned, bundle["server_location_fragment"])
        assert checked_syntax(
            nginx, root, fragment, bundle["server_location_fragment"])
        print("PASS: malformed native capacity directive refused; "
              "previous candidate intact", flush=True)

        assert original_snapshot["repositories"][0]["desired_state"] == "disabled"
        assert bundle["authorizes_nginx_activation"] is False
        print("PASS: no host NGINX reload, cache policy activation or deletion",
              flush=True)


if __name__ == "__main__":
    main()
