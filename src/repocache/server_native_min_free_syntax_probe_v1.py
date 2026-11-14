"""Disposable stock-NGINX min_free syntax capability observation (#97).

Executable tests may run ONLY as a non-root user in an explicitly marked
disposable container. No installed host/root observer, no package operation,
network request, NGINX reload, service change, live cache mutation or source
of activation authority is provided.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

_SAFE_TMP = re.compile(r"/tmp/repocache-minfree-[A-Za-z0-9_-]+\Z", re.ASCII)
_RUNTIME_ENV = "REPOCACHE_DISPOSABLE_NGINX_MIN_FREE_PROBE"
_TIMEOUT = 12


class NativeMinFreeProbeError(ValueError):
    """Fixed and non-disclosing refusal codes for the disposable probe."""


def _deny(code: str) -> None:
    raise NativeMinFreeProbeError("NATIVE_MIN_FREE_" + code)


def _config(scratch: Path, *, min_free: bool) -> bytes:
    """Fixed NGINX syntax-only configuration, not an install candidate."""
    if (type(scratch) is not type(Path('/tmp'))
            or _SAFE_TMP.fullmatch(str(scratch)) is None
            or type(min_free) is not bool):
        _deny("ARGUMENT_INVALID")
    cache = scratch / "cache"
    if min_free:
        extra = " min_free=1m"
    else:
        extra = ""
    content = (
        f"pid {scratch}/nginx.pid;\n"
        "worker_processes 1;\n"
        f"error_log {scratch}/error.log crit;\n"
        "events { worker_connections 16; }\n"
        "http {\n"
        f"proxy_temp_path {scratch}/temp;\n"
        f"proxy_cache_path {cache} levels=1:2 keys_zone=probe_zone:1m "
        f"inactive=60s max_size=4m{extra} use_temp_path=off;\n"
        "server { listen 127.0.0.1:18585; "
        "location = /__probe { return 200; } }\n"
        "}\n"
    )
    raw = content.encode("ascii")
    if len(raw) > 2048:
        _deny("CONFIG_OVERSIZE")
    return raw


def _read_os_platform() -> str:
    """Inspect only local container release identity; no host provenance."""
    try:
        text = Path("/etc/os-release").read_text(encoding="ascii")
    except (OSError, UnicodeError, ValueError):
        _deny("CONTAINER_IDENTITY_UNVERIFIED")
    pairs = {}
    for line in text.splitlines():
        if line.startswith(("ID=", "VERSION_ID=")):
            key, value = line.split("=", 1)
            if (key in pairs or not value
                    or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.\""
                           for c in value)):
                _deny("CONTAINER_IDENTITY_UNVERIFIED")
            pairs[key] = value.strip('"')
    if pairs == {"ID": "debian", "VERSION_ID": "13"}:
        return "debian13"
    if (pairs.get("ID") == "almalinux" and
            re.fullmatch(r"10(?:\.[0-9]+)?", pairs.get("VERSION_ID", ""), re.ASCII)
            and len(pairs) == 2):
        return "almalinux10"
    _deny("UNSUPPORTED_CONTAINER")


def _run_syntax(nginx: str, scratch: Path, config: Path) -> bool:
    """Return fixed-command syntax test result without decoding error text."""
    if type(nginx) is not str or nginx not in (
        "/usr/sbin/nginx", "/sbin/nginx", "/usr/bin/nginx",
    ):
        _deny("NGINX_PATH_UNVERIFIED")
    args = [nginx, "-t", "-p", str(scratch), "-c", str(config)]
    try:
        result = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False, timeout=_TIMEOUT,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        _deny("SYNTAX_EXECUTION_UNVERIFIED")
    return type(result.returncode) is int and result.returncode == 0


def _observed(platform: str, baseline: bool,
              min_free_syntax: bool) -> dict[str, Any]:
    """Keep a syntax rejection distinct from an authenticated capability."""
    if (platform not in ("debian13", "almalinux10")
            or type(baseline) is not bool
            or type(min_free_syntax) is not bool):
        _deny("OBSERVATION_INVALID")
    if not baseline:
        _deny("BASELINE_SYNTAX_UNVERIFIED")
    return {
        "schema_version": 1,
        "status": ("MIN_FREE_DISPOSABLE_SYNTAX_ACCEPTED" if min_free_syntax
                   else "MIN_FREE_DISPOSABLE_SYNTAX_NOT_ACCEPTED"),
        "platform": platform,
        "stock_nginx_baseline_syntax_accepted": True,
        "native_min_free_syntax_accepted": min_free_syntax,
        "native_package_signature_verified": False,
        "installed_host_nginx_identity_verified": False,
        "native_min_free_supported_on_host_verified": False,
        "selinux_enforcing_verified": False,
        "operator_approval_verified": False,
        "authorizes_enable_min_free_on_host": False,
        "authorizes_nginx_reload": False,
        "authorizes_cache_mutation": False,
        "authorizes_firewall_change": False,
    }


def probe_disposable_native_min_free() -> dict[str, Any]:
    """Run both actual syntax tests, without starting NGINX or opening ports.

    Only a separately authenticated installed root worker could use a
    supported native feature at activation. The boolean in this report is
    restricted to the specific disposable NGINX binary used for the test.
    """
    if (os.geteuid() == 0
            or os.environ.get(_RUNTIME_ENV) != "1"
            or not Path("/.dockerenv").is_file()):
        _deny("DISPOSABLE_NONROOT_REQUIRED")
    platform = _read_os_platform()
    binary = shutil.which("nginx")
    if binary not in ("/usr/sbin/nginx", "/sbin/nginx", "/usr/bin/nginx"):
        _deny("NGINX_PATH_UNVERIFIED")
    try:
        with tempfile.TemporaryDirectory(
            prefix="repocache-minfree-", dir="/tmp",
        ) as directory:
            scratch = Path(directory)
            if _SAFE_TMP.fullmatch(str(scratch)) is None:
                _deny("SCRATCH_PATH_INVALID")
            for part in ("cache", "temp"):
                (scratch / part).mkdir(mode=0o700)
            config = scratch / "nginx.conf"
            config.write_bytes(_config(scratch, min_free=False))
            if not _run_syntax(binary, scratch, config):
                _deny("BASELINE_SYNTAX_UNVERIFIED")
            config.write_bytes(_config(scratch, min_free=True))
            return _observed(
                platform, True, _run_syntax(binary, scratch, config),
            )
    except NativeMinFreeProbeError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        _deny("SCRATCH_IO_UNVERIFIED")


def main() -> int:
    """Explicitly gated disposable CI observation; never operator control."""
    import json
    import sys
    try:
        result = probe_disposable_native_min_free()
    except NativeMinFreeProbeError as error:
        print("REFUSED: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
