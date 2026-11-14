"""Read-only observation of packaged /usr/sbin/nginx ownership (#27).

Never treat package-database ownership as signature trust, installed-host
identity, service ownership, operator consent or permission to provision.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

_NGINX = "/usr/sbin/nginx"
_MANAGERS = {
    "debian13": ["/usr/bin/dpkg-query", "-S", _NGINX],
    "almalinux10": ["/usr/bin/rpm", "-qf", "--queryformat=%{NAME}\n", _NGINX],
}
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
_MAX_RESULT = 2048


class StockNginxPackageOwnerError(ValueError):
    """Redacted error code, never a package-manager diagnostic."""


def _deny(reason: str) -> None:
    raise StockNginxPackageOwnerError("NATIVE_NGINX_OWNER_" + reason)


def _platform(release: str) -> str:
    if type(release) is not str or len(release) > 16384 or "\x00" in release:
        _deny("OS_UNVERIFIED")
    found: dict[str, str] = {}
    for raw in release.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            _deny("OS_UNVERIFIED")
        name, value = line.split("=", 1)
        if name not in ("ID", "VERSION_ID"):
            continue
        if name in found:
            _deny("OS_UNVERIFIED")
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        if re.fullmatch(r"[A-Za-z0-9.]+", value, re.ASCII) is None:
            _deny("OS_UNVERIFIED")
        found[name] = value
    if found == {"ID": "debian", "VERSION_ID": "13"}:
        return "debian13"
    if found.get("ID") == "almalinux" and re.fullmatch(
        r"10(?:\.[0-9]+)?", found.get("VERSION_ID", ""), re.ASCII
    ):
        return "almalinux10"
    _deny("OS_UNSUPPORTED")


def _safe_binary() -> tuple[int, ...]:
    try:
        result = os.lstat(_NGINX)
    except OSError:
        _deny("BINARY_UNVERIFIED")
    if (not stat.S_ISREG(result.st_mode) or result.st_uid != 0
            or result.st_mode & 0o022
            or not result.st_mode & 0o111
            or result.st_nlink != 1
            or result.st_size < 1024):
        _deny("BINARY_UNTRUSTED")
    return (result.st_dev, result.st_ino, result.st_mode,
            result.st_uid, result.st_gid, result.st_nlink,
            result.st_size, result.st_mtime_ns, result.st_ctime_ns)


def _owner(platform: str, output: str) -> str:
    if (type(platform) is not str or platform not in _MANAGERS
            or type(output) is not str or not 1 <= len(output) <= _MAX_RESULT):
        _deny("PACKAGE_DB_UNVERIFIED")
    lines = [row.strip() for row in output.splitlines() if row.strip()]
    if len(lines) != 1:
        _deny("PACKAGE_DB_UNVERIFIED")
    if platform == "almalinux10":
        if lines[0] != "nginx-core":
            _deny("FOREIGN_PACKAGE")
        # AlmaLinux's official nginx metapackage installs the nginx-core
        # payload, which owns /usr/sbin/nginx. Never accept arbitrary forks.
        return "nginx-core"
    if ": " not in lines[0]:
        _deny("PACKAGE_DB_UNVERIFIED")
    package, path = lines[0].rsplit(": ", 1)
    if (path != _NGINX
            or re.fullmatch(r"nginx(?::[a-z0-9-]+)?", package, re.ASCII) is None):
        _deny("FOREIGN_PACKAGE")
    return "nginx"


def inspect_stock_nginx_package_owner() -> dict[str, Any]:
    """Confirm a fixed executable belongs to the expected native package.

    Caller-controlled paths, package names and command options are forbidden.
    This cannot detect a compromised package DB or attest signed payloads.
    """
    try:
        release = Path("/etc/os-release").read_text(encoding="utf-8")
        platform = _platform(release)
        before = _safe_binary()
        proc = subprocess.run(
            _MANAGERS[platform], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            check=False, timeout=12, env=_ENV, cwd="/",
        )
        if (type(proc.returncode) is not int or proc.returncode != 0
                or type(proc.stdout) is not str
                or len(proc.stdout) > _MAX_RESULT):
            _deny("PACKAGE_DB_UNVERIFIED")
        package = _owner(platform, proc.stdout)
        if _safe_binary() != before:
            _deny("BINARY_CHANGED")
    except StockNginxPackageOwnerError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError,
            subprocess.SubprocessError):
        _deny("OBSERVATION_UNVERIFIED")
    return {
        "schema_version": 1,
        "status": "READ_ONLY_STOCK_NGINX_PACKAGE_OWNER_OBSERVED",
        "platform": platform,
        "package_name": package,
        "binary_path": _NGINX,
        "native_package_db_owner_observed": True,
        "native_package_signature_verified": False,
        "package_manager_sources_verified": False,
        "installed_host_root_authenticated": False,
        "nginx_service_unit_verified": False,
        "selinux_enforcing_verified": False,
        "authorizes_package_installation": False,
        "authorizes_nginx_reload": False,
        "authorizes_nginx_adoption": False,
    }


def main() -> int:
    import sys
    try:
        observed = inspect_stock_nginx_package_owner()
    except StockNginxPackageOwnerError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(observed, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
