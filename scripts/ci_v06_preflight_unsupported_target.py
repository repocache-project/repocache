"""Test the normal read-only preflight in genuine unsupported distro CI images."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
PROTECTED = (Path("/etc/nginx"), Path("/var/lib/repocache"),
             Path("/etc/apt"), Path("/etc/yum.repos.d"))


def snapshot():
    """Compare bounded metadata only; do not read or disclose host contents."""
    result = {}
    for root in PROTECTED:
        paths = [root]
        if root.is_dir() and not root.is_symlink():
            paths.extend(root.rglob("*"))
        if len(paths) > 2048:
            raise ValueError("unexpected disposable test inventory")
        for path in paths:
            try:
                value = path.lstat()
            except FileNotFoundError:
                result[str(path)] = None
                continue
            result[str(path)] = (value.st_dev, value.st_ino, value.st_mode,
                                 value.st_uid, value.st_gid, value.st_nlink,
                                 value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    return result


def main() -> int:
    # Explicitly disposable job image only, no installation or service command.
    if not Path("/.dockerenv").is_file():
        raise ValueError("disposable container required")
    before = snapshot()
    for intent in ("inspect", "install"):
        result = subprocess.run(
            ["/usr/bin/python3", "-I", "-B", str(ROOT / "scripts/server_v06_preflight.py"),
             "--document", str(ROOT / "docs/examples/server-install-v1.json"), "--intent", intent],
            cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False,
        )
        if result.returncode != 1 or result.stderr or len(result.stdout) > 65536:
            raise ValueError("unsupported target did not return a normal refusal")
        report = json.loads(result.stdout)
        checks = {row["check"]: row for row in report["checks"]}
        if (report["status"] != "FAIL" or report["read_only"] is not True
                or report["authorizes_installation"] is not False
                or checks["supported_os_and_python"]["code"] != "UNSUPPORTED_OS_OR_PYTHON"
                or checks["supported_os_and_python"]["status"] != "FAIL"
                or checks["native_package_manager_binary"]["status"] != "NOT VERIFIED"
                or checks["native_python_identity"]["status"] != "NOT VERIFIED"
                or any(name in checks for name in ("nginx_native_binary", "storage_free_space",
                                                  "systemd_binary", "tls_reference_files"))
                or snapshot() != before):
            raise ValueError("unsupported target preflight evidence incomplete")
    print("PASS: actual unsupported distro refused for inspect and install; protected paths unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
