#!/usr/bin/env python3
"""Distro-native NGINX worker cache write and root-only log owner test (#29).

Runs ONLY in an explicitly marked new disposable Debian/AlmaLinux container.
All writes happen below a temporary isolated fixture root; never the host /.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile

from repocache.server_install_v1 import validate_os_identity
from repocache.server_native_storage_bootstrap_v1 import (
    bootstrap_native_nginx_storage_under_root,
)
from repocache.server_cache_pressure_observe_v1 import (
    observe_cache_pressure_under_root,
)


def main() -> int:
    if (os.geteuid() != 0 or not Path("/.dockerenv").is_file()
            or os.environ.get("REPOCACHE_NATIVE_STORAGE_CI")
               != "CONFIRMED_DISPOSABLE_DOCKER_ONLY"
            or Path("/proc/1/comm").read_text(encoding="ascii").strip()
               == "systemd"):
        raise SystemExit("REFUSED: storage test requires disposable Docker")
    distro = validate_os_identity(
        Path("/etc/os-release").read_text("ascii"),
        sys.version_info[:2],
    )
    worker_name = {"debian": "www-data", "almalinux": "nginx"}[distro]
    worker = pwd.getpwnam(worker_name)
    if worker.pw_uid == 0 or worker.pw_gid == 0:
        raise SystemExit("REFUSED: distro NGINX worker is privileged")
    binary = os.lstat("/usr/sbin/nginx")
    if (not stat.S_ISREG(binary.st_mode) or binary.st_uid != 0
            or stat.S_IMODE(binary.st_mode) & 0o022):
        raise SystemExit("REFUSED: native NGINX package binary unsafe")
    subprocess.run(
        ["/usr/sbin/nginx", "-t", "-q"],
        check=True, capture_output=True, timeout=20,
    )
    with tempfile.TemporaryDirectory(prefix="repocache-distro-storage-") as tmp:
        root = Path(tmp)
        root.chmod(0o755)  # Temporary only: permit the unprivileged worker to traverse.
        for relative in ("var", "var/cache", "var/cache/nginx",
                         "var/log", "var/log/nginx"):
            (root / relative).mkdir(mode=0o755)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            kwargs = {
                "root_uid": 0, "cache_uid": worker.pw_uid,
                "cache_gid": worker.pw_gid,
            }
            first = bootstrap_native_nginx_storage_under_root(fd, **kwargs)
            assert first["cache_directory_created"]
            assert first["log_directory_created"]
            assert not first["authorizes_host_installation"]
            cache = root / "var/cache/nginx/repocache-managed"
            logs = root / "var/log/nginx/repocache-managed"
            # The process that serves requests (not root) must actually be
            # able to write its cache. It must NOT write root-operated logs.
            pid = os.fork()
            if pid == 0:
                try:
                    os.setgroups([])
                    os.setgid(worker.pw_gid)
                    os.setuid(worker.pw_uid)
                    (cache / "worker-package-cache-fixture").write_bytes(
                        b"immutable-Debian-Alma-disposable-test",
                    )
                    try:
                        (logs / "unexpected-worker-write").write_bytes(b"unsafe")
                    except PermissionError:
                        pass
                    else:
                        os._exit(10)
                except BaseException:
                    os._exit(11)
                os._exit(0)
            child, status = os.waitpid(pid, 0)
            assert child == pid and os.WIFEXITED(status)
            assert os.WEXITSTATUS(status) == 0
            existing = (cache / "worker-package-cache-fixture").read_bytes()
            assert existing == b"immutable-Debian-Alma-disposable-test"
            report = observe_cache_pressure_under_root(
                fd, root_uid=0, cache_uid=worker.pw_uid,
                warning_free_bytes=1_000_000,
                critical_free_bytes=500_000,
                recovery_margin_bytes=250_000,
                previous_level="unknown",
            )
            assert report["cache_root_ownership_observed"] is True
            assert report["authorizes_installation"] is False
            second = bootstrap_native_nginx_storage_under_root(fd, **kwargs)
            assert second["existing_cache_contents_preserved"]
            assert second["existing_log_contents_preserved"]
            assert not second["cache_directory_created"]
            assert not second["log_directory_created"]
            assert (cache / "worker-package-cache-fixture").read_bytes() == existing
            assert not (logs / "unexpected-worker-write").exists()
            print(json.dumps({
                "status": "DISPOSABLE_NATIVE_STORAGE_PASS",
                "distribution": distro,
                "native_nginx_worker": worker_name,
                "actual_native_worker_cache_write_passed": True,
                "root_only_log_dir_enforced": True,
                "ownership_marker_and_repeat_preservation_passed": True,
                "read_only_free_space_observation_passed": True,
                "booted_systemd_verified": False,
                "selinux_enforcing_verified": False,
                "authorizes_host_installation": False,
            }, sort_keys=True))
        finally:
            os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
