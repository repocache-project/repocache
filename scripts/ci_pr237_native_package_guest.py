#!/usr/bin/env python3
"""PR237 disposable VM: actual native APT/DNF install from a synthetic signed worker.

No real publisher signature, external trust anchor, daemon activation, or
package effects rollback is claimed. Entire root filesystem is a QEMU guest.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path("/root/pr237-synthetic-fixture")
STATE = Path("/var/lib/repocache/server")

def run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv), capture_output=True, text=True, timeout=30, check=False,
        stdin=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )

def report(distribution: str) -> None:
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert run("/usr/bin/systemd-detect-virt", "--vm").returncode == 0
    source = Path("/home/pr237ci/combined")
    sys.path[:0] = [str(source / "src"), str(source)]
    from scripts import install_native_root_worker, stage_native_root_worker
    from repocache.server_stock_nginx_package_owner_v1 import (
        inspect_stock_nginx_package_owner, inspect_stock_nginx_package_file_integrity,
    )
    from repocache.server_native_nginx_service_unit_v1 import inspect_native_nginx_unit
    from repocache.server_native_nginx_package_journal_v1 import (
        NATIVE_PENDING_NAME, NATIVE_COMPLETE_NAME,
    )

    pins = json.loads((ROOT / "pins.json").read_bytes())
    assert set(pins) == {"commit", "archive_sha256"}
    assets = ROOT / "assets"
    assert stage_native_root_worker.verify_installed_worker(assets, **pins)["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"

    def native_observation() -> None:
        assert inspect_stock_nginx_package_owner()["native_package_db_owner_observed"] is True
        assert inspect_stock_nginx_package_file_integrity()["native_package_file_integrity_verified"] is True
        assert inspect_native_nginx_unit(distribution).code == "VENDOR_NGINX_UNIT_OBSERVED"
        assert run("/usr/sbin/nginx", "-t").returncode == 0
        enabled = run("/usr/bin/systemctl", "is-enabled", "nginx.service")
        active = run("/usr/bin/systemctl", "is-active", "nginx.service")
        assert (enabled.returncode, enabled.stdout.strip()) == (1, "disabled"), (enabled.returncode, enabled.stdout.strip())
        assert (active.returncode, active.stdout.strip()) == (3, "inactive"), (active.returncode, active.stdout.strip())
        print("PASS: audited native NGINX package and vendor unit; systemd disabled/inactive")

    pending = STATE / NATIVE_PENDING_NAME
    complete = STATE / NATIVE_COMPLETE_NAME
    assert STATE.is_dir()
    assert (STATE / ".state-v1.lock").is_file()
    assert run("/usr/bin/systemctl", "is-active", "repocache-control.socket").returncode != 0
    if len(sys.argv) != 3:
        raise AssertionError("usage: native-package guest distribution install|after")
    phase = sys.argv[2]
    if phase == "install":
        assert not Path("/usr/sbin/nginx").exists()
        assert not Path("/etc/nginx").exists()
        assert not pending.exists() and not complete.exists()
        doc = ROOT / "reviewed-install.json"
        raw = (source / "docs/examples/server-install-v1.json").read_bytes()
        fd = os.open(doc, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        digest = hashlib.sha256(raw).hexdigest()
        # Invalid input MUST be rejected before native package manager effects.
        try:
            install_native_root_worker.install_authenticated_native_nginx(
                assets, doc, "0" * 64, **pins,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("Native package install accepted invalid document SHA")
        assert not Path("/usr/sbin/nginx").exists()
        assert not pending.exists() and not complete.exists()
        print("PASS: genuine installed-worker package entry refused tampered document pin before APT/DNF")

        # Print only fixed, redacted preflight codes from the REAL observers.
        # This does not bypass any native guard or modify host/package state.
        from repocache.server_install_v1 import parse_install_bytes
        from repocache.server_native_nginx_local_boundary_v1 import inspect_native_nginx_local_boundary
        from repocache.server_native_nginx_prepackage_state_v1 import (
            inspect_current_namespace_prepackage_state, PrepackageStateInspectionError,
        )
        from repocache.server_native_package_trust_v1 import _NATIVE, _trusted_key
        import sys as native_python
        boundary = inspect_native_nginx_local_boundary(
            os_release=Path("/usr/lib/os-release").read_text(encoding="ascii"),
            python_version=native_python.version_info[:2], document=parse_install_bytes(raw),
        )
        print("native_prepackage_code=" + boundary.code, flush=True)
        print("native_prepackage_footprint=" + boundary.footprint_code, flush=True)
        print("native_distro_signing_anchor_trusted=" + str(_trusted_key(_NATIVE[distribution][2])), flush=True)
        try:
            observed = inspect_current_namespace_prepackage_state()
            print("native_protected_state_code=" + observed["status"], flush=True)
        except PrepackageStateInspectionError as exc:
            print("native_protected_state_code=" + str(exc), flush=True)

        outcome = install_native_root_worker.install_authenticated_native_nginx(
            assets, doc, digest, **pins,
        )
        assert outcome["status"] == "AUTHENTICATED_NATIVE_NGINX_PACKAGE_INSTALLED"
        assert outcome["native_package_effects_reconciled"] is True
        assert outcome["authorizes_service_activation"] is False
        assert not pending.exists() and complete.is_file()
        info = complete.stat()
        assert info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600
        native_observation()
        existing = complete.read_bytes()
        try:
            install_native_root_worker.install_authenticated_native_nginx(
                assets, doc, digest, **pins,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("Second fresh native install accepted instead of refusing")
        assert complete.read_bytes() == existing and not pending.exists()
        (ROOT / "native-completed-sha256.txt").write_text(hashlib.sha256(existing).hexdigest() + "\n")
        print("PASS: actual signed-source native APT/DNF NGINX package installer, durable completion receipt, duplicate refusal")
        print("native_completed_sha256=" + hashlib.sha256(existing).hexdigest())
    elif phase == "after":
        assert not pending.exists() and complete.is_file()
        original = (ROOT / "native-completed-sha256.txt").read_text().strip()
        assert len(original) == 64
        assert hashlib.sha256(complete.read_bytes()).hexdigest() == original
        native_observation()
        assert stage_native_root_worker.verify_installed_worker(assets, **pins)["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
        for name in ("repocache-control.socket", "repocache-control.service"):
            assert run("/usr/bin/systemctl", "is-active", name).returncode != 0
        print("PASS: actual native APT/DNF completion persisted across kernel reboot; no NGINX or REPOCACHE autostart")
        print("NOT VERIFIED: actual package-manager interruption recovery, publisher release signing, v2 activation")
    else:
        raise ValueError("Invalid phase")

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("debian", "almalinux"):
        raise SystemExit("Usage: synthetic-native-package.py debian|almalinux install|after")
    report(sys.argv[1])
