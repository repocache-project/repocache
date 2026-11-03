"""Container-only read of a preprovisioned #31 lock on a fresh NGINX host.

The dedicated CI workflow preprovisions a fixed test directory and lock in
a disposable distro image after the native download-only rehearsal. This
script itself is read-only. Its PASS never authorizes installation, systemd
operation, package transactions or real host-root privilege.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

from repocache.server_native_nginx_local_boundary_v1 import (
    inspect_native_nginx_local_boundary,
)
from repocache.server_native_nginx_prepackage_state_v1 import (
    inspect_current_namespace_prepackage_state,
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    doc = json.loads(
        (root / "docs/examples/server-install-v1.json").read_text(encoding="utf-8")
    )
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    evidence = inspect_current_namespace_prepackage_state()
    result = inspect_native_nginx_local_boundary(
        os_release=release,
        python_version=(sys.version_info.major, sys.version_info.minor),
        document=doc,
    ).to_dict()
    # Static redacted report only, no native source/host/path metadata.
    print(json.dumps({
        "prepackage_state_code": evidence["status"],
        "local_boundary_code": result["code"],
        "locked_state_read_completed": result["locked_prepackage_state_read_completed"],
        "full_nginx_manifest_verified": result["locked_manifest_read_completed"],
        "host_root_namespace_authenticated": result["host_root_namespace_authenticated"],
        "can_install": result["can_install"],
        "authorizes_package_transaction": result["authorizes_package_transaction"],
        "authorizes_nginx_activation": result["authorizes_nginx_activation"],
    }, sort_keys=True))
    if (evidence["status"] != "LOCKED_PREPACKAGE_STATE_ABSENT"
            or result["code"] != "LOCAL_READ_ONLY_SNAPSHOT_OBSERVED"
            or result["locked_prepackage_state_read_completed"] is not True
            or result["locked_manifest_read_completed"] is not False
            or result["host_root_namespace_authenticated"] is not False
            or result["can_install"] is not False
            or result["authorizes_package_transaction"] is not False
            or result["authorizes_nginx_activation"] is not False):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
