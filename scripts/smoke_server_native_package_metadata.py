"""Exercise explicitly requested native NGINX metadata checks in disposable CI.

This script neither installs NGINX nor activates any service. A positive
metadata report never authorizes installation or proves RPM/DEB payload trust.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

from repocache.server_native_package_trust_v1 import inspect_native_nginx_metadata


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    document = json.loads(
        (root / "docs/examples/server-install-v1.json").read_text(encoding="utf-8")
    )
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    report = inspect_native_nginx_metadata(
        os_release=release,
        python_version=(sys.version_info.major, sys.version_info.minor),
        document=document,
    ).to_dict()
    # The report is static/redacted; do not print native stdout/stderr, URL,
    # package key material, host source definitions, or files from the cache.
    print(json.dumps(report, sort_keys=True))
    assert report["authorizes_installation"] is False
    assert report["can_install"] is False
    assert report["payload_signature_verified"] is False
    if report["code"] != "NATIVE_CANDIDATE_OBSERVED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
