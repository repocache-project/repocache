"""Exercise explicitly requested native NGINX metadata checks in disposable CI.

This script neither installs NGINX nor activates any service. A positive
metadata report never authorizes installation or proves RPM/DEB payload trust.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from repocache.server_native_nginx_ownership_v1 import prepare_fresh_native_nginx
from repocache.server_native_package_payload_v1 import rehearse_native_nginx_downloads



def redacted_native_stage(args: list[str]) -> str:
    """Return only code-owned labels, never command-supplied package paths."""
    if not args:
        return "unknown"
    binary = args[0]
    if binary == "/usr/bin/apt-get":
        return "apt_metadata" if args[-1] == "update" else "apt_download"
    if binary == "/usr/bin/apt-cache":
        return "apt_candidate"
    if binary == "/usr/bin/dnf":
        return ("dnf_metadata" if "makecache" in args else
                "dnf_candidate" if "repoquery" in args else "dnf_download")
    if binary == "/usr/bin/dpkg-deb":
        return "deb_header"
    if binary == "/usr/bin/rpmkeys":
        return "rpm_signature"
    if binary == "/usr/bin/rpm":
        return ("rpm_private_db_init" if "--initdb" in args else
                "rpm_pubkey_import" if "--import" in args else "rpm_header")
    return "unknown"


def classified_ci_runner(args, **kwargs):
    """Print bounded *boolean* CI diagnostics; never log native output."""
    process = subprocess.run(args, **kwargs)
    if process.returncode:
        combined = (process.stdout + process.stderr).casefold()
        signals = {
            "apt_config_error": any(word in combined for word in (
                "conflicting values", "invalid option", "configuration error",
                "unsupported filetype", "ignoring keyring",
            )),
            "signature_failure": any(word in combined for word in (
                "not signed", "no_pubkey", "signature", "gpg error",
                "public key is not available",
            )),
            "network_or_tls_failure": any(word in combined for word in (
                "could not resolve", "certificate", "tls", "failed to fetch",
                "temporary failure", "could not connect",
            )),
            "repository_metadata_parse_failure": any(word in combined for word in (
                "repomd", "parse error", "failed to download metadata",
            )),
            "option_unrecognized": any(word in combined for word in (
                "unknown argument", "unknown option", "unrecognized",
                "invalid option",
            )),
            "permission_failure": any(word in combined for word in (
                "permission denied", "could not open lock",
            )),
        }
        # Identify a rejected *static* CLI token without printing an
        # operator-supplied path, repository response or native diagnostics.
        tokens = {
            "no_plugins": "--no-plugins",
            "plugins_option": "--setopt=plugins=0",
            "repo_option": "--repo=rc-baseos,rc-appstream",
            "assumeyes": "--assumeyes",
            "refresh": "--refresh",
            "makecache": "makecache",
            "persistdir": "--setopt=persistdir=",
            "varsdir": "--setopt=varsdir=",
            "system_cachedir": "--setopt=system_cachedir=",
            "repo_gpgcheck": ".repo_gpgcheck=1",
            "pkg_gpgcheck": ".pkg_gpgcheck=1",
            "installroot": "--installroot=",
            "config": "--config=",
            "releasever": "--releasever=10",
        }
        matches = [label for label, value in tokens.items()
                   if value in combined]
        print(json.dumps({
            "ci_native_manager_stage": redacted_native_stage(args),
            "return_code": process.returncode,
            "signals": signals,
            "static_dnf_argument_error_labels": matches,
        }, sort_keys=True), flush=True)
    return process


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    document = json.loads(
        (root / "docs/examples/server-install-v1.json").read_text(encoding="utf-8")
    )
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    report = prepare_fresh_native_nginx(
        os_release=release,
        python_version=(sys.version_info.major, sys.version_info.minor),
        document=document,
        runner=classified_ci_runner,
    ).to_dict()
    # The report is static/redacted; do not print native stdout/stderr, URL,
    # package key material, host source definitions, or files from the cache.
    print(json.dumps(report, sort_keys=True))
    assert report["authorizes_package_transaction"] is False
    assert report["can_install"] is False
    assert report["footprint"]["existing_instance_adoption_allowed"] is False
    if (report["footprint"]["code"] != "FRESH_NGINX_FOOTPRINT_NOT_OBSERVED"
            or report["metadata"] is None
            or report["metadata"]["code"] != "NATIVE_CANDIDATE_OBSERVED"
            or report["metadata"]["payload_signature_verified"] is not False):
        return 1
    payload = rehearse_native_nginx_downloads(
        os_release=release,
        python_version=(sys.version_info.major, sys.version_info.minor),
        document=document,
        runner=classified_ci_runner,
    ).to_dict()
    print(json.dumps(payload, sort_keys=True))
    assert payload["host_package_transaction_performed"] is False
    assert payload["authorizes_package_installation"] is False
    assert payload["can_install"] is False
    if payload["code"] != "NATIVE_PAYLOADS_VERIFIED_IN_SCRATCH":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
