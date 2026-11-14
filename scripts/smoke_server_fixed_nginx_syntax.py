"""Test-only packaged NGINX syntax: disposable container, no service reload.

The intentional broken native /etc/nginx/nginx.conf mutation is permitted
ONLY inside the designated disposable CI container and is restored
byte-for-byte before exit. Never run this script on any real host.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from repocache.server_root_control_native_syntax_v1 import (
    FixedNginxSyntaxError, inspect_installed_default_nginx_syntax_only,
)
from repocache.server_root_control_full_context_v1 import (
    FixedNginxFullContextError, inspect_installed_default_nginx_full_context_only,
)


def main() -> int:
    if (os.environ.get("REPOCACHE_NATIVE_TEST_CONTAINER")
            != "CONFIRMED_DISPOSABLE_DOCKER_ONLY"
            or os.geteuid() != 0 or not Path("/.dockerenv").is_file()):
        raise RuntimeError("DISPOSABLE_CI_CONTAINER_REQUIRED")
    conf = Path("/etc/nginx/nginx.conf")
    before = conf.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
            or before.st_nlink != 1 or before.st_size > 256 * 1024):
        raise RuntimeError("DISPOSABLE_NATIVE_NGINX_CONFIG_UNSAFE")
    original = conf.read_bytes()
    validated = inspect_installed_default_nginx_syntax_only()
    assert validated["status"] == "NATIVE_INSTALLED_DEFAULT_NGINX_SYNTAX_ONLY"
    assert validated["authorizes_nginx_reload"] is False
    assert validated["authorizes_catalog_publication"] is False
    assert validated["managed_candidate_staged_and_verified"] is False
    full = inspect_installed_default_nginx_full_context_only()
    assert full["full_context_bytes_observed"] is True
    assert full["dump_size_bytes"] > 0
    assert len(full["full_context_sha256"]) == 64
    assert full["active_exposure_verified"] is False
    assert full["authorizes_nginx_reload"] is False
    try:
        # A broken but syntactically simple config must fail and leave NGINX
        # running state untouched. The container is thrown away regardless.
        conf.write_bytes(b"repocache_unknown_directive_for_negative_test;\n")
        try:
            inspect_installed_default_nginx_syntax_only()
        except FixedNginxSyntaxError as error:
            assert str(error) == "NATIVE_NGINX_SYNTAX_CHECK_FAILED"
        else:
            raise AssertionError("BROKEN_NGINX_CONFIG_WAS_ACCEPTED")
        try:
            inspect_installed_default_nginx_full_context_only()
        except FixedNginxFullContextError as error:
            assert str(error) == "NATIVE_NGINX_FULL_CONTEXT_CHECK_FAILED"
        else:
            raise AssertionError("BROKEN_NGINX_DUMP_WAS_ACCEPTED")
    finally:
        conf.write_bytes(original)
    # Confirm fresh fixed-command verification still succeeds after undo.
    recovered = inspect_installed_default_nginx_syntax_only()
    assert recovered["default_config_syntax_observed"] is True
    recovered_dump = inspect_installed_default_nginx_full_context_only()
    assert recovered_dump["full_context_sha256"] == full["full_context_sha256"]
    print("PASS: DISPOSABLE_NATIVE_NGINX_DEFAULT_SYNTAX_AND_REFUSAL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
