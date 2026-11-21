"""Private, bounded, exact-argument native NGINX full-context observation (#64).

This code is not installed, does not perform a systemd reload, and is
NEVER imported by the root socket worker. Native nginx -T may read TLS
material, inspect foreign include files and create log/cache directories;
only a future authenticated/installed transaction may use its private
bounded output, under the retained protected state lock and after independent
owner, package, unit, mount/ACL/SELinux and exposure verification.
"""
from __future__ import annotations

import hashlib
import os
import select
import subprocess
import time
from typing import Any

from repocache.server_root_control_native_syntax_v1 import (
    _CONF, _NGINX, _trusted_fixed_files, FixedNginxSyntaxError,
)

_COMMAND = (_NGINX, "-T", "-c", _CONF)
_MAX_DUMP_BYTES = 4 * 1024 * 1024
_TIMEOUT_SECONDS = 10
_ENV = {"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"}


class FixedNginxFullContextError(ValueError):
    """Never expose NGINX stdout, stderr, paths, keys or child exceptions."""


def _deny(code: str) -> None:
    raise FixedNginxFullContextError("NATIVE_NGINX_FULL_CONTEXT_" + code)


def _capture_default_nginx_dump_private() -> bytes:
    """Private exact-root NGINX -T dump, byte-bounded before accumulation.

    This is NOT a host trust token, proof of effective systemd ownership,
    or an actual running configuration. Never print/serialize this output,
    pass it to client APIs, or let a caller supply a path or executable.
    """
    if os.geteuid() != 0:
        _deny("ROOT_REQUIRED")
    try:
        identity = _trusted_fixed_files()
    except FixedNginxSyntaxError:
        _deny("FIXED_FILES_UNVERIFIED")
    try:
        proc = subprocess.Popen(
            _COMMAND, shell=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd="/", env=_ENV,
            start_new_session=True, close_fds=True,
        )
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _deny("CHECK_UNAVAILABLE")
    try:
        if proc.stdout is None:
            _deny("OUTPUT_UNAVAILABLE")
        deadline = time.monotonic() + _TIMEOUT_SECONDS
        output: list[bytes] = []
        length = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _deny("CHECK_TIMEOUT")
            try:
                ready, _, _ = select.select(
                    [proc.stdout], [], [], remaining,
                )
                if ready:
                    chunk = os.read(
                        proc.stdout.fileno(),
                        min(65536, _MAX_DUMP_BYTES + 1 - length),
                    )
            except (OSError, ValueError, TypeError):
                _deny("OUTPUT_UNAVAILABLE")
            # Deny AFTER the OS-only exception boundary: our own
            # FixedNginxFullContextError subclasses ValueError and must
            # not be rewritten as a misleading output failure.
            if not ready:
                _deny("CHECK_TIMEOUT")
            if not chunk:
                break
            length += len(chunk)
            if length > _MAX_DUMP_BYTES:
                _deny("OUTPUT_TOO_LARGE")
            output.append(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _deny("CHECK_TIMEOUT")
        try:
            return_code = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _deny("CHECK_TIMEOUT")
        if type(return_code) is not int or return_code != 0 or not length:
            _deny("CHECK_FAILED")
        try:
            if _trusted_fixed_files() != identity:
                _deny("FIXED_FILES_CHANGED")
        except FixedNginxSyntaxError:
            _deny("FIXED_FILES_CHANGED")
        return b"".join(output)
    except FixedNginxFullContextError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _deny("CHECK_UNAVAILABLE")
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)
        except (OSError, ValueError, subprocess.SubprocessError):
            # A failed cleanup is never a reason to emit private output
            # or claim a successful full-context observation.
            pass
        if proc.stdout is not None:
            proc.stdout.close()


def inspect_installed_default_nginx_full_context_only() -> dict[str, Any]:
    """Return a hash only, never raw private configuration or reload power."""
    raw = _capture_default_nginx_dump_private()
    return {
        "schema_version": 1,
        "status": "NATIVE_DEFAULT_NGINX_FULL_CONTEXT_BYTES_ONLY",
        "fixed_nginx_t_command_executed": True,
        "full_context_bytes_observed": True,
        "full_context_sha256": hashlib.sha256(raw).hexdigest(),
        "dump_size_bytes": len(raw),
        "included_configuration_ownership_verified": False,
        "installed_signed_binary_verified": False,
        "effective_systemd_unit_verified": False,
        "operator_authorization_verified": False,
        "active_exposure_verified": False,
        "state_v2_generation_bound_to_dump_verified": False,
        "preflight_remains_valid_after_return": False,
        "authorizes_host_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }
