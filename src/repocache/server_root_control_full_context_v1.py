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
import stat
import subprocess
import time
from typing import Any

from repocache.server_root_control_native_syntax_v1 import (
    _CONF, _NGINX, _PARENTS, _signature, _trusted_fixed_files,
    FixedNginxSyntaxError,
)

_COMMAND = (_NGINX, "-T", "-c", _CONF)
_OWNED_MAIN_PATH = "/etc/nginx/repocache.conf"
_OWNED_INCLUDE_PATH = "/etc/nginx/repocache-managed.conf"
_OWNED_COMMAND = (_NGINX, "-T", "-c", _OWNED_MAIN_PATH)
_MAX_DUMP_BYTES = 4 * 1024 * 1024
_TIMEOUT_SECONDS = 10
_ENV = {"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"}


class FixedNginxFullContextError(ValueError):
    """Never expose NGINX stdout, stderr, paths, keys or child exceptions."""


def _deny(code: str) -> None:
    raise FixedNginxFullContextError("NATIVE_NGINX_FULL_CONTEXT_" + code)


def _trusted_owned_fixed_files(managed: bool) -> tuple:
    """Pin fixed private files, never infer their ownership from metadata alone."""
    try:
        parents = []
        for path in _PARENTS:
            info = os.lstat(path)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
                _deny("FIXED_FILES_UNVERIFIED")
            parents.append((info.st_dev, info.st_ino, info.st_uid,
                            info.st_gid, info.st_mode))
        files = []
        for path, mode, limit in (
            (_NGINX, 0o755, 128 * 1024 * 1024),
            (_OWNED_MAIN_PATH, 0o644, 4096),
            (_OWNED_INCLUDE_PATH, 0o644, 1024 * 1024),
        ):
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                if path == _OWNED_INCLUDE_PATH and not managed:
                    files.append(None)
                    continue
                raise
            if ((path == _OWNED_INCLUDE_PATH and not managed)
                    or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != mode
                    or not 1 <= info.st_size <= limit):
                _deny("FIXED_FILES_UNVERIFIED")
            files.append(_signature(info))
        return tuple(parents), tuple(files)
    except FixedNginxFullContextError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        _deny("FIXED_FILES_UNVERIFIED")


def _capture_default_nginx_dump_private() -> bytes:
    """Private bounded dump of the fixed vendor context."""
    return _capture_fixed_nginx_dump_private(owned=False, managed=False)


def _capture_owned_nginx_dump_private(*, managed: bool) -> bytes:
    """Private bounded syntax/dump of the fixed independent context.

    Only an internal transaction holding its ownership lock and having
    verified the exact expected main/include bytes may use this helper.
    Metadata alone is not authority; no path, executable, or argument is
    accepted from a caller.
    """
    if type(managed) is not bool:
        _deny("FIXED_FILES_UNVERIFIED")
    return _capture_fixed_nginx_dump_private(owned=True, managed=managed)


def _capture_fixed_nginx_dump_private(*, owned: bool, managed: bool) -> bytes:
    """Private exact-root NGINX -T dump, byte-bounded before accumulation."""
    if os.geteuid() != 0:
        _deny("ROOT_REQUIRED")
    def observe():
        if owned:
            return _trusted_owned_fixed_files(managed)
        return _trusted_fixed_files()
    try:
        identity = observe()
    except FixedNginxSyntaxError:
        _deny("FIXED_FILES_UNVERIFIED")
    try:
        proc = subprocess.Popen(
            _OWNED_COMMAND if owned else _COMMAND, shell=False,
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
            observed_after = observe()
        except (FixedNginxSyntaxError, FixedNginxFullContextError):
            _deny("FIXED_FILES_CHANGED")
        if observed_after != identity:
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
