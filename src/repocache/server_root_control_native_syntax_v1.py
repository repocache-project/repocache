"""Fixed-argument native NGINX syntax inspection prerequisite for issue #64.

Unlike an arbitrary nginx command runner, this module checks only the
installed distro default /etc/nginx/nginx.conf with /usr/sbin/nginx -t.
It is deliberately NOT wired into the root-control socket worker. The
native package provenance, effective systemd unit, managed include, TLS,
SELinux and #31 WAL must be independently validated by a future installed
broker before any privileged apply/reload/catalog publication.

Even nginx -t can read host configuration and create NGINX log files; do not
call from an untrusted host or mistake this for a mutation-free policy check.
"""
from __future__ import annotations

import os
import stat
import subprocess
from typing import Any

_NGINX = "/usr/sbin/nginx"
_CONF = "/etc/nginx/nginx.conf"
_COMMAND = (_NGINX, "-t", "-c", _CONF)
_PARENTS = ("/", "/usr", "/usr/sbin", "/etc", "/etc/nginx")
_TIMEOUT_SECONDS = 10


class FixedNginxSyntaxError(ValueError):
    """Fixed redacted NGINX validation refusals; never expose stdout/stderr."""


def _deny(code: str) -> None:
    raise FixedNginxSyntaxError("NATIVE_NGINX_SYNTAX_" + code)


def _signature(info: os.stat_result) -> tuple[int, ...]:
    """Snapshot metadata without following a caller-controlled symlink."""
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _trusted_fixed_files() -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Necessary on-disk checks; not package provenance or include ownership."""
    try:
        for path in _PARENTS:
            info = os.lstat(path)
            if (not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                _deny("UNSAFE_PATH")
        executable = os.lstat(_NGINX)
        config = os.lstat(_CONF)
        if (not stat.S_ISREG(executable.st_mode)
                or executable.st_uid != 0 or executable.st_gid != 0
                or executable.st_nlink != 1
                or stat.S_IMODE(executable.st_mode) != 0o755
                or not stat.S_ISREG(config.st_mode)
                or config.st_uid != 0 or config.st_gid != 0
                or config.st_nlink != 1
                or stat.S_IMODE(config.st_mode) & 0o022):
            _deny("UNSAFE_PATH")
        return _signature(executable), _signature(config)
    except FixedNginxSyntaxError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        _deny("PATH_UNAVAILABLE")


def inspect_installed_default_nginx_syntax_only() -> dict[str, Any]:
    """Run one fixed native syntax check, never signal or reload a service.

    A successful check proves only that this invocation parsed the current
    default configuration at the instant of execution; it does not establish
    installed code provenance, a managed config, a candidate staging lease,
    or an authenticated administrator's intent. No caller input is used.
    """
    if os.geteuid() != 0:
        _deny("ROOT_REQUIRED")
    before = _trusted_fixed_files()
    try:
        # No caller executable, args, shell, inherited environment, stdin or
        # captured private NGINX configuration. The child cannot output text
        # to logs or to this process's returned report.
        completed = subprocess.run(
            _COMMAND,
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
            timeout=_TIMEOUT_SECONDS,
            start_new_session=True,
            close_fds=True,
        )
    except subprocess.TimeoutExpired:
        _deny("CHECK_TIMEOUT")
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _deny("CHECK_UNAVAILABLE")
    # Check *before* interpreting exit code: even a successful nginx -t
    # must not silently accept replacement of the fixed executable/config.
    if _trusted_fixed_files() != before:
        _deny("FILES_CHANGED")
    if type(completed.returncode) is not int or completed.returncode != 0:
        _deny("CHECK_FAILED")
    return {
        "schema_version": 1,
        "status": "NATIVE_INSTALLED_DEFAULT_NGINX_SYNTAX_ONLY",
        "fixed_native_command_executed": True,
        "default_config_syntax_observed": True,
        "managed_candidate_staged_and_verified": False,
        "installed_binary_package_provenance_verified": False,
        "effective_systemd_unit_verified": False,
        "native_host_root_provenance_verified": False,
        "almalinux_selinux_enforcing_verified": False,
        "operator_authorization_verified": False,
        "authorizes_host_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }
