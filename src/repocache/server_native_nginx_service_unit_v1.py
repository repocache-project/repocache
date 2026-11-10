"""Read-only vendor nginx.service inventory for native #27 provisioning.

The vendor systemd unit MUST originate from an authenticated OS package.
A safe-looking on-disk file or a successful parse is not package trust,
authorization to invoke systemctl, proof of PID 1 or an NGINX service test.

This module never spawns subprocesses, writes, loads arbitrary unit names,
follows leaf symlinks or opens private keys. Paths are fixed, not arguments.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
from typing import Any

VENDOR_UNIT = "/usr/lib/systemd/system/nginx.service"
MAX_UNIT_BYTES = 65536
# systemd's unit load path includes D-Bus control, transient and generator
# roots that can supersede an apparently safe distro vendor unit. Check fixed
# service names AND type-wide service.d drop-ins; never infer the effective
# PID 1 unit from the vendor file alone. The distributor unit itself is
# intentionally excluded from the shadow set.
_SYSTEM_SHADOW_ROOTS = (
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/run/systemd/generator.late",
)
_SHADOW_PATHS = tuple(
    root + "/" + entry
    for root in _SYSTEM_SHADOW_ROOTS
    for entry in (
        "nginx.service", "nginx.service.d", "service.d",
        # systemd loads implicit dependencies from these unit-specific
        # directories even when nginx.service itself is unmodified.
        "nginx.service.wants", "nginx.service.requires",
        "nginx.service.upholds",
    )
) + tuple(
    "/usr/lib/systemd/system/" + entry
    for entry in (
        "nginx.service.d", "service.d",
        "nginx.service.wants", "nginx.service.requires",
        "nginx.service.upholds",
    )
)
_PARENT_PATHS = (
    "/", "/usr", "/usr/lib", "/usr/lib/systemd", "/usr/lib/systemd/system",
)
_OPEN_FLAGS = (
    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
)
_CODES = frozenset({
    "VENDOR_NGINX_UNIT_OBSERVED",
    "VENDOR_NGINX_UNIT_MISSING",
    "VENDOR_NGINX_UNIT_UNSAFE",
    "VENDOR_NGINX_PARENT_UNSAFE",
    "VENDOR_NGINX_SHADOW_REFUSED",
    "VENDOR_NGINX_UNIT_CHANGED",
    "VENDOR_NGINX_UNIT_UNAVAILABLE",
    "VENDOR_NGINX_UNIT_UNSUPPORTED",
})
_STARTS = frozenset((
    "/usr/sbin/nginx",
    "/usr/sbin/nginx -g 'daemon on; master_process on;'",
))
_RELOADS = frozenset((
    "/usr/sbin/nginx -s reload",
    "/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload",
    # AlmaLinux's distro unit may additionally signal its existing MainPID
    # before the explicit NGINX reload. A signal-only reload is not enough.
    "/bin/kill -s HUP $MAINPID",
))
# systemd has many directives with side effects unrelated to ExecStart:
# mount/namespace credentials, dependencies, capabilities and environment
# can change execution even when all reviewed NGINX commands match. An
# allowlist is safer than listing a handful of known-dangerous directives.
_UNIT_KEYS = frozenset({
    "Description", "Documentation", "After", "Wants",
    "ConditionPathExists", "ConditionFileIsExecutable",
})
_SERVICE_KEYS = frozenset({
    "Type", "PIDFile", "ExecStartPre", "ExecStart", "ExecReload",
    "ExecStop", "KillSignal", "KillMode", "TimeoutStopSec", "PrivateTmp",
})
_INSTALL_KEYS = frozenset({"WantedBy"})
_KNOWN_UNIT_AFTER = frozenset({
    "network.target", "network-online.target", "remote-fs.target",
    "nss-lookup.target",
})
_OPTIONAL_SERVICE_VALUES = {
    "KillSignal": frozenset({"SIGQUIT"}),
    "KillMode": frozenset({"mixed"}),
    "TimeoutStopSec": frozenset({"5", "5s"}),
    "PrivateTmp": frozenset({"true", "yes"}),
}


class NginxServiceUnitInspectionError(ValueError):
    """Static redacted refusal; never include unit contents or local paths."""


@dataclass(frozen=True)
class NativeNginxUnitObservation:
    code: str
    digest: str | None

    def __post_init__(self) -> None:
        if (type(self.code) is not str or self.code not in _CODES
                or (self.code == "VENDOR_NGINX_UNIT_OBSERVED")
                   != (type(self.digest) is str
                       and len(self.digest) == 64
                       and all(c in "0123456789abcdef" for c in self.digest))):
            raise ValueError("invalid native NGINX unit observation")
        if self.code != "VENDOR_NGINX_UNIT_OBSERVED" and self.digest is not None:
            raise ValueError("failed native NGINX unit observations have no digest")

    def to_dict(self) -> dict[str, Any]:
        observed = self.code == "VENDOR_NGINX_UNIT_OBSERVED"
        return {
            "schema_version": 1,
            "code": self.code,
            "status": "PASS" if observed else (
                "FAIL" if self.code in {
                    "VENDOR_NGINX_SHADOW_REFUSED",
                    "VENDOR_NGINX_UNIT_UNSAFE",
                    "VENDOR_NGINX_PARENT_UNSAFE",
                } else "NOT VERIFIED"
            ),
            "unit_name": "nginx.service",
            "vendor_unit_sha256": self.digest,
            "vendor_unit_bounded_and_owned": observed,
            "known_unit_shadows_absent": observed,
            "nginx_start_and_reload_shape_observed": observed,
            "native_package_file_ownership_verified": False,
            "systemd_pid1_and_active_service_verified": False,
            "selinux_enforcing_service_verified": False,
            "authorizes_systemctl": False,
            "authorizes_nginx_reload": False,
            "authorizes_native_package_installation": False,
            "can_install": False,
        }


def _unit_layout_supported(raw: bytes) -> bool:
    """Conservative parser for known distro NGINX unit *shape*, not systemd.

    It intentionally refuses continuation syntax, ambiguous multiple sections,
    duplicate commands and unreviewed executable paths. systemd resolves
    dependencies, aliases, linked units and drop-ins separately; the parser
    does not claim to reproduce that interpretation.
    """
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_UNIT_BYTES:
        return False
    try:
        contents = raw.decode("utf-8", "strict")
    except UnicodeError:
        return False
    if "\x00" in contents or "\r" in contents:
        return False
    section = None
    seen_sections: set[str] = set()
    relevant: dict[str, list[str]] = {}
    for line in contents.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.endswith("\\"):
            return False
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section not in ("Unit", "Service", "Install"):
                return False
            if section in seen_sections:
                return False
            seen_sections.add(section)
            continue
        if "=" not in line:
            return False
        name, value = line.split("=", 1)
        allowed = {
            "Unit": _UNIT_KEYS, "Service": _SERVICE_KEYS,
            "Install": _INSTALL_KEYS,
        }
        if section not in allowed or name not in allowed[section]:
            return False
        relevant.setdefault(section + ":" + name, []).append(value.strip())
    if seen_sections != {"Unit", "Service", "Install"}:
        return False
    # Unknown dependencies could start unrelated units even if ExecStart is
    # the expected native NGINX binary. Do not accept aliases or other unit
    # dependencies as inert metadata.
    descriptions = relevant.get("Unit:Description", [])
    if (len(descriptions) != 1
            or not 1 <= len(descriptions[0]) <= 180
            or not descriptions[0].isprintable()):
        return False
    if relevant.get("Unit:Documentation", []) not in (
        [], ["man:nginx(8)"],
    ):
        return False
    after = relevant.get("Unit:After", [])
    if (len(after) != 1
            or not after[0].split()
            or len(after[0].split()) != len(set(after[0].split()))
            or any(value not in _KNOWN_UNIT_AFTER
                   for value in after[0].split())):
        return False
    if relevant.get("Unit:Wants", []) not in (
        [], ["network-online.target"],
    ):
        return False
    if relevant.get("Unit:ConditionPathExists", []) not in (
        [], ["/usr/sbin/nginx"],
    ):
        return False
    # Debian 13's official nginx-common unit uses
    # ConditionFileIsExecutable=/usr/sbin/nginx rather than PathExists;
    # both are constrained to the native executable, never an input path.
    if relevant.get("Unit:ConditionFileIsExecutable", []) not in (
        [], ["/usr/sbin/nginx"],
    ):
        return False
    for name, values in _OPTIONAL_SERVICE_VALUES.items():
        observed = relevant.get("Service:" + name, [])
        if len(observed) > 1 or any(
            value not in values for value in observed
        ):
            return False
    starts = relevant.get("Service:ExecStart", [])
    reloads = relevant.get("Service:ExecReload", [])
    before = relevant.get("Service:ExecStartPre", [])
    if (len(starts) != 1 or starts[0] not in _STARTS
            or not 1 <= len(reloads) <= 2
            or len(set(reloads)) != len(reloads)
            or any(value not in _RELOADS for value in reloads)
            or not any(value.startswith("/usr/sbin/nginx ") for value in reloads)
            or len(relevant.get("Service:Type", [])) != 1
            or relevant["Service:Type"] != ["forking"]
            or relevant.get("Service:PIDFile") not in (
                ["/run/nginx.pid"], ["/var/run/nginx.pid"]
            )):
        return False
    valid_preflight = (
        "/usr/sbin/nginx -t",
        "/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'",
    )
    nginx_validation = [value for value in before if value in valid_preflight]
    if len(nginx_validation) != 1:
        return False
    if before not in (
        nginx_validation,
        ["/usr/bin/rm -f /run/nginx.pid", nginx_validation[0]],
    ):
        # The only reviewed optional preflight is deleting the stale vendor
        # PID before exactly one nginx -t; repeated validation commands,
        # alternate ordering or arbitrary pre-actions are unsupported.
        return False
    # Debian's packaged stop helper is fixed. An unrecognized stop command
    # is as important as an unexpected start/reload command when a future
    # authorized root helper contemplates service ownership.
    stops = relevant.get("Service:ExecStop", [])
    if stops not in (
        [],
        ["-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 "
         "--pidfile /run/nginx.pid"],
    ):
        return False
    return relevant.get("Install:WantedBy") == ["multi-user.target"]


def _metadata(info: os.stat_result, *, directory: bool) -> bool:
    if (info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        return False
    return (
        stat.S_ISDIR(info.st_mode) if directory else (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) in (0o600, 0o640, 0o644)
            and 1 <= info.st_size <= MAX_UNIT_BYTES
        )
    )


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _empty_safe_dropin_directory(path: str, before: os.stat_result) -> bool:
    """Accept empty package-created .d directories, never a real override.

    AlmaLinux ships EMPTY systemd nginx.service.d directories in /etc and
    /usr/lib; rejecting their mere existence breaks an official clean install.
    Only a root-owned stable directory with *zero* entries is inert. Any
    contained entry (including hidden or dangling symlinks), unsafe parent,
    mount boundary, leaf symlink, open failure or race remains a hard block.
    This is an observation, never ownership or systemctl authorization.
    """
    if not _metadata(before, directory=True):
        return False
    try:
        parent = os.lstat(os.path.dirname(path))
        if (not _metadata(parent, directory=True)
                or before.st_dev != parent.st_dev):
            return False
        fd = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            if _identity(os.fstat(fd)) != _identity(before):
                return False
            with os.scandir(fd) as entries:
                if next(entries, None) is not None:
                    return False
            return (_identity(os.fstat(fd)) == _identity(before)
                    and _identity(os.lstat(path)) == _identity(before)
                    and _identity(os.lstat(os.path.dirname(path)))
                        == _identity(parent))
        finally:
            os.close(fd)
    except OSError:
        return False


def _shadows_present() -> bool:
    for path in _SHADOW_PATHS:
        try:
            observed = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError:
            # Unknown snapshots must not masquerade as verified absence.
            return True
        if path.endswith(".d") and _empty_safe_dropin_directory(path, observed):
            continue
        return True
    return False


def _read_vendor() -> tuple[str, bytes | None]:
    parents: list[os.stat_result] = []
    try:
        for path in _PARENT_PATHS:
            info = os.lstat(path)
            if not _metadata(info, directory=True):
                return "VENDOR_NGINX_PARENT_UNSAFE", None
            parents.append(info)
        fd = os.open(VENDOR_UNIT, _OPEN_FLAGS)
    except FileNotFoundError:
        return "VENDOR_NGINX_UNIT_MISSING", None
    except OSError:
        return "VENDOR_NGINX_UNIT_UNAVAILABLE", None
    try:
        start = os.fstat(fd)
        if not _metadata(start, directory=False):
            return "VENDOR_NGINX_UNIT_UNSAFE", None
        raw = os.read(fd, MAX_UNIT_BYTES + 1)
        if len(raw) != start.st_size:
            return "VENDOR_NGINX_UNIT_CHANGED", None
        end = os.fstat(fd)
        named = os.stat(VENDOR_UNIT, follow_symlinks=False)
        if (_identity(start) != _identity(end)
                or _identity(start) != _identity(named)):
            return "VENDOR_NGINX_UNIT_CHANGED", None
        for path, previous in zip(_PARENT_PATHS, parents):
            if _identity(previous) != _identity(os.lstat(path)):
                return "VENDOR_NGINX_UNIT_CHANGED", None
        return "VENDOR_NGINX_UNIT_OBSERVED", raw
    except OSError:
        return "VENDOR_NGINX_UNIT_UNAVAILABLE", None
    finally:
        os.close(fd)


def inspect_native_nginx_unit(distribution: str) -> NativeNginxUnitObservation:
    """Read only the fixed distro vendor unit; never approve a service action.

    Call only after separately authenticated Debian 13 / AlmaLinux 10
    package installation. A third-party unit, independent drop-in, a changed
    namespace or a merely root-owned file is not package provenance.
    """
    if type(distribution) is not str or distribution not in (
        "debian", "almalinux"
    ):
        raise NginxServiceUnitInspectionError("NGINX_UNIT_DISTRIBUTION_INVALID")
    try:
        if _shadows_present():
            return NativeNginxUnitObservation("VENDOR_NGINX_SHADOW_REFUSED", None)
        code, contents = _read_vendor()
        if code != "VENDOR_NGINX_UNIT_OBSERVED":
            return NativeNginxUnitObservation(code, None)
        if contents is None or not _unit_layout_supported(contents):
            return NativeNginxUnitObservation("VENDOR_NGINX_UNIT_UNSUPPORTED", None)
        # Check the same shadow paths after the read to avoid promoting a
        # snapshot when an override appears concurrently. The observation
        # always expires before any hypothetical later privileged action.
        if _shadows_present():
            return NativeNginxUnitObservation("VENDOR_NGINX_SHADOW_REFUSED", None)
        return NativeNginxUnitObservation(
            "VENDOR_NGINX_UNIT_OBSERVED", hashlib.sha256(contents).hexdigest()
        )
    except OSError:
        return NativeNginxUnitObservation("VENDOR_NGINX_UNIT_UNAVAILABLE", None)
