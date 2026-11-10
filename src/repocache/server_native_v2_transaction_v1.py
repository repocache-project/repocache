"""Fixed-path, crash-recoverable NGINX/state-v2/catalog transaction (#31/#64).

This module performs real descriptor-relative filesystem mutations, unlike
the earlier shadow WAL. It is NOT an installer, a privileged CLI, a socket
dispatcher or package-signature verifier. Native use is exclusively behind
the separately reviewed signed root worker; the live entry points insist
on initial-root/PID1, fixed systemd/NGINX and OS path checks. Fixture
entry points are private and refuse use against the live namespace '/'.

The durable transaction holds #31's single exclusive lock throughout:
  validate exact owner/CAS -> WAL -> managed include -> state ->
  fixed syntax + systemctl reload -> TLS health/exposure -> native -T
  route/catalog agreement -> active-only catalog -> owner manifest -> WAL clear.
A failed step restores the old bytes and reloads the previous service.
Crashes leave the WAL for a separate fixed recover-v2 request. No file path,
service unit, executable, environment or callback comes from the socket peer.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import stat
import subprocess
from contextlib import ExitStack
from typing import Any

from repocache.server_install_v1 import parse_install_bytes
from repocache.server_locked_manifest_reconcile_v1 import (
    _validate_proposed_v2_snapshot, preview_proposed_v2_state_transition,
    _verify_current_root_fd,
)
from repocache.server_native_nginx_effective_unit_v1 import (
    inspect_effective_native_nginx_unit,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)
from repocache.server_derived_catalog_candidate_v1 import (
    preview_derived_catalog_from_nginx_dump,
)
from repocache.server_proposed_state_v2_store import (
    V2_STATE, MAX_V2_STATE_BYTES, _legacy_refusal, _pending, _read_v2,
    _refuse_actual_root_fixture_write,
)
from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _walk, _recheck,
)
from repocache.server_protected_state_store_v1 import (
    _canonical, _json, _locked, _read_file, _unlink_known,
    _write_exclusive,
)
from repocache.server_root_control_fixed_candidate_v1 import (
    _load_private_under_root,
)
from repocache.server_root_control_full_context_v1 import (
    _capture_default_nginx_dump_private,
)
from repocache.server_root_control_host_preflight_v1 import (
    require_native_host_preconditions,
)
from repocache.server_root_control_native_syntax_v1 import (
    inspect_installed_default_nginx_syntax_only,
)
from repocache.server_upstream_address_preflight_v1 import (
    inspect_upstream_address_snapshot,
)

# Fixed, non-operator-selected on-disk ownership domains. Provision the
# directories securely BEFORE enabling any future signed root worker.
_INCLUDE_DIR = ("etc", "nginx", "conf.d")
_PUBLIC_DIR = ("var", "lib", "repocache", "public")
_INCLUDE = "repocache-managed.conf"
_CATALOG = "catalog.json"
_MANIFEST = ".state-v2-native.manifest"
_WAL = ".state-v2-native.pending"
_WAL_TMP = ".state-v2-native.pending-tmp"
_STAGE = ".repocache-v2-native.stage"
_STATE_STAGE = ".state-v2-native.stage"
_MANIFEST_STAGE = ".state-v2-native.manifest-stage"
_LIMIT = {V2_STATE: MAX_V2_STATE_BYTES, _INCLUDE: 1024 * 1024,
          _CATALOG: 512000, _MANIFEST: 8192}
_ORDER = (V2_STATE, _INCLUDE, _CATALOG, _MANIFEST)
_MAX_WAL = 8 * 1024 * 1024
_NGINX = "/usr/sbin/nginx"
_SYSTEMCTL = "/usr/bin/systemctl"
_UNIT = "nginx.service"
_ENV = {"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"}
_HEALTH = "/__repocache/healthz"
_CA = {"debian": "/etc/ssl/certs/ca-certificates.crt",
       "almalinux": "/etc/pki/tls/certs/ca-bundle.crt"}


class NativeV2TransactionError(ValueError):
    """Only stable redacted codes; never forward configuration or TLS bytes."""


def _deny(code: str) -> None:
    raise NativeV2TransactionError("NATIVE_V2_" + code)


def _hash(raw: bytes | None) -> str | None:
    return None if raw is None else hashlib.sha256(raw).hexdigest()


def _encode(raw: bytes | None) -> str | None:
    return None if raw is None else base64.b64encode(raw).decode("ascii")


def _decode(value: Any, maximum: int) -> bytes | None:
    if value is None:
        return None
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        _deny("WAL_INVALID")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        _deny("WAL_INVALID")
    if not 1 <= len(raw) <= maximum or _encode(raw) != value:
        _deny("WAL_INVALID")
    return raw


def _valid_sha(value: Any) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_public(parent: int, name: str, maximum: int) -> bytes | None:
    """Reject symlink, hardlink, unowned file, non-0644 and changed inode."""
    try:
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _deny("RESOURCE_UNAVAILABLE")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
    except OSError:
        _deny("RESOURCE_UNSAFE")
    try:
        old = os.fstat(fd)
        directory = os.fstat(parent)
        if (not stat.S_ISREG(old.st_mode) or old.st_uid != 0
                or old.st_gid != 0 or old.st_nlink != 1
                or stat.S_IMODE(old.st_mode) != 0o644
                or old.st_dev != directory.st_dev
                or not 1 <= old.st_size <= maximum
                or _identity(named) != _identity(old)):
            _deny("RESOURCE_UNSAFE")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - total))
            if not part:
                break
            total += len(part)
            chunks.append(part)
        after = os.fstat(fd)
        named2 = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (total != old.st_size or total > maximum
                or _identity(after) != _identity(old)
                or _identity(named2) != _identity(old)):
            _deny("RESOURCE_CHANGED")
        return b"".join(chunks)
    except NativeV2TransactionError:
        raise
    except OSError:
        _deny("RESOURCE_UNAVAILABLE")
    finally:
        os.close(fd)


def _write_public(parent: int, name: str, before: bytes | None,
                  after: bytes | None, maximum: int) -> None:
    """Atomic same-parent replacement, fsynced; no foreign target takeover."""
    if _read_public(parent, name, maximum) != before:
        _deny("RESOURCE_DRIFT")
    if after is None:
        if before is None:
            return
        try:
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
        except OSError:
            _deny("RESOURCE_WRITE_FAILED")
        return
    if type(after) is not bytes or not 1 <= len(after) <= maximum:
        _deny("RESOURCE_SIZE")
    if _read_public(parent, _STAGE, maximum) is not None:
        _deny("ORPHAN_STAGE")
    try:
        fd = os.open(_STAGE, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                     | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                     0o600, dir_fd=parent)
    except OSError:
        _deny("STAGE_UNAVAILABLE")
    try:
        try:
            os.fchmod(fd, 0o644)
            position = 0
            while position < len(after):
                count = os.write(fd, after[position:])
                if count <= 0:
                    _deny("STAGE_WRITE_FAILED")
                position += count
            os.fsync(fd)
        except OSError:
            _deny("STAGE_WRITE_FAILED")
    finally:
        os.close(fd)
    try:
        if _read_public(parent, name, maximum) != before:
            _deny("RESOURCE_DRIFT")
        os.replace(_STAGE, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    except NativeV2TransactionError:
        raise
    except OSError:
        _deny("RESOURCE_WRITE_FAILED")
    if _read_public(parent, name, maximum) != after:
        _deny("RESOURCE_CHANGED")


def _write_private(parent: int, name: str, stage: str,
                   before: bytes | None, after: bytes | None,
                   maximum: int) -> None:
    if _read_file(parent, name, 0, maximum) != before:
        _deny("PROTECTED_DRIFT")
    if after is None:
        if before is not None:
            _unlink_known(parent, name, before, 0, maximum)
        return
    if _read_file(parent, stage, 0, maximum) is not None:
        _deny("ORPHAN_STAGE")
    _write_exclusive(parent, stage, after, 0, maximum)
    try:
        os.replace(stage, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    except OSError:
        _deny("PROTECTED_WRITE_FAILED")
    if _read_file(parent, name, 0, maximum) != after:
        _deny("PROTECTED_DRIFT")


def _read_all(state_fd: int, include_fd: int, public_fd: int
              ) -> dict[str, bytes | None]:
    return {
        V2_STATE: _read_file(state_fd, V2_STATE, 0, _LIMIT[V2_STATE]),
        _INCLUDE: _read_public(include_fd, _INCLUDE, _LIMIT[_INCLUDE]),
        _CATALOG: _read_public(public_fd, _CATALOG, _LIMIT[_CATALOG]),
        _MANIFEST: _read_file(state_fd, _MANIFEST, 0, _LIMIT[_MANIFEST]),
    }


def _manifest_for(state: bytes, include: bytes, catalog: bytes) -> bytes:
    return _canonical({
        "manifest_schema_version": 1,
        "status": "NATIVE_V2_MANAGED_RESOURCES",
        "state_sha256": _hash(state),
        "include_sha256": _hash(include),
        "catalog_sha256": _hash(catalog),
    }, limit=_LIMIT[_MANIFEST])


def _verify_owned(old: dict[str, bytes | None]) -> None:
    """Only a complete exact owned previous generation may be repaired."""
    state = old[V2_STATE]
    if state is None:
        if any(old[name] is not None for name in (_INCLUDE, _CATALOG, _MANIFEST)):
            _deny("FOREIGN_BOOTSTRAP_RESOURCE")
        return
    if (old[_INCLUDE] is None or old[_CATALOG] is None
            or old[_MANIFEST] is None
            or old[_MANIFEST] != _manifest_for(
                state, old[_INCLUDE], old[_CATALOG],
            )):
        _deny("OWNER_MANIFEST_DRIFT")
    try:
        snapshot = _json(state, limit=_LIMIT[V2_STATE])
        _validate_proposed_v2_snapshot(snapshot)
        catalog = _json(old[_CATALOG], limit=_LIMIT[_CATALOG])
        if (type(catalog) is not dict or set(catalog)
                != {"schema", "repositories"} or catalog["schema"] != 1
                or type(catalog["repositories"]) is not list):
            _deny("CATALOG_DRIFT")
        if len(catalog["repositories"]) != sum(
            row["desired_state"] == "active"
            for row in snapshot["repository_records"]
        ):
            _deny("CATALOG_DRIFT")
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError):
        _deny("OWNER_MANIFEST_DRIFT")


def _wal_record(old: dict[str, bytes | None],
                new: dict[str, bytes]) -> bytes:
    return _canonical({
        "version": 1,
        "old_base64": {name: _encode(old[name]) for name in _ORDER},
        "old_sha256": {name: _hash(old[name]) for name in _ORDER},
        "new_sha256": {name: _hash(new[name]) for name in _ORDER},
    }, limit=_MAX_WAL)


def _read_wal(state_fd: int, name: str) -> tuple[dict, dict, bytes] | None:
    raw = _read_file(state_fd, name, 0, _MAX_WAL)
    if raw is None:
        return None
    try:
        data = _json(raw, limit=_MAX_WAL)
        if (type(data) is not dict
                or set(data) != {"version", "old_base64", "old_sha256", "new_sha256"}
                or type(data["version"]) is not int or data["version"] != 1):
            _deny("WAL_INVALID")
        for field in ("old_base64", "old_sha256", "new_sha256"):
            if type(data[field]) is not dict or set(data[field]) != set(_ORDER):
                _deny("WAL_INVALID")
        old = {name: _decode(data["old_base64"][name], _LIMIT[name])
               for name in _ORDER}
        if any(data["old_sha256"][name] != _hash(old[name]) for name in _ORDER):
            _deny("WAL_INVALID")
        if any(not _valid_sha(data["new_sha256"][name])
               for name in _ORDER):
            _deny("WAL_INVALID")
        _verify_owned(old)
        return old, data["new_sha256"], raw
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError):
        _deny("WAL_INVALID")


def _no_conflicting_pending(state_fd: int) -> None:
    _legacy_refusal(state_fd, 0)
    # Existing v2-only and shadow WALs cannot coexist with this domain.
    if _pending(state_fd, 0):
        _deny("FOREIGN_PENDING")
    for name, bound in ((_WAL, _MAX_WAL), (_WAL_TMP, _MAX_WAL),
                        (_STATE_STAGE, _LIMIT[V2_STATE]),
                        (_MANIFEST_STAGE, _LIMIT[_MANIFEST])):
        if _read_file(state_fd, name, 0, bound) is not None:
            _deny("NATIVE_RECOVERY_REQUIRED")


def _current_resources_allowed(old: dict[str, bytes | None],
                               sha: dict[str, str], now: dict[str, bytes | None],
                               *, exact_old: bool = False) -> None:
    for name in _ORDER:
        if exact_old:
            if now[name] != old[name]:
                _deny("PREPARE_DRIFT")
        elif _hash(now[name]) not in (sha[name], _hash(old[name])):
            _deny("FOREIGN_RESOURCE_DRIFT")


def _cleanup_stage(parent: int, maximum: int, new_shas: set[str]) -> None:
    # A stale stage is never trusted unless it is exactly a WAL-recorded new
    # resource. A foreign stage refuses recovery rather than deleting it.
    raw = _read_public(parent, _STAGE, maximum)
    if raw is not None:
        if _hash(raw) not in new_shas:
            _deny("FOREIGN_STAGE")
        os.unlink(_STAGE, dir_fd=parent)
        os.fsync(parent)


def _cleanup_private_stage(state_fd: int, name: str, maximum: int,
                           next_shas: set[str]) -> None:
    raw = _read_file(state_fd, name, 0, maximum)
    if raw is not None:
        if _hash(raw) not in next_shas:
            _deny("FOREIGN_STAGE")
        _unlink_known(state_fd, name, raw, 0, maximum)


def _fixed_command(argv: tuple[str, ...], *, timeout: int) -> None:
    if argv not in ((
        _SYSTEMCTL, "reload", _UNIT,
    ),):
        _deny("COMMAND_REFUSED")
    try:
        proc = subprocess.run(
            argv, shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd="/", env=_ENV, timeout=timeout, close_fds=True,
            start_new_session=True, check=False,
        )
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _deny("COMMAND_UNAVAILABLE")
    if type(proc.returncode) is not int or proc.returncode != 0:
        _deny("COMMAND_FAILED")


def _reload_native(distribution: str) -> None:
    # Both observations must prove the same intended vendor unit, active
    # master identity and immutable fixed command across the reload.
    before = inspect_effective_native_nginx_unit(distribution)
    if (before["unit_name"] != _UNIT
            or before["authorizes_nginx_reload"] is not False):
        _deny("FOREIGN_UNIT")
    _fixed_command((_SYSTEMCTL, "reload", _UNIT), timeout=10)
    after = inspect_effective_native_nginx_unit(distribution)
    if (after["unit_name"] != _UNIT
            or before["vendor_unit_sha256"] != after["vendor_unit_sha256"]
            or before["main_pid_observed"] != after["main_pid_observed"]):
        _deny("UNIT_CHANGED")


def _local_https_generation(document: dict[str, Any], generation: int) -> None:
    """Verify *running* TLS NGINX answers with the exact staged generation."""
    address = document["deployment"]["listen"]["bind_address"]
    hostname = document["deployment"]["listen"]["hostname"]
    port = document["deployment"]["listen"]["https_port"]
    if address in ("0.0.0.0", "::"):
        address = "127.0.0.1" if address == "0.0.0.0" else "::1"
    try:
        context = ssl.create_default_context()
        with socket.create_connection((address, port), timeout=4) as tcp:
            with context.wrap_socket(tcp, server_hostname=hostname) as tls:
                tls.settimeout(4)
                tls.sendall((
                    "GET " + _HEALTH + " HTTP/1.1\r\nHost: " + hostname
                    + "\r\nConnection: close\r\n\r\n"
                ).encode("ascii"))
                response = tls.recv(4096)
    except (OSError, ValueError, ssl.SSLError, TimeoutError):
        _deny("EXPOSURE_UNVERIFIED")
    marker = f"X-Repocache-Generation: {generation}".encode("ascii").lower()
    if (not response.startswith(b"HTTP/1.1 204 ")
            or marker not in response.split(b"\r\n\r\n", 1)[0].lower()):
        _deny("EXPOSURE_UNVERIFIED")


def _resolve_pins(document: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    """Native OS resolution, not a caller-supplied socket payload or JSON."""
    from urllib.parse import urlsplit
    answers = {}
    for repository in document["repositories"]:
        if repository["desired_state"] != "active":
            continue
        rid = repository["id"]
        host_map = {}
        port = urlsplit(repository["upstream"]["base_url"]).port or 443
        for host in repository["upstream"]["allowed_hosts"]:
            try:
                found = socket.getaddrinfo(
                    host, port, family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
                )
            except (OSError, ValueError):
                _deny("DNS_UNVERIFIED")
            addresses = sorted(set(item[4][0] for item in found))
            if not 1 <= len(addresses) <= 32:
                _deny("DNS_UNVERIFIED")
            host_map[host] = addresses
        try:
            inspect_upstream_address_snapshot(
                document, repository_id=rid, answers_by_host=host_map,
            )
        except (ValueError, TypeError):
            _deny("DNS_UNVERIFIED")
        answers[rid] = host_map
    return answers


def _render(document: dict[str, Any], generation: int,
            distribution: str) -> tuple[bytes, bytes, dict, dict]:
    """Complete fixed NGINX http{} include and canonical active-only catalog."""
    try:
        bundle = render_repository_nginx_bundle_candidate(
            document, expected_state_generation=generation - 1,
            candidate_pins_by_repository=_resolve_pins(document),
            ca_bundle_path=_CA[distribution],
        )
        config = document["deployment"]
        listen = config["listen"]
        tls = config["tls"]
        # XML/NGINX directives are not permitted in these schema fields.
        names = (listen["hostname"], listen["bind_address"],
                 tls["certificate_file"], tls["private_key_file"])
        if any(re.fullmatch(r"[A-Za-z0-9_.:/+-]+", s) is None for s in names):
            _deny("NGINX_TOKEN_UNSAFE")
        if listen["bind_address"] == "::":
            addr = "[::]"
        elif ":" in listen["bind_address"]:
            addr = "[" + listen["bind_address"] + "]"
        else:
            addr = listen["bind_address"]
        # The catalog endpoint is fixed and private assets stay in /var.
        # NGINX's alias target must be provisioned root:root with 0755 parent.
        nginx = (
            "# REPOCACHE managed v2 - do not edit\n"
            + bundle["http_upstream_fragment"]
            + "\nserver {\n"
            + f"    listen {addr}:{listen['https_port']} ssl;\n"
            + f"    server_name {listen['hostname']};\n"
            + f"    ssl_certificate {tls['certificate_file']};\n"
            + f"    ssl_certificate_key {tls['private_key_file']};\n"
            + f"    location = {_HEALTH} {{\n"
            + '        default_type text/plain;\n'
            + f'        add_header X-Repocache-Generation "{generation}" always;\n'
            + "        return 204;\n"
            + "    }\n"
            + "    location = /.well-known/repocache/catalog.json {\n"
            + "        default_type application/json;\n"
            + "        alias /var/lib/repocache/public/catalog.json;\n"
            + "        limit_except GET HEAD { deny all; }\n"
            + "    }\n"
            + bundle["server_location_fragment"]
            + "}\n"
        ).encode("ascii")
        if not 1 <= len(nginx) <= _LIMIT[_INCLUDE]:
            _deny("NGINX_SIZE")
        # Pure preview only. Real -T/full-context and effective exposure
        # MUST be checked after actual reload and before publication.
        preview = preview_derived_catalog_from_nginx_dump(
            document, candidate_pins_by_repository=_resolve_pins(document),
            ca_bundle_path=_CA[distribution],
            nginx_dump_text=nginx.decode("ascii"), nginx_t_exit_code=0,
        )
        catalog = _canonical(preview["candidate_catalog"], limit=_LIMIT[_CATALOG])
        return nginx, catalog, bundle, preview
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, UnicodeError, KeyError, OverflowError):
        _deny("RENDER_INVALID")


def _route_dump_check(document: dict, include: bytes, catalog: bytes,
                      distribution: str, generation: int,
                      pins: dict) -> None:
    """Private fixed native -T must match exact staged bytes and catalog."""
    try:
        dump = _capture_default_nginx_dump_private()
        text = dump.decode("utf-8", "strict")
        if include.decode("utf-8") not in text:
            _deny("NGINX_DUMP_MISMATCH")
        preview = preview_derived_catalog_from_nginx_dump(
            document, candidate_pins_by_repository=pins,
            ca_bundle_path=_CA[distribution], nginx_dump_text=text,
            nginx_t_exit_code=0,
        )
        if _canonical(preview["candidate_catalog"], limit=_LIMIT[_CATALOG]) != catalog:
            _deny("CATALOG_MISMATCH")
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, UnicodeError):
        _deny("NGINX_DUMP_UNVERIFIED")


def _native_syntax_check() -> None:
    report = inspect_installed_default_nginx_syntax_only()
    if (report["status"] != "NATIVE_INSTALLED_DEFAULT_NGINX_SYNTAX_ONLY"
            or report["authorizes_nginx_reload"] is not False):
        _deny("SYNTAX_UNVERIFIED")


def _apply_locked(root_fd: int, state_fd: int,
                  include_fd: int, public_fd: int,
                  distribution: str, *, fixture: bool = False) -> dict:
    """A complete WAL-held cross-directory apply, no caller-supplied effects."""
    _no_conflicting_pending(state_fd)
    old = _read_all(state_fd, include_fd, public_fd)
    _verify_owned(old)
    previous, previous_raw = _read_v2(state_fd, 0)
    if previous_raw != old[V2_STATE]:
        _deny("STATE_CHANGED")
    generation = 0 if previous is None else previous["state_generation"]
    report, candidate = _load_private_under_root(
        root_fd, owner_uid=0, owner_gid=0,
    )
    if report["expected_generation"] != generation or (
        report["expected_state_sha256"] != _hash(previous_raw)
    ):
        _deny("STATE_STALE")
    try:
        snapshot = _json(candidate, limit=_LIMIT[V2_STATE])
        transition = preview_proposed_v2_state_transition(
            snapshot, expected_generation=generation,
            previous_snapshot=previous,
        )
        doc = parse_install_bytes(
            base64.b64decode(snapshot["configuration_base64"], validate=True),
            for_apply=True,
        )
        # All NGINX paths stay fixed: no document-specified include/state root.
        if (doc["deployment"]["paths"]["generated_include"]
                != "/etc/nginx/conf.d/repocache-managed.conf"
                or doc["deployment"]["paths"]["state_root"]
                   != "/var/lib/repocache/server"):
            _deny("LAYOUT_UNSUPPORTED")
        pins = _resolve_pins(doc)
        bundle = render_repository_nginx_bundle_candidate(
            doc, expected_state_generation=generation,
            candidate_pins_by_repository=pins, ca_bundle_path=_CA[distribution],
        )
        # Build exact deterministic file and active-only catalog.
        include, catalog, _bundle, _preview = _render_using_pins(
            doc, snapshot["state_generation"], distribution, pins, bundle,
        )
        if transition["proposed_generation"] != snapshot["state_generation"]:
            _deny("STATE_STALE")
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, UnicodeError, KeyError, OverflowError):
        _deny("CANDIDATE_INVALID")

    new = {
        V2_STATE: candidate, _INCLUDE: include, _CATALOG: catalog,
        _MANIFEST: _manifest_for(candidate, include, catalog),
    }
    if previous is not None and all(old[name] == new[name] for name in _ORDER):
        return {"status": "NATIVE_V2_NO_CHANGE", "state_generation": generation}
    # Re-read candidate before publishing any WAL or file.
    again, again_candidate = _load_private_under_root(
        root_fd, owner_uid=0, owner_gid=0,
    )
    if again != report or again_candidate != candidate:
        _deny("CANDIDATE_CHANGED")
    if _read_all(state_fd, include_fd, public_fd) != old:
        _deny("PREPARE_DRIFT")

    wal = _wal_record(old, new)
    _write_exclusive(state_fd, _WAL_TMP, wal, 0, _MAX_WAL)
    if _read_all(state_fd, include_fd, public_fd) != old:
        _deny("PREPARE_DRIFT")
    os.replace(_WAL_TMP, _WAL, src_dir_fd=state_fd, dst_dir_fd=state_fd)
    os.fsync(state_fd)
    try:
        _write_public(include_fd, _INCLUDE, old[_INCLUDE],
                      new[_INCLUDE], _LIMIT[_INCLUDE])
        _write_private(state_fd, V2_STATE, _STATE_STAGE, old[V2_STATE],
                       new[V2_STATE], _LIMIT[V2_STATE])
        _native_syntax_check()
        _reload_native(distribution)
        # Exactly one fixed generation health endpoint must have become live.
        _local_https_generation(doc, snapshot["state_generation"])
        _route_dump_check(doc, new[_INCLUDE], new[_CATALOG],
                          distribution, snapshot["state_generation"], pins)
        # Never publish before observing the new real route generation.
        _write_public(public_fd, _CATALOG, old[_CATALOG],
                      new[_CATALOG], _LIMIT[_CATALOG])
        _write_private(state_fd, _MANIFEST, _MANIFEST_STAGE,
                       old[_MANIFEST], new[_MANIFEST], _LIMIT[_MANIFEST])
        if _read_all(state_fd, include_fd, public_fd) != new:
            _deny("POST_COMMIT_DRIFT")
        if _read_file(state_fd, _WAL, 0, _MAX_WAL) != wal:
            _deny("WAL_CHANGED")
        _unlink_known(state_fd, _WAL, wal, 0, _MAX_WAL)
        return {
            "status": "NATIVE_V2_COMMITTED",
            "state_generation": snapshot["state_generation"],
            "active_catalog_published": True,
            "nginx_reload_and_generation_observed": True,
            "durable_wal_cleared": True,
        }
    except Exception:
        # Rollback occurs under the SAME exclusive lock. If the OS crashes,
        # recovery is a separate fixed operation; never claim success.
        try:
            _recover_locked(state_fd, include_fd, public_fd, distribution)
        except Exception:
            _deny("APPLY_FAILED_RECOVERY_REQUIRED")
        _deny("APPLY_FAILED_ROLLED_BACK")


def _render_using_pins(document: dict, next_generation: int,
                       distribution: str, pins: dict, bundle: dict
                       ) -> tuple[bytes, bytes, dict, dict]:
    """Pure deterministic rendering; pins resolved exactly once per apply."""
    cfg = document["deployment"]
    listen, tls = cfg["listen"], cfg["tls"]
    names = (listen["hostname"], listen["bind_address"],
             tls["certificate_file"], tls["private_key_file"])
    if any(type(s) is not str or re.fullmatch(r"[A-Za-z0-9_.:/+-]+", s) is None
           for s in names):
        _deny("NGINX_TOKEN_UNSAFE")
    address = listen["bind_address"]
    bind = "[" + address + "]" if ":" in address else address
    include = (
        "# REPOCACHE managed v2\n"
        + bundle["http_upstream_fragment"]
        + "\nserver {\n"
        + f"    listen {bind}:{listen['https_port']} ssl;\n"
        + f"    server_name {listen['hostname']};\n"
        + f"    ssl_certificate {tls['certificate_file']};\n"
        + f"    ssl_certificate_key {tls['private_key_file']};\n"
        + f"    location = {_HEALTH} {{\n"
        + '        default_type text/plain;\n'
        + f'        add_header X-Repocache-Generation "{next_generation}" always;\n'
        + "        return 204;\n"
        + "    }\n"
        + "    location = /.well-known/repocache/catalog.json {\n"
        + "        default_type application/json;\n"
        + "        alias /var/lib/repocache/public/catalog.json;\n"
        + "        limit_except GET HEAD { deny all; }\n"
        + "    }\n"
        + bundle["server_location_fragment"]
        + "}\n"
    ).encode("ascii")
    if not 1 <= len(include) <= _LIMIT[_INCLUDE]:
        _deny("NGINX_SIZE")
    preview = preview_derived_catalog_from_nginx_dump(
        document, candidate_pins_by_repository=pins,
        ca_bundle_path=_CA[distribution],
        nginx_dump_text=include.decode("ascii"), nginx_t_exit_code=0,
    )
    catalog = _canonical(preview["candidate_catalog"], limit=_LIMIT[_CATALOG])
    return include, catalog, bundle, preview


def _recover_locked(state_fd: int, include_fd: int,
                    public_fd: int, distribution: str) -> dict:
    journal = _read_wal(state_fd, _WAL)
    uncommitted = _read_wal(state_fd, _WAL_TMP)
    if journal is not None and uncommitted is not None:
        _deny("CONFLICTING_WALS")
    if journal is None and uncommitted is None:
        old = _read_all(state_fd, include_fd, public_fd)
        _verify_owned(old)
        return {"status": "NATIVE_V2_CLEAN", "recovery_required": False}
    old, new_sha, raw = journal if journal is not None else uncommitted
    now = _read_all(state_fd, include_fd, public_fd)
    _current_resources_allowed(old, new_sha, now,
                               exact_old=journal is None)
    _cleanup_stage(include_fd, _LIMIT[_INCLUDE], {new_sha[_INCLUDE]})
    _cleanup_stage(public_fd, _LIMIT[_CATALOG], {new_sha[_CATALOG]})
    _cleanup_private_stage(state_fd, _STATE_STAGE, _LIMIT[V2_STATE],
                           {new_sha[V2_STATE]})
    _cleanup_private_stage(state_fd, _MANIFEST_STAGE, _LIMIT[_MANIFEST],
                           {new_sha[_MANIFEST]})
    if journal is None:
        _unlink_known(state_fd, _WAL_TMP, raw, 0, _MAX_WAL)
        return {"status": "NATIVE_V2_UNPUBLISHED_WAL_DISCARDED",
                "recovery_required": False}
    # Revoke newly exposed catalog first. Never advertise routes about to
    # be removed by a compensating service reload.
    if now[_CATALOG] != old[_CATALOG]:
        _write_public(public_fd, _CATALOG, now[_CATALOG],
                      old[_CATALOG], _LIMIT[_CATALOG])
    if now[_INCLUDE] != old[_INCLUDE]:
        _write_public(include_fd, _INCLUDE, now[_INCLUDE],
                      old[_INCLUDE], _LIMIT[_INCLUDE])
    # Revalidate and reload previous installed config before declaring
    # rollback complete. On failure, retain WAL for later exact recovery.
    _native_syntax_check()
    _reload_native(distribution)
    if now[V2_STATE] != old[V2_STATE]:
        _write_private(state_fd, V2_STATE, _STATE_STAGE, now[V2_STATE],
                       old[V2_STATE], _LIMIT[V2_STATE])
    if now[_MANIFEST] != old[_MANIFEST]:
        _write_private(state_fd, _MANIFEST, _MANIFEST_STAGE,
                       now[_MANIFEST], old[_MANIFEST], _LIMIT[_MANIFEST])
    _verify_owned(_read_all(state_fd, include_fd, public_fd))
    _unlink_known(state_fd, _WAL, raw, 0, _MAX_WAL)
    return {"status": "NATIVE_V2_ROLLED_BACK", "recovery_required": False}


def _operation_under_root(root_fd: int, *, distribution: str,
                          operation: str, fixture: bool = False) -> dict:
    """Internal entry. Only trusted root code selects the fixed operation."""
    if type(distribution) is not str or distribution not in _CA:
        _deny("DISTRIBUTION_UNSUPPORTED")
    if operation not in ("APPLY_V2", "RECOVER_V2"):
        _deny("OPERATION_REFUSED")
    if fixture:
        _refuse_actual_root_fixture_write(root_fd)
    with ExitStack() as stack:
        with _locked(root_fd, 0) as state_fd:
            include_fd, include_chain = _walk(root_fd, _INCLUDE_DIR, stack, 0)
            public_fd, public_chain = _walk(root_fd, _PUBLIC_DIR, stack, 0)
            # Do not use a foreign state/catalog filesystem without reviewed
            # mount controls. _walk enforces trusted owner + same-dev ancestry.
            if stat.S_IMODE(os.fstat(public_fd).st_mode) != 0o755:
                _deny("PUBLIC_DIRECTORY_MODE_UNSAFE")
            if operation == "APPLY_V2":
                result = _apply_locked(root_fd, state_fd, include_fd,
                                       public_fd, distribution, fixture=fixture)
            else:
                _legacy_refusal(state_fd, 0)
                if _pending(state_fd, 0):
                    _deny("FOREIGN_PENDING")
                result = _recover_locked(state_fd, include_fd,
                                         public_fd, distribution)
            # Mutation alters leaf-directory timestamps, so recheck only
            # stable ancestors and structural leaf inode/ownership.
            _recheck(include_chain[:-1], 0)
            _recheck(public_chain[:-1], 0)
            return result


def execute_native_fixed_v2_transaction(operation: str,
                                        distribution: str) -> dict:
    """Actual root-only entry, deliberately uninstalled until signed release.

    This API has no root FD, file path, config bytes, unit name, executable,
    shell or callback from its caller. Socket worker integration MUST prove
    signed worker/unit provenance and separate issue #64 approval first.
    """
    report = require_native_host_preconditions()
    if report["host_root_provenance_verified"] is not False:
        _deny("HOST_CONTEXT_INVALID")
    # A fixed working vendor NGINX unit must already exist, be active and
    # have unmodified default systemd identity, before *any* host mutation.
    inspect_effective_native_nginx_unit(distribution)
    fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        _verify_current_root_fd(fd)
        result = _operation_under_root(
            fd, distribution=distribution, operation=operation,
        )
        _verify_current_root_fd(fd)
        return result
    except NativeV2TransactionError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("HOST_OPERATION_REFUSED")
    finally:
        os.close(fd)
