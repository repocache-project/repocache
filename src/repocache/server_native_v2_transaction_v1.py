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
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from typing import Any

from repocache.server_bounded_dns_v1 import DEFAULT_DNS_SECONDS, bounded_getaddrinfo
from repocache.server_install_v1 import parse_install_bytes, validate_install_document
from repocache.server_locked_manifest_reconcile_v1 import (
    _validate_proposed_v2_snapshot, preview_proposed_v2_state_transition,
    _verify_current_root_fd,
)
from repocache.server_native_nginx_effective_unit_v1 import (
    EffectiveNginxUnitError, inspect_effective_native_nginx_unit,
    OWNED_NGINX_CONFIG_MARKER_PREFIX,
    inspect_signed_owned_nginx_unit, require_owned_bootstrap_health,
    _inspect_owned_nginx_unit_bytes,
)
from repocache.server_native_installed_storage_v1 import (
    InstalledStorageError, verify_control_storage, verify_service_storage_mounts,
)
from repocache.server_native_nginx_package_journal_v1 import (
    _read_completed_native_install_under_lock, NativePackageJournalError,
)
from repocache.server_native_nginx_service_unit_v1 import (
    inspect_native_nginx_unit, NginxServiceUnitInspectionError,
)
from repocache.server_stock_nginx_package_owner_v1 import (
    inspect_stock_nginx_package_file_integrity, StockNginxPackageOwnerError,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)
from repocache.server_nginx_tls_listener_candidate_v1 import (
    NativeTLSListenerCandidateError, render_native_tls_listener_candidate,
)
from repocache.server_derived_catalog_candidate_v1 import (
    preview_derived_catalog_from_nginx_dump,
)
from repocache.server_proposed_state_v2_store import (
    V2_STATE, MAX_V2_STATE_BYTES, _legacy_refusal, _pending, _read_v2,
    _refuse_actual_root_fixture_write, _shadow_multi_resource_pending,
)
from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _walk, _recheck,
)
from repocache.server_protected_state_store_v1 import (
    _canonical, _json, _locked, _read_file, _unlink_known,
    _recheck_after_mutation,
    _write_exclusive,
)
from repocache.server_root_control_fixed_candidate_v1 import (
    _load_private_under_root,
)
from repocache.server_root_control_full_context_v1 import (
    _capture_default_nginx_dump_private, _capture_owned_nginx_dump_private,
    _OWNED_MAIN_PATH, _OWNED_INCLUDE_PATH, FixedNginxFullContextError,
)
from repocache.server_root_control_host_preflight_v1 import (
    require_socket_worker_host_preconditions,
    _path_snapshot,
)
from repocache.server_root_control_worker_v1 import (
    require_installed_control_receipt, RootControlWorkerError, _metadata_no_acl,
)
from repocache.server_root_control_pinned_tls_pair_v1 import (
    _inspect_pinned_tls_pair_for_future_transaction,
)
from repocache.server_root_control_native_syntax_v1 import (
    inspect_installed_default_nginx_syntax_only,
)
from repocache.server_upstream_rotation_v1 import (
    UpstreamRotationError, propose_automatic_upstream_refresh,
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
# Separate on-disk domain: the legacy reader must never interpret a
# dedicated main-config rollback as a vendor include-only rollback.
_OWNED_DIR = ("etc", "nginx", "repocache.d")
_OWNED_MAIN = "repocache.conf"
_OWNED_MANIFEST = ".state-v2-owned-nginx.manifest"
_OWNED_WAL = ".state-v2-owned-nginx.pending"
_OWNED_WAL_TMP = ".state-v2-owned-nginx.pending-tmp"
_OWNED_ORDER = (V2_STATE, _OWNED_MAIN, _INCLUDE, _CATALOG, _OWNED_MANIFEST)
_OWNED_LIMIT = {V2_STATE: _LIMIT[V2_STATE], _OWNED_MAIN: 4096,
                _INCLUDE: _LIMIT[_INCLUDE], _CATALOG: _LIMIT[_CATALOG],
                _OWNED_MANIFEST: _LIMIT[_MANIFEST]}
_OWNED_WAL_DOMAIN = "repocache-nginx.service"
_OWNED_STAGES = {
    V2_STATE: ".state-v2-owned-nginx.state-stage",
    _OWNED_MAIN: ".repocache-owned-main.stage",
    _INCLUDE: ".repocache-owned-include.stage",
    _CATALOG: ".repocache-owned-catalog.stage",
    _OWNED_MANIFEST: ".state-v2-owned-nginx.manifest-stage",
}
_OWNED_PRIVATE = (V2_STATE, _OWNED_MANIFEST)
_NGINX = "/usr/sbin/nginx"
_SYSTEMCTL = "/usr/bin/systemctl"
_UNIT = "nginx.service"
# These paths are disjoint from the vendor's default auto-included conf.d.
# The bootstrap bytes are also the exact signed archive member used by the
# installer. Never change them without an explicit signed ownership migration.
_OWNED_BOOTSTRAP_CONFIG = "# Authenticated bootstrap only. Never include the vendor's nginx.conf.\n# The fixed local endpoint has no repository routes, TLS or external listener.\n# Full managed TLS/route activation remains a separate guarded transaction.\npid /run/repocache-nginx/nginx.pid;\nerror_log stderr warn;\nworker_processes 1;\nevents {\n    worker_connections 128;\n}\nhttp {\n    access_log off;\n    server {\n        listen 127.0.0.1:8008;\n        server_name localhost;\n        location = /__repocache/private {\n            return 204;\n        }\n        location / {\n            return 404;\n        }\n    }\n}\n".encode("ascii")
_OWNED_MANAGED_CONTEXT = (
    b"pid /run/repocache-nginx/nginx.pid;\n"
    b"error_log stderr warn;\n"
    b"worker_processes 1;\n"
    b"events {\n    worker_connections 128;\n}\n"
    b"http {\n    access_log off;\n"
    b"    include /etc/nginx/repocache.d/repocache-managed.conf;\n}\n"
)
# The distro package's build-time default can be nobody instead of the
# stock service account. Bind the same fixed non-root user/group as storage.
# Keep signed loopback bootstrap bytes unchanged; managed context is WAL-bound.
_OWNED_MANAGED_CONFIGS = {
    distribution: (b"# REPOCACHE dedicated managed NGINX context v1\n"
                   + directive + _OWNED_MANAGED_CONTEXT)
    for distribution, directive in (
        ("debian", b"user www-data www-data;\n"),
        ("almalinux", b"user nginx nginx;\n"),
    )
}
# Default only for pure Debian filesystem/parser fixtures, never native selection.
_OWNED_MANAGED_CONFIG = _OWNED_MANAGED_CONFIGS["debian"]


def _owned_managed_config(distribution: str) -> bytes:
    if type(distribution) is not str or distribution not in _OWNED_MANAGED_CONFIGS:
        _deny("DISTRIBUTION_UNSUPPORTED")
    return _OWNED_MANAGED_CONFIGS[distribution]


_ENV = {"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"}
_HEALTH = "/__repocache/healthz"
_DNS_CHILD_ID = 65534  # Unprivileged nobody identity on both supported distros.
_DNS_BUDGET_SECONDS = 45
_CA = {"debian": "/etc/ssl/certs/ca-certificates.crt",
       "almalinux": "/etc/pki/tls/certs/ca-bundle.crt"}


class NativeV2TransactionError(ValueError):
    """Only stable redacted codes; never forward configuration or TLS bytes."""


def _deny(code: str) -> None:
    raise NativeV2TransactionError("NATIVE_V2_" + code)


# Closed, first-party diagnostic vocabulary. Never render arbitrary exception
# text, paths, NGINX output, request fields or configuration into the journal.
_AUDIT_FAILURE_CODES = frozenset({
    "NATIVE_V2_CANDIDATE_CHANGED",
    "NATIVE_V2_CANDIDATE_INVALID",
    "NATIVE_V2_CATALOG_DRIFT",
    "NATIVE_V2_CATALOG_EXPOSURE_UNVERIFIED",
    "NATIVE_V2_CATALOG_MISMATCH",
    "NATIVE_V2_COMMAND_FAILED",
    "NATIVE_V2_COMMAND_REFUSED",
    "NATIVE_V2_COMMAND_UNAVAILABLE",
    "NATIVE_V2_DNS_UNVERIFIED",
    "NATIVE_V2_EXPOSURE_OVERSIZE",
    "NATIVE_V2_EXPOSURE_TIMEOUT",
    "NATIVE_V2_EXPOSURE_TLS_LEAF_MISMATCH",
    "NATIVE_V2_EXPOSURE_UNVERIFIED",
    "NATIVE_V2_FOREIGN_BOOTSTRAP_RESOURCE",
    "NATIVE_V2_FOREIGN_PENDING",
    "NATIVE_V2_FOREIGN_RESOURCE_DRIFT",
    "NATIVE_V2_FOREIGN_STAGE",
    "NATIVE_V2_FOREIGN_UNIT",
    "NATIVE_V2_HOST_CONTEXT_INVALID",
    "NATIVE_V2_HOST_OPERATION_REFUSED",
    "NATIVE_V2_NATIVE_PACKAGE_COMPLETION_REQUIRED",
    "NATIVE_V2_NATIVE_PACKAGE_INTEGRITY_CHANGED",
    "NATIVE_V2_NATIVE_PACKAGE_PROVENANCE_UNVERIFIED",
    "NATIVE_V2_NATIVE_PACKAGE_UNIT_CHANGED",
    "NATIVE_V2_ORPHAN_STAGE",
    "NATIVE_V2_OWNED_CONTEXT_CANDIDATE_INVALID",
    "NATIVE_V2_OWNED_CONTEXT_CLAIM_CHANGED",
    "NATIVE_V2_OWNED_CONTEXT_CLAIM_REQUIRED",
    "NATIVE_V2_OWNED_CONTEXT_DUMP_INVALID",
    "NATIVE_V2_OWNED_CONTEXT_DUMP_MISMATCH",
    "NATIVE_V2_OWNED_CONTEXT_FILE_DRIFT",
    "NATIVE_V2_OWNED_CONTEXT_LAYOUT_UNSUPPORTED",
    "NATIVE_V2_OWNED_CONTEXT_PROBE_REFUSED",
    "NATIVE_V2_OWNED_DIRECTORY_FOREIGN_ENTRY",
    "NATIVE_V2_OWNED_DIRECTORY_MODE_UNSAFE",
    "NATIVE_V2_OWNED_LIVE_APPLY_RECOVERY_REQUIRED",
    "NATIVE_V2_OWNED_LIVE_APPLY_ROLLED_BACK",
    "NATIVE_V2_OWNED_LIVE_BOOTSTRAP_DRIFT",
    "NATIVE_V2_OWNED_LIVE_CATALOG_REQUIRED",
    "NATIVE_V2_OWNED_LIVE_CATALOG_UNVERIFIED",
    "NATIVE_V2_OWNED_LIVE_COMMIT_DRIFT",
    "NATIVE_V2_OWNED_LIVE_GENERATION_UNVERIFIED",
    "NATIVE_V2_OWNED_LIVE_LISTENER_CHANGED",
    "NATIVE_V2_OWNED_LIVE_LISTENER_FD_INVALID",
    "NATIVE_V2_OWNED_LIVE_LISTENER_FD_LIMIT",
    "NATIVE_V2_OWNED_LIVE_LISTENER_NAMESPACE_CHANGED",
    "NATIVE_V2_OWNED_LIVE_LISTENER_PROCESS_CHANGED",
    "NATIVE_V2_OWNED_LIVE_LISTENER_TABLE_INVALID",
    "NATIVE_V2_OWNED_LIVE_LISTENER_UNVERIFIED",
    "NATIVE_V2_OWNED_LIVE_POST_RELOAD_DRIFT",
    "NATIVE_V2_OWNED_LIVE_PRE_RELOAD_DRIFT",
    "NATIVE_V2_OWNED_LIVE_RECOVERY_DRIFT",
    "NATIVE_V2_OWNED_LIVE_RELOAD_FAILED",
    "NATIVE_V2_OWNED_LIVE_RELOAD_UNAVAILABLE",
    "NATIVE_V2_OWNED_LIVE_RESOURCE_DRIFT",
    "NATIVE_V2_OWNED_LIVE_TLS_CHANGED",
    "NATIVE_V2_OWNED_LIVE_UNIT_CHANGED",
    "NATIVE_V2_OWNED_LIVE_UNIT_UNVERIFIED",
    "NATIVE_V2_OWNED_LIVE_WAL_REQUIRED",
    "NATIVE_V2_OWNED_LIVE_WAL_REQUIRES_RUNTIME_RECOVERY",
    "NATIVE_V2_OWNED_NGINX_TRANSITION_REQUIRED",
    "NATIVE_V2_OWNED_SOCKET_ACTIVE_STORAGE_UNVERIFIED",
    "NATIVE_V2_OWNED_SOCKET_ATOMIC_WRITE_BOUNDARY_UNVERIFIED",
    "NATIVE_V2_OWNED_SOCKET_CONFIG_LABEL_UNVERIFIED",
    "NATIVE_V2_OWNED_SOCKET_CONFIG_METADATA_UNVERIFIED",
    "NATIVE_V2_OWNED_SOCKET_HOST_BOUNDARY_REFUSED",
    "NATIVE_V2_OWNED_SOCKET_MOUNT_VIEW_CHANGED",
    "NATIVE_V2_OWNED_SOCKET_RECOVERY_UNVERIFIED",
    "NATIVE_V2_OWNED_SOCKET_RESULT_UNVERIFIED",
    "NATIVE_V2_OWNED_SOCKET_SELINUX_REQUIRED",
    "NATIVE_V2_OWNED_SOCKET_STORAGE_UNVERIFIED",
    "NATIVE_V2_OWNED_SOCKET_VENDOR_STATE_REFUSED",
    "NATIVE_V2_OWNED_SOCKET_WRITE_BOUNDARY_REFUSED",
    "NATIVE_V2_OWNED_WAL_APPLY_FILES_RESTORED",
    "NATIVE_V2_OWNED_WAL_APPLY_RECOVERY_REQUIRED",
    "NATIVE_V2_OWNED_WAL_BOOTSTRAP_DRIFT",
    "NATIVE_V2_OWNED_WAL_CANDIDATE_REQUIRED",
    "NATIVE_V2_OWNED_WAL_CHANGED",
    "NATIVE_V2_OWNED_WAL_COMMIT_DRIFT",
    "NATIVE_V2_OWNED_WAL_CONFLICTING_RECORDS",
    "NATIVE_V2_OWNED_WAL_DOMAIN_REQUIRED",
    "NATIVE_V2_OWNED_WAL_DOMAIN_UNVERIFIED",
    "NATIVE_V2_OWNED_WAL_FOREIGN_DRIFT",
    "NATIVE_V2_OWNED_WAL_GENERATION_INVALID",
    "NATIVE_V2_OWNED_WAL_INVALID",
    "NATIVE_V2_OWNED_WAL_LAYOUT_UNSUPPORTED",
    "NATIVE_V2_OWNED_WAL_MANAGED_IDENTITY_CHANGED",
    "NATIVE_V2_OWNED_WAL_MANIFEST_DRIFT",
    "NATIVE_V2_OWNED_WAL_PREPARE_DRIFT",
    "NATIVE_V2_OWNED_WAL_RESOURCES_INVALID",
    "NATIVE_V2_OWNED_WAL_RESTORE_DRIFT",
    "NATIVE_V2_OWNED_WAL_UNPUBLISHED_DRIFT",
    "NATIVE_V2_OWNED_WAL_VENDOR_DOMAIN_CONFLICT",
    "NATIVE_V2_PROTECTED_DRIFT",
    "NATIVE_V2_PROTECTED_WRITE_FAILED",
    "NATIVE_V2_RESOURCE_CHANGED",
    "NATIVE_V2_RESOURCE_DRIFT",
    "NATIVE_V2_RESOURCE_SIZE",
    "NATIVE_V2_RESOURCE_UNAVAILABLE",
    "NATIVE_V2_RESOURCE_UNSAFE",
    "NATIVE_V2_RESOURCE_WRITE_FAILED",
    "NATIVE_V2_STAGE_UNAVAILABLE",
    "NATIVE_V2_STAGE_WRITE_FAILED",
    "NATIVE_V2_STATE_CHANGED",
    "NATIVE_V2_STATE_STALE",
    "NATIVE_V2_TLS_FILE_UNAVAILABLE",
    "NATIVE_V2_TLS_IDENTITY_INVALID",
    "NATIVE_V2_TLS_PAIR_INVALID",
    "NATIVE_V2_TLS_PATH_CHANGED",
    "NATIVE_V2_TLS_PATH_REFUSED",
    "NATIVE_V2_WAL_CHANGED",
    "NATIVE_V2_WAL_INVALID",
    "NATIVE_V2_WAL_UNAVAILABLE",
})


def _audit_native_failure(exc: BaseException) -> None:
    """Best-effort local service journal diagnostic, never a protocol field."""
    code = "NATIVE_V2_OTHER_REFUSAL"
    if (type(exc) is NativeV2TransactionError and len(exc.args) == 1
            and type(exc.args[0]) is str and exc.args[0] in _AUDIT_FAILURE_CODES):
        code = exc.args[0]
    try:
        print("REPOCACHE_FIXED_TRANSACTION_REFUSAL: " + code,
              file=sys.stderr, flush=True)
    except (OSError, ValueError):
        # Losing a diagnostic must not prevent rollback or change refusal.
        pass


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
                  after: bytes | None, maximum: int, *, stage: str = _STAGE) -> None:
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
    if _read_public(parent, stage, maximum) is not None:
        _deny("ORPHAN_STAGE")
    try:
        fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                     | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                     0o600, dir_fd=parent)
    except OSError:
        _deny("STAGE_UNAVAILABLE")
    try:
        try:
            # Leave the temporary 0600 until all candidate bytes are fully
            # durable. A crash during writing leaves a recognizably unfinished
            # fixed stage which the WAL-backed recovery can safely discard.
            position = 0
            while position < len(after):
                count = os.write(fd, after[position:])
                if count <= 0:
                    _deny("STAGE_WRITE_FAILED")
                position += count
            os.fsync(fd)
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        except OSError:
            _deny("STAGE_WRITE_FAILED")
    finally:
        os.close(fd)
    try:
        if _read_public(parent, name, maximum) != before:
            _deny("RESOURCE_DRIFT")
        os.replace(stage, name, src_dir_fd=parent, dst_dir_fd=parent)
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
                != {"schema", "repositories"}
                or type(catalog["schema"]) is not int
                or catalog["schema"] != 1
                or type(catalog["repositories"]) is not list):
            _deny("CATALOG_DRIFT")
        document = parse_install_bytes(
            base64.b64decode(snapshot["configuration_base64"], validate=True),
            for_apply=True,
        )
        listen = document["deployment"]["listen"]
        origin = "https://" + listen["hostname"] + (
            "" if listen["https_port"] == 443
            else ":" + str(listen["https_port"])
        )
        expected = sorted((
            {"upstream": repo["upstream"]["base_url"],
             "cache": origin + "/__repocache/repos/" + repo["id"] + "/"}
            for repo in document["repositories"]
            if repo["desired_state"] == "active"
        ), key=lambda row: (row["upstream"], row["cache"]))
        if catalog["repositories"] != expected:
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


def _refuse_owned_nginx_transaction_artifacts(state_fd: int) -> None:
    """No legacy or bootstrap operation may consume an owned-domain WAL."""
    for name in (_OWNED_WAL, _OWNED_WAL_TMP, _OWNED_MANIFEST,
                 *(_OWNED_STAGES[key] for key in _OWNED_PRIVATE)):
        try:
            os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            _deny("OWNED_WAL_DOMAIN_UNVERIFIED")
        _deny("OWNED_WAL_DOMAIN_REQUIRED")


def _no_conflicting_pending(state_fd: int) -> None:
    _refuse_owned_nginx_transaction_artifacts(state_fd)
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


def _cleanup_stage(parent: int, maximum: int, new_shas: set[str], *,
                   stage: str = _STAGE, remove: bool = True) -> None:
    """Discard known fixed stage only after verifying its on-disk identity.

    Before the final chmod a crash leaves a partial 0600 root-owned inode.
    A completed 0644 stage must exactly match the WAL-recorded next digest.
    Symlink, hardlink, foreign owner, unexpected mode/dev/size always refuses.
    """
    try:
        named = os.stat(stage, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        _deny("FOREIGN_STAGE")
    try:
        before = os.stat(stage, dir_fd=parent, follow_symlinks=False)
        directory = os.fstat(parent)
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or before.st_dev != directory.st_dev
                or mode not in (0o600, 0o644)
                or not 0 <= before.st_size <= maximum
                or _identity(named) != _identity(before)):
            _deny("FOREIGN_STAGE")
        if mode == 0o644:
            raw = _read_public(parent, stage, maximum)
            if raw is None or _hash(raw) not in new_shas:
                _deny("FOREIGN_STAGE")
        # A 0600 stage cannot be complete/published: its contents may be
        # empty/partial, but this exact root-owned staging path is safe to
        # discard while a validated durable WAL protects the old targets.
        if _identity(before) != _identity(
                os.stat(stage, dir_fd=parent, follow_symlinks=False)):
            _deny("FOREIGN_STAGE")
        if remove:
            os.unlink(stage, dir_fd=parent)
            os.fsync(parent)
    except NativeV2TransactionError:
        raise
    except OSError:
        _deny("FOREIGN_STAGE")


def _cleanup_private_stage(state_fd: int, name: str, maximum: int,
                           next_shas: set[str]) -> None:
    """Discard only the fixed root-owned private stage under verified WAL.

    The durable WAL is written before these stages. SIGKILL during
    _write_exclusive may leave a partial 0600 file: its content is not a
    committed target or authority, and must not strand valid recovery.
    """
    raw = _read_file(state_fd, name, 0, maximum)
    if raw is not None:
        # Verify exact owned file metadata with _read_file, including no
        # hardlink, symlink or writable mode. The journal and target SHA
        # constraints have already been validated before this cleanup.
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


def _require_active_nginx_before_wal(distribution: str) -> None:
    """Refuse an inactive or foreign NGINX service before persistent changes.

    A clean native package install deliberately leaves nginx.service stopped
    and disabled. APPLY_V2 must not write a WAL or a managed include and only
    *then* discover that reload is impossible. This read-only observation
    never starts/unmasks/enables a service; later reload rechecks the unit.
    """
    try:
        observed = inspect_effective_native_nginx_unit(distribution)
    except (EffectiveNginxUnitError, NginxServiceUnitInspectionError,
            OSError, ValueError, TypeError):
        _deny("NGINX_NOT_ACTIVE_BEFORE_WAL")
    if (type(observed) is not dict
            or observed.get("status")
                != "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION"
            or observed.get("unit_name") != _UNIT
            or type(observed.get("main_pid_observed")) is not int
            or observed["main_pid_observed"] <= 0
            or observed.get("kernel_nginx_master_executable_inode_observed") is not True
            or observed.get("effective_unit_shape_observed") is not True
            or type(observed.get("vendor_unit_sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", observed["vendor_unit_sha256"]) is None
            or observed.get("authorizes_systemctl") is not False
            or observed.get("authorizes_nginx_reload") is not False):
        _deny("NGINX_NOT_ACTIVE_BEFORE_WAL")


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


def _fixed_https_get(document: dict[str, Any], path: str,
                     maximum: int, *, expected_leaf_sha256: str | None = None) -> bytes:
    """Bounded verified-TLS local request, exact health/catalog paths only."""
    if path not in (_HEALTH, "/.well-known/repocache/catalog.json"):
        _deny("HTTP_PATH_REFUSED")
    address = document["deployment"]["listen"]["bind_address"]
    hostname = document["deployment"]["listen"]["hostname"]
    port = document["deployment"]["listen"]["https_port"]
    if address in ("0.0.0.0", "::"):
        address = "127.0.0.1" if address == "0.0.0.0" else "::1"
    request = (
        "GET " + path + " HTTP/1.1\r\nHost: " + hostname
        + "\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((address, port), timeout=4) as tcp:
            with context.wrap_socket(tcp, server_hostname=hostname) as tls:
                if expected_leaf_sha256 is not None:
                    leaf = tls.getpeercert(binary_form=True)
                    if (not _valid_sha(expected_leaf_sha256)
                            or type(leaf) is not bytes
                            or _hash(leaf) != expected_leaf_sha256):
                        _deny("EXPOSURE_TLS_LEAF_MISMATCH")
                tls.settimeout(4)
                tls.sendall(request)
                fragments = []
                size = 0
                deadline = time.monotonic() + 10.0
                while size <= maximum:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        _deny("EXPOSURE_TIMEOUT")
                    tls.settimeout(min(4.0, remaining))
                    chunk = tls.recv(min(8192, maximum + 1 - size))
                    if not chunk:
                        break
                    fragments.append(chunk)
                    size += len(chunk)
    except (OSError, ValueError, ssl.SSLError, TimeoutError):
        _deny("EXPOSURE_UNVERIFIED")
    if size > maximum:
        _deny("EXPOSURE_OVERSIZE")
    raw = b"".join(fragments)
    if b"\r\n\r\n" not in raw:
        _deny("EXPOSURE_UNVERIFIED")
    return raw


def _local_https_generation(document: dict[str, Any], generation: int) -> None:
    response = _fixed_https_get(document, _HEALTH, 8192)
    header, body = response.split(b"\r\n\r\n", 1)
    marker = f"X-Repocache-Generation: {generation}".encode("ascii").lower()
    if (not header.startswith(b"HTTP/1.1 204 ")
            or marker not in header.lower().split(b"\r\n")
            or body):
        _deny("EXPOSURE_UNVERIFIED")


def _local_https_catalog(document: dict[str, Any], catalog: bytes) -> None:
    response = _fixed_https_get(
        document, "/.well-known/repocache/catalog.json",
        _LIMIT[_CATALOG] + 8192,
    )
    header, body = response.split(b"\r\n\r\n", 1)
    lines = header.lower().split(b"\r\n")
    length = b"content-length: " + str(len(catalog)).encode("ascii")
    if (not header.startswith(b"HTTP/1.1 200 ")
            or lines.count(length) != 1
            or any(line.startswith((b"transfer-encoding:", b"content-encoding:"))
                   for line in lines)
            or body != catalog):
        _deny("CATALOG_EXPOSURE_UNVERIFIED")


def _verify_tls_pair(root_fd: int, document: dict[str, Any], *,
                     verify_identity: bool = False) -> str | None:
    """Open real root-owned cert/key without symlinks and verify exact pair.

    Absolute paths originate in the *independently root-owned*, full-schema
    candidate, not any socket request. All path ancestors must be root-owned
    and non-writable by non-root. Pinned FDs stay open through OpenSSL load.
    """
    tls = document["deployment"]["tls"]
    paths = (tls["certificate_file"], tls["private_key_file"])
    opened: list[int] = []
    pinned_paths = []
    with ExitStack() as stack:
        for path in paths:
            if (type(path) is not str or not path.startswith("/")
                    or "//" in path or path.endswith("/")
                    or any(part in ("", ".", "..") for part in path[1:].split("/"))):
                _deny("TLS_PATH_REFUSED")
            segments = path[1:].split("/")
            parent_fd, chain = _walk(
                root_fd, tuple(segments[:-1]), stack, 0,
            )
            try:
                fd = os.open(
                    segments[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                    | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd,
                )
            except OSError:
                _deny("TLS_FILE_UNAVAILABLE")
            stack.callback(os.close, fd)
            opened.append(fd)
            _recheck(chain, 0)
            if verify_identity:
                # Mode bits alone do not exclude POSIX ACLs on the key or
                # writable/default ACLs on its root-owned ancestors.
                for _, _, ancestor, _ in chain:
                    _metadata_no_acl(ancestor, directory=True)
                _metadata_no_acl(fd)
            pinned_paths.append((parent_fd, segments[-1], fd, chain, _identity(os.fstat(fd))))
        try:
            report = _inspect_pinned_tls_pair_for_future_transaction(
                opened[0], opened[1], expected_owner_uid=0,
                **({"expected_hostname": document["deployment"]["listen"]["hostname"]}
                   if verify_identity else {}),
            )
        except (OSError, TypeError, ValueError):
            _deny("TLS_PAIR_INVALID")
        if (report.get("status") != "PINNED_OPEN_FD_CERT_KEY_PAIR_ONLY"
                or report.get("private_key_pair_load_observed") is not True
                or report.get("authorizes_nginx_reload") is not False):
            _deny("TLS_PAIR_INVALID")
        if verify_identity:
            for parent, name, fd, chain, before in pinned_paths:
                if (_identity(os.fstat(fd)) != before or
                        _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before):
                    _deny("TLS_PATH_CHANGED")
                _recheck(chain, 0)
            leaf = report.get("private_verified_leaf_der_sha256")
            if (report.get("certificate_issuer_hostname_expiry_verified") is not True
                    or not _valid_sha(leaf)):
                _deny("TLS_IDENTITY_INVALID")
            return leaf
        return None


def _resolve_pins(document: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    """Resolve approved names with the shared policy and a bounded nonroot child."""
    answers = {}
    deadline = time.monotonic() + _DNS_BUDGET_SECONDS

    def lookup(host: str, port: int, **socket_parameters: int) -> list:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.gaierror("DNS worker: transaction deadline")
        return bounded_getaddrinfo(
            host, port, timeout_seconds=min(remaining, DEFAULT_DNS_SECONDS),
            run_as_uid=_DNS_CHILD_ID, run_as_gid=_DNS_CHILD_ID, **socket_parameters,
        )

    for repository in document["repositories"]:
        if repository["desired_state"] != "active":
            continue
        rid = repository["id"]
        try:
            proposal = propose_automatic_upstream_refresh(
                document, repository_id=rid,
                current_generation=document["expected_state_generation"],
                previous_pins_by_host=None, resolver=lookup,
            )
        except UpstreamRotationError:
            _deny("DNS_UNVERIFIED")
        answers[rid] = proposal["candidate_pins_by_host"]
    return answers


def _route_dump_check(document: dict, include: bytes, catalog: bytes,
                      distribution: str, generation: int,
                      pins: dict) -> None:
    """Private fixed native -T must match exact staged bytes and catalog."""
    try:
        dump = _capture_default_nginx_dump_private()
        # A matching byte substring in another file or comment does not
        # prove the *fixed managed include* is actually loaded. Require the
        # unique, exact -T section before deriving the public catalog.
        _verify_owned_include_in_dump(include, captured_dump=dump)
        text = dump.decode("utf-8", "strict")
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


def _verify_owned_include_in_dump(
    include: bytes | None, *, captured_dump: bytes | None = None,
) -> None:
    """Match native -T to the exact managed include, including absence.

    Apply, explicit reload and WAL recovery share the strict identity check.
    Recovery must verify no managed section after rolling back an initial
    installation, or the exact prior section after a managed update.
    """
    header = b"/etc/nginx/conf.d/repocache-managed.conf:\n"
    dump = (_capture_default_nginx_dump_private()
            if captured_dump is None else captured_dump)
    sections = re.split(rb"(?m)^# configuration file ", dump)[1:]
    managed = [section[len(header):] for section in sections if section.startswith(header)]
    if include is None:
        # A failed first install must restore an *absent* managed include;
        # foreign configuration must not reintroduce it before WAL cleanup.
        if managed:
            _deny("NGINX_DUMP_MISMATCH")
    elif len(managed) != 1 or managed[0] not in (include, include + b"\n"):
        _deny("NGINX_DUMP_MISMATCH")


def _reload_owned_locked(
    root_fd: int, state_fd: int, include_fd: int, public_fd: int, distribution: str,
) -> dict:
    """Reload only the last verified committed generation, without staging files."""
    _no_conflicting_pending(state_fd)
    old = _read_all(state_fd, include_fd, public_fd)
    _verify_owned(old)
    snapshot, raw = _read_v2(state_fd, 0)
    if snapshot is None or raw != old[V2_STATE]:
        _deny("MANAGED_GENERATION_REQUIRED")
    document = parse_install_bytes(
        base64.b64decode(snapshot["configuration_base64"], validate=True), for_apply=True,
    )
    generation = snapshot["state_generation"]
    _verify_tls_pair(root_fd, document)
    _local_https_generation(document, generation)
    _local_https_catalog(document, old[_CATALOG])
    _native_syntax_check()
    _verify_owned_include_in_dump(old[_INCLUDE])
    if _read_all(state_fd, include_fd, public_fd) != old:
        _deny("PRE_RELOAD_DRIFT")
    # NGINX reloads the same known-good generation. There are no staged
    # state/catalog bytes to promote, restore or mark committed on failure.
    _reload_native(distribution)
    _local_https_generation(document, generation)
    _local_https_catalog(document, old[_CATALOG])
    # The reloaded service is not allowed to report success if the fixed
    # NGINX -T include section changed during reload, even when the saved
    # state/catalog bytes and the generation health endpoint still match.
    # This is a refusal to certify success, not authority to mutate or
    # compensate an independently changed host configuration.
    _verify_owned_include_in_dump(old[_INCLUDE])
    if _read_all(state_fd, include_fd, public_fd) != old:
        _deny("POST_RELOAD_DRIFT")
    return {"status": "NATIVE_V2_RELOADED", "state_generation": generation}


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
    if candidate == previous_raw and report["expected_generation"] == generation - 1:
        # A completed request remains at the fixed intake path. Retrying it
        # acknowledges only the exact owned bytes already committed above.
        again, again_candidate = _load_private_under_root(
            root_fd, owner_uid=0, owner_gid=0,
        )
        if again != report or again_candidate != candidate:
            _deny("CANDIDATE_CHANGED")
        # An idempotent replay must not certify working exposure solely
        # from saved bytes. The service may be stopped, serving a stale
        # generation, or loading a foreign effective managed include.
        document = parse_install_bytes(
            base64.b64decode(previous["configuration_base64"], validate=True),
            for_apply=True,
        )
        _verify_tls_pair(root_fd, document)
        _verify_owned_include_in_dump(old[_INCLUDE])
        _local_https_generation(document, generation)
        _local_https_catalog(document, old[_CATALOG])
        if _read_all(state_fd, include_fd, public_fd) != old:
            _deny("PREPARE_DRIFT")
        return {"status": "NATIVE_V2_NO_CHANGE", "state_generation": generation}
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
        _verify_tls_pair(root_fd, doc)
        pins = _resolve_pins(doc)
        bundle = render_repository_nginx_bundle_candidate(
            doc, expected_state_generation=snapshot["state_generation"],
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
    # Re-read candidate before publishing any WAL or file.
    again, again_candidate = _load_private_under_root(
        root_fd, owner_uid=0, owner_gid=0,
    )
    if again != report or again_candidate != candidate:
        _deny("CANDIDATE_CHANGED")
    if _read_all(state_fd, include_fd, public_fd) != old:
        _deny("PREPARE_DRIFT")

    # The authenticated native installer intentionally leaves nginx.service
    # inactive. Reject an unsafe early APPLY before writing any durable WAL,
    # include, state or catalog. Fixture tests supply a synthetic reload.
    if not fixture:
        _require_active_nginx_before_wal(distribution)

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
        # Verify the unique, byte-exact managed include and its derived
        # catalog BEFORE asking systemd to activate candidate NGINX config.
        # Reject foreign/duplicated includes without reloading the candidate;
        # the WAL still restores the previous known-good generation.
        _route_dump_check(doc, new[_INCLUDE], new[_CATALOG],
                          distribution, snapshot["state_generation"], pins)
        _reload_native(distribution)
        # Exactly one fixed generation health endpoint must have become live.
        _local_https_generation(doc, snapshot["state_generation"])
        # Reobserve AFTER the actual reload: the pre-reload dump alone cannot
        # prove that another privileged actor left the include unchanged.
        _route_dump_check(doc, new[_INCLUDE], new[_CATALOG],
                          distribution, snapshot["state_generation"], pins)
        # Never publish before observing the new real route generation.
        _write_public(public_fd, _CATALOG, old[_CATALOG],
                      new[_CATALOG], _LIMIT[_CATALOG])
        _local_https_catalog(doc, new[_CATALOG])
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
    # Reuse the approved strict listener for actual v2 NGINX state.
    # The manual include previously omitted explicit TLS protocol restrictions,
    # session ticket refusal and hidden NGINX version headers.
    try:
        tls = render_native_tls_listener_candidate(document)
    except (NativeTLSListenerCandidateError, ValueError, TypeError):
        _deny("NGINX_TLS_CANDIDATE_INVALID")
    if (tls.get("status") != "NATIVE_TLS_LISTENER_CANDIDATE_ONLY"
            or tls.get("authorizes_nginx_activation") is not False
            or tls.get("authorizes_firewall_change") is not False):
        _deny("NGINX_TLS_CANDIDATE_UNTRUSTED")
    include = (
        "# REPOCACHE managed v2\n"
        + bundle["http_upstream_fragment"]
        + "\nserver {\n"
        + tls["server_context_fragment"]
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


def _render_owned_managed_candidate(
    document: dict[str, Any], next_generation: int, distribution: str,
    pins: dict[str, dict[str, list[str]]],
) -> tuple[bytes, bytes, bytes]:
    """Pure candidate for the independent service; no installed-file authority.

    The legacy document path is refused, not silently redirected. Only the
    reviewed fixed dedicated path is eligible. The returned main config is
    distinct from the signed private bootstrap; a future WAL must bind both
    the transition and the generated include before any write or reload.
    """
    try:
        if (type(distribution) is not str or distribution not in _CA
                or type(next_generation) is not int or next_generation < 1):
            _deny("OWNED_CONTEXT_CANDIDATE_INVALID")
        validated = validate_install_document(document, for_apply=True)
        paths = validated["deployment"]["paths"]
        if (paths["generated_include"] != _OWNED_INCLUDE_PATH
                or paths["state_root"] != "/var/lib/repocache/server"
                or (any(row["desired_state"] == "active" for row in validated["repositories"])
                    and (paths["cache_root"] != "/var/cache/nginx/repocache-managed"
                         or paths["log_root"] != "/var/log/nginx/repocache-managed"))):
            _deny("OWNED_CONTEXT_LAYOUT_UNSUPPORTED")
        bundle = render_repository_nginx_bundle_candidate(
            validated, expected_state_generation=next_generation,
            candidate_pins_by_repository=pins, ca_bundle_path=_CA[distribution],
        )
        include, catalog, _, _ = _render_using_pins(
            validated, next_generation, distribution, pins, bundle,
        )
        return _owned_managed_config(distribution), include, catalog
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        _deny("OWNED_CONTEXT_CANDIDATE_INVALID")


def _verify_owned_context_dump(dump: bytes, include: bytes | None, *,
                               managed_main: bytes | None = None) -> None:
    """Check the entire fixed main/include dump against exact expected bytes.

    None represents the original signed loopback bootstrap. A managed
    candidate must have exactly one dedicated include section, no default
    config, no extra included files and no foreign directives in the main
    file. Native nginx -T appends a separator newline to dumped files.
    This pure comparison is not proof of native execution, installed-file
    provenance, a running service or permission to activate anything.
    """
    if type(dump) is not bytes or not 1 <= len(dump) <= 4 * 1024 * 1024:
        _deny("OWNED_CONTEXT_DUMP_INVALID")
    if include is not None and (
            type(include) is not bytes or not 1 <= len(include) <= _LIMIT[_INCLUDE]
            or not include.startswith(b"# REPOCACHE managed v2\n")
            or not include.endswith(b"\n") or not include.isascii()
            or b"\x00" in include or b"\r" in include
            or b"# configuration file " in include):
        _deny("OWNED_CONTEXT_DUMP_INVALID")
    if managed_main is None:
        managed_main = _OWNED_MANAGED_CONFIG
    if managed_main not in _OWNED_MANAGED_CONFIGS.values():
        _deny("OWNED_CONTEXT_DUMP_INVALID")
    main = (_OWNED_BOOTSTRAP_CONFIG if include is None else managed_main)
    head = b"# configuration file " + _OWNED_MAIN_PATH.encode("ascii") + b":\n"
    first = head + main
    if include is None:
        if dump not in (first, first + b"\n"):
            _deny("OWNED_CONTEXT_DUMP_MISMATCH")
        return
    section = (b"# configuration file " + _OWNED_INCLUDE_PATH.encode("ascii")
               + b":\n" + include)
    # Permit only the native section-separator newline; every other byte and
    # the order/count of sections must match the fixed complete context.
    if not any(dump == first + gap + section + tail
               for gap in (b"", b"\n") for tail in (b"", b"\n")):
        _deny("OWNED_CONTEXT_DUMP_MISMATCH")


def _owned_config_marker_identity(state_fd: int) -> tuple[int, ...]:
    """Observe the exact existing installer claim, not a new/adopted marker."""
    name = (OWNED_NGINX_CONFIG_MARKER_PREFIX
            + hashlib.sha256(b"/etc/nginx/repocache.d/\0" + _OWNED_BOOTSTRAP_CONFIG).hexdigest())
    try:
        claims = sorted(entry for entry in os.listdir(state_fd)
                        if entry.startswith(OWNED_NGINX_CONFIG_MARKER_PREFIX))
        if claims != [name]:
            _deny("OWNED_CONTEXT_CLAIM_REQUIRED")
        before = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        if before.st_gid != 0 or _read_file(state_fd, name, 0, 0) != b"":
            _deny("OWNED_CONTEXT_CLAIM_REQUIRED")
        after = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        if _identity(before) != _identity(after):
            _deny("OWNED_CONTEXT_CLAIM_REQUIRED")
        return _identity(after)
    except NativeV2TransactionError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("OWNED_CONTEXT_CLAIM_REQUIRED")


def _probe_owned_context_locked(
    root_fd: int, state_fd: int, include: bytes | None, *,
    managed_main: bytes | None = None,
) -> bytes:
    """Verify exact fixed private files and perform a bounded native syntax dump.

    The authenticated transaction must retain its protected lock and supply
    only renderer- or WAL-verified include bytes. This is a prerequisite for
    reload, not a reload authorization. Never expose the private dump.
    """
    if managed_main is None:
        managed_main = _OWNED_MANAGED_CONFIG
    if managed_main not in _OWNED_MANAGED_CONFIGS.values():
        _deny("OWNED_CONTEXT_DUMP_INVALID")
    expected_main = (_OWNED_BOOTSTRAP_CONFIG if include is None else managed_main)
    # Validate bounds and expected section shape before invoking native nginx.
    synthetic = (b"# configuration file " + _OWNED_MAIN_PATH.encode("ascii")
                 + b":\n" + expected_main)
    if include is not None:
        if type(include) is not bytes or len(include) > _LIMIT[_INCLUDE]:
            _deny("OWNED_CONTEXT_DUMP_INVALID")
        synthetic += (b"# configuration file " + _OWNED_INCLUDE_PATH.encode("ascii")
                      + b":\n" + include)
    _verify_owned_context_dump(synthetic, include, managed_main=managed_main)
    try:
        _verify_current_root_fd(root_fd)
        with ExitStack() as stack:
            directory, chain = _walk(root_fd, _OWNED_DIR, stack, 0)
            marker = _owned_config_marker_identity(state_fd)

            def verify_bytes() -> None:
                if (_read_public(directory, "repocache.conf", 4096) != expected_main
                        or _read_public(directory, _INCLUDE, _LIMIT[_INCLUDE]) != include):
                    _deny("OWNED_CONTEXT_FILE_DRIFT")
                _recheck(chain, 0)
                if _owned_config_marker_identity(state_fd) != marker:
                    _deny("OWNED_CONTEXT_CLAIM_CHANGED")

            verify_bytes()
            dump = _capture_owned_nginx_dump_private(managed=include is not None)
            _verify_owned_context_dump(dump, include, managed_main=managed_main)
            verify_bytes()
            _verify_current_root_fd(root_fd)
            return dump
    except NativeV2TransactionError:
        raise
    except (OSError, ValueError, TypeError, FixedNginxFullContextError):
        _deny("OWNED_CONTEXT_PROBE_REFUSED")


def _owned_manifest_for(state: bytes, main: bytes, include: bytes,
                        catalog: bytes) -> bytes:
    """Bind the separate main context and service domain to a generation."""
    return _canonical({
        "manifest_schema_version": 2,
        "status": "NATIVE_V2_OWNED_NGINX_RESOURCES",
        "service_domain": _OWNED_WAL_DOMAIN,
        "state_sha256": _hash(state),
        "main_sha256": _hash(main),
        "include_sha256": _hash(include),
        "catalog_sha256": _hash(catalog),
    }, limit=_OWNED_LIMIT[_OWNED_MANIFEST])


def _validate_owned_resources(resources: dict[str, bytes | None], *,
                              distribution: str | None = None) -> dict | None:
    """Validate closed bootstrap/managed snapshot without claiming runtime."""
    try:
        if type(resources) is not dict or set(resources) != set(_OWNED_ORDER):
            _deny("OWNED_WAL_RESOURCES_INVALID")
        for name in _OWNED_ORDER:
            raw = resources[name]
            if raw is not None and (
                    type(raw) is not bytes or not 1 <= len(raw) <= _OWNED_LIMIT[name]):
                _deny("OWNED_WAL_RESOURCES_INVALID")
        state = resources[V2_STATE]
        main = resources[_OWNED_MAIN]
        include = resources[_INCLUDE]
        catalog = resources[_CATALOG]
        manifest = resources[_OWNED_MANIFEST]
        if state is None:
            if (main != _OWNED_BOOTSTRAP_CONFIG or include is not None
                    or catalog is not None or manifest is not None):
                _deny("OWNED_WAL_BOOTSTRAP_DRIFT")
            return None
        allowed_main = (_OWNED_MANAGED_CONFIGS.values() if distribution is None
                        else (_owned_managed_config(distribution),))
        if (main not in allowed_main or include is None or catalog is None
                or manifest != _owned_manifest_for(state, main, include, catalog)):
            _deny("OWNED_WAL_MANIFEST_DRIFT")
        # Reuse closed state and active-only catalog semantics without
        # accepting a vendor manifest as ownership of the private context.
        _verify_owned({
            V2_STATE: state, _INCLUDE: include, _CATALOG: catalog,
            _MANIFEST: _manifest_for(state, include, catalog),
        })
        snapshot = _json(state, limit=_LIMIT[V2_STATE])
        doc = parse_install_bytes(
            base64.b64decode(snapshot["configuration_base64"], validate=True),
            for_apply=True,
        )
        if (doc["deployment"]["paths"]["generated_include"] != _OWNED_INCLUDE_PATH
                or doc["deployment"]["paths"]["state_root"]
                   != "/var/lib/repocache/server"):
            _deny("OWNED_WAL_LAYOUT_UNSUPPORTED")
        # A manifest pins already verified bytes, not arbitrary directives.
        # This checks the closed dump section shape; deterministic rendering
        # and authentic native exposure are still separate runtime gates.
        dump = (b"# configuration file " + _OWNED_MAIN_PATH.encode("ascii")
                + b":\n" + main + b"\n# configuration file "
                + _OWNED_INCLUDE_PATH.encode("ascii") + b":\n" + include)
        _verify_owned_context_dump(dump, include, managed_main=main)
        return snapshot
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        _deny("OWNED_WAL_RESOURCES_INVALID")


def _owned_wal_record(old: dict[str, bytes | None],
                      new: dict[str, bytes | None], *, live: bool = False) -> bytes:
    """Versioned five-resource journal, with exact rollback bytes."""
    previous = _validate_owned_resources(old)
    candidate = _validate_owned_resources(new)
    if candidate is None:
        _deny("OWNED_WAL_CANDIDATE_REQUIRED")
    if previous is not None and old[_OWNED_MAIN] != new[_OWNED_MAIN]:
        _deny("OWNED_WAL_MANAGED_IDENTITY_CHANGED")
    generation = 0 if previous is None else previous["state_generation"]
    try:
        transition = preview_proposed_v2_state_transition(
            candidate, expected_generation=generation, previous_snapshot=previous,
        )
        if transition["proposed_generation"] != generation + 1:
            _deny("OWNED_WAL_GENERATION_INVALID")
        if type(live) is not bool:
            _deny("OWNED_WAL_INVALID")
        return _canonical({
            "version": 3 if live else 2,
            **({"catalog_withdrawal": True} if live else {}),
            "service_domain": _OWNED_WAL_DOMAIN,
            "old_base64": {name: _encode(old[name]) for name in _OWNED_ORDER},
            "old_sha256": {name: _hash(old[name]) for name in _OWNED_ORDER},
            "new_sha256": {name: _hash(new[name]) for name in _OWNED_ORDER},
        }, limit=_MAX_WAL)
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        _deny("OWNED_WAL_GENERATION_INVALID")


def _decode_owned_wal(raw: bytes, *, distribution: str | None = None) -> tuple[dict, dict]:
    """Never interpret an old vendor journal as a private main-config WAL."""
    try:
        if type(raw) is not bytes:
            _deny("OWNED_WAL_INVALID")
        data = _json(raw, limit=_MAX_WAL)
        fields = {"version", "service_domain", "old_base64", "old_sha256", "new_sha256"}
        if (type(data) is not dict or type(data.get("version")) is not int
                or data["version"] not in (2, 3)
                or set(data) != (fields | {"catalog_withdrawal"}
                                 if data["version"] == 3 else fields)
                or (data["version"] == 3 and data["catalog_withdrawal"] is not True)
                or data["service_domain"] != _OWNED_WAL_DOMAIN):
            _deny("OWNED_WAL_INVALID")
        for field in ("old_base64", "old_sha256", "new_sha256"):
            if type(data[field]) is not dict or set(data[field]) != set(_OWNED_ORDER):
                _deny("OWNED_WAL_INVALID")
        old = {name: _decode(data["old_base64"][name], _OWNED_LIMIT[name])
               for name in _OWNED_ORDER}
        if (any(data["old_sha256"][name] != _hash(old[name])
                or not _valid_sha(data["new_sha256"][name])
                for name in _OWNED_ORDER)
                ):
            _deny("OWNED_WAL_INVALID")
        snapshot = _validate_owned_resources(old, distribution=distribution)
        # A managed predecessor fixes the exact worker identity for the
        # successor. For bootstrap, the trusted host selects its distro.
        allowed_main = (
            (old[_OWNED_MAIN],) if snapshot is not None
            else tuple(_OWNED_MANAGED_CONFIGS.values()) if distribution is None
            else (_owned_managed_config(distribution),)
        )
        if data["new_sha256"][_OWNED_MAIN] not in {_hash(value) for value in allowed_main}:
            _deny("OWNED_WAL_INVALID")
        return old, data["new_sha256"]
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        _deny("OWNED_WAL_INVALID")


def _owned_wal_resource_drift(old: dict, new_sha: dict, current: dict,
                              *, unpublished: bool,
                              catalog_withdrawal: bool = False) -> None:
    """Only old or candidate bytes may be reconciled after WAL publication."""
    if (type(unpublished) is not bool or type(current) is not dict
            or set(current) != set(_OWNED_ORDER)):
        _deny("OWNED_WAL_RESOURCES_INVALID")
    for name in _OWNED_ORDER:
        raw = current[name]
        if raw is not None and (
                type(raw) is not bytes or not 1 <= len(raw) <= _OWNED_LIMIT[name]):
            _deny("OWNED_WAL_RESOURCES_INVALID")
        if unpublished:
            if raw != old[name]:
                _deny("OWNED_WAL_UNPUBLISHED_DRIFT")
        elif (name == _CATALOG and raw is None and catalog_withdrawal is True):
            # The live protocol deliberately withdraws the catalog before a
            # route change; only an explicitly versioned live WAL allows it.
            continue
        elif _hash(raw) not in (_hash(old[name]), new_sha[name]):
            _deny("OWNED_WAL_FOREIGN_DRIFT")


def _read_owned_resources(state_fd: int, nginx_fd: int,
                          public_fd: int) -> dict[str, bytes | None]:
    return {
        V2_STATE: _read_file(state_fd, V2_STATE, 0, _LIMIT[V2_STATE]),
        _OWNED_MAIN: _read_public(nginx_fd, _OWNED_MAIN, _OWNED_LIMIT[_OWNED_MAIN]),
        _INCLUDE: _read_public(nginx_fd, _INCLUDE, _LIMIT[_INCLUDE]),
        _CATALOG: _read_public(public_fd, _CATALOG, _LIMIT[_CATALOG]),
        _OWNED_MANIFEST: _read_file(state_fd, _OWNED_MANIFEST, 0,
                                    _OWNED_LIMIT[_OWNED_MANIFEST]),
    }


def _no_conflicting_owned_wal_pending(state_fd: int, *, recovering: bool = False) -> None:
    """Dedicated domain may recognize its own manifest, never other WALs."""
    _legacy_refusal(state_fd, 0)
    if (_pending(state_fd, 0, include_multi=False)
            or _shadow_multi_resource_pending(state_fd, 0)):
        _deny("FOREIGN_PENDING")
    names = (_WAL, _WAL_TMP, _STATE_STAGE, _MANIFEST_STAGE)
    if not recovering:
        names += (_OWNED_WAL, _OWNED_WAL_TMP,
                  *(_OWNED_STAGES[key] for key in _OWNED_PRIVATE))
    for name in names:
        # Presence itself is a conflict; even dangling or malformed entries
        # cannot be silently treated as absent or garbage-collected.
        try:
            os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            _deny("OWNED_WAL_DOMAIN_UNVERIFIED")
        _deny("OWNED_WAL_DOMAIN_REQUIRED")


def _owned_resource_parent(name: str, state_fd: int, nginx_fd: int,
                           public_fd: int) -> int:
    if name in _OWNED_PRIVATE:
        return state_fd
    if name in (_OWNED_MAIN, _INCLUDE):
        return nginx_fd
    if name == _CATALOG:
        return public_fd
    _deny("OWNED_WAL_RESOURCES_INVALID")


def _owned_require_absent(parent: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        _deny("OWNED_WAL_DOMAIN_UNVERIFIED")
    _deny("ORPHAN_STAGE")


@contextmanager
def _owned_layout_locked(root_fd: int, state_fd: int, *, recovering: bool):
    """Retain the fixed resource directories; caller holds the state lock.

    This is an internal layout helper, not a host-operation authorization.
    The installed native dispatcher must independently establish host,
    signed worker, package and storage authority before using it.
    """
    with ExitStack() as stack:
        _no_conflicting_owned_wal_pending(state_fd, recovering=recovering)
        marker = _owned_config_marker_identity(state_fd)
        nginx_fd, nginx_chain = _walk(root_fd, _OWNED_DIR, stack, 0)
        vendor_fd, vendor_chain = _walk(root_fd, _INCLUDE_DIR, stack, 0)
        shared_fd = nginx_chain[-1][0]
        if stat.S_IMODE(os.fstat(nginx_fd).st_mode) != 0o755:
            _deny("OWNED_DIRECTORY_MODE_UNSAFE")
        public_fd, public_chain = _walk(root_fd, _PUBLIC_DIR, stack, 0)
        if stat.S_IMODE(os.fstat(public_fd).st_mode) != 0o755:
            _deny("PUBLIC_DIRECTORY_MODE_UNSAFE")

        def check_layout():
            # Recheck competing transaction domains throughout the retained
            # lock, not just on entry. Never proceed after foreign drift.
            _no_conflicting_owned_wal_pending(state_fd, recovering=True)
            if (_read_file(state_fd, _MANIFEST, 0, _LIMIT[_MANIFEST]) is not None
                    or _read_public(vendor_fd, _INCLUDE, _LIMIT[_INCLUDE]) is not None):
                _deny("OWNED_WAL_VENDOR_DOMAIN_CONFLICT")
            for name in (_OWNED_MAIN, _INCLUDE, *_OWNED_STAGES.values()):
                _owned_require_absent(shared_fd, name)
            if set(os.listdir(nginx_fd)) - {_OWNED_MAIN, _INCLUDE,
                    _OWNED_STAGES[_OWNED_MAIN], _OWNED_STAGES[_INCLUDE]}:
                _deny("OWNED_DIRECTORY_FOREIGN_ENTRY")
            for fd in (nginx_fd, vendor_fd, public_fd):
                _owned_require_absent(fd, _STAGE)
            # The dedicated nginx leaf may change directory timestamps.
            # Its vendor child must remain completely unchanged.
            _recheck_after_mutation(nginx_chain, 0)
            _recheck(vendor_chain, 0)
            _recheck_after_mutation(public_chain, 0)
            if _owned_config_marker_identity(state_fd) != marker:
                _deny("OWNED_CONTEXT_CLAIM_CHANGED")

        check_layout()
        if not recovering:
            _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
        yield state_fd, nginx_fd, public_fd, check_layout
        check_layout()


@contextmanager
def _owned_fixture_layout(root_fd: int, *, recovering: bool):
    """Pin the full fixture namespace; never expose a host operation."""
    _refuse_actual_root_fixture_write(root_fd)
    with _locked(root_fd, 0) as state_fd:
        with _owned_layout_locked(root_fd, state_fd, recovering=recovering) as layout:
            yield layout


def _owned_check_stages_absent(state_fd: int, nginx_fd: int, public_fd: int) -> None:
    for name in _OWNED_ORDER:
        parent = _owned_resource_parent(name, state_fd, nginx_fd, public_fd)
        _owned_require_absent(parent, _OWNED_STAGES[name])


def _publish_owned_wal_locked(state_fd: int, nginx_fd: int, public_fd: int,
                              old: dict, new: dict, check_layout, *,
                              live: bool = False) -> bytes:
    """Durably publish the rollback bytes before touching any target."""
    wal = _owned_wal_record(old, new, live=live)
    _write_exclusive(state_fd, _OWNED_WAL_TMP, wal, 0, _MAX_WAL)
    _owned_wal_resource_drift(
        old, _decode_owned_wal(wal)[1],
        _read_owned_resources(state_fd, nginx_fd, public_fd), unpublished=True,
    )
    check_layout()
    _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
    if _read_file(state_fd, _OWNED_WAL, 0, _MAX_WAL) is not None:
        _deny("OWNED_WAL_DOMAIN_REQUIRED")
    if _read_file(state_fd, _OWNED_WAL_TMP, 0, _MAX_WAL) != wal:
        _deny("OWNED_WAL_CHANGED")
    os.replace(_OWNED_WAL_TMP, _OWNED_WAL,
               src_dir_fd=state_fd, dst_dir_fd=state_fd)
    os.fsync(state_fd)
    if _read_file(state_fd, _OWNED_WAL, 0, _MAX_WAL) != wal:
        _deny("OWNED_WAL_INVALID")
    return wal


def _publish_owned_wal_fixture(root_fd: int, new: dict[str, bytes | None]) -> bytes:
    """Fixture-only WAL publication, before any target mutation."""
    with _owned_fixture_layout(root_fd, recovering=False) as layout:
        state_fd, nginx_fd, public_fd, check_layout = layout
        old = _read_owned_resources(state_fd, nginx_fd, public_fd)
        return _publish_owned_wal_locked(state_fd, nginx_fd, public_fd,
                                         old, new, check_layout)


def _owned_write_resource(state_fd: int, nginx_fd: int, public_fd: int,
                          name: str, before: bytes | None,
                          after: bytes | None) -> None:
    if before == after:
        return
    parent = _owned_resource_parent(name, state_fd, nginx_fd, public_fd)
    stage = _OWNED_STAGES[name]
    maximum = _OWNED_LIMIT[name]
    if name in _OWNED_PRIVATE:
        _write_private(parent, name, stage, before, after, maximum)
    else:
        _write_public(parent, name, before, after, maximum, stage=stage)


def _owned_cleanup_stages(state_fd: int, nginx_fd: int, public_fd: int,
                          old: dict, new_sha: dict) -> None:
    """Check ALL fixed stages before unlinking any; only under a valid WAL."""
    private = []
    for name in _OWNED_ORDER:
        parent = _owned_resource_parent(name, state_fd, nginx_fd, public_fd)
        stage = _OWNED_STAGES[name]
        maximum = _OWNED_LIMIT[name]
        if name in _OWNED_PRIVATE:
            raw = _read_file(parent, stage, 0, maximum)
            if raw is not None:
                # A 0600 stage may be torn by SIGKILL; its exact bytes are
                # rechecked on unlink, never used as committed authority.
                private.append((parent, stage, raw, maximum))
        else:
            hashes = {new_sha[name], _hash(old[name])} - {None}
            _cleanup_stage(parent, maximum, hashes, stage=stage, remove=False)
    for parent, stage, raw, maximum in private:
        _unlink_known(parent, stage, raw, 0, maximum)
    for name in _OWNED_ORDER:
        if name not in _OWNED_PRIVATE:
            parent = _owned_resource_parent(name, state_fd, nginx_fd, public_fd)
            hashes = {new_sha[name], _hash(old[name])} - {None}
            _cleanup_stage(parent, _OWNED_LIMIT[name], hashes,
                           stage=_OWNED_STAGES[name])


def _owned_require_exact_wal(state_fd: int, expected: bytes) -> None:
    """A different or missing WAL cannot authorize further target effects."""
    if (_read_file(state_fd, _OWNED_WAL, 0, _MAX_WAL) != expected
            or _read_file(state_fd, _OWNED_WAL_TMP, 0, _MAX_WAL) is not None):
        _deny("OWNED_WAL_CHANGED")


def _owned_restore_files_locked(state_fd: int, nginx_fd: int, public_fd: int,
                                check_layout, *, expected_wal: bytes | None = None) -> dict:
    """Restore bytes only; this is not live service compensation."""
    check_layout()
    wal = _read_file(state_fd, _OWNED_WAL, 0, _MAX_WAL)
    tmp = _read_file(state_fd, _OWNED_WAL_TMP, 0, _MAX_WAL)
    current = _read_owned_resources(state_fd, nginx_fd, public_fd)
    if expected_wal is not None and (wal != expected_wal or tmp is not None):
        _deny("OWNED_WAL_CHANGED")
    if wal is not None and tmp is not None:
        _deny("OWNED_WAL_CONFLICTING_RECORDS")
    for raw in (wal, tmp):
        if raw is not None:
            _decode_owned_wal(raw)
            if _json(raw, limit=_MAX_WAL)["version"] == 3:
                _deny("OWNED_LIVE_WAL_REQUIRES_RUNTIME_RECOVERY")
    if wal is None and tmp is None:
        _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
        _validate_owned_resources(current)
        return {"status": "OWNED_FIXTURE_CLEAN", "fixture_only": True,
                "authorizes_nginx_reload": False}
    if wal is None:
        # No published journal => no target write was allowed. A malformed
        # temp is deliberately retained, never guessed or removed.
        old, new_sha = _decode_owned_wal(tmp)
        _owned_wal_resource_drift(old, new_sha, current, unpublished=True)
        _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
        check_layout()
        _unlink_known(state_fd, _OWNED_WAL_TMP, tmp, 0, _MAX_WAL)
        return {"status": "OWNED_FIXTURE_UNPUBLISHED_WAL_DISCARDED",
                "fixture_only": True, "authorizes_nginx_reload": False}
    old, new_sha = _decode_owned_wal(wal)
    _owned_wal_resource_drift(old, new_sha, current, unpublished=False)
    _owned_require_exact_wal(state_fd, wal)
    _owned_cleanup_stages(state_fd, nginx_fd, public_fd, old, new_sha)
    # Restore bootstrap main BEFORE removing the managed include; a
    # managed previous generation keeps its fixed main unchanged. This is
    # disk-only fixture ordering, not authorization to advertise live routes.
    for name in (_CATALOG, _OWNED_MAIN, _INCLUDE, V2_STATE, _OWNED_MANIFEST):
        check_layout()
        _owned_require_exact_wal(state_fd, wal)
        current = _read_owned_resources(state_fd, nginx_fd, public_fd)
        _owned_wal_resource_drift(old, new_sha, current, unpublished=False)
        _owned_write_resource(state_fd, nginx_fd, public_fd, name,
                              current[name], old[name])
    if _read_owned_resources(state_fd, nginx_fd, public_fd) != old:
        _deny("OWNED_WAL_RESTORE_DRIFT")
    _validate_owned_resources(old)
    check_layout()
    _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
    _owned_require_exact_wal(state_fd, wal)
    _unlink_known(state_fd, _OWNED_WAL, wal, 0, _MAX_WAL)
    return {"status": "OWNED_FIXTURE_FILES_RESTORED", "fixture_only": True,
            "authorizes_nginx_reload": False}


def _recover_owned_files_fixture(root_fd: int) -> dict:
    with _owned_fixture_layout(root_fd, recovering=True) as layout:
        return _owned_restore_files_locked(*layout)


def _apply_owned_files_fixture(root_fd: int, new: dict[str, bytes | None]) -> dict:
    """Exercise real five-resource writes and rollback, strictly in fixtures.

    No native command, callback, privileged dispatch or actual listener
    verification is provided. The live path must additionally retain its
    WAL across authenticated service reload and generation/catalog checks.
    """
    with _owned_fixture_layout(root_fd, recovering=False) as layout:
        state_fd, nginx_fd, public_fd, check_layout = layout
        _validate_owned_resources(new)
        new = dict(new)
        old = _read_owned_resources(state_fd, nginx_fd, public_fd)
        wal = _publish_owned_wal_locked(state_fd, nginx_fd, public_fd,
                                        old, new, check_layout)
        expected = dict(old)
        try:
            # First stage the include, then the main that references it.
            # The catalog and manifest are last; there is no live exposure
            # in this isolated fixture namespace.
            for name in (_INCLUDE, _OWNED_MAIN, V2_STATE, _CATALOG, _OWNED_MANIFEST):
                check_layout()
                _owned_require_exact_wal(state_fd, wal)
                current = _read_owned_resources(state_fd, nginx_fd, public_fd)
                if current != expected:
                    _deny("OWNED_WAL_PREPARE_DRIFT")
                _owned_write_resource(state_fd, nginx_fd, public_fd, name,
                                      expected[name], new[name])
                expected[name] = new[name]
            if _read_owned_resources(state_fd, nginx_fd, public_fd) != new:
                _deny("OWNED_WAL_COMMIT_DRIFT")
            _validate_owned_resources(new)
            check_layout()
            _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
            _owned_require_exact_wal(state_fd, wal)
            _unlink_known(state_fd, _OWNED_WAL, wal, 0, _MAX_WAL)
            return {"status": "OWNED_FIXTURE_FILES_COMMITTED", "fixture_only": True,
                    "authorizes_nginx_reload": False,
                    "authorizes_catalog_publication": False}
        except Exception:
            try:
                result = _owned_restore_files_locked(*layout, expected_wal=wal)
                if (result["status"] != "OWNED_FIXTURE_FILES_RESTORED"
                        or _read_owned_resources(state_fd, nginx_fd, public_fd) != old):
                    _deny("OWNED_WAL_RESTORE_DRIFT")
            except Exception:
                # In particular, unlink may have succeeded before fsync
                # failed. A missing WAL plus a valid new generation is NOT
                # evidence of compensation. Never claim rollback in that case.
                _deny("OWNED_WAL_APPLY_RECOVERY_REQUIRED")
            _deny("OWNED_WAL_APPLY_FILES_RESTORED")


def _owned_live_observe(root_fd: int, *, expected_unit: bytes | None = None) -> tuple:
    """Private read-only observation; installer bytes must be authenticated.

    Broker dispatch never supplies expected_unit; it uses its embedded unit.
    This parameter cannot authorize a mutation or bypass a signed installer.
    """
    _verify_current_root_fd(root_fd)
    try:
        observed = (inspect_signed_owned_nginx_unit() if expected_unit is None
                    else _inspect_owned_nginx_unit_bytes(expected_unit))
        if (observed.get("unit_name") != _OWNED_WAL_DOMAIN
                or observed.get("signed_worker_unit_bytes_match") is not True
                or observed.get("authorizes_nginx_reload") is not False
                or observed.get("authorizes_systemctl") is not False
                or type(observed.get("main_pid_observed")) is not int
                or observed["main_pid_observed"] <= 1
                or type(observed.get("private_unit_identity")) is not tuple):
            _deny("OWNED_LIVE_UNIT_UNVERIFIED")
        return observed["main_pid_observed"], observed["private_unit_identity"]
    except (EffectiveNginxUnitError, OSError, TypeError, ValueError):
        _deny("OWNED_LIVE_UNIT_UNVERIFIED")


def _owned_live_validate(root_fd: int, state_fd: int, resources: dict) -> tuple:
    """Bind trusted TLS identity and exact native syntax to the snapshot."""
    snapshot = _validate_owned_resources(resources)
    if snapshot is None:
        _probe_owned_context_locked(root_fd, state_fd, None)
        return None, None, None
    document = parse_install_bytes(
        base64.b64decode(snapshot["configuration_base64"], validate=True),
        for_apply=True,
    )
    leaf = _verify_tls_pair(root_fd, document, verify_identity=True)
    _probe_owned_context_locked(root_fd, state_fd, resources[_INCLUDE],
                                managed_main=resources[_OWNED_MAIN])
    if _verify_tls_pair(root_fd, document, verify_identity=True) != leaf:
        _deny("OWNED_LIVE_TLS_CHANGED")
    return document, snapshot["state_generation"], leaf


def _owned_live_reload(root_fd: int, identity: tuple) -> None:
    """Only the fixed dedicated service; never fall back to vendor reload."""
    if _owned_live_observe(root_fd) != identity:
        _deny("OWNED_LIVE_UNIT_CHANGED")
    try:
        result = subprocess.run(
            (_SYSTEMCTL, "reload", _OWNED_WAL_DOMAIN),
            shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd="/", env=_ENV, timeout=10, close_fds=True,
            start_new_session=True, check=False,
        )
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        _deny("OWNED_LIVE_RELOAD_UNAVAILABLE")
    if type(result.returncode) is not int or result.returncode != 0:
        _deny("OWNED_LIVE_RELOAD_FAILED")
    if _owned_live_observe(root_fd) != identity:
        _deny("OWNED_LIVE_UNIT_CHANGED")


def _owned_live_health(context: tuple, catalog: bytes | None, *, publish: bool) -> None:
    """Observe generation and (after publication) exact catalog, with pinned TLS."""
    document, generation, leaf = context
    if document is None:
        if catalog is not None:
            _deny("OWNED_LIVE_BOOTSTRAP_DRIFT")
        require_owned_bootstrap_health()
        return
    response = _fixed_https_get(document, _HEALTH, 8192, expected_leaf_sha256=leaf)
    header, body = response.split(b"\r\n\r\n", 1)
    lines = header.lower().split(b"\r\n")
    markers = [line for line in lines if line.startswith(b"x-repocache-generation:")]
    if (not header.startswith(b"HTTP/1.1 204 ") or body
            or markers != [f"x-repocache-generation: {generation}".encode("ascii")]
            or any(line.startswith((b"transfer-encoding:", b"content-encoding:"))
                   for line in lines)
            or [line for line in lines if line.startswith(b"content-length:")]
               not in ([], [b"content-length: 0"])):
        _deny("OWNED_LIVE_GENERATION_UNVERIFIED")
    if publish:
        if type(catalog) is not bytes:
            _deny("OWNED_LIVE_CATALOG_REQUIRED")
        response = _fixed_https_get(
            document, "/.well-known/repocache/catalog.json",
            _LIMIT[_CATALOG] + 8192, expected_leaf_sha256=leaf,
        )
        header, body = response.split(b"\r\n\r\n", 1)
        lines = header.lower().split(b"\r\n")
        lengths = [line for line in lines if line.startswith(b"content-length:")]
        if (not header.startswith(b"HTTP/1.1 200 ") or body != catalog
                or lengths != [b"content-length: " + str(len(catalog)).encode("ascii")]
                or any(line.startswith((b"transfer-encoding:", b"content-encoding:"))
                       for line in lines)):
            _deny("OWNED_LIVE_CATALOG_UNVERIFIED")


def _owned_listener_rows(raw: bytes, *, ipv6: bool, port: int) -> list[tuple[str, int]]:
    """Bounded Linux x86_64 TCP LISTEN table, not established connections."""
    if (type(raw) is not bytes or not 1 <= len(raw) <= 4 * 1024 * 1024
            or type(ipv6) is not bool or type(port) is not int
            or not 1 <= port <= 65535):
        _deny("OWNED_LIVE_LISTENER_TABLE_INVALID")
    try:
        lines = raw.decode("ascii", "strict").splitlines()
        if len(lines) > 32768 or lines[0].split()[:4] not in (
                ["sl", "local_address", "rem_address", "st"],
                ["sl", "local_address", "remote_address", "st"]):
            _deny("OWNED_LIVE_LISTENER_TABLE_INVALID")
        result = []
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10 or not re.fullmatch(r"[0-9A-Fa-f]{2}", fields[3]):
                _deny("OWNED_LIVE_LISTENER_TABLE_INVALID")
            address, separator, hex_port = fields[1].partition(":")
            if (not separator or len(address) != (32 if ipv6 else 8)
                    or not re.fullmatch(r"[0-9A-Fa-f]+", address)
                    or not re.fullmatch(r"[0-9A-Fa-f]{4}", hex_port)):
                _deny("OWNED_LIVE_LISTENER_TABLE_INVALID")
            if fields[3].upper() != "0A" or int(hex_port, 16) != port:
                continue
            inode = fields[9]
            if not re.fullmatch(r"[0-9]{1,20}", inode) or int(inode) <= 0:
                _deny("OWNED_LIVE_LISTENER_TABLE_INVALID")
            packed = bytes.fromhex(address)
            network = b"".join(packed[i:i + 4][::-1] for i in range(0, len(packed), 4))
            result.append((str(ipaddress.ip_address(network)), int(inode)))
        return result
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, IndexError, UnicodeError, OverflowError):
        _deny("OWNED_LIVE_LISTENER_TABLE_INVALID")


def _owned_read_proc_table(directory: int, name: str) -> bytes:
    if name not in ("tcp", "tcp6"):
        _deny("OWNED_LIVE_LISTENER_TABLE_INVALID")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            _deny("OWNED_LIVE_LISTENER_TABLE_INVALID")
        data = bytearray()
        while len(data) <= 4 * 1024 * 1024:
            block = os.read(fd, min(32768, 4 * 1024 * 1024 + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if not data or len(data) > 4 * 1024 * 1024:
            _deny("OWNED_LIVE_LISTENER_TABLE_INVALID")
        return bytes(data)
    finally:
        os.close(fd)


def _owned_require_listener(rows: list[tuple[str, int]], sockets: set[int],
                            address: str) -> int:
    # Refuse every other listener on the same port, including another
    # interface, address family or SO_REUSEPORT group.
    if len(rows) != 1 or rows[0][0] != address or rows[0][1] not in sockets:
        _deny("OWNED_LIVE_LISTENER_UNVERIFIED")
    return rows[0][1]


def _owned_live_verify_listener(root_fd: int, identity: tuple, context: tuple, *,
                                expected_unit: bytes | None = None) -> int:
    """Bind the fixed endpoint to the observed signed-unit master socket."""
    def observe():
        return (_owned_live_observe(root_fd) if expected_unit is None
                else _owned_live_observe(root_fd, expected_unit=expected_unit))
    if observe() != identity:
        _deny("OWNED_LIVE_UNIT_CHANGED")
    pid = identity[0]
    document = context[0]
    if document is None:
        address, port = "127.0.0.1", 8008
    else:
        listen = document["deployment"]["listen"]
        address, port = listen["bind_address"], listen["https_port"]
    try:
        if str(ipaddress.ip_address(address)) != address or type(port) is not int:
            _deny("OWNED_LIVE_LISTENER_UNVERIFIED")
        with ExitStack() as stack:
            proc = os.open("/proc", _DIRECTORY_FLAGS)
            stack.callback(os.close, proc)
            master = os.open(str(pid), _DIRECTORY_FLAGS, dir_fd=proc)
            stack.callback(os.close, master)
            info = os.fstat(master)
            if info.st_uid != 0 or info.st_mode & 0o022:
                _deny("OWNED_LIVE_LISTENER_UNVERIFIED")
            master_id = (info.st_dev, info.st_ino)
            fds = os.open("fd", _DIRECTORY_FLAGS, dir_fd=master)
            stack.callback(os.close, fds)
            net = os.open("net", _DIRECTORY_FLAGS, dir_fd=master)
            stack.callback(os.close, net)

            def sample():
                local_ns = os.stat("/proc/self/ns/net")
                master_ns = os.stat("ns/net", dir_fd=master)
                if (local_ns.st_dev, local_ns.st_ino) != (master_ns.st_dev, master_ns.st_ino):
                    _deny("OWNED_LIVE_LISTENER_NAMESPACE_CHANGED")
                current = os.stat(str(pid), dir_fd=proc, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != master_id:
                    _deny("OWNED_LIVE_LISTENER_PROCESS_CHANGED")
                names = os.listdir(fds)
                if len(names) > 4096:
                    _deny("OWNED_LIVE_LISTENER_FD_LIMIT")
                sockets = set()
                for name in names:
                    if not re.fullmatch(r"[0-9]{1,10}", name):
                        _deny("OWNED_LIVE_LISTENER_FD_INVALID")
                    target = os.readlink(name, dir_fd=fds)
                    match = re.fullmatch(r"socket:\[([0-9]{1,20})\]", target)
                    if match:
                        sockets.add(int(match[1]))
                rows = _owned_listener_rows(
                    _owned_read_proc_table(net, "tcp"), ipv6=False, port=port,
                ) + _owned_listener_rows(
                    _owned_read_proc_table(net, "tcp6"), ipv6=True, port=port,
                )
                return _owned_require_listener(rows, sockets, address), (local_ns.st_dev, local_ns.st_ino)

            first = sample()
            if observe() != identity or sample() != first:
                _deny("OWNED_LIVE_LISTENER_CHANGED")
            return first[0]
    except NativeV2TransactionError:
        raise
    except (OSError, TypeError, ValueError, KeyError, OverflowError):
        _deny("OWNED_LIVE_LISTENER_UNVERIFIED")


def _owned_live_health_bound(root_fd: int, identity: tuple, context: tuple,
                             catalog: bytes | None, *, publish: bool,
                             expected_unit: bytes | None = None) -> None:
    def listener():
        return (_owned_live_verify_listener(root_fd, identity, context)
                if expected_unit is None else _owned_live_verify_listener(
                    root_fd, identity, context, expected_unit=expected_unit))
    before = listener()
    _owned_live_health(context, catalog, publish=publish)
    if listener() != before:
        _deny("OWNED_LIVE_LISTENER_CHANGED")


def _owned_live_wait_generation(root_fd: int, identity: tuple, context: tuple) -> None:
    """A graceful reload is asynchronous; bounded retries cannot change authority."""
    deadline = time.monotonic() + 12
    for attempt in range(3):
        if _owned_live_observe(root_fd) != identity:
            _deny("OWNED_LIVE_UNIT_CHANGED")
        try:
            _owned_live_health_bound(root_fd, identity, context, None, publish=False)
            return
        except (NativeV2TransactionError, EffectiveNginxUnitError):
            if attempt == 2 or time.monotonic() >= deadline:
                raise
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def _owned_live_guard(state_fd: int, nginx_fd: int, public_fd: int,
                      check_layout, wal: bytes, expected: dict) -> None:
    check_layout()
    _owned_require_exact_wal(state_fd, wal)
    if _read_owned_resources(state_fd, nginx_fd, public_fd) != expected:
        _deny("OWNED_LIVE_RESOURCE_DRIFT")


def _owned_live_write(state_fd: int, nginx_fd: int, public_fd: int,
                      check_layout, wal: bytes, expected: dict,
                      name: str, after: bytes | None) -> None:
    _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
    _owned_write_resource(state_fd, nginx_fd, public_fd, name, expected[name], after)
    expected[name] = after
    _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)


def _owned_live_finish(state_fd: int, nginx_fd: int, public_fd: int,
                       check_layout, wal: bytes, expected: dict) -> None:
    _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
    _validate_owned_resources(expected)
    _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
    _owned_require_exact_wal(state_fd, wal)
    _unlink_known(state_fd, _OWNED_WAL, wal, 0, _MAX_WAL)


def _recover_owned_live_locked(root_fd: int, state_fd: int, nginx_fd: int,
                               public_fd: int, check_layout, *,
                               expected_wal: bytes | None = None) -> dict:
    """Recover a published live WAL under a retained trusted state lock.

    Not connected to host dispatch. The future caller must establish native
    package, signed worker, storage/ACL/SELinux and listener provenance first.
    Failure to prove the old service retains the journal and withdraws any
    candidate catalog. Never infer rollback from the absence of a WAL.
    """
    check_layout()
    wal = _read_file(state_fd, _OWNED_WAL, 0, _MAX_WAL)
    temporary = _read_file(state_fd, _OWNED_WAL_TMP, 0, _MAX_WAL)
    if expected_wal is not None and (wal != expected_wal or temporary is not None):
        _deny("OWNED_LIVE_WAL_REQUIRED")
    if wal is None:
        current = _read_owned_resources(state_fd, nginx_fd, public_fd)
        if temporary is not None:
            old, hashes = _decode_owned_wal(temporary)
            if _json(temporary, limit=_MAX_WAL)["version"] != 3:
                _deny("OWNED_LIVE_WAL_REQUIRED")
            _owned_wal_resource_drift(old, hashes, current, unpublished=True)
        _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
        identity = _owned_live_observe(root_fd)
        context = _owned_live_validate(root_fd, state_fd, current)
        _owned_live_health_bound(root_fd, identity, context, current[_CATALOG], publish=True)
        check_layout()
        if (_owned_live_observe(root_fd) != identity
                or _read_owned_resources(state_fd, nginx_fd, public_fd) != current
                or _read_file(state_fd, _OWNED_WAL, 0, _MAX_WAL) is not None
                or _read_file(state_fd, _OWNED_WAL_TMP, 0, _MAX_WAL) != temporary):
            _deny("OWNED_LIVE_RECOVERY_DRIFT")
        _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
        if temporary is not None:
            _unlink_known(state_fd, _OWNED_WAL_TMP, temporary, 0, _MAX_WAL)
        return {"status": ("OWNED_LIVE_UNPUBLISHED_WAL_DISCARDED" if temporary is not None
                           else "OWNED_LIVE_CLEAN_OBSERVED"), "recovery_required": False}
    _owned_require_exact_wal(state_fd, wal)
    old, new_sha = _decode_owned_wal(wal)
    if _json(wal, limit=_MAX_WAL)["version"] != 3:
        _deny("OWNED_LIVE_WAL_REQUIRED")
    expected = _read_owned_resources(state_fd, nginx_fd, public_fd)
    _owned_wal_resource_drift(old, new_sha, expected, unpublished=False,
                              catalog_withdrawal=True)
    identity = _owned_live_observe(root_fd)
    _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
    _owned_cleanup_stages(state_fd, nginx_fd, public_fd, old, new_sha)
    # Both a newly published and a previous catalog may advertise a route
    # that the next reload will remove. Withdraw before restoring context.
    for name, after in ((_CATALOG, None), (_OWNED_MAIN, old[_OWNED_MAIN]),
                        (_INCLUDE, old[_INCLUDE]), (V2_STATE, old[V2_STATE])):
        _owned_live_write(state_fd, nginx_fd, public_fd, check_layout, wal,
                          expected, name, after)
    context = _owned_live_validate(root_fd, state_fd, old)
    _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
    _owned_live_reload(root_fd, identity)
    _owned_live_wait_generation(root_fd, identity, context)
    if (_owned_live_observe(root_fd) != identity
            or _owned_live_validate(root_fd, state_fd, old) != context):
        _deny("OWNED_LIVE_RECOVERY_DRIFT")
    _owned_live_write(state_fd, nginx_fd, public_fd, check_layout, wal,
                      expected, _CATALOG, old[_CATALOG])
    try:
        _owned_live_health_bound(root_fd, identity, context, old[_CATALOG], publish=True)
        _owned_live_write(state_fd, nginx_fd, public_fd, check_layout, wal,
                          expected, _OWNED_MANIFEST, old[_OWNED_MANIFEST])
        if (expected != old or _owned_live_observe(root_fd) != identity
                or _owned_live_validate(root_fd, state_fd, old) != context):
            _deny("OWNED_LIVE_RECOVERY_DRIFT")
        _owned_live_finish(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
    except Exception:
        # Only withdraw our own still-exact catalog while the same WAL
        # remains durable. A changed resource or missing WAL is not ours
        # to compensate; retain uncertainty, never certify rollback.
        _owned_live_write(state_fd, nginx_fd, public_fd, check_layout, wal,
                          expected, _CATALOG, None)
        raise
    return {"status": "OWNED_LIVE_ROLLBACK_OBSERVED", "recovery_required": False}


def _apply_owned_live_locked(root_fd: int, state_fd: int, nginx_fd: int,
                             public_fd: int, check_layout, new: dict, *,
                             expected_intake: dict | None = None) -> dict:
    """Private WAL-held service transaction; not yet a socket operation.

    The future fixed dispatch must supply only a deterministic CAS-approved
    candidate, retain the protected lock, and establish storage, SELinux,
    package and kernel listener authority. No callback comes from the peer.
    """
    check_layout()
    old = _read_owned_resources(state_fd, nginx_fd, public_fd)
    new = dict(new)
    _validate_owned_resources(new)
    identity = _owned_live_observe(root_fd)
    context = _owned_live_validate(root_fd, state_fd, old)
    _owned_live_health_bound(root_fd, identity, context, old[_CATALOG], publish=True)
    if _owned_live_observe(root_fd) != identity:
        _deny("OWNED_LIVE_UNIT_CHANGED")
    if expected_intake is not None:
        again, candidate = _load_private_under_root(root_fd, owner_uid=0, owner_gid=0)
        if again != expected_intake or candidate != new[V2_STATE]:
            _deny("CANDIDATE_CHANGED")
    else:
        # The simulation-only call shape cannot perform a real host write.
        _refuse_actual_root_fixture_write(root_fd)
    wal = _publish_owned_wal_locked(state_fd, nginx_fd, public_fd,
                                    old, new, check_layout, live=True)
    expected = dict(old)
    try:
        for name, after in ((_CATALOG, None), (_INCLUDE, new[_INCLUDE]),
                            (_OWNED_MAIN, new[_OWNED_MAIN]), (V2_STATE, new[V2_STATE])):
            _owned_live_write(state_fd, nginx_fd, public_fd, check_layout, wal,
                              expected, name, after)
        context = _owned_live_validate(root_fd, state_fd, new)
        _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
        _owned_live_reload(root_fd, identity)
        _owned_live_wait_generation(root_fd, identity, context)
        if (_owned_live_observe(root_fd) != identity
                or _owned_live_validate(root_fd, state_fd, new) != context):
            _deny("OWNED_LIVE_COMMIT_DRIFT")
        _owned_live_write(state_fd, nginx_fd, public_fd, check_layout, wal,
                          expected, _CATALOG, new[_CATALOG])
        _owned_live_health_bound(root_fd, identity, context, new[_CATALOG], publish=True)
        _owned_live_write(state_fd, nginx_fd, public_fd, check_layout, wal,
                          expected, _OWNED_MANIFEST, new[_OWNED_MANIFEST])
        if (expected != new or _owned_live_observe(root_fd) != identity
                or _owned_live_validate(root_fd, state_fd, new) != context):
            _deny("OWNED_LIVE_COMMIT_DRIFT")
        _owned_live_finish(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
        return {"status": "OWNED_LIVE_COMMIT_OBSERVED",
                "state_generation": context[1], "recovery_required": False}
    except Exception as exc:
        _audit_native_failure(exc)
        try:
            _recover_owned_live_locked(root_fd, state_fd, nginx_fd, public_fd,
                                       check_layout, expected_wal=wal)
        except Exception as recovery_error:
            _audit_native_failure(recovery_error)
            _deny("OWNED_LIVE_APPLY_RECOVERY_REQUIRED")
        _deny("OWNED_LIVE_APPLY_ROLLED_BACK")


def _prepare_owned_live_candidate_locked(root_fd: int, state_fd: int,
                                         nginx_fd: int, public_fd: int,
                                         distribution: str) -> tuple[dict, dict, dict]:
    """Read only the fixed root intake; never accept bytes from a socket peer.

    Returns the old/new exact resource sets and intake report. A future
    dispatcher must retain the same lock and re-read both intake and
    resources immediately before starting the live WAL. Replay is handled
    separately by verified committed-generation reload/no-change.
    """
    old = _read_owned_resources(state_fd, nginx_fd, public_fd)
    previous = _validate_owned_resources(old, distribution=distribution)
    generation = 0 if previous is None else previous["state_generation"]
    report, candidate = _load_private_under_root(root_fd, owner_uid=0, owner_gid=0)
    if (report["expected_generation"] != generation
            or report["expected_state_sha256"] != _hash(old[V2_STATE])):
        _deny("STATE_STALE")
    try:
        snapshot = _json(candidate, limit=_LIMIT[V2_STATE])
        transition = preview_proposed_v2_state_transition(
            snapshot, expected_generation=generation, previous_snapshot=previous,
        )
        document = parse_install_bytes(
            base64.b64decode(snapshot["configuration_base64"], validate=True),
            for_apply=True,
        )
        if transition["proposed_generation"] != snapshot["state_generation"]:
            _deny("STATE_STALE")
        # Ensure the new cert/key can actually complete a trusted handshake
        # before withdrawing the previously published catalog or writing WAL.
        _verify_tls_pair(root_fd, document, verify_identity=True)
        pins = _resolve_pins(document)
        main, include, catalog = _render_owned_managed_candidate(
            document, snapshot["state_generation"], distribution, pins,
        )
        new = {
            V2_STATE: candidate, _OWNED_MAIN: main, _INCLUDE: include,
            _CATALOG: catalog,
            _OWNED_MANIFEST: _owned_manifest_for(candidate, main, include, catalog),
        }
        _validate_owned_resources(new, distribution=distribution)
    except NativeV2TransactionError:
        raise
    except (ValueError, TypeError, KeyError, OverflowError):
        _deny("CANDIDATE_INVALID")
    again, again_candidate = _load_private_under_root(root_fd, owner_uid=0, owner_gid=0)
    if (again != report or again_candidate != candidate
            or _read_owned_resources(state_fd, nginx_fd, public_fd) != old):
        _deny("CANDIDATE_CHANGED")
    return old, new, report


def _apply_prepared_owned_live_locked(root_fd: int, state_fd: int, nginx_fd: int,
                                      public_fd: int, check_layout,
                                      distribution: str) -> dict:
    """Fixed intake, CAS preparation and live transaction under one lock."""
    check_layout()
    previous = _read_owned_resources(state_fd, nginx_fd, public_fd)
    snapshot = _validate_owned_resources(previous, distribution=distribution)
    report, candidate = _load_private_under_root(root_fd, owner_uid=0, owner_gid=0)
    if (snapshot is not None and candidate == previous[V2_STATE]
            and report["expected_generation"] == snapshot["state_generation"] - 1):
        again, raw = _load_private_under_root(root_fd, owner_uid=0, owner_gid=0)
        if again != report or raw != candidate:
            _deny("CANDIDATE_CHANGED")
        return _reload_owned_live_committed_locked(
            root_fd, state_fd, nginx_fd, public_fd, check_layout, reload=False,
        )
    old, new, prepared = _prepare_owned_live_candidate_locked(
        root_fd, state_fd, nginx_fd, public_fd, distribution,
    )
    if (old != previous or prepared != report or new[V2_STATE] != candidate):
        _deny("CANDIDATE_CHANGED")
    return _apply_owned_live_locked(
        root_fd, state_fd, nginx_fd, public_fd, check_layout, new,
        expected_intake=prepared,
    )


def _reload_owned_live_committed_locked(root_fd: int, state_fd: int, nginx_fd: int,
                                       public_fd: int, check_layout, *,
                                       reload: bool = True) -> dict:
    """Explicit reload or no-change of one exact committed generation only.

    No WAL or catalog writes, no fallback to the vendor service. Not an
    authorization entry; same host gates as the future live apply dispatcher.
    """
    if type(reload) is not bool:
        _deny("OPERATION_REFUSED")
    def clean():
        check_layout()
        for name in (_OWNED_WAL, _OWNED_WAL_TMP):
            _owned_require_absent(state_fd, name)
        _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
    clean()
    old = _read_owned_resources(state_fd, nginx_fd, public_fd)
    if _validate_owned_resources(old) is None:
        _deny("MANAGED_GENERATION_REQUIRED")
    identity = _owned_live_observe(root_fd)
    context = _owned_live_validate(root_fd, state_fd, old)
    _owned_live_health_bound(root_fd, identity, context, old[_CATALOG], publish=True)
    clean()
    if (_read_owned_resources(state_fd, nginx_fd, public_fd) != old
            or _owned_live_observe(root_fd) != identity):
        _deny("OWNED_LIVE_PRE_RELOAD_DRIFT")
    if reload:
        _owned_live_reload(root_fd, identity)
        _owned_live_wait_generation(root_fd, identity, context)
    if _owned_live_validate(root_fd, state_fd, old) != context:
        _deny("OWNED_LIVE_POST_RELOAD_DRIFT")
    _owned_live_health_bound(root_fd, identity, context, old[_CATALOG], publish=True)
    clean()
    if (_read_owned_resources(state_fd, nginx_fd, public_fd) != old
            or _owned_live_observe(root_fd) != identity):
        _deny("OWNED_LIVE_POST_RELOAD_DRIFT")
    return {"status": "OWNED_LIVE_RELOADED" if reload else "OWNED_LIVE_NO_CHANGE",
            "state_generation": context[1]}


def _recover_locked(state_fd: int, include_fd: int,
                    public_fd: int, distribution: str) -> dict:
    journal = _read_wal(state_fd, _WAL)
    try:
        uncommitted = _read_wal(state_fd, _WAL_TMP)
    except NativeV2TransactionError:
        # A torn, unpublished WAL_TMP cannot have changed any target:
        # the writer fsyncs and publishes the WAL before first mutation.
        # Refuse all foreign target/temporary files and malformed published
        # WALs. Only then safely discard this one root-owned temp file.
        if journal is not None:
            raise
        old = _read_all(state_fd, include_fd, public_fd)
        _verify_owned(old)
        for fd, limit in ((include_fd, _LIMIT[_INCLUDE]),
                          (public_fd, _LIMIT[_CATALOG])):
            try:
                os.stat(_STAGE, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                _deny("ORPHAN_STAGE")
            _deny("ORPHAN_STAGE")
        for name, limit in ((_STATE_STAGE, _LIMIT[V2_STATE]),
                            (_MANIFEST_STAGE, _LIMIT[_MANIFEST])):
            if _read_file(state_fd, name, 0, limit) is not None:
                _deny("ORPHAN_STAGE")
        torn = _read_file(state_fd, _WAL_TMP, 0, _MAX_WAL)
        if torn is None:
            _deny("WAL_UNAVAILABLE")
        _unlink_known(state_fd, _WAL_TMP, torn, 0, _MAX_WAL)
        return {"status": "NATIVE_V2_UNPUBLISHED_WAL_DISCARDED",
                "recovery_required": False}
    if journal is not None and uncommitted is not None:
        _deny("CONFLICTING_WALS")
    if journal is None and uncommitted is None:
        # Never report CLEAN when a crash left an unclaimed staging inode.
        for fd, limit in ((include_fd, _LIMIT[_INCLUDE]),
                          (public_fd, _LIMIT[_CATALOG])):
            if _read_public(fd, _STAGE, limit) is not None:
                _deny("ORPHAN_STAGE")
        for name, limit in ((_STATE_STAGE, _LIMIT[V2_STATE]),
                            (_MANIFEST_STAGE, _LIMIT[_MANIFEST])):
            if _read_file(state_fd, name, 0, limit) is not None:
                _deny("ORPHAN_STAGE")
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
    if old[V2_STATE] is not None:
        try:
            prior_state = _json(old[V2_STATE], limit=_LIMIT[V2_STATE])
            prior_doc = parse_install_bytes(
                base64.b64decode(prior_state["configuration_base64"], validate=True),
                for_apply=True,
            )
        except (ValueError, TypeError):
            _deny("PREVIOUS_STATE_INVALID")
        _local_https_generation(prior_doc, prior_state["state_generation"])
        _local_https_catalog(prior_doc, old[_CATALOG])
    # A successful syntax check and a matching health endpoint do not prove
    # that the *exact old managed include* is loaded (or absent for an
    # interrupted fresh install). Retain the durable WAL until the fixed
    # effective -T dump agrees with the restored filesystem generation.
    _verify_owned_include_in_dump(old[_INCLUDE])
    _verify_owned(_read_all(state_fd, include_fd, public_fd))
    _unlink_known(state_fd, _WAL, raw, 0, _MAX_WAL)
    return {"status": "NATIVE_V2_ROLLED_BACK", "recovery_required": False}


def _require_audited_native_package_for_activation(
    state_fd: int, *, distribution: str,
) -> None:
    """Gate host APPLY/RELOAD on durable package audit and current file integrity.

    The completion receipt is root-owned install-local evidence, NOT a signed
    REPOCACHE publisher assertion, OS authorization or permission to reload.
    Only the authenticated fixed host worker may invoke this production path.
    Recovery of an already-pending WAL remains possible without this gate.
    """
    _legacy_refusal(state_fd, 0)
    try:
        receipt = _read_completed_native_install_under_lock(
            state_fd, owner_uid=0, distribution=distribution,
        )
        if receipt is None:
            _deny("NATIVE_PACKAGE_COMPLETION_REQUIRED")
        integrity = inspect_stock_nginx_package_file_integrity()
        if (integrity.get("status") !=
                "READ_ONLY_STOCK_NGINX_PACKAGE_FILE_INTEGRITY_OBSERVED"
                or integrity.get("platform") !=
                    ("debian13" if distribution == "debian" else "almalinux10")
                or integrity.get("native_package_file_integrity_verified") is not True
                or integrity.get("native_package_signature_verified") is not False
                or integrity.get("authorizes_native_marker_removal") is not False
                or integrity.get("authorizes_nginx_activation") is not False):
            _deny("NATIVE_PACKAGE_INTEGRITY_CHANGED")
        # Compare the current fixed vendor unit with the exact audited
        # package-install receipt. File integrity alone is insufficient:
        # a foreign or replaced unit must not inherit old completion.
        unit = inspect_native_nginx_unit(distribution).to_dict()
        if (unit.get("code") != "VENDOR_NGINX_UNIT_OBSERVED"
                or unit.get("unit_name") != "nginx.service"
                or unit.get("vendor_unit_bounded_and_owned") is not True
                or unit.get("vendor_unit_sha256") != receipt["vendor_unit_sha256"]
                or unit.get("authorizes_systemctl") is not False
                or unit.get("authorizes_nginx_reload") is not False):
            _deny("NATIVE_PACKAGE_UNIT_CHANGED")
    except NativeV2TransactionError:
        raise
    except (NativePackageJournalError, StockNginxPackageOwnerError,
            NginxServiceUnitInspectionError, OSError, TypeError, ValueError):
        _deny("NATIVE_PACKAGE_PROVENANCE_UNVERIFIED")


def _refuse_legacy_vendor_mode_after_owned_claim(state_fd: int) -> None:
    """A bootstrap ownership claim must never fall back to vendor operations.

    Called under the same protected lock as the installer. Any entry in the
    reserved marker namespace, even a malformed or dangling entry, blocks
    legacy apply, reload and recovery until the dedicated service transaction
    is implemented. Never remove a marker or guess which service owns a WAL.
    """
    try:
        claimed = any(name.startswith(OWNED_NGINX_CONFIG_MARKER_PREFIX)
                      for name in os.listdir(state_fd))
    except (OSError, ValueError, TypeError):
        _deny("NGINX_OWNERSHIP_UNVERIFIED")
    if claimed:
        _deny("OWNED_NGINX_TRANSITION_REQUIRED")



def _owned_socket_host_boundary(root_fd: int, state_fd: int,
                                nginx_fd: int, public_fd: int,
                                distribution: str) -> None:
    """Require the fixed isolated writable directory and read-only shared parent."""
    try:
        _verify_current_root_fd(root_fd)
        require_installed_control_receipt(root_fd, state_fd)
        _require_audited_native_package_for_activation(
            state_fd, distribution=distribution,
        )
        for action, expected in (("is-active", (3, b"inactive\n")),
                                 ("is-enabled", (1, b"disabled\n"))):
            result = subprocess.run(
                (_SYSTEMCTL, action, _UNIT), shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
                env=_ENV, timeout=5, check=False,
            )
            if (result.returncode, result.stdout) != expected:
                _deny("OWNED_SOCKET_VENDOR_STATE_REFUSED")
        if distribution == "almalinux":
            enforcing = subprocess.run(
                ("/usr/sbin/getenforce",), shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
                env=_ENV, timeout=5, check=False,
            )
            if enforcing.returncode != 0 or enforcing.stdout != b"Enforcing\n":
                _deny("OWNED_SOCKET_SELINUX_REQUIRED")
        # Match the actual fixed paths with PID1's view; the generic legacy
        # mount observation does not include these dedicated paths.
        with ExitStack() as stack:
            host = os.open("/proc/1/root", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, host)
            for path, kind in (
                ("/etc/nginx", stat.S_IFDIR),
                ("/etc/nginx/repocache.d", stat.S_IFDIR),
                ("/etc/nginx/repocache.d/repocache.conf", stat.S_IFREG),
                ("/run/repocache-nginx", stat.S_IFDIR),
                ("/etc/systemd/system", stat.S_IFDIR),
                ("/var/cache/nginx", stat.S_IFDIR),
                ("/var/cache/nginx/repocache-managed", stat.S_IFDIR),
                ("/var/cache/nginx/.repocache-managed.owner-v1", stat.S_IFREG),
                ("/var/log/nginx", stat.S_IFDIR),
                ("/var/log/nginx/repocache-managed", stat.S_IFDIR),
                ("/var/log/nginx/.repocache-managed.owner-v1", stat.S_IFREG),
            ):
                reference = _path_snapshot(host, path, leaf_type=kind)
                if (_path_snapshot(root_fd, path, leaf_type=kind) != reference
                        or _path_snapshot(host, path, leaf_type=kind) != reference):
                    _deny("OWNED_SOCKET_MOUNT_VIEW_CHANGED")
            shared = os.open("/etc/nginx", _DIRECTORY_FLAGS)
            stack.callback(os.close, shared)
            if (not os.fstatvfs(shared).f_flag & os.ST_RDONLY
                    or os.fstatvfs(nginx_fd).f_flag & os.ST_RDONLY):
                _deny("OWNED_SOCKET_ATOMIC_WRITE_BOUNDARY_UNVERIFIED")
            _metadata_no_acl(shared, directory=True)
            if distribution == "almalinux":
                if os.getxattr(nginx_fd, "security.selinux").split(b":")[2:3] != [b"httpd_config_t"]:
                    _deny("OWNED_SOCKET_CONFIG_LABEL_UNVERIFIED")
            for fd in (state_fd, nginx_fd, public_fd):
                _metadata_no_acl(fd, directory=True)
            for parent, name in ((nginx_fd, _OWNED_MAIN), (nginx_fd, _INCLUDE),
                                 (public_fd, _CATALOG), (state_fd, V2_STATE),
                                 (state_fd, _OWNED_MANIFEST)):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                                 | os.O_CLOEXEC, dir_fd=parent)
                except FileNotFoundError:
                    continue
                stack.callback(os.close, fd)
                _metadata_no_acl(fd)
                if parent == nginx_fd:
                    reference = _path_snapshot(host, "/etc/nginx/repocache.d/" + name,
                                               leaf_type=stat.S_IFREG)
                    if (_path_snapshot(root_fd, "/etc/nginx/repocache.d/" + name,
                                       leaf_type=stat.S_IFREG) != reference
                            or os.fstatvfs(fd).f_flag & os.ST_RDONLY):
                        _deny("OWNED_SOCKET_MOUNT_VIEW_CHANGED")
                    if (distribution == "almalinux"
                            and os.getxattr(fd, "security.selinux").split(b":")[2:3] != [b"httpd_config_t"]):
                        _deny("OWNED_SOCKET_CONFIG_LABEL_UNVERIFIED")
        # Reuse the installer's descriptor-pinned storage verifier in PID1's
        # original view. This is observation only; no storage is created by
        # a socket request. Bind the same fixed roots to the actual signed
        # NGINX master's mount namespace before any WAL mutation or reload.
        observed = _owned_live_observe(root_fd)
        storage = verify_control_storage(distribution)
        if storage != {"cache_root_verified": True, "log_root_verified": True,
                       "selinux_enforcing_labels_verified": distribution == "almalinux",
                       "actual_service_write_verified": False}:
            _deny("OWNED_SOCKET_STORAGE_UNVERIFIED")
        verify_service_storage_mounts(observed[0])
        if _owned_live_observe(root_fd) != observed:
            _deny("OWNED_SOCKET_STORAGE_UNVERIFIED")
    except NativeV2TransactionError:
        raise
    except InstalledStorageError:
        _deny("OWNED_SOCKET_STORAGE_UNVERIFIED")
    except (RootControlWorkerError, OSError, ValueError, TypeError,
            subprocess.SubprocessError):
        _deny("OWNED_SOCKET_HOST_BOUNDARY_REFUSED")



def _owned_socket_recheck_write_boundary(root_fd: int, nginx_fd: int,
                                        distribution: str) -> None:
    """Cheap retained mount/metadata check before every WAL resource effect."""
    try:
        with ExitStack() as stack:
            shared = os.open("/etc/nginx", _DIRECTORY_FLAGS)
            stack.callback(os.close, shared)
            host = os.open("/proc/1/root", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            stack.callback(os.close, host)
            if (not os.fstatvfs(shared).f_flag & os.ST_RDONLY
                    or os.fstatvfs(nginx_fd).f_flag & os.ST_RDONLY):
                _deny("OWNED_SOCKET_ATOMIC_WRITE_BOUNDARY_UNVERIFIED")
            _metadata_no_acl(shared, directory=True)
            _metadata_no_acl(nginx_fd, directory=True)
            if (distribution == "almalinux" and
                    os.getxattr(nginx_fd, "security.selinux").split(b":")[2:3] != [b"httpd_config_t"]):
                _deny("OWNED_SOCKET_CONFIG_LABEL_UNVERIFIED")
            for name in (_OWNED_MAIN, _INCLUDE):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                                 | os.O_CLOEXEC, dir_fd=nginx_fd)
                except FileNotFoundError:
                    continue
                stack.callback(os.close, fd)
                info = _metadata_no_acl(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o644
                        or os.fstatvfs(fd).f_flag & os.ST_RDONLY):
                    _deny("OWNED_SOCKET_CONFIG_METADATA_UNVERIFIED")
                path = "/etc/nginx/repocache.d/" + name
                reference = _path_snapshot(host, path, leaf_type=stat.S_IFREG)
                if (_path_snapshot(root_fd, path, leaf_type=stat.S_IFREG) != reference
                        or _path_snapshot(host, path, leaf_type=stat.S_IFREG) != reference
                        or (info.st_dev, info.st_ino) != reference[-1][:2]):
                    _deny("OWNED_SOCKET_MOUNT_VIEW_CHANGED")
                if (distribution == "almalinux" and
                        os.getxattr(fd, "security.selinux").split(b":")[2:3] != [b"httpd_config_t"]):
                    _deny("OWNED_SOCKET_CONFIG_LABEL_UNVERIFIED")
    except NativeV2TransactionError:
        raise
    except (RootControlWorkerError, OSError, ValueError, TypeError):
        _deny("OWNED_SOCKET_WRITE_BOUNDARY_REFUSED")


def _owned_socket_require_inactive_routes(snapshot: dict | None) -> None:
    """Until #450 storage and live access are verified, no active routes."""
    if snapshot is None:
        return
    document = parse_install_bytes(
        base64.b64decode(snapshot["configuration_base64"], validate=True),
        for_apply=True,
    )
    if any(row["desired_state"] == "active" for row in document["repositories"]):
        _deny("OWNED_SOCKET_ACTIVE_STORAGE_UNVERIFIED")


def _owned_socket_operation_locked(root_fd: int, state_fd: int,
                                   distribution: str, operation: str) -> dict:
    """Fixed isolated live operations, retaining one lock and no vendor fallback."""
    with _owned_layout_locked(root_fd, state_fd, recovering=operation == "RECOVER_V2") as layout:
        _, nginx_fd, public_fd, check_layout = layout
        _owned_socket_host_boundary(
            root_fd, state_fd, nginx_fd, public_fd, distribution,
        )
        retained_check = check_layout
        def check_layout():
            retained_check()
            _owned_socket_recheck_write_boundary(root_fd, nginx_fd, distribution)
        layout = (state_fd, nginx_fd, public_fd, check_layout)
        check_layout()
        current = _read_owned_resources(state_fd, nginx_fd, public_fd)
        if operation == "RECOVER_V2":
            # A partially applied resource set is not a committed snapshot.
            # Validate the WAL's closed prior state instead.
            wal = _read_file(state_fd, _OWNED_WAL, 0, _MAX_WAL)
            temporary = _read_file(state_fd, _OWNED_WAL_TMP, 0, _MAX_WAL)
            if wal is not None or temporary is not None:
                old, _ = _decode_owned_wal(wal if wal is not None else temporary,
                                           distribution=distribution)
                _owned_socket_require_inactive_routes(
                    _validate_owned_resources(old, distribution=distribution))
            else:
                _owned_socket_require_inactive_routes(
                    _validate_owned_resources(current, distribution=distribution))
            result = _recover_owned_live_locked(root_fd, *layout)
            mapping = {
                "OWNED_LIVE_CLEAN_OBSERVED": "NATIVE_V2_CLEAN",
                "OWNED_LIVE_UNPUBLISHED_WAL_DISCARDED": "NATIVE_V2_UNPUBLISHED_WAL_DISCARDED",
                "OWNED_LIVE_ROLLBACK_OBSERVED": "NATIVE_V2_ROLLED_BACK",
            }
            if result.get("status") not in mapping or result.get("recovery_required") is not False:
                _deny("OWNED_SOCKET_RECOVERY_UNVERIFIED")
            return {"status": mapping[result["status"]]}
        snapshot = _validate_owned_resources(current, distribution=distribution)
        _owned_socket_require_inactive_routes(snapshot)
        if operation == "APPLY_V2":
            report, candidate = _load_private_under_root(root_fd, owner_uid=0, owner_gid=0)
            # Check both candidate and predecessor before any WAL effect.
            _owned_socket_require_inactive_routes(_json(candidate, limit=_LIMIT[V2_STATE]))
            # Bind the storage gate to the *same* intake used at WAL publication.
            if (snapshot is not None and candidate == current[V2_STATE]
                    and report["expected_generation"] == snapshot["state_generation"] - 1):
                result = _reload_owned_live_committed_locked(root_fd, *layout, reload=False)
                again, raw = _load_private_under_root(root_fd, owner_uid=0, owner_gid=0)
                if again != report or raw != candidate:
                    _deny("CANDIDATE_CHANGED")
            else:
                old, new, prepared = _prepare_owned_live_candidate_locked(
                    root_fd, state_fd, nginx_fd, public_fd, distribution,
                )
                if old != current or prepared != report or new[V2_STATE] != candidate:
                    _deny("CANDIDATE_CHANGED")
                result = _apply_owned_live_locked(
                    root_fd, *layout, new, expected_intake=prepared,
                )
            mapping = {"OWNED_LIVE_COMMIT_OBSERVED": "NATIVE_V2_COMMITTED",
                       "OWNED_LIVE_NO_CHANGE": "NATIVE_V2_NO_CHANGE"}
        elif operation == "RELOAD_V2":
            result = _reload_owned_live_committed_locked(root_fd, *layout)
            mapping = {"OWNED_LIVE_RELOADED": "NATIVE_V2_RELOADED"}
        else:
            _deny("OPERATION_REFUSED")
        check_layout()
        if result.get("status") not in mapping:
            _deny("OWNED_SOCKET_RESULT_UNVERIFIED")
        committed = _validate_owned_resources(
            _read_owned_resources(state_fd, nginx_fd, public_fd),
            distribution=distribution)
        if (committed is None
                or result.get("state_generation") != committed["state_generation"]):
            _deny("OWNED_SOCKET_RESULT_UNVERIFIED")
        return {"status": mapping[result["status"]],
                "state_generation": committed["state_generation"]}


def _operation_under_root(root_fd: int, *, distribution: str,
                          operation: str, fixture: bool = False,
                          socket_dispatch: bool = False) -> dict:
    """Internal entry. Only trusted root code selects the fixed operation."""
    if type(distribution) is not str or distribution not in _CA:
        _deny("DISTRIBUTION_UNSUPPORTED")
    if operation not in ("APPLY_V2", "RECOVER_V2", "RELOAD_V2"):
        _deny("OPERATION_REFUSED")
    if fixture:
        _refuse_actual_root_fixture_write(root_fd)
    with ExitStack() as stack:
        with _locked(root_fd, 0) as state_fd:
            if socket_dispatch:
                if fixture:
                    _deny("OPERATION_REFUSED")
                # A malformed or dangling reserved marker still selects the
                # dedicated domain; no denial may fall through to vendor.
                claimed = any(name.startswith(OWNED_NGINX_CONFIG_MARKER_PREFIX)
                              for name in os.listdir(state_fd))
                if claimed:
                    return _owned_socket_operation_locked(
                        root_fd, state_fd, distribution, operation,
                    )
            _refuse_owned_nginx_transaction_artifacts(state_fd)
            if not fixture:
                _refuse_legacy_vendor_mode_after_owned_claim(state_fd)
                if socket_dispatch:
                    inspect_effective_native_nginx_unit(distribution)
            include_fd, include_chain = _walk(root_fd, _INCLUDE_DIR, stack, 0)
            public_fd, public_chain = _walk(root_fd, _PUBLIC_DIR, stack, 0)
            # Do not use a foreign state/catalog filesystem without reviewed
            # mount controls. _walk enforces trusted owner + same-dev ancestry.
            if stat.S_IMODE(os.fstat(public_fd).st_mode) != 0o755:
                _deny("PUBLIC_DIRECTORY_MODE_UNSAFE")
            if operation == "APPLY_V2":
                if not fixture:
                    _require_audited_native_package_for_activation(
                        state_fd, distribution=distribution,
                    )
                result = _apply_locked(root_fd, state_fd, include_fd,
                                       public_fd, distribution, fixture=fixture)
            elif operation == "RELOAD_V2":
                if not fixture:
                    _require_audited_native_package_for_activation(
                        state_fd, distribution=distribution,
                    )
                result = _reload_owned_locked(root_fd, state_fd, include_fd,
                                              public_fd, distribution)
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
    report = require_socket_worker_host_preconditions()
    if report["host_root_provenance_verified"] is not False:
        _deny("HOST_CONTEXT_INVALID")
    # Select ownership domain only under the retained state lock. Never
    # inspect/reload the vendor unit as a fallback from a dedicated claim.
    fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        _verify_current_root_fd(fd)
        result = _operation_under_root(
            fd, distribution=distribution, operation=operation,
            socket_dispatch=True,
        )
        _verify_current_root_fd(fd)
        return result
    except NativeV2TransactionError:
        raise
    except (OSError, ValueError, TypeError):
        _deny("HOST_OPERATION_REFUSED")
    finally:
        os.close(fd)
