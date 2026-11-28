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
import pwd
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from typing import Any
from urllib.parse import urlsplit

from repocache.server_bounded_dns_v1 import DEFAULT_DNS_SECONDS, bounded_getaddrinfo
from repocache.server_install_v1 import parse_install_bytes, validate_install_document
from repocache.server_locked_manifest_reconcile_v1 import (
    _validate_proposed_v2_snapshot, preview_proposed_v2_state_transition,
    _verify_current_root_fd,
)
from repocache.server_native_egress_candidate_v1 import (
    derive_pinned_egress_candidate, render_namespace_egress_candidate,
    render_bootstrap_egress_candidate, _replace_fixed_namespace_egress,
    _prepare_boot_egress_locked, _fresh_boot_egress_intent_locked,
    _create_fixed_loopback_namespace_locked, _read_boot_egress_receipt,
)
from repocache.server_native_nginx_effective_unit_v1 import (
    EffectiveNginxUnitError, inspect_effective_native_nginx_unit,
    OWNED_NGINX_CONFIG_MARKER_PREFIX,
    inspect_signed_owned_nginx_unit, require_owned_bootstrap_health,
    _inspect_owned_nginx_unit_bytes,
)
from repocache.server_native_installed_storage_v1 import (
    InstalledStorageError, verify_control_storage, verify_service_storage_mounts, _mount, _Labels,
    _rename_directory_noreplace,
)
from repocache.server_protected_namespace_bootstrap_v1 import (
    _DEDICATED_PUBLIC_CONTEXT, _dedicated_public_directory, _dedicated_ancestry,
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
# Native packages have build-time vendor temp paths. Neither managed
# context may create or chown vendor data. Use the existing signed runtime
# domain, whose parent is root-owned. These are transient scratch paths,
# not repository cache or persistent log storage. The bootstrap is unchanged.
_OWNED_RUNTIME_TEMP_NAMES = (
    ("client_body_temp_path", "client-body"),
    ("proxy_temp_path", "proxy"),
    ("fastcgi_temp_path", "fastcgi"),
    ("scgi_temp_path", "scgi"),
    ("uwsgi_temp_path", "uwsgi"),
)
for _distribution, _main in tuple(_OWNED_MANAGED_CONFIGS.items()):
    _OWNED_MANAGED_CONFIGS[_distribution] = _main.replace(
        b"http {\n    access_log off;\n",
        b"http {\n    access_log off;\n" + b"".join(
            f"    {directive} /run/repocache-nginx/{name};\n".encode("ascii")
            for directive, name in _OWNED_RUNTIME_TEMP_NAMES
        ),
    )
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
    "NATIVE_V2_APPLY_FAILED_RECOVERY_REQUIRED",
    "NATIVE_V2_APPLY_FAILED_ROLLED_BACK",
    "NATIVE_V2_LEGACY_GENERATION_STALE",
    "NATIVE_V2_NGINX_DUMP_MISMATCH",
    "NATIVE_V2_NGINX_DUMP_UNVERIFIED",
    "NATIVE_V2_NGINX_NOT_ACTIVE_BEFORE_WAL",
    "NATIVE_V2_POST_COMMIT_DRIFT",
    "NATIVE_V2_POST_RELOAD_DRIFT",
    "NATIVE_V2_PRE_RELOAD_DRIFT",
    "NATIVE_V2_PREVIOUS_STATE_INVALID",
    "NATIVE_V2_PREPARE_DRIFT",
    "NATIVE_V2_SYNTAX_UNVERIFIED",
    "NATIVE_V2_UNIT_CHANGED",
    "NATIVE_V2_OWNER_MANIFEST_DRIFT",
    "NATIVE_V2_MANAGED_GENERATION_REQUIRED",
    "NATIVE_V2_LAYOUT_UNSUPPORTED",
    "NATIVE_V2_NGINX_TLS_CANDIDATE_INVALID",
    "NATIVE_V2_NGINX_TLS_CANDIDATE_UNTRUSTED",
    "NATIVE_V2_NGINX_SIZE",
    "NATIVE_V2_CONFLICTING_WALS",
    "NATIVE_V2_NATIVE_RECOVERY_REQUIRED",
    "NATIVE_V2_NGINX_OWNERSHIP_UNVERIFIED",
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
    "NATIVE_V2_OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED",
    "NATIVE_V2_OWNED_CONTEXT_VENDOR_TEMP_READ_ONLY",
    "NATIVE_V2_OWNED_CONTEXT_VENDOR_TEMP_PERMISSION",
    "NATIVE_V2_OWNED_CONTEXT_VENDOR_TEMP_MISSING",
    "NATIVE_V2_OWNED_CONTEXT_CHECK_PERMISSION",
    "NATIVE_V2_OWNED_CONTEXT_CHECK_READ_ONLY",
    "NATIVE_V2_OWNED_CONTEXT_DIAGNOSTIC_LIMIT",
    "NATIVE_V2_OWNED_DIRECTORY_FOREIGN_ENTRY",
    "NATIVE_V2_OWNED_DIRECTORY_MODE_UNSAFE",
    "NATIVE_V2_OWNED_DEDICATED_CATALOG_LABEL_UNVERIFIED",
    "NATIVE_V2_OWNED_DEDICATED_FINISH_RESOURCE_CHANGED",
    "NATIVE_V2_OWNED_DEDICATED_RECOVERY_INPUT_INVALID",
    "NATIVE_V2_OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED",
    "NATIVE_V2_OWNED_DEDICATED_RECOVERY_MASTER_CHANGED",
    "NATIVE_V2_OWNED_DEDICATED_INSTALLER_PIN_REFUSED",
    "NATIVE_V2_OWNED_DEDICATED_INSTALLER_PLACEMENT_REFUSED",
    "NATIVE_V2_OWNED_DEDICATED_INSTALLER_PACKAGE_REFUSED",
    "NATIVE_V2_OWNED_DEDICATED_INSTALLER_PROFILE_REFUSED",
    "NATIVE_V2_OWNED_DEDICATED_INSTALLER_BOOT_REFUSED",
    "NATIVE_V2_OWNED_DEDICATED_INSTALLER_RESULT_REFUSED",
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


def _require_dedicated_public_label(fd: int) -> None:
    if (set(os.listxattr(fd)) != {"security.selinux"}
            or os.getxattr(fd, "security.selinux").rstrip(b"\0") != _DEDICATED_PUBLIC_CONTEXT):
        _deny("OWNED_DEDICATED_CATALOG_LABEL_UNVERIFIED")


def _dedicated_readonly_config_labels(nginx: int, public: int, *, catalog_present: bool,
                                      bootstrap: bool = False,
                                      allowed_stage: str | None = None) -> tuple:
    """Read-only exact label/identity proof for the retained owned layout."""
    code = "OWNED_DEDICATED_READONLY_LABEL_UNVERIFIED"
    if (type(catalog_present) is not bool or type(bootstrap) is not bool
            or (bootstrap and catalog_present)
            or (allowed_stage is not None and (catalog_present or allowed_stage not in (
                _OWNED_STAGES[_OWNED_MAIN], _OWNED_STAGES[_INCLUDE])))):
        _deny(code)
    try:
        with ExitStack() as stack:
            parents = (nginx, public)
            before = tuple(_identity(os.fstat(fd)) for fd in parents)
            mounts = tuple(_mount(fd) for fd in parents)
            held = []
            for parent in parents:
                info = os.fstat(parent)
                if (not stat.S_ISDIR(info.st_mode) or
                        (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o755)):
                    _deny(code)
                _require_dedicated_public_label(parent)
            names = [(nginx, _OWNED_MAIN)]
            if not bootstrap:
                names.append((nginx, _INCLUDE))
            if catalog_present:
                names.append((public, _CATALOG))
            for parent, name in names:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
                stack.callback(os.close, fd)
                info = os.fstat(fd)
                identity = _identity(info)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o644)
                        or _mount(fd) != _mount(parent)
                        or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity):
                    _deny(code)
                _require_dedicated_public_label(fd)
                held.append((parent, name, fd, identity))
            for parent, name, fd, identity in held:
                _require_dedicated_public_label(fd)
                if (_identity(os.fstat(fd)) != identity
                        or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity
                        or _mount(fd) != _mount(parent)):
                    _deny(code)
            if bootstrap or allowed_stage is not None:
                expected_names = {name for parent, name in names if parent == nginx}
                permitted = (expected_names, expected_names | {allowed_stage})
                if set(os.listdir(nginx)) not in permitted or os.listdir(public):
                    _deny(code)
            if not catalog_present:
                try:
                    os.stat(_CATALOG, dir_fd=public, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    _deny(code)
            for parent in parents:
                _require_dedicated_public_label(parent)
            if (tuple(_identity(os.fstat(fd)) for fd in parents) != before
                    or tuple(_mount(fd) for fd in parents) != mounts):
                _deny(code)
            return (before, mounts, tuple(identity for _, _, _, identity in held))
    except NativeV2TransactionError:
        raise
    except (OSError, InstalledStorageError, ValueError, TypeError):
        _deny(code)


def _dedicated_recovery_config_identity(nginx: int, public: int, *,
                                        catalog_present: bool) -> tuple:
    """Pin unchanged config while permitting only the catalog phase transition."""
    parents, mounts, files = _dedicated_readonly_config_labels(
        nginx, public, catalog_present=catalog_present)
    # Catalog publication/withdrawal changes the public directory's size
    # and timestamps. The full proof above still checks those within each
    # observation. Across phases retain its inode, mode, owner, links and
    # mount, plus the complete immutable NGINX directory and file identities.
    return (parents[0], parents[1][:6], mounts, files[:2])


def _require_dedicated_catalog_label(parent: int) -> None:
    _require_dedicated_public_label(parent)
    fd = os.open(_CATALOG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                 | os.O_CLOEXEC, dir_fd=parent)
    try:
        _require_dedicated_public_label(fd)
        if _identity(os.fstat(fd)) != _identity(
                os.stat(_CATALOG, dir_fd=parent, follow_symlinks=False)):
            _deny("RESOURCE_CHANGED")
    finally:
        os.close(fd)


def _write_dedicated_fresh_public(parent: int, name: str, raw: bytes) -> None:
    """Publish only a fixed fresh read-only leaf, with no-replace semantics.

    Caller retains the authenticated ownership lock and independently pins
    the parent. The only accepted main bytes are the signed inert bootstrap.
    No existing inode is relabelled, replaced or removed here.
    """
    code = "OWNED_DEDICATED_FRESH_PUBLIC_REFUSED"
    if (name not in (_CATALOG, _OWNED_MAIN) or type(raw) is not bytes
            or not 1 <= len(raw) <= _OWNED_LIMIT[name]
            or (name == _OWNED_MAIN and raw != _OWNED_BOOTSTRAP_CONFIG)):
        _deny(code)
    _write_dedicated_public_leaf(parent, name, None, raw, recheck=lambda: None)


def _write_dedicated_public_leaf(parent: int, name: str, prior: bytes | None,
                                 raw: bytes | None, *, recheck) -> None:
    """Labelled fresh staging and exact-target replacement under a trusted lock.

    No existing inode is relabelled. Only initial configuration rollback may
    remove a managed include. Existing-file replacement assumes the original
    root-only ownership boundary and cooperating state lock, not hostile root.
    """
    code = ("OWNED_DEDICATED_FRESH_PUBLIC_REFUSED" if prior is None
            and name in (_CATALOG, _OWNED_MAIN) else "OWNED_DEDICATED_PUBLIC_WRITE_REFUSED")
    if (name not in (_CATALOG, _OWNED_MAIN, _INCLUDE)
            or not callable(recheck) or prior == raw
            or (raw is None and name != _INCLUDE)
            or (name == _CATALOG and prior is not None)
            or any(value is not None and
                   (type(value) is not bytes or not 1 <= len(value) <= _OWNED_LIMIT[name])
                   for value in (prior, raw))):
        _deny(code)
    stage = _OWNED_STAGES[name]
    target = None
    try:
        parent_identity = _identity(os.fstat(parent))[:6]
        mount = _mount(parent)

        def check_parent():
            info = os.fstat(parent)
            if (not stat.S_ISDIR(info.st_mode)
                    or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o755)
                    or _identity(info)[:6] != parent_identity or _mount(parent) != mount
                    or os.fstatvfs(parent).f_flag & os.ST_RDONLY):
                _deny(code)
            _require_dedicated_public_label(parent)

        recheck()
        check_parent()
        target_identity = None
        if prior is not None:
            target = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
            target_identity = _identity(os.fstat(target))

        def check_target():
            if prior is None:
                _owned_require_absent(parent, name)
                return
            info = os.fstat(target)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o644)
                    or _mount(target) != mount or info.st_size != len(prior)
                    or _identity(info) != target_identity
                    or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != target_identity):
                _deny(code)
            _require_dedicated_public_label(target)
            if (os.pread(target, len(prior) + 1, 0) != prior
                    or _identity(os.fstat(target)) != target_identity
                    or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != target_identity):
                _deny(code)

        check_target()
        _owned_require_absent(parent, stage)
        if raw is None:
            recheck()
            check_parent()
            check_target()
            _owned_require_absent(parent, stage)
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
            check_parent()
            _owned_require_absent(parent, name)
            return

        fd = os.open(stage, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            def check_stage(mode, size):
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_size)
                           != (0, 0, mode, size)
                        or _mount(fd) != mount
                        or _identity(os.stat(stage, dir_fd=parent, follow_symlinks=False)) != _identity(info)
                        or set(os.listxattr(fd)) != {"security.selinux"}):
                    _deny(code)
                return _identity(info)

            check_parent()
            check_stage(0o600, 0)
            if os.getxattr(fd, "security.selinux").rstrip(b"\0") != _DEDICATED_PUBLIC_CONTEXT:
                os.setxattr(fd, "security.selinux", _DEDICATED_PUBLIC_CONTEXT + b"\0")
            _require_dedicated_public_label(fd)
            position = 0
            while position < len(raw):
                count = os.write(fd, raw[position:])
                if count <= 0:
                    _deny(code)
                position += count
            os.fsync(fd)
            check_stage(0o600, len(raw))
            os.fchmod(fd, 0o644)
            os.fsync(fd)
            identity = check_stage(0o644, len(raw))
            _require_dedicated_public_label(fd)
            if os.pread(fd, len(raw) + 1, 0) != raw:
                _deny(code)
            recheck()
            check_parent()
            if check_stage(0o644, len(raw)) != identity:
                _deny(code)
            _require_dedicated_public_label(fd)
            check_target()
            if check_stage(0o644, len(raw)) != identity:
                _deny(code)
            _require_dedicated_public_label(fd)
            if prior is None:
                # Preserve a late-arriving foreign target, even identical bytes.
                _rename_directory_noreplace(parent, stage, parent, name)
            else:
                os.replace(stage, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            current = _identity(os.fstat(fd))
            # Rename may advance ctime; every other field remains pinned.
            if (current[:-1] != identity[:-1]
                    or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != current
                    or _mount(fd) != mount or os.pread(fd, len(raw) + 1, 0) != raw):
                _deny(code)
            _require_dedicated_public_label(fd)
            check_parent()
            _owned_require_absent(parent, stage)
            if (_read_public(parent, name, _OWNED_LIMIT[name]) != raw
                    or _identity(os.fstat(fd)) != current):
                _deny(code)
        finally:
            os.close(fd)
    except NativeV2TransactionError:
        raise
    except (OSError, ValueError, TypeError, InstalledStorageError):
        _deny(code)
    finally:
        if target is not None:
            os.close(target)


def _write_public(parent: int, name: str, before: bytes | None,
                  after: bytes | None, maximum: int, *, stage: str = _STAGE,
                  dedicated_catalog: bool = False) -> None:
    """Atomic same-parent replacement, fsynced; no foreign target takeover."""
    if dedicated_catalog:
        if (name != _CATALOG or before is not None or after is None
                or stage != _OWNED_STAGES[_CATALOG] or maximum != _OWNED_LIMIT[_CATALOG]):
            _deny("OWNED_DEDICATED_CATALOG_LABEL_UNVERIFIED")
        _write_dedicated_fresh_public(parent, name, after)
        return
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


def _native_reload_identity(distribution: str) -> tuple[str, int]:
    observed = inspect_effective_native_nginx_unit(distribution)
    if (observed["unit_name"] != _UNIT
            or observed["authorizes_nginx_reload"] is not False):
        _deny("FOREIGN_UNIT")
    return observed["vendor_unit_sha256"], observed["main_pid_observed"]


def _reload_native(distribution: str) -> tuple[str, int]:
    # Both observations must prove the same intended vendor unit, active
    # master identity and immutable fixed command across the reload.
    before = _native_reload_identity(distribution)
    _fixed_command((_SYSTEMCTL, "reload", _UNIT), timeout=10)
    if _native_reload_identity(distribution) != before:
        _deny("UNIT_CHANGED")
    return before


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


def _local_https_generation(document: dict[str, Any], generation: int, *,
                            stale_generation: int | None = None) -> None:
    response = _fixed_https_get(document, _HEALTH, 8192)
    header, body = response.split(b"\r\n\r\n", 1)
    lines = header.lower().split(b"\r\n")
    markers = [line for line in lines if line.startswith(b"x-repocache-generation:")]
    if (not header.startswith(b"HTTP/1.1 204 ") or body
            or any(line.startswith((b"transfer-encoding:", b"content-encoding:"))
                   for line in lines)
            or [line for line in lines if line.startswith(b"content-length:")]
               not in ([], [b"content-length: 0"])):
        _deny("EXPOSURE_UNVERIFIED")
    marker = f"x-repocache-generation: {generation}".encode("ascii")
    if markers == [marker]:
        return
    if (stale_generation is not None and stale_generation != generation
            and markers == [f"x-repocache-generation: {stale_generation}".encode("ascii")]):
        _deny("LEGACY_GENERATION_STALE")
    _deny("EXPOSURE_UNVERIFIED")


def _wait_native_generation(document: dict[str, Any], generation: int,
                            distribution: str, identity: tuple[str, int], *,
                            stale_generation: int | None) -> None:
    """Wait only for the known adjacent generation after a fixed reload.

    Preserve the observed vendor unit/master throughout; never retry a TLS,
    malformed-response, unrelated-generation or ownership failure.
    """
    deadline = time.monotonic() + 12
    for attempt in range(61):
        if _native_reload_identity(distribution) != identity:
            _deny("UNIT_CHANGED")
        try:
            _local_https_generation(document, generation, stale_generation=stale_generation)
        except NativeV2TransactionError as exc:
            if exc.args != ("NATIVE_V2_LEGACY_GENERATION_STALE",):
                raise
            if _native_reload_identity(distribution) != identity:
                _deny("UNIT_CHANGED")
            remaining = deadline - time.monotonic()
            if attempt == 60 or remaining <= 0:
                raise
            time.sleep(min(0.2, remaining))
        else:
            if _native_reload_identity(distribution) != identity:
                _deny("UNIT_CHANGED")
            return


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


def _dedicated_readonly_tls_labels(root_fd: int, document: dict[str, Any]) -> tuple:
    """Observe the authenticated generation's TLS paths; never change labels."""
    code = "OWNED_DEDICATED_TLS_LABEL_UNVERIFIED"
    try:
        tls = document["deployment"]["tls"]
        with ExitStack() as stack:
            held = []
            for field in ("certificate_file", "private_key_file"):
                path = tls[field]
                if (type(path) is not str or not path.startswith("/")
                        or any(part in ("", ".", "..") for part in path[1:].split("/"))):
                    _deny(code)
                segments = path[1:].split("/")
                if len(segments) < 2:
                    _deny(code)
                parent, chain = _walk(root_fd, tuple(segments[:-1]), stack, 0)
                _metadata_no_acl(root_fd, directory=True)
                for ancestor, _, child, _ in chain:
                    _metadata_no_acl(child, directory=True)
                    if _mount(child) != _mount(ancestor):
                        _deny(code)
                _require_dedicated_public_label(parent)
                fd = os.open(segments[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
                stack.callback(os.close, fd)
                info = _metadata_no_acl(fd)
                identity = _identity(info)
                forbidden = 0o077 if field == "private_key_file" else 0o022
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) & forbidden
                        or not 0 < info.st_size <= 128 * 1024
                        or _mount(fd) != _mount(parent)
                        or _identity(os.stat(segments[-1], dir_fd=parent,
                                             follow_symlinks=False)) != identity):
                    _deny(code)
                _require_dedicated_public_label(fd)
                held.append((parent, segments[-1], fd, identity, chain))
            if held[0][3][:2] == held[1][3][:2]:
                _deny(code)
            proof = []
            for parent, name, fd, identity, chain in held:
                _recheck(chain, 0)
                _metadata_no_acl(root_fd, directory=True)
                for ancestor, _, child, _ in chain:
                    _metadata_no_acl(child, directory=True)
                    if _mount(child) != _mount(ancestor):
                        _deny(code)
                _require_dedicated_public_label(parent)
                _require_dedicated_public_label(fd)
                if (_identity(_metadata_no_acl(fd)) != identity
                        or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity
                        or _mount(fd) != _mount(parent)):
                    _deny(code)
                proof.append((tuple((snapshot, _mount(child)) for _, _, child, snapshot in chain),
                              identity, _mount(fd)))
            return tuple(proof)
    except NativeV2TransactionError:
        raise
    except (OSError, ValueError, TypeError, KeyError, InstalledStorageError, RootControlWorkerError):
        _deny(code)


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
    identity = _reload_native(distribution)
    _wait_native_generation(document, generation, distribution, identity,
                            stale_generation=None)
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
        identity = _reload_native(distribution)
        # systemctl reload is asynchronous. Accept only the exact next
        # generation; the known prior generation may briefly answer.
        _wait_native_generation(doc, snapshot["state_generation"], distribution,
                                identity, stale_generation=generation or None)
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
    except Exception as exc:
        # Rollback occurs under the SAME exclusive lock. If the OS crashes,
        # recovery is a separate fixed operation; never claim success.
        _audit_native_failure(exc)
        try:
            _recover_locked(state_fd, include_fd, public_fd, distribution)
        except Exception as recovery_error:
            _audit_native_failure(recovery_error)
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


def _owned_debian_runtime_temps(root_fd: int, *, require_all: bool,
                                inactive: bool = False) -> tuple:
    """Observe the fixed private runtime paths before/after native nginx -T.

    NGINX itself creates the missing paths under a root-owned parent. A
    worker cannot replace a direct child or mount over it. Reject symlinks,
    aliases/mounts, foreign owners and unexpected xattrs before root invokes
    NGINX. Inactive repair may reuse only empty, correctly owned scratch
    directories (or an empty root-owned partial mkdir from the same runtime).
    No persistent cache, vendor path or caller-supplied path is changed.
    """
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

    def empty(fd):
        with os.scandir(fd) as entries:
            return next(entries, None) is None

    try:
        worker = pwd.getpwnam("www-data")
        if not 0 < worker.pw_uid < 2**32 - 1:
            _deny("OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED")
        with ExitStack() as stack:
            run = os.open("run", _DIRECTORY_FLAGS, dir_fd=root_fd)
            stack.callback(os.close, run)
            runtime = os.open("repocache-nginx", _DIRECTORY_FLAGS, dir_fd=run)
            stack.callback(os.close, runtime)
            parent = os.fstat(run)
            info = os.fstat(runtime)
            if (parent.st_uid != 0 or parent.st_gid != 0 or parent.st_mode & 0o022
                    or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o755
                    or os.listxattr(runtime)
                    or os.fstatvfs(runtime).f_flag & os.ST_RDONLY
                    or identity(os.stat("repocache-nginx", dir_fd=run,
                                        follow_symlinks=False)) != identity(info)):
                _deny("OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED")
            runtime_mount = _mount(runtime)
            names = {name for _, name in _OWNED_RUNTIME_TEMP_NAMES}
            if inactive:
                with os.scandir(runtime) as entries:
                    if any(entry.name not in names for entry in entries):
                        _deny("OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED")
            observed = {}
            for name in sorted(names):
                try:
                    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=runtime)
                except FileNotFoundError:
                    if require_all:
                        _deny("OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED")
                    continue
                stack.callback(os.close, fd)
                child = os.fstat(fd)
                # Allow only the fixed worker, or an empty root-owned
                # partial mkdir under the protected runtime before a probe.
                correct_owner = (child.st_uid == worker.pw_uid or
                                 (not require_all and child.st_uid == 0 and empty(fd)))
                if (not stat.S_ISDIR(child.st_mode) or child.st_gid != 0
                        or stat.S_IMODE(child.st_mode) != 0o700 or not correct_owner
                        or os.listxattr(fd) or _mount(fd) != runtime_mount
                        or os.fstatvfs(fd).f_flag & os.ST_RDONLY
                        or identity(os.stat(name, dir_fd=runtime,
                                            follow_symlinks=False)) != identity(child)
                        or (inactive and not empty(fd))):
                    _deny("OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED")
                observed[name] = identity(child)
            if (identity(os.fstat(runtime)) != identity(info)
                    or identity(os.stat("repocache-nginx", dir_fd=run,
                                        follow_symlinks=False)) != identity(info)
                    or identity(os.stat("run", dir_fd=root_fd,
                                        follow_symlinks=False)) != identity(parent)):
                _deny("OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED")
            return identity(info), observed
    except NativeV2TransactionError:
        raise
    except (InstalledStorageError, OSError, ValueError, KeyError, TypeError):
        _deny("OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED")


def _owned_alma_runtime_temps(root_fd: int, *, dedicated: bool,
                              allow_create: bool = False, require_all: bool = True,
                              inactive: bool = False) -> tuple:
    """Verify the five fixed Alma runtime leaves, or prepare fresh ones.

    Only the authenticated lifecycle/syntax caller under the original state
    lock may create them. The runtime parent stays root-owned and the
    dedicated PID label never becomes a cache/scratch label. No existing
    inode is relabelled, chmodded, chowned or removed. A partial/foreign
    leaf is refused; no persistent or vendor storage is changed.
    """
    code = "OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED"
    if (any(type(value) is not bool for value in
            (dedicated, allow_create, require_all, inactive))
            or (allow_create and not require_all)):
        _deny(code)

    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

    def label(fd, types):
        if set(os.listxattr(fd)) != {"security.selinux"}:
            _deny(code)
        value = os.getxattr(fd, "security.selinux").rstrip(b"\x00")
        if value not in {user + b":object_r:" + kind + b":s0"
                         for user in (b"system_u", b"unconfined_u") for kind in types}:
            _deny(code)
        return value

    try:
        labels = _Labels("almalinux", dedicated=dedicated)
        worker = pwd.getpwnam("nginx")
        if not 0 < worker.pw_uid < 2**32 - 1:
            _deny(code)
        parent_types = ((b"repocache_nginx_pid_t",) if dedicated else
                        (b"var_run_t", b"httpd_var_run_t"))
        child_type = b"repocache_nginx_rw_t" if dedicated else b"httpd_var_run_t"
        fresh_label = b"system_u:object_r:" + child_type + b":s0\x00"
        names = tuple(sorted(name for _, name in _OWNED_RUNTIME_TEMP_NAMES))
        with ExitStack() as stack:
            run = os.open("run", _DIRECTORY_FLAGS, dir_fd=root_fd)
            stack.callback(os.close, run)
            runtime = os.open("repocache-nginx", _DIRECTORY_FLAGS, dir_fd=run)
            stack.callback(os.close, runtime)
            parent = os.fstat(run)
            info = os.fstat(runtime)
            if (parent.st_uid != 0 or parent.st_gid != 0 or parent.st_mode & 0o022
                    or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o755
                    or os.fstatvfs(runtime).f_flag & os.ST_RDONLY):
                _deny(code)
            runtime_label = label(runtime, parent_types)
            runtime_mount = _mount(runtime)

            def guard():
                if (identity(os.fstat(run)) != identity(parent)
                        or identity(os.stat("run", dir_fd=root_fd,
                                            follow_symlinks=False)) != identity(parent)
                        or identity(os.fstat(runtime)) != identity(info)
                        or identity(os.stat("repocache-nginx", dir_fd=run,
                                            follow_symlinks=False)) != identity(info)
                        or label(runtime, parent_types) != runtime_label
                        or _mount(runtime) != runtime_mount
                        or os.fstatvfs(runtime).f_flag & os.ST_RDONLY):
                    _deny(code)
                if inactive and set(os.listdir(runtime)) - set(names):
                    _deny(code)

            def sample(name, fd):
                child = os.fstat(fd)
                if (not stat.S_ISDIR(child.st_mode)
                        or (child.st_uid, child.st_gid, stat.S_IMODE(child.st_mode))
                        != (worker.pw_uid, 0, 0o700)
                        or _mount(fd) != runtime_mount
                        or os.fstatvfs(fd).f_flag & os.ST_RDONLY
                        or identity(os.stat(name, dir_fd=runtime,
                                            follow_symlinks=False)) != identity(child)):
                    _deny(code)
                if inactive and os.listdir(fd):
                    _deny(code)
                return identity(child) + (label(fd, (child_type,)),)

            guard()
            held = {}
            observed = {}
            for name in names:
                try:
                    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=runtime)
                except FileNotFoundError:
                    if require_all and not allow_create:
                        _deny(code)
                    continue
                stack.callback(os.close, fd)
                held[name] = fd
                observed[name] = sample(name, fd)
            # Validate all existing leaves before any creation. No worker can
            # replace a direct child of the root-owned runtime parent.
            guard()
            if allow_create:
                for name in names:
                    if name in held:
                        continue
                    guard()
                    os.mkdir(name, 0o700, dir_fd=runtime)
                    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=runtime)
                    stack.callback(os.close, fd)
                    fresh = os.fstat(fd)
                    if ((fresh.st_uid, fresh.st_gid, stat.S_IMODE(fresh.st_mode))
                            != (0, 0, 0o700) or os.listdir(fd)
                            or _mount(fd) != runtime_mount
                            or identity(os.stat(name, dir_fd=runtime,
                                                follow_symlinks=False)) != identity(fresh)
                            or set(os.listxattr(fd)) != {"security.selinux"}):
                        _deny(code)
                    os.setxattr(fd, "security.selinux", fresh_label)
                    os.fchown(fd, worker.pw_uid, 0)
                    os.fsync(fd)
                    os.fsync(runtime)
                    held[name] = fd
                    observed[name] = sample(name, fd)
            guard()
            if (require_all and set(held) != set(names)
                    or any(sample(name, fd) != observed[name] for name, fd in held.items())):
                _deny(code)
            guard()
            labels.finish()
            return identity(info) + (runtime_label,), observed
    except NativeV2TransactionError:
        raise
    except (InstalledStorageError, OSError, ValueError, KeyError, TypeError):
        _deny(code)


def _prepare_owned_dedicated_bootstrap_locked(root_fd: int, state_fd: int, *, recheck_owned) -> dict:
    """Fresh signed inert config only; caller holds the authenticated state lock.

    Requires a previously prepared, exactly labelled public directory and
    enforcing dedicated policy. No legacy adoption, service or TLS effects.
    An interrupted partial claim is preserved and refused.
    """
    code = "OWNED_DEDICATED_BOOTSTRAP_REFUSED"
    if not callable(recheck_owned):
        _deny(code)
    marker = (OWNED_NGINX_CONFIG_MARKER_PREFIX
              + hashlib.sha256(b"/etc/nginx/repocache.d/\0" + _OWNED_BOOTSTRAP_CONFIG).hexdigest())

    def named(parent, name):
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None

    try:
        labels = _Labels("almalinux", dedicated=True)
        recheck_owned()
        with ExitStack() as stack:
            shared, chain = _walk(root_fd, _OWNED_DIR[:-1], stack, 0)
            vendor, vendor_chain = _walk(root_fd, _INCLUDE_DIR, stack, 0)
            public, public_chain = _walk(root_fd, _PUBLIC_DIR, stack, 0)
            state, state_chain = _walk(root_fd, ("var", "lib", "repocache", "server"), stack, 0)
            shared_before = _identity(os.fstat(shared))[:5]
            mount = _mount(shared)
            state_before = _identity(os.fstat(state_fd))[:6]
            if (_identity(os.fstat(state))[:6] != state_before or _mount(state_fd) != _mount(state)
                    or (os.fstat(state_fd).st_uid, os.fstat(state_fd).st_gid,
                        stat.S_IMODE(os.fstat(state_fd).st_mode)) != (0, 0, 0o700)):
                _deny(code)

            def boundary():
                recheck_owned()
                for paths in (chain, vendor_chain, public_chain, state_chain):
                    _dedicated_ancestry(root_fd, paths)
                _recheck(chain[:-1], 0)
                parent, name, _, _ = chain[-1]
                if (_identity(os.fstat(shared))[:5] != shared_before
                        or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] != shared_before
                        or _mount(shared) != mount):
                    _deny(code)
                # The shared NGINX parent changes only during our mkdir;
                # the vendor conf.d child itself must remain unchanged.
                _recheck(vendor_chain[:-2], 0)
                if (_identity(os.fstat(vendor)) != vendor_chain[-1][3]
                        or _identity(os.stat(_INCLUDE_DIR[-1], dir_fd=shared,
                                             follow_symlinks=False)) != vendor_chain[-1][3]):
                    _deny(code)
                _recheck(public_chain, 0)
                _recheck_after_mutation(state_chain, 0)
                if (_identity(os.fstat(state_fd))[:6] != state_before
                        or _mount(state_fd) != _mount(state)):
                    _deny(code)
                _dedicated_public_directory(public)
                if os.listdir(public):
                    _deny(code)
                _no_conflicting_owned_wal_pending(state_fd)
                if (_read_v2(state_fd, 0)[0] is not None
                        or _read_file(state_fd, _OWNED_MANIFEST, 0, _OWNED_LIMIT[_OWNED_MANIFEST]) is not None
                        or _read_file(state_fd, _MANIFEST, 0, _LIMIT[_MANIFEST]) is not None
                        or _read_public(vendor, _INCLUDE, _LIMIT[_INCLUDE]) is not None):
                    _deny(code)
                for leaf in (_OWNED_MAIN, _INCLUDE, *_OWNED_STAGES.values(), _STAGE):
                    _owned_require_absent(shared, leaf)
                _owned_require_absent(vendor, _STAGE)

            boundary()
            claims = {name for name in os.listdir(state_fd)
                      if name.startswith(OWNED_NGINX_CONFIG_MARKER_PREFIX)}
            existing = named(shared, _OWNED_DIR[-1])
            fresh = existing is None
            if fresh:
                if claims:
                    _deny(code)
                # A durable claim precedes any NGINX leaf. Any ambiguous
                # interruption is retained and must not be silently adopted.
                fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o600, dir_fd=state_fd)
                try:
                    info = _metadata_no_acl(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0
                            or _mount(fd) != _mount(state_fd)
                            or _identity(os.stat(marker, dir_fd=state_fd, follow_symlinks=False)) != _identity(info)):
                        _deny(code)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(state_fd)
                claim = _owned_config_marker_identity(state_fd)
                boundary()
                os.mkdir(_OWNED_DIR[-1], 0o700, dir_fd=shared)
            else:
                if claims != {marker}:
                    _deny(code)
                claim = _owned_config_marker_identity(state_fd)
            nginx = os.open(_OWNED_DIR[-1], _DIRECTORY_FLAGS, dir_fd=shared)
            stack.callback(os.close, nginx)
            initial = _identity(os.fstat(nginx))[:2]

            def check_config_dir():
                boundary()
                info = os.fstat(nginx)
                if (_identity(info)[:2] != initial or _mount(nginx) != mount
                        or _identity(os.stat(_OWNED_DIR[-1], dir_fd=shared,
                                             follow_symlinks=False)) != _identity(info)
                        or _owned_config_marker_identity(state_fd) != claim):
                    _deny(code)

            check_config_dir()
            if fresh:
                _dedicated_public_directory(nginx, fresh=True)
                check_config_dir()
                os.fchmod(nginx, 0o755)
                os.fsync(nginx)
                os.fsync(shared)
                check_config_dir()
                _dedicated_public_directory(nginx)
                _write_dedicated_fresh_public(nginx, _OWNED_MAIN, _OWNED_BOOTSTRAP_CONFIG)
            check_config_dir()
            _dedicated_public_directory(nginx)
            if set(os.listdir(nginx)) != {_OWNED_MAIN}:
                _deny(code)
            main = os.open(_OWNED_MAIN, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                           dir_fd=nginx)
            stack.callback(os.close, main)
            identity = _identity(os.fstat(main))
            _require_dedicated_public_label(main)
            if (_mount(main) != mount or _read_public(nginx, _OWNED_MAIN, _OWNED_LIMIT[_OWNED_MAIN])
                    != _OWNED_BOOTSTRAP_CONFIG):
                _deny(code)
            with _owned_layout_locked(root_fd, state_fd, recovering=False) as layout:
                if _validate_owned_resources(_read_owned_resources(*layout[:3])) is not None:
                    _deny(code)
                layout[3]()
            check_config_dir()
            if (_identity(os.fstat(main)) != identity
                    or _identity(os.stat(_OWNED_MAIN, dir_fd=nginx,
                                         follow_symlinks=False)) != identity):
                _deny(code)
            _require_dedicated_public_label(main)
            labels.finish()
            return {"status": "OWNED_DEDICATED_BOOTSTRAP_PREPARED",
                    "config_directory_identity": initial, "main_identity": identity[:2],
                    "bootstrap_sha256": hashlib.sha256(_OWNED_BOOTSTRAP_CONFIG).hexdigest(),
                    "authorizes_nginx_activation": False, "authorizes_catalog_publication": False}
    except NativeV2TransactionError:
        raise
    except (OSError, ValueError, TypeError, InstalledStorageError, RootControlWorkerError):
        _deny(code)


def _prepare_owned_dedicated_runtime_locked(root_fd: int, *, recheck_owned) -> tuple:
    """Prepare only the fixed boot-local parent and empty dedicated scratch.

    The authenticated stopped-service caller retains the state lock. Never
    change an existing parent, adopt a partial parent or remove any inode.
    The existing scratch primitive verifies all leaves before creating any.
    """
    code = "OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED"
    if not callable(recheck_owned):
        _deny(code)

    def identity(info):
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid

    context = b"system_u:object_r:repocache_nginx_pid_t:s0"
    try:
        labels = _Labels("almalinux", dedicated=True)
        recheck_owned()
        with ExitStack() as stack:
            run = os.open("run", _DIRECTORY_FLAGS, dir_fd=root_fd)
            stack.callback(os.close, run)
            run_info = os.fstat(run)
            run_mount = _mount(run)

            def guard_run():
                recheck_owned()
                if (run_info.st_uid != 0 or run_info.st_gid != 0
                        or run_info.st_mode & 0o022
                        or identity(os.fstat(run)) != identity(run_info)
                        or identity(os.stat("run", dir_fd=root_fd, follow_symlinks=False)) != identity(run_info)
                        or _mount(run) != run_mount
                        or os.fstatvfs(run).f_flag & os.ST_RDONLY):
                    _deny(code)
                labels.check(run)

            guard_run()
            fresh = False
            try:
                runtime = os.open("repocache-nginx", _DIRECTORY_FLAGS, dir_fd=run)
            except FileNotFoundError:
                guard_run()
                os.mkdir("repocache-nginx", 0o700, dir_fd=run)
                runtime = os.open("repocache-nginx", _DIRECTORY_FLAGS, dir_fd=run)
                fresh = True
            stack.callback(os.close, runtime)
            initial = os.fstat(runtime)

            def guard_runtime(mode):
                guard_run()
                current = os.fstat(runtime)
                if (not stat.S_ISDIR(current.st_mode)
                        or (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino)
                        or (current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode)) != (0, 0, mode)
                        or identity(os.stat("repocache-nginx", dir_fd=run, follow_symlinks=False)) != identity(current)
                        or _mount(runtime) != run_mount
                        or os.fstatvfs(runtime).f_flag & os.ST_RDONLY
                        or set(os.listxattr(runtime)) != {"security.selinux"}):
                    _deny(code)
                return current

            if fresh:
                guard_runtime(0o700)
                if os.listdir(runtime):
                    _deny(code)
                os.setxattr(runtime, "security.selinux", context + b"\x00")
                guard_runtime(0o700)
                if os.getxattr(runtime, "security.selinux").rstrip(b"\x00") != context or os.listdir(runtime):
                    _deny(code)
                os.fchmod(runtime, 0o755)
                os.fsync(runtime)
                os.fsync(run)
            guard_runtime(0o755)
            if os.getxattr(runtime, "security.selinux").rstrip(b"\x00") != context:
                _deny(code)
            prepared = _owned_alma_runtime_temps(root_fd, dedicated=True, allow_create=True, inactive=True)
            guard_runtime(0o755)
            if (_owned_alma_runtime_temps(root_fd, dedicated=True, inactive=True) != prepared
                    or prepared[0] != identity(os.fstat(runtime)) + (context,)
                    or set(prepared[1]) != {name for _, name in _OWNED_RUNTIME_TEMP_NAMES}):
                _deny(code)
            guard_runtime(0o755)
            if os.getxattr(runtime, "security.selinux").rstrip(b"\x00") != context:
                _deny(code)
            labels.finish()
            return prepared
    except NativeV2TransactionError:
        raise
    except (InstalledStorageError, OSError, ValueError, KeyError, TypeError):
        _deny(code)


def _verify_owned_alma_runtime_service_view(pid: int, expected: tuple) -> None:
    """Compare the signed master's private mount view with retained host leaves."""
    code = "OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED"
    if type(pid) is not int or not 2 <= pid < 2**31 or os.geteuid() != 0:
        _deny(code)
    try:
        ns_path = f"/proc/{pid}/ns/mnt"
        def identity(info):
            return info.st_dev, info.st_ino
        namespace = identity(os.stat(ns_path))
        if namespace == identity(os.stat("/proc/self/ns/mnt")):
            _deny(code)
        # This one kernel-owned proc link intentionally resolves to the
        # already authenticated master's root; all descendants are nofollow.
        fd = os.open(f"/proc/{pid}/root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            if (_owned_alma_runtime_temps(fd, dedicated=True) != expected
                    or identity(os.fstat(fd)) != identity(os.stat(f"/proc/{pid}/root"))
                    or identity(os.stat(ns_path)) != namespace):
                _deny(code)
        finally:
            os.close(fd)
    except NativeV2TransactionError:
        raise
    except (OSError, ValueError, TypeError):
        _deny(code)


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
            debian_runtime = (include is not None
                              and managed_main == _OWNED_MANAGED_CONFIGS["debian"])
            if debian_runtime:
                runtime_before, temp_before = _owned_debian_runtime_temps(
                    root_fd, require_all=False,
                )
            alma_runtime = (include is not None
                            and managed_main == _OWNED_MANAGED_CONFIGS["almalinux"])
            if alma_runtime:
                # Stock httpd_t owns its native runtime type. Prepare only
                # fresh fixed leaves before the exact legacy syntax command.
                alma_before = _owned_alma_runtime_temps(
                    root_fd, dedicated=False, allow_create=True)
            dump = _capture_owned_nginx_dump_private(managed=include is not None)
            if alma_runtime and _owned_alma_runtime_temps(
                    root_fd, dedicated=False) != alma_before:
                _deny("OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED")
            if debian_runtime:
                runtime_after, temp_after = _owned_debian_runtime_temps(
                    root_fd, require_all=True,
                )
                # New directories and NGINX's root-to-worker chown of a
                # partial empty directory are expected; inode replacement is not.
                if (runtime_before != runtime_after
                        or any(temp_after[name][:3] != prior[:3]
                               or temp_after[name][4] != prior[4]
                               for name, prior in temp_before.items())):
                    _deny("OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED")
            _verify_owned_context_dump(dump, include, managed_main=managed_main)
            verify_bytes()
            _verify_current_root_fd(root_fd)
            return dump
    except NativeV2TransactionError:
        raise
    except FixedNginxFullContextError as exc:
        # Accept only the closed native probe categories; all other
        # diagnostic text remains generic and never reaches the socket.
        from repocache.server_root_control_full_context_v1 import _OWNED_PROBE_FAILURE_CODES
        for code in _OWNED_PROBE_FAILURE_CODES:
            if exc.args == ("NATIVE_NGINX_FULL_CONTEXT_" + code,):
                _deny(code)
        _deny("OWNED_CONTEXT_PROBE_REFUSED")
    except (OSError, ValueError, TypeError):
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
        # Recover the exact egress tuple candidate from the same state and
        # include bytes already bound by the manifest/WAL. Do not persist a
        # second allowlist or resolve DNS on replay/rollback.
        header = b"# REPOCACHE managed v2\n"
        prefix, separator, _ = include.partition(b"\nserver {\n")
        if not separator or not prefix.startswith(header):
            _deny("OWNED_WAL_EGRESS_CANDIDATE_INVALID")
        try:
            derive_pinned_egress_candidate(
                doc, generation=snapshot["state_generation"],
                http_fragment=prefix[len(header):],
            )
        except ValueError:
            _deny("OWNED_WAL_EGRESS_CANDIDATE_INVALID")
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


def _owned_generation_egress(resources, *, distribution: str, worker_uid: int):
    """Derive the closed ruleset from exact owned bytes, never from fresh DNS."""
    snapshot = _validate_owned_resources(resources, distribution=distribution)
    if snapshot is None:
        return render_bootstrap_egress_candidate(worker_uid=worker_uid)
    document = parse_install_bytes(
        base64.b64decode(snapshot["configuration_base64"], validate=True),
        for_apply=True,
    )
    fragment = resources[_INCLUDE].partition(b"\nserver {\n")[0]
    fragment = fragment[len(b"# REPOCACHE managed v2\n"):]
    plan = render_namespace_egress_candidate(
        document, generation=snapshot["state_generation"],
        http_fragment=fragment, worker_uid=worker_uid,
    )
    # Check the entire rendered include and catalog, not merely the upstream
    # groups. Additional locations or altered TLS cannot inherit a ruleset.
    pins = {
        repo["id"]: {
            urlsplit(repo["upstream"]["base_url"]).hostname: [
                addr for addr, _ in plan["repository_destinations"][repo["id"]]
            ]
        }
        for repo in document["repositories"] if repo["desired_state"] == "active"
    }
    # Non-base allowed hosts are not represented in the installed upstream
    # groups and are never granted egress. Scope only the re-render check
    # to the recoverable base host, just as the tuple parser does.
    render_document = {**document, "repositories": [
        {**repo, "upstream": {**repo["upstream"], "allowed_hosts": [
            urlsplit(repo["upstream"]["base_url"]).hostname
        ]}} if repo["desired_state"] == "active" else repo
        for repo in document["repositories"]
    ]}
    main, include, catalog = _render_owned_managed_candidate(
        render_document, snapshot["state_generation"], distribution, pins,
    )
    if (main, include, catalog) != (
            resources[_OWNED_MAIN], resources[_INCLUDE], resources[_CATALOG]):
        _deny("OWNED_EGRESS_GENERATION_DRIFT")
    return plan


def _owned_boot_egress_plan(resources, *, distribution: str, worker_uid: int):
    """Bind canonical prior bytes to the existing boot-receipt identity."""
    plan = _owned_generation_egress(
        resources, distribution=distribution, worker_uid=worker_uid)
    manifest = resources[_OWNED_MANIFEST]
    if manifest is None:
        # Generation zero uses its exact bootstrap resource inventory.
        manifest = _canonical({
            "schema_version": 1,
            "service_domain": _OWNED_WAL_DOMAIN,
            "bootstrap_generation": 0,
            "resources_sha256": {name: _hash(resources[name]) for name in _OWNED_ORDER},
        }, limit=_OWNED_LIMIT[_OWNED_MANIFEST])
    return {**plan, "generation_manifest_sha256": _hash(manifest),
            "authorizes_catalog_publication": False}


@contextmanager
def _owned_committed_boot_egress_generation_locked(
    root_fd: int, state_fd: int, *, distribution: str, worker_uid: int,
):
    """Retain exact committed resources for boot-specific policy preparation.

    No pending WAL, foreign domain or staged file can be treated as a
    committed generation. No DNS, kernel mutation, activation or catalog
    publication occurs here. The caller retains the state lock and proves
    signed release, native package, executable/profile, worker identity and
    service/namespace ownership. Recovery of a pending WAL is separate.
    """
    if type(distribution) is not str or distribution not in _CA:
        _deny("OWNED_EGRESS_DISTRIBUTION_INVALID")
    with _owned_layout_locked(root_fd, state_fd, recovering=False) as layout:
        state, nginx, public, check_layout = layout
        current = _read_owned_resources(state, nginx, public)
        evidence = {**_owned_boot_egress_plan(
            current, distribution=distribution, worker_uid=worker_uid),
            "committed_resources_verified": True}
        active = True

        def recheck():
            if not active:
                _deny("OWNED_BOOT_EGRESS_SCOPE_EXPIRED")
            check_layout()
            _no_conflicting_owned_wal_pending(state)
            _owned_check_stages_absent(state, nginx, public)
            if _read_owned_resources(state, nginx, public) != current:
                _deny("OWNED_BOOT_EGRESS_GENERATION_CHANGED")

        try:
            recheck()
            yield evidence, recheck
            recheck()
        finally:
            active = False


def _prepare_owned_committed_boot_egress_locked(
    root_fd: int, state_fd: int, *, distribution: str, worker_uid: int,
    namespace_identity: tuple[int, int], profile_receipt_sha256: str,
    executable_receipt_sha256: str, recheck_namespace_owner, allow_prepare: bool,
    allow_boot_rollover: bool = False, expected_existing_receipt: bytes | None = None,
) -> dict:
    """Connect committed generation evidence to the boot receipt candidate.

    Only an already authenticated, owning lifecycle caller can use this
    internal function. No installed dispatch, namespace creation, pending
    WAL recovery or service start authority is introduced.
    """
    if (not callable(recheck_namespace_owner) or type(allow_prepare) is not bool
            or type(allow_boot_rollover) is not bool
            or (allow_boot_rollover and not allow_prepare)
            or (expected_existing_receipt is not None and (
                type(expected_existing_receipt) is not bytes or not expected_existing_receipt
                or not allow_prepare or allow_boot_rollover))):
        _deny("OWNED_BOOT_EGRESS_INPUT_INVALID")
    with _owned_committed_boot_egress_generation_locked(
            root_fd, state_fd, distribution=distribution, worker_uid=worker_uid,
    ) as (plan, recheck):
        def owned():
            recheck()
            recheck_namespace_owner()
            recheck()

        owned()
        result = _prepare_boot_egress_locked(
            root_fd, state_fd, plan["nft_candidate"],
            namespace_identity=namespace_identity, generation=plan["generation"],
            generation_manifest_sha256=plan["generation_manifest_sha256"],
            profile_receipt_sha256=profile_receipt_sha256,
            executable_receipt_sha256=executable_receipt_sha256,
            recheck_owned=owned, allow_prepare=allow_prepare,
            allow_boot_rollover=allow_boot_rollover,
            **({"expected_previous_receipt": expected_existing_receipt}
               if expected_existing_receipt is not None else {}))
        owned()
        return {**result, "generation_manifest_sha256": plan["generation_manifest_sha256"],
                "committed_resources_verified": True,
                "authorizes_nginx_activation": False,
                "authorizes_catalog_publication": False}


def _create_owned_committed_boot_egress_locked(
    root_fd: int, state_fd: int, *, distribution: str, worker_uid: int,
    profile_receipt_sha256: str, executable_receipt_sha256: str,
    recheck_stopped_owner, allow_boot_rollover: bool = False,
    expected_previous_receipt_sha256: str | None = None,
) -> dict:
    """Prepare a fresh loopback-only namespace from committed disabled state.

    The authenticated lifecycle caller retains the state lock and proves
    service exclusion, native package and signed profile/executable identity.
    Keep the exact committed resource scope across creation and policy
    preparation. Neither active-route ingress nor same-boot adoption,
    service start, installed dispatch or catalog publication is authorized.
    """
    if (not callable(recheck_stopped_owner) or type(allow_boot_rollover) is not bool
            or not _valid_sha(profile_receipt_sha256)
            or not _valid_sha(executable_receipt_sha256)):
        _deny("OWNED_BOOT_EGRESS_INPUT_INVALID")
    with _owned_committed_boot_egress_generation_locked(
            root_fd, state_fd, distribution=distribution, worker_uid=worker_uid,
    ) as (plan, recheck):
        return {**_create_owned_boot_egress_from_plan_locked(
            root_fd, state_fd, plan, recheck,
            profile_receipt_sha256=profile_receipt_sha256,
            executable_receipt_sha256=executable_receipt_sha256,
            recheck_stopped_owner=recheck_stopped_owner,
            allow_boot_rollover=allow_boot_rollover,
            expected_previous_receipt_sha256=expected_previous_receipt_sha256),
            "committed_resources_verified": True}


@contextmanager
def _owned_prepared_wal_boot_egress_generation_locked(
    root_fd: int, state_fd: int, *, distribution: str, worker_uid: int,
    expected_wal: bytes,
):
    """Retain prepared prior bytes and withdrawn catalog under the exact v3 WAL.

    This does not repair files, publish a catalog, remove the WAL or authorize
    service activation. A trusted stopped-service caller must first complete
    the existing prior-byte preparation and independently prove ownership.
    """
    if (type(distribution) is not str or distribution not in _CA
            or type(expected_wal) is not bytes
            or not 1 <= len(expected_wal) <= _MAX_WAL):
        _deny("OWNED_BOOT_EGRESS_INPUT_INVALID")
    with _owned_layout_locked(root_fd, state_fd, recovering=True) as layout:
        state, nginx, public, check_layout = layout
        _owned_require_exact_wal(state, expected_wal)
        old, _ = _decode_owned_wal(expected_wal, distribution=distribution)
        if _json(expected_wal, limit=_MAX_WAL)["version"] != 3:
            _deny("OWNED_LIVE_WAL_REQUIRED")
        snapshot = _validate_owned_resources(old, distribution=distribution)
        _owned_socket_require_inactive_routes(snapshot)
        withdrawn = {**old, _CATALOG: None}
        active = True

        def recheck():
            if not active:
                _deny("OWNED_BOOT_EGRESS_SCOPE_EXPIRED")
            _owned_live_guard(state, nginx, public, check_layout,
                              expected_wal, withdrawn)
            _owned_check_stages_absent(state, nginx, public)
            _owned_live_guard(state, nginx, public, check_layout,
                              expected_wal, withdrawn)

        try:
            recheck()
            plan = _owned_boot_egress_plan(
                old, distribution=distribution, worker_uid=worker_uid)
            recheck()
            yield plan, recheck
            recheck()
        finally:
            active = False


def _verify_owned_prepared_wal_boot_egress_locked(
    root_fd: int, state_fd: int, *, distribution: str, worker_uid: int,
    expected_wal: bytes, namespace_identity: tuple[int, int],
    profile_receipt_sha256: str, executable_receipt_sha256: str,
    recheck_stopped_owner,
) -> dict:
    """Read back the exact prepared prior policy; never create or replace it."""
    return _check_owned_prepared_wal_boot_egress_locked(
        root_fd, state_fd, distribution=distribution, worker_uid=worker_uid,
        expected_wal=expected_wal, namespace_identity=namespace_identity,
        profile_receipt_sha256=profile_receipt_sha256,
        executable_receipt_sha256=executable_receipt_sha256,
        recheck_stopped_owner=recheck_stopped_owner, resume=False)


def _resume_owned_prepared_wal_boot_egress_locked(
    root_fd: int, state_fd: int, *, distribution: str, worker_uid: int,
    expected_wal: bytes, namespace_identity: tuple[int, int],
    profile_receipt_sha256: str, executable_receipt_sha256: str,
    recheck_stopped_owner,
) -> dict:
    """Resume only an existing exact same-boot receipt under the pending WAL.

    A missing receipt, foreign namespace or different boot is refused.
    The independently authenticated owner must prove service exclusion;
    an empty table alone is never enough to claim ownership.
    """
    return _check_owned_prepared_wal_boot_egress_locked(
        root_fd, state_fd, distribution=distribution, worker_uid=worker_uid,
        expected_wal=expected_wal, namespace_identity=namespace_identity,
        profile_receipt_sha256=profile_receipt_sha256,
        executable_receipt_sha256=executable_receipt_sha256,
        recheck_stopped_owner=recheck_stopped_owner, resume=True)


def _check_owned_prepared_wal_boot_egress_locked(
    root_fd: int, state_fd: int, *, distribution: str, worker_uid: int,
    expected_wal: bytes, namespace_identity: tuple[int, int],
    profile_receipt_sha256: str, executable_receipt_sha256: str,
    recheck_stopped_owner, resume: bool,
) -> dict:
    if (type(resume) is not bool or not callable(recheck_stopped_owner)
            or not _valid_sha(profile_receipt_sha256)
            or not _valid_sha(executable_receipt_sha256)):
        _deny("OWNED_BOOT_EGRESS_INPUT_INVALID")
    with _owned_prepared_wal_boot_egress_generation_locked(
            root_fd, state_fd, distribution=distribution, worker_uid=worker_uid,
            expected_wal=expected_wal,
    ) as (plan, recheck):
        if plan["destinations"]:
            _deny("OWNED_BOOT_EGRESS_ACTIVE_ROUTES_REFUSED")

        def owned():
            recheck()
            recheck_stopped_owner()
            recheck()

        owned()
        options = {}
        if resume:
            saved = _read_boot_egress_receipt(state_fd, 0, 0)
            if saved is None:
                _deny("OWNED_BOOT_EGRESS_RESUME_RECEIPT_REQUIRED")
            # CAS against this exact durable receipt. The underlying helper
            # independently checks its boot, inode, generation and rule
            # bindings before initializing an empty policy.
            options["expected_previous_receipt"] = saved
            owned()
        result = _prepare_boot_egress_locked(
            root_fd, state_fd, plan["nft_candidate"],
            namespace_identity=namespace_identity, generation=plan["generation"],
            generation_manifest_sha256=plan["generation_manifest_sha256"],
            profile_receipt_sha256=profile_receipt_sha256,
            executable_receipt_sha256=executable_receipt_sha256,
            recheck_owned=owned, allow_prepare=resume, allow_boot_rollover=False,
            **options)
        owned()
        return {**result, "generation_manifest_sha256": plan["generation_manifest_sha256"],
                "prior_resources_verified": True, "recovery_required": True,
                "catalog_withdrawn": True,
                "wal_sha256": hashlib.sha256(expected_wal).hexdigest(),
                "authorizes_nginx_activation": False,
                "authorizes_catalog_publication": False}


def _create_owned_prepared_wal_boot_egress_locked(
    root_fd: int, state_fd: int, *, distribution: str, worker_uid: int,
    expected_wal: bytes, profile_receipt_sha256: str,
    executable_receipt_sha256: str, recheck_stopped_owner,
    allow_boot_rollover: bool = False,
    expected_previous_receipt_sha256: str | None = None,
) -> dict:
    """Candidate-only fresh namespace from the WAL's prepared prior generation.

    Uses the same exact boot/profile/executable/ruleset receipt as committed
    preparation. Only the prior closed loopback policy may be created; no
    pending proposed policy, same-boot adoption or active-route authority.
    The journal and withdrawn resources remain intact on every outcome.
    """
    if (not callable(recheck_stopped_owner) or type(allow_boot_rollover) is not bool
            or not _valid_sha(profile_receipt_sha256)
            or not _valid_sha(executable_receipt_sha256)):
        _deny("OWNED_BOOT_EGRESS_INPUT_INVALID")
    with _owned_prepared_wal_boot_egress_generation_locked(
            root_fd, state_fd, distribution=distribution, worker_uid=worker_uid,
            expected_wal=expected_wal,
    ) as (plan, recheck):
        result = _create_owned_boot_egress_from_plan_locked(
            root_fd, state_fd, plan, recheck,
            profile_receipt_sha256=profile_receipt_sha256,
            executable_receipt_sha256=executable_receipt_sha256,
            recheck_stopped_owner=recheck_stopped_owner,
            allow_boot_rollover=allow_boot_rollover,
            expected_previous_receipt_sha256=expected_previous_receipt_sha256)
        return {**result, "prior_resources_verified": True,
                "recovery_required": True, "catalog_withdrawn": True,
                "wal_sha256": hashlib.sha256(expected_wal).hexdigest()}


def _create_owned_boot_egress_from_plan_locked(
    root_fd: int, state_fd: int, plan: dict, recheck, *,
    profile_receipt_sha256: str, executable_receipt_sha256: str,
    recheck_stopped_owner, allow_boot_rollover: bool,
    expected_previous_receipt_sha256: str | None = None,
) -> dict:
    """Shared private creation sequence; caller retains exact generation scope."""
    if (expected_previous_receipt_sha256 is not None
            and (not allow_boot_rollover or not _valid_sha(expected_previous_receipt_sha256))):
        _deny("OWNED_BOOT_EGRESS_INPUT_INVALID")
    if plan["destinations"]:
        _deny("OWNED_BOOT_EGRESS_ACTIVE_ROUTES_REFUSED")

    def owned():
        recheck()
        recheck_stopped_owner()
        recheck()

    def intent():
        return _fresh_boot_egress_intent_locked(
            state_fd, plan["nft_candidate"], generation=plan["generation"],
            generation_manifest_sha256=plan["generation_manifest_sha256"],
            profile_receipt_sha256=profile_receipt_sha256,
            executable_receipt_sha256=executable_receipt_sha256,
            allow_boot_rollover=allow_boot_rollover)

    owned()
    before = intent()
    if (expected_previous_receipt_sha256 is not None
            and (before[1] is None or hashlib.sha256(before[1]).hexdigest() !=
                 expected_previous_receipt_sha256)):
        _deny("OWNED_BOOT_EGRESS_INTENT_CHANGED")

    def before_create():
        owned()
        if intent() != before:
            _deny("OWNED_BOOT_EGRESS_INTENT_CHANGED")
        owned()

    before_create()
    creation = _create_fixed_loopback_namespace_locked(recheck_owned=before_create)
    before_create()
    if (creation["boot_id"] != before[0]
            or not creation["loopback_only_observed"]
            or not creation["empty_ruleset_observed"]):
        _deny("OWNED_BOOT_EGRESS_CREATION_UNVERIFIED")
    identity = (creation["namespace_device"], creation["namespace_inode"])
    result = _prepare_boot_egress_locked(
        root_fd, state_fd, plan["nft_candidate"],
        namespace_identity=identity, generation=plan["generation"],
        generation_manifest_sha256=plan["generation_manifest_sha256"],
        profile_receipt_sha256=profile_receipt_sha256,
        executable_receipt_sha256=executable_receipt_sha256,
        recheck_owned=owned, allow_prepare=True,
        allow_boot_rollover=allow_boot_rollover,
        expected_previous_receipt=before[1])
    owned()
    if (result["boot_id"] != before[0]
            or (result["namespace_device"], result["namespace_inode"]) != identity):
        _deny("OWNED_BOOT_EGRESS_CREATION_CHANGED")
    return {**result, "generation_manifest_sha256": plan["generation_manifest_sha256"],
            "authorizes_nginx_activation": False,
            "authorizes_catalog_publication": False}


def _owned_live_egress_recovery_candidates(
    raw: bytes, current: dict, *, distribution: str, worker_uid: int,
) -> dict:
    """Read-only v3 WAL policy evidence; no kernel or publication authority.

    A partial transition permits only derivation of the prior policy.
    Recover the proposed policy only if all three necessary current byte
    streams match the WAL, and deterministic reconstruction of the missing
    catalog and manifest reproduces every proposed hash and the entire WAL.
    The caller must independently own the lock, namespace and service.
    """
    if type(distribution) is not str or distribution not in _CA:
        _deny("OWNED_EGRESS_DISTRIBUTION_INVALID")
    old, hashes = _decode_owned_wal(raw, distribution=distribution)
    if _json(raw, limit=_MAX_WAL)["version"] != 3:
        _deny("OWNED_LIVE_WAL_REQUIRED")
    _owned_wal_resource_drift(old, hashes, current, unpublished=False,
                              catalog_withdrawal=True)
    prior = _owned_generation_egress(old, distribution=distribution, worker_uid=worker_uid)
    proposed = None
    if all(_hash(current[name]) == hashes[name] for name in (
            V2_STATE, _OWNED_MAIN, _INCLUDE)):
        snapshot = _json(current[V2_STATE], limit=_LIMIT[V2_STATE])
        document = parse_install_bytes(
            base64.b64decode(snapshot["configuration_base64"], validate=True),
            for_apply=True,
        )
        listen = document["deployment"]["listen"]
        origin = "https://" + listen["hostname"] + (
            "" if listen["https_port"] == 443 else ":" + str(listen["https_port"])
        )
        catalog = _canonical({"schema": 1, "repositories": sorted((
            {"upstream": repo["upstream"]["base_url"],
             "cache": origin + "/__repocache/repos/" + repo["id"] + "/"}
            for repo in document["repositories"] if repo["desired_state"] == "active"
        ), key=lambda row: (row["upstream"], row["cache"]))}, limit=_LIMIT[_CATALOG])
        candidate = {
            **current, _CATALOG: catalog,
            _OWNED_MANIFEST: _owned_manifest_for(
                current[V2_STATE], current[_OWNED_MAIN], current[_INCLUDE], catalog),
        }
        if _owned_wal_record(old, candidate, live=True) != raw:
            _deny("OWNED_EGRESS_PROPOSED_WAL_DRIFT")
        proposed = _owned_generation_egress(
            candidate, distribution=distribution, worker_uid=worker_uid,
        )
    return {
        "prior": prior, "proposed": proposed,
        "wal_sha256": hashlib.sha256(raw).hexdigest(),
        "runtime_egress_verified": False,
        "authorizes_firewall_change": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
    }


def _owned_live_replace_egress_locked(state_fd: int, nginx_fd: int, public_fd: int,
                                      check_layout, *, wal: bytes, distribution: str,
                                      worker_uid: int, namespace_identity: tuple[int, int],
                                      recheck_namespace_owner, restore: bool) -> dict:
    """Internal WAL-bound candidate operation, not wired into live dispatch.

    The owning caller must retain the verified service namespace and server
    state lock, and establish the generation's native worker identity.
    Catalog withdrawal and all proposed bytes must precede the forward
    replacement. Recovery before restoring the files replaces only the exact proposed
    rules with the prior rules. An already restored policy must be observed
    independently by the caller. An unknown kernel policy is never guessed or overwritten.
    """
    if type(restore) is not bool:
        _deny("OWNED_EGRESS_DIRECTION_INVALID")
    check_layout()
    _owned_require_exact_wal(state_fd, wal)
    current = _read_owned_resources(state_fd, nginx_fd, public_fd)
    if current[_CATALOG] is not None:
        _deny("OWNED_EGRESS_CATALOG_NOT_WITHDRAWN")
    evidence = _owned_live_egress_recovery_candidates(
        wal, current, distribution=distribution, worker_uid=worker_uid)
    prior, proposed = evidence["prior"], evidence["proposed"]
    if proposed is None:
        # Partial file publication cannot establish proposed kernel policy.
        # Do not mutate; callers must recover while that evidence is intact.
        _deny("OWNED_EGRESS_PROPOSED_POLICY_UNVERIFIED")

    def owned():
        check_layout()
        _owned_require_exact_wal(state_fd, wal)
        if _read_owned_resources(state_fd, nginx_fd, public_fd) != current:
            _deny("OWNED_EGRESS_RESOURCES_CHANGED")
        recheck_namespace_owner()

    old, new = (proposed, prior) if restore else (prior, proposed)
    owned()
    result = _replace_fixed_namespace_egress(
        old["nft_candidate"], new["nft_candidate"],
        namespace_identity=namespace_identity, recheck_owned=owned)
    owned()
    return {**result, "wal_sha256": evidence["wal_sha256"],
            "from_generation": old["generation"], "to_generation": new["generation"],
            "authorizes_catalog_publication": False, "authorizes_nginx_activation": False}



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
                          after: bytes | None, *, dedicated_catalog: bool = False) -> None:
    if before == after:
        return
    parent = _owned_resource_parent(name, state_fd, nginx_fd, public_fd)
    stage = _OWNED_STAGES[name]
    maximum = _OWNED_LIMIT[name]
    if name in _OWNED_PRIVATE:
        _write_private(parent, name, stage, before, after, maximum)
    else:
        if dedicated_catalog:
            _write_public(parent, name, before, after, maximum, stage=stage,
                          dedicated_catalog=True)
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
    return _owned_master_listener(identity, context, observe)


def _owned_master_listener(identity: tuple, context: tuple, observe, *,
                           namespace_identity: tuple[int, int] | None = None) -> int:
    """Shared fixed listener readback; no new mutation or caller authority.

    Legacy callers still require the current network namespace. Dedicated
    callers must independently retain the verified fixed nsfs descriptor.
    """
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
                local_identity = (local_ns.st_dev, local_ns.st_ino)
                required = local_identity if namespace_identity is None else namespace_identity
                if (required != (master_ns.st_dev, master_ns.st_ino)
                        or (namespace_identity is not None and required == local_identity)):
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
                return _owned_require_listener(rows, sockets, address), required

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


def _require_dedicated_catalog_withdrawn(context: tuple) -> None:
    """A fresh pinned TLS client must observe the withdrawn catalog as 404."""
    document, _, leaf = context
    if document is None or not _valid_sha(leaf):
        _deny("OWNED_DEDICATED_CATALOG_WITHDRAWAL_UNVERIFIED")
    response = _fixed_https_get(
        document, "/.well-known/repocache/catalog.json", 8192,
        expected_leaf_sha256=leaf)
    header, _ = response.split(b"\r\n\r\n", 1)
    if not header.startswith(b"HTTP/1.1 404 "):
        _deny("OWNED_DEDICATED_CATALOG_WITHDRAWAL_UNVERIFIED")


def _run_dedicated_health_child(net: int, namespace_identity: tuple[int, int],
                                context: tuple, catalog: bytes | None, *, publish: bool,
                                require_withdrawn: bool = False) -> None:
    """Run only the fixed local health read in a bounded disposable child.

    Never switch the caller's network namespace or expose an arbitrary
    command. This is a single-threaded trusted native lifecycle primitive,
    not available to the confined socket dispatcher.
    """
    import signal
    import threading

    if (threading.active_count() != 1 or len(os.listdir("/proc/self/task")) != 1
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
            or not hasattr(os, "setns") or not hasattr(os, "CLONE_NEWNET")):
        _deny("OWNED_DEDICATED_HEALTH_CHILD_REFUSED")
    pid = os.fork()
    if pid == 0:
        try:
            os.setns(net, os.CLONE_NEWNET)
            seen = os.stat("/proc/self/ns/net")
            if (seen.st_dev, seen.st_ino) != namespace_identity:
                os._exit(1)
            _owned_live_health(context, catalog, publish=publish)
            if require_withdrawn:
                _require_dedicated_catalog_withdrawn(context)
        except BaseException:
            os._exit(1)
        os._exit(0)

    reaped = False
    try:
        deadline = time.monotonic() + 45
        while True:
            found, status = os.waitpid(pid, os.WNOHANG)
            if found == pid:
                reaped = True
                if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                    _deny("OWNED_DEDICATED_HEALTH_UNVERIFIED")
                return
            if found != 0:
                _deny("OWNED_DEDICATED_HEALTH_CHILD_REFUSED")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _deny("OWNED_DEDICATED_HEALTH_TIMEOUT")
            time.sleep(min(0.05, remaining))
    finally:
        if not reaped:
            # Never signal a PID already reaped or an unrelated process.
            # The single-thread/default-SIGCHLD precondition means the
            # unreaped child PID cannot be recycled between these calls.
            try:
                found, _ = os.waitpid(pid, os.WNOHANG)
                if found == 0:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def _owned_dedicated_live_health_bound(
    root_fd: int, context: tuple, catalog: bytes | None, *, publish: bool,
    namespace_identity: tuple[int, int], executable_identity: tuple[int, int],
    recheck_owned, require_withdrawn: bool = False,
) -> dict:
    """Observe the fixed signed dedicated listener and pinned local health.

    The trusted lifecycle caller must retain the original state lock,
    authenticate the context/certificate, executable and boot/profile
    receipts and recheck the fixed kernel policy and storage. No active
    ingress, namespace preparation, process or publication operation is
    authorized by this observation. Only the loopback candidate is enabled.
    """
    from repocache.server_native_egress_candidate_v1 import (
        _fixed_namespace_scope, NativeEgressCandidateError,
    )
    from repocache.server_native_nginx_effective_unit_v1 import (
        _inspect_signed_owned_namespace_runtime,
    )
    if (not callable(recheck_owned) or type(publish) is not bool
            or type(require_withdrawn) is not bool or (require_withdrawn and publish)
            or type(context) is not tuple or len(context) != 3
            or (publish and type(catalog) is not bytes)
            or (not publish and catalog is not None)
            or any(type(pair) is not tuple or len(pair) != 2
                   or any(type(value) is not int or value <= 0 for value in pair)
                   for pair in (namespace_identity, executable_identity))):
        _deny("OWNED_DEDICATED_HEALTH_INPUT_INVALID")
    _verify_current_root_fd(root_fd)
    document, generation, leaf = context
    try:
        if document is None:
            if generation is not None or leaf is not None or publish or require_withdrawn:
                _deny("OWNED_DEDICATED_HEALTH_INPUT_INVALID")
            port = 8008
        else:
            validated = validate_install_document(document, for_apply=True)
            listen = validated["deployment"]["listen"]
            if (listen["bind_address"] != "127.0.0.1"
                    or type(generation) is not int
                    or validated["expected_state_generation"] != generation
                    or not _valid_sha(leaf)):
                _deny("OWNED_DEDICATED_HEALTH_INPUT_INVALID")
            port = listen["https_port"]
            # Use only the normalized, validated snapshot for the listener
            # and child protocol, not a second view of caller-owned data.
            context = (validated, generation, leaf)
        with _fixed_namespace_scope() as (net, current, recheck):
            if current != namespace_identity:
                _deny("OWNED_DEDICATED_HEALTH_NAMESPACE_CHANGED")

            def observe():
                recheck()
                recheck_owned()
                report = _inspect_signed_owned_namespace_runtime(
                    https_port=port, namespace_identity=current,
                    executable_identity=executable_identity)
                recheck_owned()
                recheck()
                return report

            first = observe()
            identity = (first["main_pid_observed"], first["private_unit_identity"])

            def same_master():
                if observe() != first:
                    _deny("OWNED_DEDICATED_HEALTH_MASTER_CHANGED")
                return identity

            def listener():
                return _owned_master_listener(
                    identity, context, same_master, namespace_identity=current)

            before = listener()
            _run_dedicated_health_child(
                net, current, context, catalog, publish=publish,
                **({"require_withdrawn": True} if require_withdrawn else {}))
            if listener() != before or observe() != first:
                _deny("OWNED_LIVE_LISTENER_CHANGED")
            return {"status": "OWNED_DEDICATED_HEALTH_OBSERVED",
                    "listener_inode": before, "main_pid": identity[0],
                    "generation": generation, "catalog_observed": publish,
                    "authorizes_nginx_activation": False,
                    "authorizes_catalog_publication": False}
    except NativeV2TransactionError:
        raise
    except (NativeEgressCandidateError, EffectiveNginxUnitError, OSError,
            ValueError, TypeError, KeyError, OverflowError):
        _deny("OWNED_DEDICATED_HEALTH_UNVERIFIED")


def _start_owned_committed_dedicated_locked(
    root_fd: int, state_fd: int, *, namespace_identity: tuple[int, int],
    executable_identity: tuple[int, int], profile_receipt_sha256: str,
    executable_receipt_sha256: str, recheck_authenticated_owner,
) -> dict:
    """Start only an exact committed, disabled-route dedicated generation."""
    return _start_owned_dedicated_generation_locked(
        root_fd, state_fd, namespace_identity=namespace_identity,
        executable_identity=executable_identity,
        profile_receipt_sha256=profile_receipt_sha256,
        executable_receipt_sha256=executable_receipt_sha256,
        recheck_authenticated_owner=recheck_authenticated_owner,
        expected_wal=None)


def _start_or_verify_owned_committed_dedicated_locked(
    root_fd: int, state_fd: int, *, namespace_identity: tuple[int, int],
    executable_identity: tuple[int, int], profile_receipt_sha256: str,
    executable_receipt_sha256: str, recheck_authenticated_owner,
) -> dict:
    """Authenticated activation repeat; observe an existing master, never stop it."""
    return _start_owned_dedicated_generation_locked(
        root_fd, state_fd, namespace_identity=namespace_identity,
        executable_identity=executable_identity,
        profile_receipt_sha256=profile_receipt_sha256,
        executable_receipt_sha256=executable_receipt_sha256,
        recheck_authenticated_owner=recheck_authenticated_owner,
        expected_wal=None, allow_active_repeat=True)


def _start_owned_prepared_wal_dedicated_locked(
    root_fd: int, state_fd: int, *, namespace_identity: tuple[int, int],
    executable_identity: tuple[int, int], profile_receipt_sha256: str,
    executable_receipt_sha256: str, expected_wal: bytes,
    recheck_authenticated_owner, expected_stopped: dict | None = None,
) -> dict:
    """Start exact prepared prior bytes while retaining WAL and withdrawal.

    No recovery completion, catalog publication or WAL removal is implied.
    Only the authenticated isolated lifecycle caller under the original
    lock may invoke this; a subsequent phase must independently prove and
    finalize recovery. Bootstrap and active-route predecessors are refused.
    """
    if type(expected_wal) is not bytes or not 1 <= len(expected_wal) <= _MAX_WAL:
        _deny("OWNED_DEDICATED_START_INPUT_INVALID")
    return _start_owned_dedicated_generation_locked(
        root_fd, state_fd, namespace_identity=namespace_identity,
        executable_identity=executable_identity,
        profile_receipt_sha256=profile_receipt_sha256,
        executable_receipt_sha256=executable_receipt_sha256,
        recheck_authenticated_owner=recheck_authenticated_owner,
        expected_wal=expected_wal, expected_stopped=expected_stopped)


def _start_owned_dedicated_generation_locked(
    root_fd: int, state_fd: int, *, namespace_identity: tuple[int, int],
    executable_identity: tuple[int, int], profile_receipt_sha256: str,
    executable_receipt_sha256: str, recheck_authenticated_owner,
    expected_wal: bytes | None, expected_stopped: dict | None = None,
    allow_active_repeat: bool = False,
) -> dict:
    """Explicit isolated-candidate start of an already prepared profile.

    The trusted signed lifecycle caller holds the original state lock,
    independently authenticates the installed worker, exact executable
    and profile receipts and dedicated labels/policy, and prepares the
    stopped service's storage and boot namespace. This is NOT socket
    dispatch, an installer CLI, namespace provisioning or automatic boot.
    Only a disabled, inactive AlmaLinux service and a managed loopback
    generation with no active routes is accepted. A pending WAL must be
    explicitly supplied and bind exact prepared prior bytes and withdrawal.
    Neither enablement nor configuration, receipts, policy, WAL or catalog
    may change. On start failure stop only the exact, still-owned master
    spawned by this operation. An authenticated committed active repeat
    is observation-only and must never enter the start compensation path.
    """
    from repocache.server_native_nginx_effective_unit_v1 import (
        inspect_signed_owned_namespace_unit, _inspect_signed_owned_namespace_runtime,
        _safe_native_systemctl,
    )
    from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions

    if (not callable(recheck_authenticated_owner)
            or type(allow_active_repeat) is not bool
            or (allow_active_repeat and (expected_wal is not None or expected_stopped is not None))
            or (expected_stopped is not None and type(expected_stopped) is not dict)
            or not _valid_sha(profile_receipt_sha256)
            or not _valid_sha(executable_receipt_sha256)
            or any(type(pair) is not tuple or len(pair) != 2
                   or any(type(value) is not int or value <= 0 for value in pair)
                   for pair in (namespace_identity, executable_identity))):
        _deny("OWNED_DEDICATED_START_INPUT_INVALID")
    require_native_host_preconditions()
    _verify_current_root_fd(root_fd)
    _require_audited_native_package_for_activation(state_fd, distribution="almalinux")

    def fixed_systemctl(action):
        if (action not in ("is-enabled", "start", "stop", "is-active")
                or (action == "is-active" and not allow_active_repeat)):
            _deny("OWNED_DEDICATED_START_COMMAND_REFUSED")
        _safe_native_systemctl()
        result = subprocess.run(
            (_SYSTEMCTL, action, _OWNED_WAL_DOMAIN), shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if action in ("is-enabled", "is-active") else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, cwd="/", env=_ENV,
            timeout=5 if action in ("is-enabled", "is-active") else 40,
            close_fds=True, start_new_session=True, check=False)
        if action == "is-enabled":
            if result.returncode != 1 or result.stdout != b"disabled\n":
                _deny("OWNED_DEDICATED_START_ENABLEMENT_REFUSED")
        elif action == "is-active":
            if (result.returncode, result.stdout) == (0, b"active\n"):
                return True
            if (result.returncode, result.stdout) == (3, b"inactive\n"):
                return False
            _deny("OWNED_DEDICATED_START_OWNER_REFUSED")
        elif type(result.returncode) is not int or result.returncode != 0:
            _deny("OWNED_DEDICATED_START_COMMAND_FAILED")

    if expected_wal is not None and (type(expected_wal) is not bytes
                                     or not 1 <= len(expected_wal) <= _MAX_WAL):
        _deny("OWNED_DEDICATED_START_INPUT_INVALID")
    recovering = expected_wal is not None
    try:
        with _owned_layout_locked(root_fd, state_fd, recovering=recovering) as layout:
            state, nginx, public, check_layout = layout
            resources = _read_owned_resources(state, nginx, public)
            if recovering:
                _owned_require_exact_wal(state, expected_wal)
                prior, _ = _decode_owned_wal(expected_wal, distribution="almalinux")
                if _json(expected_wal, limit=_MAX_WAL)["version"] != 3:
                    _deny("OWNED_LIVE_WAL_REQUIRED")
                if resources != {**prior, _CATALOG: None}:
                    _deny("OWNED_DEDICATED_START_PRIOR_NOT_PREPARED")
                _owned_check_stages_absent(state, nginx, public)
            else:
                prior = resources
            snapshot = _validate_owned_resources(prior, distribution="almalinux")
            if snapshot is None:
                _deny("OWNED_DEDICATED_START_MANAGED_REQUIRED")
            _owned_socket_require_inactive_routes(snapshot)
            document = parse_install_bytes(base64.b64decode(
                snapshot["configuration_base64"], validate=True), for_apply=True)
            listen = document["deployment"]["listen"]
            if listen["bind_address"] != "127.0.0.1":
                _deny("OWNED_DEDICATED_START_LOOPBACK_REQUIRED")
            port = listen["https_port"]
            worker = pwd.getpwnam("nginx")
            plan = _owned_boot_egress_plan(prior, distribution="almalinux",
                                           worker_uid=worker.pw_uid)
            if plan["destinations"]:
                _deny("OWNED_BOOT_EGRESS_ACTIVE_ROUTES_REFUSED")
            from repocache.server_native_installed_storage_v1 import prepare_dedicated_candidate_storage
            recheck_authenticated_owner()
            storage = prepare_dedicated_candidate_storage(
                "almalinux", document, allow_create=False)
            active_repeat = allow_active_repeat and fixed_systemctl("is-active")
            scratch = _owned_alma_runtime_temps(
                root_fd, dedicated=True, inactive=not active_repeat)
            tls_labels = _dedicated_readonly_tls_labels(root_fd, document)
            leaf = _verify_tls_pair(root_fd, document, verify_identity=True)
            config_labels = _dedicated_readonly_config_labels(
                nginx, public, catalog_present=not recovering)
            context = (document, snapshot["state_generation"], leaf)

            def exact():
                check_layout()
                if recovering:
                    _owned_require_exact_wal(state, expected_wal)
                else:
                    _no_conflicting_owned_wal_pending(state)
                _owned_check_stages_absent(state, nginx, public)
                if _read_owned_resources(state, nginx, public) != resources:
                    _deny("OWNED_DEDICATED_START_GENERATION_CHANGED")
                if _dedicated_readonly_config_labels(
                        nginx, public, catalog_present=not recovering) != config_labels:
                    _deny("OWNED_DEDICATED_READONLY_LABEL_CHANGED")
                if _dedicated_readonly_tls_labels(root_fd, document) != tls_labels:
                    _deny("OWNED_DEDICATED_TLS_LABEL_CHANGED")
                recheck_authenticated_owner()

            def owner(active):
                exact()
                observed = inspect_signed_owned_namespace_unit(https_port=port, active=active)
                exact()
                return observed

            def policy(active):
                return _prepare_boot_egress_locked(
                    root_fd, state, plan["nft_candidate"],
                    namespace_identity=namespace_identity, generation=plan["generation"],
                    generation_manifest_sha256=plan["generation_manifest_sha256"],
                    profile_receipt_sha256=profile_receipt_sha256,
                    executable_receipt_sha256=executable_receipt_sha256,
                    recheck_owned=lambda: owner(active), allow_prepare=False,
                    allow_boot_rollover=False)

            fixed_systemctl("is-enabled")
            if active_repeat:
                # This master predates our invocation. Even failed health or
                # authority checks must not stop, reload or compensate it.
                observed = owner(True)
                runtime = _inspect_signed_owned_namespace_runtime(
                    https_port=port, namespace_identity=namespace_identity,
                    executable_identity=executable_identity)
                if (runtime["main_pid_observed"] <= 0
                        or any(runtime[key] != observed[key] for key in (
                            "main_pid_observed", "private_unit_identity", "private_dropin_identity"))):
                    _deny("OWNED_DEDICATED_START_OWNER_CHANGED")
                before_policy = policy(True)
                witness = _owned_dedicated_live_health_bound(
                    root_fd, context, resources[_CATALOG], publish=True,
                    namespace_identity=namespace_identity,
                    executable_identity=executable_identity, recheck_owned=exact)
                if (witness["main_pid"] != runtime["main_pid_observed"]
                        or witness["catalog_observed"] is not True
                        or witness["generation"] != snapshot["state_generation"]
                        or owner(True) != observed
                        or _verify_tls_pair(root_fd, document, verify_identity=True) != leaf
                        or prepare_dedicated_candidate_storage(
                            "almalinux", document, allow_create=False) != storage
                        or _owned_alma_runtime_temps(root_fd, dedicated=True) != scratch
                        or policy(True) != before_policy):
                    _deny("OWNED_DEDICATED_START_POSTCHECK_FAILED")
                verify_service_storage_mounts(runtime["main_pid_observed"])
                _verify_owned_alma_runtime_service_view(runtime["main_pid_observed"], scratch)
                _require_audited_native_package_for_activation(state, distribution="almalinux")
                fixed_systemctl("is-enabled")
                exact()
                if (not fixed_systemctl("is-active") or owner(True) != observed
                        or _inspect_signed_owned_namespace_runtime(
                            https_port=port, namespace_identity=namespace_identity,
                            executable_identity=executable_identity) != runtime
                        or _owned_alma_runtime_temps(root_fd, dedicated=True) != scratch
                        or policy(True) != before_policy):
                    _deny("OWNED_DEDICATED_START_POSTCHECK_FAILED")
                return {**witness, "status": "OWNED_DEDICATED_COMMITTED_ACTIVE_VERIFIED",
                        "storage": storage, "service_storage_mounts_verified": True,
                        "service_scratch_mounts_verified": True, "enablement_changed": False}

            stopped = owner(False)
            if (expected_stopped is not None and stopped != expected_stopped):
                _deny("OWNED_DEDICATED_RECOVERY_MASTER_CHANGED")
            if stopped["main_pid_observed"] != 0:
                _deny("OWNED_DEDICATED_START_OWNER_REFUSED")
            before_policy = policy(False)
            _require_audited_native_package_for_activation(state, distribution="almalinux")
            if (owner(False) != stopped
                    or _verify_tls_pair(root_fd, document, verify_identity=True) != leaf
                    or prepare_dedicated_candidate_storage(
                        "almalinux", document, allow_create=False) != storage
                    or _owned_alma_runtime_temps(
                        root_fd, dedicated=True, inactive=True) != scratch
                    or policy(False) != before_policy):
                _deny("OWNED_DEDICATED_START_OWNER_CHANGED")
            fixed_systemctl("is-enabled")
            started = None
            try:
                # PID1 executes the exact signed ExecStartPre syntax check
                # in the prepared namespace before the actual master starts.
                fixed_systemctl("start")
                started = _inspect_signed_owned_namespace_runtime(
                    https_port=port, namespace_identity=namespace_identity,
                    executable_identity=executable_identity)
                if (started["private_unit_identity"] != stopped["private_unit_identity"]
                        or started["private_dropin_identity"] != stopped["private_dropin_identity"]
                        or policy(True) != before_policy):
                    _deny("OWNED_DEDICATED_START_OWNER_CHANGED")
                witness = _owned_dedicated_live_health_bound(
                    root_fd, context, resources[_CATALOG], publish=not recovering,
                    **({"require_withdrawn": True} if recovering else {}),
                    namespace_identity=namespace_identity,
                    executable_identity=executable_identity, recheck_owned=exact)
                if (witness["main_pid"] != started["main_pid_observed"]
                        or witness["catalog_observed"] != (not recovering)
                        or witness["generation"] != snapshot["state_generation"]
                        or _inspect_signed_owned_namespace_runtime(
                            https_port=port, namespace_identity=namespace_identity,
                            executable_identity=executable_identity) != started
                        or _verify_tls_pair(root_fd, document, verify_identity=True) != leaf
                        or prepare_dedicated_candidate_storage(
                            "almalinux", document, allow_create=False) != storage
                        or _owned_alma_runtime_temps(root_fd, dedicated=True) != scratch
                        or policy(True) != before_policy):
                    _deny("OWNED_DEDICATED_START_POSTCHECK_FAILED")
                verify_service_storage_mounts(started["main_pid_observed"])
                _verify_owned_alma_runtime_service_view(started["main_pid_observed"], scratch)
                _require_audited_native_package_for_activation(state, distribution="almalinux")
                fixed_systemctl("is-enabled")
                exact()
                if (_inspect_signed_owned_namespace_runtime(
                        https_port=port, namespace_identity=namespace_identity,
                        executable_identity=executable_identity) != started
                        or _owned_alma_runtime_temps(root_fd, dedicated=True) != scratch
                        or policy(True) != before_policy):
                    _deny("OWNED_DEDICATED_START_POSTCHECK_FAILED")
                result = {**witness, "status": "OWNED_DEDICATED_COMMITTED_START_OBSERVED",
                          "storage": storage, "service_storage_mounts_verified": True,
                          "service_scratch_mounts_verified": True,
                          "enablement_changed": False}
                if recovering:
                    result.update(
                        status="OWNED_DEDICATED_PREPARED_WAL_START_OBSERVED",
                        wal_sha256=hashlib.sha256(expected_wal).hexdigest(),
                        catalog_withdrawn=True, recovery_required=True)
                return result
            except Exception:
                try:
                    fixed_systemctl("is-enabled")
                    exact()
                    try:
                        inactive = owner(False)
                    except EffectiveNginxUnitError:
                        active = _inspect_signed_owned_namespace_runtime(
                            https_port=port, namespace_identity=namespace_identity,
                            executable_identity=executable_identity)
                        if (active["private_unit_identity"] != stopped["private_unit_identity"]
                                or active["private_dropin_identity"] != stopped["private_dropin_identity"]
                                or (started is not None and active != started)
                                or policy(True) != before_policy):
                            _deny("OWNED_DEDICATED_START_RECOVERY_REQUIRED")
                        exact()
                        if _inspect_signed_owned_namespace_runtime(
                                https_port=port, namespace_identity=namespace_identity,
                                executable_identity=executable_identity) != active:
                            _deny("OWNED_DEDICATED_START_RECOVERY_REQUIRED")
                        fixed_systemctl("is-enabled")
                        fixed_systemctl("stop")
                        inactive = owner(False)
                    fixed_systemctl("is-enabled")
                    if inactive != stopped or policy(False) != before_policy:
                        _deny("OWNED_DEDICATED_START_RECOVERY_REQUIRED")
                except Exception:
                    _deny("OWNED_DEDICATED_START_RECOVERY_REQUIRED")
                _deny("OWNED_DEDICATED_START_FAILED_STOPPED")
    except NativeV2TransactionError:
        raise
    except (EffectiveNginxUnitError, InstalledStorageError, OSError, TypeError,
            ValueError, KeyError, OverflowError, subprocess.SubprocessError):
        _deny("OWNED_DEDICATED_START_UNVERIFIED")


def _finish_owned_prepared_wal_dedicated_locked(
    root_fd: int, state_fd: int, *, namespace_identity: tuple[int, int],
    executable_identity: tuple[int, int], profile_receipt_sha256: str,
    executable_receipt_sha256: str, expected_wal: bytes,
    recheck_authenticated_owner, expected_runtime: dict | None = None,
    expected_listener: int | None = None,
) -> dict:
    """Finalize an already running, authenticated disabled-route candidate.

    No process or policy changes, socket dispatch, or automatic boot authority.
    The signed lifecycle caller retains the original state lock. Re-establish
    the prior generation and exact namespace/master independently of start's
    report, then publish the prior catalog before removing the exact v3 WAL.
    """
    from repocache.server_native_nginx_effective_unit_v1 import (
        _inspect_signed_owned_namespace_runtime,
    )
    from repocache.server_native_installed_storage_v1 import prepare_dedicated_candidate_storage
    from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions

    if (not callable(recheck_authenticated_owner)
            or type(expected_wal) is not bytes or not 1 <= len(expected_wal) <= _MAX_WAL
            or (expected_runtime is not None and type(expected_runtime) is not dict)
            or (expected_listener is not None
                and (type(expected_listener) is not int or expected_listener <= 0))
            or not _valid_sha(profile_receipt_sha256)
            or not _valid_sha(executable_receipt_sha256)
            or any(type(pair) is not tuple or len(pair) != 2
                   or any(type(value) is not int or value <= 0 for value in pair)
                   for pair in (namespace_identity, executable_identity))):
        _deny("OWNED_DEDICATED_FINISH_INPUT_INVALID")
    require_native_host_preconditions()
    _verify_current_root_fd(root_fd)
    with _owned_layout_locked(root_fd, state_fd, recovering=True) as layout:
        state, nginx, public, check_layout = layout
        _owned_require_exact_wal(state, expected_wal)
        old, _ = _decode_owned_wal(expected_wal, distribution="almalinux")
        if _json(expected_wal, limit=_MAX_WAL)["version"] != 3:
            _deny("OWNED_LIVE_WAL_REQUIRED")
        snapshot = _validate_owned_resources(old, distribution="almalinux")
        if snapshot is None:
            _deny("OWNED_DEDICATED_FINISH_MANAGED_REQUIRED")
        _owned_socket_require_inactive_routes(snapshot)
        document = parse_install_bytes(base64.b64decode(
            snapshot["configuration_base64"], validate=True), for_apply=True)
        listen = document["deployment"]["listen"]
        if listen["bind_address"] != "127.0.0.1":
            _deny("OWNED_DEDICATED_FINISH_LOOPBACK_REQUIRED")
        port = listen["https_port"]
        plan = _owned_boot_egress_plan(old, distribution="almalinux",
                                      worker_uid=pwd.getpwnam("nginx").pw_uid)
        if plan["destinations"]:
            _deny("OWNED_BOOT_EGRESS_ACTIVE_ROUTES_REFUSED")
        withdrawn = {**old, _CATALOG: None}
        current = _read_owned_resources(state, nginx, public)
        # A killed finalizer may have published the exact prior catalog
        # while the WAL remains durable. Do not adopt any other bytes.
        if current != withdrawn and current != old:
            _deny("OWNED_DEDICATED_FINISH_RESOURCE_CHANGED")
        expected = dict(current)
        published_before_retry = current == old
        config_identity = _dedicated_recovery_config_identity(
            nginx, public, catalog_present=published_before_retry)

        def exact():
            _owned_live_guard(state, nginx, public, check_layout, expected_wal, expected)
            _owned_check_stages_absent(state, nginx, public)
            if _dedicated_recovery_config_identity(
                    nginx, public, catalog_present=expected[_CATALOG] is not None) != config_identity:
                _deny("OWNED_DEDICATED_FINISH_CONFIG_CHANGED")

        exact()
        recheck_authenticated_owner()
        _require_audited_native_package_for_activation(state, distribution="almalinux")
        storage = prepare_dedicated_candidate_storage("almalinux", document, allow_create=False)
        scratch = _owned_alma_runtime_temps(root_fd, dedicated=True)
        tls_labels = _dedicated_readonly_tls_labels(root_fd, document)
        leaf = _verify_tls_pair(root_fd, document, verify_identity=True)
        context = (document, snapshot["state_generation"], leaf)

        def runtime():
            return _inspect_signed_owned_namespace_runtime(
                https_port=port, namespace_identity=namespace_identity,
                executable_identity=executable_identity)

        master = runtime()
        if expected_runtime is not None and master != expected_runtime:
            _deny("OWNED_DEDICATED_RECOVERY_MASTER_CHANGED")

        def owner():
            exact()
            recheck_authenticated_owner()
            _require_audited_native_package_for_activation(state, distribution="almalinux")
            if (runtime() != master
                    or _dedicated_readonly_tls_labels(root_fd, document) != tls_labels
                    or _verify_tls_pair(root_fd, document, verify_identity=True) != leaf
                    or prepare_dedicated_candidate_storage(
                        "almalinux", document, allow_create=False) != storage
                    or _owned_alma_runtime_temps(root_fd, dedicated=True) != scratch):
                _deny("OWNED_DEDICATED_FINISH_OWNER_CHANGED")
            verify_service_storage_mounts(master["main_pid_observed"])
            _verify_owned_alma_runtime_service_view(master["main_pid_observed"], scratch)
            exact()

        def policy():
            return _prepare_boot_egress_locked(
                root_fd, state, plan["nft_candidate"], namespace_identity=namespace_identity,
                generation=plan["generation"],
                generation_manifest_sha256=plan["generation_manifest_sha256"],
                profile_receipt_sha256=profile_receipt_sha256,
                executable_receipt_sha256=executable_receipt_sha256,
                recheck_owned=owner, allow_prepare=False, allow_boot_rollover=False)

        owner()
        baseline = policy()

        def guarded():
            owner()
            if policy() != baseline:
                _deny("OWNED_DEDICATED_FINISH_POLICY_CHANGED")
            owner()

        def health(publish):
            result = _owned_dedicated_live_health_bound(
                root_fd, context, old[_CATALOG] if publish else None,
                publish=publish, require_withdrawn=not publish,
                namespace_identity=namespace_identity, executable_identity=executable_identity,
                recheck_owned=guarded)
            if (result["main_pid"] != master["main_pid_observed"]
                    or result["generation"] != snapshot["state_generation"]
                    or result["catalog_observed"] is not publish):
                _deny("OWNED_DEDICATED_FINISH_HEALTH_CHANGED")
            return result

        # After a process interruption, first revoke only the exact
        # previously published catalog, with its label and all ownership,
        # runtime, policy and WAL checks intact. A fresh 404 and subsequent
        # exact 200 are still mandatory; prior publication is not proof.
        if published_before_retry:
            guarded()
            _owned_live_write(state, nginx, public, guarded, expected_wal,
                              expected, _CATALOG, None)
        before = health(False)
        if expected_listener is not None and before["listener_inode"] != expected_listener:
            _deny("OWNED_DEDICATED_RECOVERY_MASTER_CHANGED")
        guarded()
        try:
            _owned_live_write(state, nginx, public, guarded, expected_wal,
                              expected, _CATALOG, old[_CATALOG], dedicated_catalog=True)
            after = health(True)
            if before["listener_inode"] != after["listener_inode"] or expected != old:
                _deny("OWNED_DEDICATED_FINISH_LISTENER_CHANGED")
            _owned_live_finish(state, nginx, public, guarded, expected_wal, expected)
        except Exception:
            # No journal or foreign bytes means no compensating authority.
            # Even if runtime health was lost, withdraw only our exact catalog
            # under the still-published WAL; never claim recovery on error.
            check_layout()
            if (_read_file(state, _OWNED_WAL, 0, _MAX_WAL) == expected_wal
                    and _read_owned_resources(state, nginx, public) == old):
                _owned_live_write(state, nginx, public, check_layout, expected_wal,
                                  dict(old), _CATALOG, None)
            raise
        return {**after, "status": "OWNED_DEDICATED_WAL_ROLLBACK_OBSERVED",
                "wal_sha256": hashlib.sha256(expected_wal).hexdigest(),
                "recovery_required": False, "storage": storage}


def _recover_owned_prepared_dedicated_locked(
    root_fd: int, state_fd: int, *, namespace_identity: tuple[int, int],
    executable_identity: tuple[int, int], profile_receipt_sha256: str,
    executable_receipt_sha256: str, expected_wal: bytes,
    recheck_authenticated_owner,
) -> dict:
    """Compose prepared-profile start and recovery under the original lock.

    The trusted signed lifecycle caller independently authenticates release,
    executable, profile and boot intent and retains the state lock. This
    accepts only a previously prepared, disabled AlmaLinux loopback profile.
    It never provisions, enables, stops a foreign unit or falls back to the
    vendor service. Active retry retains the exact verified runtime. If the
    finalizer fails, its WAL remains the authority; do not automatically
    stop the service or retry another ownership domain.
    """
    from repocache.server_native_nginx_effective_unit_v1 import (
        inspect_signed_owned_namespace_unit, _inspect_signed_owned_namespace_runtime,
        _safe_native_systemctl,
    )
    from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions

    if (not callable(recheck_authenticated_owner)
            or type(expected_wal) is not bytes or not 1 <= len(expected_wal) <= _MAX_WAL
            or not _valid_sha(profile_receipt_sha256)
            or not _valid_sha(executable_receipt_sha256)
            or any(type(pair) is not tuple or len(pair) != 2
                   or any(type(value) is not int or value <= 0 for value in pair)
                   for pair in (namespace_identity, executable_identity))):
        _deny("OWNED_DEDICATED_RECOVERY_INPUT_INVALID")
    require_native_host_preconditions()
    _verify_current_root_fd(root_fd)
    _require_audited_native_package_for_activation(state_fd, distribution="almalinux")

    def status(action, unit):
        if action not in ("is-active", "is-enabled") or unit not in (_UNIT, _OWNED_WAL_DOMAIN):
            _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
        _safe_native_systemctl()
        try:
            result = subprocess.run(
                (_SYSTEMCTL, action, unit), shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
                env=_ENV, timeout=5, close_fds=True, start_new_session=True, check=False)
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
        return result.returncode, result.stdout

    def guard():
        recheck_authenticated_owner()
        if (status("is-active", _UNIT) != (3, b"inactive\n")
                or status("is-enabled", _UNIT) != (1, b"disabled\n")
                or status("is-enabled", _OWNED_WAL_DOMAIN) != (1, b"disabled\n")):
            _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")

    with _owned_layout_locked(root_fd, state_fd, recovering=True) as layout:
        state, nginx, public, check_layout = layout
        _owned_require_exact_wal(state, expected_wal)
        old, _ = _decode_owned_wal(expected_wal, distribution="almalinux")
        if _json(expected_wal, limit=_MAX_WAL)["version"] != 3:
            _deny("OWNED_LIVE_WAL_REQUIRED")
        snapshot = _validate_owned_resources(old, distribution="almalinux")
        if snapshot is None:
            _deny("OWNED_DEDICATED_FINISH_MANAGED_REQUIRED")
        _owned_socket_require_inactive_routes(snapshot)
        document = parse_install_bytes(base64.b64decode(
            snapshot["configuration_base64"], validate=True), for_apply=True)
        listen = document["deployment"]["listen"]
        if listen["bind_address"] != "127.0.0.1":
            _deny("OWNED_DEDICATED_FINISH_LOOPBACK_REQUIRED")
        port = listen["https_port"]
        withdrawn = {**old, _CATALOG: None}
        current = _read_owned_resources(state, nginx, public)
        if current != withdrawn and current != old:
            _deny("OWNED_DEDICATED_FINISH_RESOURCE_CHANGED")

        def exact():
            _owned_live_guard(state, nginx, public, check_layout, expected_wal, current)
            _owned_check_stages_absent(state, nginx, public)
            _require_dedicated_public_label(public)
            if current == old:
                _require_dedicated_catalog_label(public)
            guard()

        exact()
        service = status("is-active", _OWNED_WAL_DOMAIN)
        if service not in ((3, b"inactive\n"), (0, b"active\n")):
            _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
        active = service == (0, b"active\n")
        if not active and current != withdrawn:
            _deny("OWNED_DEDICATED_FINISH_RESOURCE_CHANGED")
        selected = inspect_signed_owned_namespace_unit(https_port=port, active=active)
        exact()
        if status("is-active", _OWNED_WAL_DOMAIN) != service:
            _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")

    options = dict(namespace_identity=namespace_identity,
                   executable_identity=executable_identity,
                   profile_receipt_sha256=profile_receipt_sha256,
                   executable_receipt_sha256=executable_receipt_sha256,
                   expected_wal=expected_wal, recheck_authenticated_owner=guard)
    listener = None
    if not active:
        started = _start_owned_prepared_wal_dedicated_locked(
            root_fd, state_fd, **options, expected_stopped=selected)
        if (started.get("status") != "OWNED_DEDICATED_PREPARED_WAL_START_OBSERVED"
                or started.get("wal_sha256") != hashlib.sha256(expected_wal).hexdigest()
                or started.get("catalog_withdrawn") is not True
                or started.get("recovery_required") is not True
                or started.get("generation") != snapshot["state_generation"]
                or started.get("enablement_changed") is not False
                or type(started.get("listener_inode")) is not int
                or started["listener_inode"] <= 0):
            _deny("OWNED_DEDICATED_RECOVERY_MASTER_CHANGED")
        listener = started["listener_inode"]
    guard()
    runtime = _inspect_signed_owned_namespace_runtime(
        https_port=port, namespace_identity=namespace_identity,
        executable_identity=executable_identity)
    if (runtime["private_unit_identity"] != selected["private_unit_identity"]
            or runtime["private_dropin_identity"] != selected["private_dropin_identity"]
            or runtime["main_pid_observed"] !=
               (selected["main_pid_observed"] if active else started["main_pid"])):
        _deny("OWNED_DEDICATED_RECOVERY_MASTER_CHANGED")
    return _finish_owned_prepared_wal_dedicated_locked(
        root_fd, state_fd, **options, expected_runtime=runtime,
        expected_listener=listener)


def _retained_rolled_dedicated_recovery_pins_locked(root_fd: int, state_fd: int) -> dict:
    """Resolve only already prepared post-reboot recovery; no writes or effects."""
    return _retained_rolled_dedicated_pins_locked(root_fd, state_fd, pending=True)


def _retained_rolled_committed_dedicated_pins_locked(root_fd: int, state_fd: int) -> dict:
    """Resolve already prepared committed post-reboot start without a WAL."""
    return _retained_rolled_dedicated_pins_locked(root_fd, state_fd, pending=False)


def _retained_rolled_dedicated_pins_locked(root_fd: int, state_fd: int, *, pending: bool) -> dict:
    """Reconstruct exact pins from independent history and retained resources."""
    from repocache.server_native_egress_candidate_v1 import (
        _BOOT_EGRESS_HISTORY_PREFIX, _BOOT_EGRESS_ROLLOVER, _BOOT_EGRESS_RECEIPT_MAX,
        _current_boot_id, _fixed_namespace_scope, _read_namespace_rules,
        _reconstruct_rolled_boot_receipt, verify_namespace_egress_readback,
    )

    if type(pending) is not bool:
        _deny("OWNED_DEDICATED_INSTALLER_PIN_REFUSED")
    _verify_current_root_fd(root_fd)
    with _owned_layout_locked(root_fd, state_fd, recovering=pending) as layout:
        state, nginx, public, check_layout = layout
        wal = _read_file(state, _OWNED_WAL, 0, _MAX_WAL)
        if (wal is not None) != pending:
            _deny("OWNED_WAL_CHANGED")
        current = _read_owned_resources(state, nginx, public)
        if pending:
            old, _ = _decode_owned_wal(wal, distribution="almalinux")
            if _json(wal, limit=_MAX_WAL)["version"] != 3:
                _deny("OWNED_WAL_CHANGED")
            if current not in (old, {**old, _CATALOG: None}):
                _deny("OWNED_LIVE_RESOURCE_DRIFT")
        else:
            old = current
        snapshot = _validate_owned_resources(old, distribution="almalinux")
        if snapshot is None:
            _deny("OWNED_DEDICATED_FINISH_MANAGED_REQUIRED")
        _owned_socket_require_inactive_routes(snapshot)
        plan = _owned_boot_egress_plan(
            old, distribution="almalinux", worker_uid=pwd.getpwnam("nginx").pw_uid)

        def history():
            names = sorted(name for name in os.listdir(state)
                           if name.startswith(_BOOT_EGRESS_HISTORY_PREFIX))
            if not 1 <= len(names) <= 64 or _read_boot_egress_receipt(
                    state, 0, 0, name=_BOOT_EGRESS_ROLLOVER) is not None:
                _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")
            return tuple((name, _read_boot_egress_receipt(state, 0, 0, name=name))
                         for name in names)

        with _fixed_namespace_scope() as (net, identity, recheck_namespace):
            boot = _current_boot_id()
            retained = history()
            expected = _reconstruct_rolled_boot_receipt(
                retained, plan["nft_candidate"], boot=boot, namespace_identity=identity,
                generation=plan["generation"],
                generation_manifest_sha256=plan["generation_manifest_sha256"])

            def guard():
                if pending:
                    _owned_live_guard(state, nginx, public, check_layout, wal, current)
                else:
                    check_layout()
                    _no_conflicting_owned_wal_pending(state)
                    if _read_owned_resources(state, nginx, public) != current:
                        _deny("OWNED_LIVE_RESOURCE_DRIFT")
                _owned_check_stages_absent(state, nginx, public)
                recheck_namespace()
                if (_current_boot_id() != boot or history() != retained
                        or _read_boot_egress_receipt(state, 0, 0) != expected):
                    _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")
                recheck_namespace()

            for _ in range(2):
                guard()
                verify_namespace_egress_readback(
                    plan["nft_candidate"], _read_namespace_rules(net))
            guard()
            record = _json(expected, limit=_BOOT_EGRESS_RECEIPT_MAX)
            return {key: record[key] for key in
                    ("profile_receipt_sha256", "executable_receipt_sha256")} | {
                "boot_receipt_sha256": hashlib.sha256(expected).hexdigest(),
                **({"wal_sha256": hashlib.sha256(wal).hexdigest()} if pending else
                   {"generation_manifest_sha256": plan["generation_manifest_sha256"]}),
            }


def _recover_installed_prepared_dedicated(pins: dict) -> dict:
    """Private root installer handoff, not the socket dispatcher.

    All pins come from the independently authenticated installer. Acquire
    our own exclusive lock and recheck the exact prepared profile before
    any mutation. Never derive a receipt's expected digest from itself.
    """
    return _installed_dedicated_lifecycle(pins, prepare=False)


def _stage_installed_committed_dedicated_profile(pins: dict) -> dict:
    """Private authenticated initial fixed profile placement; no systemd effects."""
    return _installed_dedicated_lifecycle(pins, prepare=True, stage_profile=True)


def _load_installed_committed_dedicated_profile(pins: dict) -> dict:
    """Private authenticated fixed profile load; no service start or enablement."""
    return _installed_dedicated_lifecycle(pins, prepare=True, load_profile=True)


def _prepare_installed_committed_dedicated(pins: dict) -> dict:
    """Private signed-installer first-boot namespace preparation; no service start."""
    return _installed_dedicated_lifecycle(pins, prepare=True)


def _rollover_installed_committed_dedicated(pins: dict) -> dict:
    """Private signed-installer recreation of a pinned prior boot."""
    return _installed_dedicated_lifecycle(pins, prepare=True, rollover=True)


def _prepare_installed_prepared_wal_dedicated(pins: dict) -> dict:
    """Private first-boot preparation; retain WAL and withdrawn catalog."""
    return _installed_dedicated_lifecycle(pins, prepare=True, pending_prepare=True)


def _resume_installed_committed_dedicated(pins: dict) -> dict:
    """Private same-boot committed intent resume; no service effects."""
    return _installed_dedicated_lifecycle(pins, prepare=True, resume_boot=True)


def _resume_installed_prepared_wal_dedicated(pins: dict) -> dict:
    """Private same-boot pending intent resume; no service or catalog effects."""
    return _installed_dedicated_lifecycle(pins, prepare=True, pending_prepare=True,
                                          resume_boot=True)


def _rollover_installed_prepared_wal_dedicated(pins: dict) -> dict:
    """Recreate the pinned prior namespace without recovering or publishing WAL."""
    return _installed_dedicated_lifecycle(pins, prepare=True, rollover=True,
                                          pending_prepare=True)


def _closed_committed_dedicated_storage_report(report) -> bool:
    """Require exact typed evidence; booleans must not be integer lookalikes."""
    return (type(report) is dict
            and set(report) == {"repository_cache_roots_verified", "metrics_file_verified",
                                "selinux_enforcing_labels_verified", "actual_service_write_verified"}
            and type(report["repository_cache_roots_verified"]) is list
            and not report["repository_cache_roots_verified"]
            and report["metrics_file_verified"] is False
            and report["selinux_enforcing_labels_verified"] is True
            and report["actual_service_write_verified"] is False)


def _prepare_installed_committed_dedicated_storage(pins: dict) -> dict:
    """Private authenticated storage preparation; no migration or activation."""
    return _installed_dedicated_lifecycle(pins, prepare=False, prepare_storage=True)


def _prepare_installed_prepared_wal_dedicated_storage(pins: dict) -> dict:
    """Private stopped prior-generation storage placement under an exact WAL."""
    return _installed_dedicated_lifecycle(
        pins, prepare=False, prepare_storage=True, pending_placement=True)


def _prepare_installed_prepared_wal_dedicated_runtime(pins: dict) -> dict:
    """Private stopped prior-generation runtime placement under an exact WAL."""
    return _installed_dedicated_lifecycle(
        pins, prepare=False, prepare_runtime=True, pending_placement=True)


def _prepare_installed_committed_dedicated_runtime(pins: dict) -> dict:
    """Private authenticated stopped runtime placement; no service effects."""
    return _installed_dedicated_lifecycle(pins, prepare=False, prepare_runtime=True)


def _start_installed_committed_dedicated(pins: dict) -> dict:
    """Private signed-installer start of an independently prepared profile."""
    return _installed_dedicated_lifecycle(pins, prepare=False, start=True)


def _start_or_verify_installed_committed_dedicated(pins: dict) -> dict:
    """Private authenticated rolled activation; repeat is observation-only."""
    return _installed_dedicated_lifecycle(pins, prepare=False, start=True, active_repeat=True)


def _start_installed_prepared_wal_dedicated(pins: dict) -> dict:
    """Private authenticated start of prior bytes with the catalog withdrawn."""
    return _installed_dedicated_lifecycle(pins, prepare=False, start=True,
                                          pending_start=True)


def _installed_dedicated_lifecycle(pins: dict, *, prepare: bool, start: bool = False,
                                   rollover: bool = False, pending_prepare: bool = False,
                                   resume_boot: bool = False,
                                   pending_start: bool = False, active_repeat: bool = False,
                                   stage_profile: bool = False,
                                   load_profile: bool = False,
                                   prepare_storage: bool = False,
                                   prepare_runtime: bool = False,
                                   pending_placement: bool = False) -> dict:
    import zipimport
    from repocache.server_native_nginx_executable_v1 import (
        signed_owned_nginx_policy_candidate, verify_nginx_candidate_receipt,
    )
    from repocache.server_native_nginx_effective_unit_v1 import (
        _signed_owned_unit_bytes, _stage_namespace_dropin_under_lock,
    )
    from repocache.server_native_egress_candidate_v1 import _fixed_namespace_scope
    from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions
    from repocache.server_root_control_worker_v1 import (
        _placement_receipt, _placement_file_digest, _UNIT_NAMES,
    )
    from repocache.server_native_root_control_entrypoint_v1 import _native_distro

    worker = "/usr/libexec/repocache/server-control-worker"
    digests = {"worker_sha256", "placement_sha256", "archive_sha256",
               "native_payload_sha256", "binary_sha256", "executable_receipt_sha256",
               "profile_receipt_sha256"} | (
        {"generation_manifest_sha256"} if prepare else
        {"generation_manifest_sha256", "boot_receipt_sha256"} if start or prepare_storage or prepare_runtime else
        {"boot_receipt_sha256", "wal_sha256"})
    if stage_profile:
        digests.remove("profile_receipt_sha256")
    if rollover:
        digests.add("previous_boot_receipt_sha256")
    if pending_prepare or pending_start or pending_placement:
        digests.add("wal_sha256")
    if resume_boot:
        digests.add("boot_receipt_sha256")
    if (type(prepare) is not bool or type(start) is not bool or type(rollover) is not bool
            or type(pending_prepare) is not bool or (pending_prepare and not prepare)
            or type(resume_boot) is not bool or (resume_boot and (not prepare or rollover))
            or type(pending_start) is not bool or (pending_start and not start)
            or type(active_repeat) is not bool or (active_repeat and (not start or pending_start))
            or type(stage_profile) is not bool or (stage_profile and (
                not prepare or rollover or pending_prepare or resume_boot))
            or type(load_profile) is not bool or (load_profile and (
                not prepare or rollover or pending_prepare or resume_boot or stage_profile))
            or type(prepare_storage) is not bool or (prepare_storage and (prepare or start))
            or type(prepare_runtime) is not bool or (prepare_runtime and (prepare or start or prepare_storage))
            or type(pending_placement) is not bool
            or (pending_placement and not (prepare_storage or prepare_runtime))
            or (prepare and start) or (rollover and not prepare)
            or not isinstance(__loader__, zipimport.zipimporter)
            or __loader__.archive != worker or not sys.flags.isolated
            or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
            or type(pins) is not dict
            or set(pins) != digests | {"source_sha", "package_identity"}
            or any(not _valid_sha(pins[key]) for key in digests)
            or type(pins["source_sha"]) is not str
            or re.fullmatch(r"[0-9a-f]{40}", pins["source_sha"]) is None
            or type(pins["package_identity"]) is not str
            or re.fullmatch(r"nginx-core-[0-9]+:[A-Za-z0-9._+~-]+-[A-Za-z0-9._+~-]+\.x86_64",
                            pins["package_identity"]) is None):
        _deny("OWNED_DEDICATED_INSTALLER_PIN_REFUSED")
    require_native_host_preconditions()
    if _native_distro() != "almalinux":
        _deny("OWNED_DEDICATED_INSTALLER_PIN_REFUSED")
    with ExitStack() as stack:
        root = os.open("/", _DIRECTORY_FLAGS)
        stack.callback(os.close, root)
        state = stack.enter_context(_locked(root, 0))
        _verify_current_root_fd(root)
        directory, chain = _walk(root, ("usr", "libexec", "repocache"), stack, 0)
        receipt_name = ".native-worker-receipt-v1.json"
        prefix = ".native-worker-placement."
        complete = prefix + "complete-" + pins["placement_sha256"]
        raw = _read_file(state, receipt_name, 0, 8192)
        if raw is None or hashlib.sha256(raw).hexdigest() != pins["placement_sha256"]:
            _deny("OWNED_DEDICATED_INSTALLER_PLACEMENT_REFUSED")
        receipt = _placement_receipt(raw)
        if (receipt["source_sha"] != pins["source_sha"]
                or receipt["archive_sha256"] != pins["archive_sha256"]
                or receipt["files"]["server-control-worker"] != pins["worker_sha256"]):
            _deny("OWNED_DEDICATED_INSTALLER_PLACEMENT_REFUSED")

        def placement():
            _recheck(chain, 0)
            if (_read_file(state, receipt_name, 0, 8192) != raw
                    or {name for name in os.listdir(state) if name.startswith(prefix)} != {complete}
                    or _read_file(state, complete, 0, 0) != b""):
                _deny("OWNED_DEDICATED_INSTALLER_PLACEMENT_REFUSED")
            for name in (receipt_name, complete):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             os.O_CLOEXEC, dir_fd=state)
                try:
                    info = _metadata_no_acl(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o600):
                        _deny("OWNED_DEDICATED_INSTALLER_PLACEMENT_REFUSED")
                finally:
                    os.close(fd)
            files = [(("usr", "libexec", "repocache", "server-control-worker"),
                      0o755, 16 * 1024 * 1024)]
            files += [(("etc", "systemd", "system", name), 0o644, 16384)
                      for name in _UNIT_NAMES]
            for segments, mode, limit in files:
                if _placement_file_digest(root, segments, mode, limit) != receipt["files"][segments[-1]]:
                    _deny("OWNED_DEDICATED_INSTALLER_PLACEMENT_REFUSED")
            if _placement_file_digest(root, ("usr", "sbin", "nginx"), 0o755,
                                      32 * 1024 * 1024) != pins["binary_sha256"]:
                _deny("OWNED_DEDICATED_INSTALLER_PACKAGE_REFUSED")
            _recheck(chain, 0)

        def package():
            result = subprocess.run(
                ("/usr/bin/rpm", "-q",
                 "--queryformat=%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}",
                 "nginx-core"), shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/", env=_ENV,
                timeout=12, close_fds=True, check=False)
            if (result.returncode != 0 or result.stderr != b""
                    or result.stdout != pins["package_identity"].encode("ascii")):
                _deny("OWNED_DEDICATED_INSTALLER_PACKAGE_REFUSED")
            _require_audited_native_package_for_activation(state, distribution="almalinux")

        placement()
        package()
        if pending_prepare or pending_start or pending_placement:
            wal = _read_file(state, _OWNED_WAL, 0, _MAX_WAL)
            if wal is None or hashlib.sha256(wal).hexdigest() != pins["wal_sha256"]:
                _deny("OWNED_WAL_CHANGED")
            old, _ = _decode_owned_wal(wal, distribution="almalinux")
            manifest = old[_OWNED_MANIFEST]
            if (manifest is None or hashlib.sha256(manifest).hexdigest() !=
                    pins["generation_manifest_sha256"]):
                _deny("OWNED_DEDICATED_INSTALLER_PIN_REFUSED")
        elif prepare or start or prepare_storage or prepare_runtime:
            with _owned_layout_locked(root, state, recovering=False) as layout:
                old = _read_owned_resources(*layout[:3])
                manifest = old[_OWNED_MANIFEST]
                if (manifest is None or hashlib.sha256(manifest).hexdigest() !=
                        pins["generation_manifest_sha256"]):
                    _deny("OWNED_DEDICATED_INSTALLER_PIN_REFUSED")
        else:
            wal = _read_file(state, _OWNED_WAL, 0, _MAX_WAL)
            if wal is None or hashlib.sha256(wal).hexdigest() != pins["wal_sha256"]:
                _deny("OWNED_WAL_CHANGED")
            old, _ = _decode_owned_wal(wal, distribution="almalinux")
        snapshot = _validate_owned_resources(old, distribution="almalinux")
        if snapshot is None:
            _deny("OWNED_DEDICATED_FINISH_MANAGED_REQUIRED")
        _owned_socket_require_inactive_routes(snapshot)
        doc = parse_install_bytes(base64.b64decode(
            snapshot["configuration_base64"], validate=True), for_apply=True)
        port = doc["deployment"]["listen"]["https_port"]
        signed_unit = _signed_owned_unit_bytes()
        policy = signed_owned_nginx_policy_candidate()["policy_sha256"]

        def executable():
            return verify_nginx_candidate_receipt(
                directory, expected_receipt_sha256=pins["executable_receipt_sha256"],
                distribution="almalinux", package_identity=pins["package_identity"],
                native_payload_sha256=pins["native_payload_sha256"],
                authenticated_sha256=pins["binary_sha256"],
                release_source_sha=pins["source_sha"], release_archive_sha256=pins["archive_sha256"],
                dedicated_policy_sha256=policy)

        def profile():
            report = _stage_namespace_dropin_under_lock(
                root, state, signed_unit, https_port=port, owner_uid=0,
                owner_gid=0, allow_create=False)
            if report["receipt_sha256"] != pins["profile_receipt_sha256"]:
                _deny("OWNED_DEDICATED_INSTALLER_PROFILE_REFUSED")
            return report

        executable_before = executable()

        def require_disabled_unit(unit, *, inactive):
            from repocache.server_native_nginx_effective_unit_v1 import _safe_native_systemctl
            _safe_native_systemctl()
            operations = [("is-enabled", 1, b"disabled\n")]
            if inactive:
                operations.append(("is-active", 3, b"inactive\n"))
            for action, code, output in operations:
                observed = subprocess.run(
                    (_SYSTEMCTL, action, unit), shell=False, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
                    env=_ENV, timeout=5, close_fds=True, start_new_session=True, check=False)
                if (observed.returncode, observed.stdout) != (code, output):
                    _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")

        def prepared_resources():
            with _owned_layout_locked(root, state, recovering=pending_prepare or pending_start or pending_placement) as layout:
                if pending_prepare or pending_start or pending_placement:
                    state_dir, nginx, public, check_layout = layout
                    _owned_live_guard(state_dir, nginx, public, check_layout,
                                      wal, {**old, _CATALOG: None})
                    _owned_check_stages_absent(state_dir, nginx, public)
                    _owned_live_guard(state_dir, nginx, public, check_layout,
                                      wal, {**old, _CATALOG: None})
                elif _read_owned_resources(*layout[:3]) != old:
                    _deny("OWNED_LIVE_RESOURCE_DRIFT")

        if stage_profile or load_profile:
            from repocache.server_native_nginx_effective_unit_v1 import (
                _NAMESPACE_PROFILE_RECEIPT, _NAMESPACE_PATH,
                inspect_effective_owned_nginx_unit,
                _inspect_signed_owned_namespace_load_state, _safe_native_systemctl,
            )
            from repocache.server_native_egress_candidate_v1 import (
                _BOOT_EGRESS_RECEIPT,
            )
            if doc["deployment"]["listen"]["bind_address"] != "127.0.0.1":
                _deny("OWNED_DEDICATED_INSTALLER_PIN_REFUSED")

            def fresh_boundary(*, placed):
                placement()
                package()
                if executable() != executable_before:
                    _deny("OWNED_DEDICATED_INSTALLER_PROFILE_REFUSED")
                require_disabled_unit(_UNIT, inactive=True)
                require_disabled_unit(_OWNED_WAL_DOMAIN, inactive=True)
                names = set(os.listdir(state))
                prefix = _NAMESPACE_PROFILE_RECEIPT.removesuffix(".json")
                expected = {_NAMESPACE_PROFILE_RECEIPT} if placed else set()
                if ({name for name in names if name.startswith(prefix)} != expected
                        or any(name.startswith(_BOOT_EGRESS_RECEIPT.removesuffix(".json"))
                               for name in names)
                        or os.path.lexists(_NAMESPACE_PATH)):
                    _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")
                with _owned_layout_locked(root, state, recovering=False) as layout:
                    state_dir, nginx, public, check_layout = layout
                    check_layout()
                    _no_conflicting_owned_wal_pending(state_dir)
                    _owned_check_stages_absent(state_dir, nginx, public)
                    if _read_owned_resources(state_dir, nginx, public) != old:
                        _deny("OWNED_LIVE_RESOURCE_DRIFT")
                    check_layout()

            if load_profile:
                # Existing receipt and generation pins are independently
                # authenticated. A reload failure never starts or compensates
                # a service; retry may observe the exact already-loaded unit.
                fresh_boundary(placed=True)
                retained_profile = profile()
                if (retained_profile.get("receipt_matches_owned_dropin") is not True
                        or retained_profile.get("authorizes_systemctl") is not False
                        or retained_profile.get("authorizes_nginx_activation") is not False):
                    _deny("OWNED_DEDICATED_INSTALLER_PROFILE_REFUSED")

                def load_boundary():
                    fresh_boundary(placed=True)
                    if profile() != retained_profile:
                        _deny("OWNED_DEDICATED_INSTALLER_PROFILE_REFUSED")

                load_boundary()
                before = _inspect_signed_owned_namespace_load_state(https_port=port)
                load_boundary()
                if (type(before.get("profile_loaded")) is not bool
                        or before.get("main_pid_observed") != 0
                        or _inspect_signed_owned_namespace_load_state(https_port=port) != before):
                    _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
                reloaded = not before["profile_loaded"]
                if reloaded:
                    _safe_native_systemctl()
                    load_boundary()
                    if _inspect_signed_owned_namespace_load_state(https_port=port) != before:
                        _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
                    try:
                        result = subprocess.run(
                            (_SYSTEMCTL, "daemon-reload"), shell=False,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, cwd="/", env=_ENV,
                            timeout=30, close_fds=True, start_new_session=True, check=False)
                    except (OSError, subprocess.SubprocessError):
                        _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
                    if type(result.returncode) is not int or result.returncode != 0:
                        _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
                load_boundary()
                after = _inspect_signed_owned_namespace_load_state(https_port=port)
                if (after.get("profile_loaded") is not True
                        or after.get("main_pid_observed") != 0
                        or {k: v for k, v in after.items() if k != "profile_loaded"} !=
                           {k: v for k, v in before.items() if k != "profile_loaded"}):
                    _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
                load_boundary()
                if _inspect_signed_owned_namespace_load_state(https_port=port) != after:
                    _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
                load_boundary()
                return {**retained_profile, "status": "OWNED_DEDICATED_PROFILE_LOADED",
                        "profile_loaded": True, "daemon_reloaded": reloaded,
                        "generation_manifest_sha256": pins["generation_manifest_sha256"],
                        "executable_receipt_sha256": pins["executable_receipt_sha256"],
                        "authorizes_nginx_activation": False,
                        "authorizes_catalog_publication": False}

            fresh_boundary(placed=False)
            stopped = inspect_effective_owned_nginx_unit(active=False)
            fresh_boundary(placed=False)
            if (stopped["main_pid_observed"] != 0
                    or inspect_effective_owned_nginx_unit(active=False) != stopped):
                _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
            staged = _stage_namespace_dropin_under_lock(
                root, state, signed_unit, https_port=port, owner_uid=0,
                owner_gid=0, allow_create=True)
            fresh_boundary(placed=True)
            observed = _stage_namespace_dropin_under_lock(
                root, state, signed_unit, https_port=port, owner_uid=0,
                owner_gid=0, allow_create=False)
            if (observed != staged or not _valid_sha(staged.get("receipt_sha256"))
                    or staged.get("receipt_matches_owned_dropin") is not True
                    or staged.get("authorizes_systemctl") is not False
                    or staged.get("authorizes_nginx_activation") is not False):
                _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
            fresh_boundary(placed=True)
            return {**observed, "status": "OWNED_DEDICATED_PROFILE_STAGED",
                    "generation_manifest_sha256": pins["generation_manifest_sha256"],
                    "executable_receipt_sha256": pins["executable_receipt_sha256"],
                    "authorizes_catalog_publication": False}

        profile_before = profile()
        if prepare:
            from repocache.server_native_nginx_effective_unit_v1 import (
                inspect_signed_owned_namespace_unit,
            )
            if doc["deployment"]["listen"]["bind_address"] != "127.0.0.1":
                _deny("OWNED_DEDICATED_INSTALLER_PIN_REFUSED")
            stopped = inspect_signed_owned_namespace_unit(https_port=port, active=False)
            if rollover:
                from repocache.server_native_egress_candidate_v1 import (
                    _BOOT_EGRESS_HISTORY_PREFIX, _BOOT_EGRESS_RECEIPT_MAX, _current_boot_id,
                )
                previous_boot = _read_boot_egress_receipt(state, 0, 0)
                if (previous_boot is None or hashlib.sha256(previous_boot).hexdigest() !=
                        pins["previous_boot_receipt_sha256"]):
                    _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")
                previous_record = _json(previous_boot, limit=_BOOT_EGRESS_RECEIPT_MAX)
                if (type(previous_record) is not dict or
                        previous_record.get("boot_id") == _current_boot_id()):
                    _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")

            def stopped_owner():
                placement()
                if executable() != executable_before or profile() != profile_before:
                    _deny("OWNED_DEDICATED_INSTALLER_PROFILE_REFUSED")
                require_disabled_unit(_UNIT, inactive=True)
                require_disabled_unit(_OWNED_WAL_DOMAIN, inactive=True)
                if (stopped["main_pid_observed"] != 0
                        or inspect_signed_owned_namespace_unit(https_port=port, active=False) != stopped):
                    _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
                prepared_resources()

            options = dict(distribution="almalinux", worker_uid=pwd.getpwnam("nginx").pw_uid,
                           profile_receipt_sha256=pins["profile_receipt_sha256"],
                           executable_receipt_sha256=pins["executable_receipt_sha256"])
            stopped_owner()
            if resume_boot:
                # Never create a namespace or replace a receipt in this path.
                # The lower-level primitive independently binds the exact saved
                # canonical intent to the current boot, inode and closed policy.
                saved = _read_boot_egress_receipt(state, 0, 0)
                if saved is None or hashlib.sha256(saved).hexdigest() != pins["boot_receipt_sha256"]:
                    _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")
                _, identity, recheck_namespace = stack.enter_context(_fixed_namespace_scope())

                def resume_owner():
                    stopped_owner()
                    recheck_namespace()
                    if _read_boot_egress_receipt(state, 0, 0) != saved:
                        _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")
                    recheck_namespace()

                resume_owner()
                if pending_prepare:
                    result = _resume_owned_prepared_wal_boot_egress_locked(
                        root, state, **options, namespace_identity=identity,
                        expected_wal=wal, recheck_stopped_owner=resume_owner)
                else:
                    result = _prepare_owned_committed_boot_egress_locked(
                        root, state, **options, namespace_identity=identity,
                        recheck_namespace_owner=resume_owner, allow_prepare=True,
                        expected_existing_receipt=saved)
                resume_owner()
                package()
                if pending_prepare:
                    observed = _verify_owned_prepared_wal_boot_egress_locked(
                        root, state, **options, namespace_identity=identity,
                        expected_wal=wal, recheck_stopped_owner=resume_owner)
                else:
                    observed = _prepare_owned_committed_boot_egress_locked(
                        root, state, **options, namespace_identity=identity,
                        recheck_namespace_owner=resume_owner, allow_prepare=False)
                if (observed != result or result.get("receipt_sha256") != pins["boot_receipt_sha256"]
                        or result.get("generation_manifest_sha256") != pins["generation_manifest_sha256"]):
                    _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
                resume_owner()
                return result
            previous_pin = ({"expected_previous_receipt_sha256": pins["previous_boot_receipt_sha256"]}
                            if rollover else {})
            if pending_prepare:
                result = _create_owned_prepared_wal_boot_egress_locked(
                    root, state, **options, expected_wal=wal, recheck_stopped_owner=stopped_owner,
                    allow_boot_rollover=rollover, **previous_pin)
            else:
                result = _create_owned_committed_boot_egress_locked(
                    root, state, **options, recheck_stopped_owner=stopped_owner,
                    allow_boot_rollover=rollover, **previous_pin)
            stopped_owner()
            package()
            identity = (result["namespace_device"], result["namespace_inode"])
            if pending_prepare:
                observed = _verify_owned_prepared_wal_boot_egress_locked(
                    root, state, **options, namespace_identity=identity,
                    expected_wal=wal, recheck_stopped_owner=stopped_owner)
            else:
                observed = _prepare_owned_committed_boot_egress_locked(
                    root, state, **options, namespace_identity=identity,
                    recheck_namespace_owner=stopped_owner, allow_prepare=False)
            if (observed != result or result.get("generation_manifest_sha256") !=
                    pins["generation_manifest_sha256"]):
                _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
            if rollover:
                archive = _BOOT_EGRESS_HISTORY_PREFIX + previous_record["boot_id"]
                if (_read_boot_egress_receipt(state, 0, 0, name=archive) != previous_boot
                        or result.get("boot_id") == previous_record["boot_id"]
                        or result.get("receipt_sha256") == pins["previous_boot_receipt_sha256"]):
                    _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")
                stopped_owner()
            return result

        _, namespace_identity, recheck_namespace = stack.enter_context(_fixed_namespace_scope())

        def guard():
            placement()
            recheck_namespace()
            boot = _read_boot_egress_receipt(state, 0, 0)
            if boot is None or hashlib.sha256(boot).hexdigest() != pins["boot_receipt_sha256"]:
                _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")
            if executable() != executable_before or profile() != profile_before:
                _deny("OWNED_DEDICATED_INSTALLER_PROFILE_REFUSED")
            recheck_namespace()

        if prepare_storage or prepare_runtime:
            from repocache.server_native_nginx_effective_unit_v1 import (
                inspect_signed_owned_namespace_unit,
            )
            from repocache.server_native_installed_storage_v1 import (
                prepare_dedicated_candidate_storage,
            )
            if doc["deployment"]["listen"]["bind_address"] != "127.0.0.1":
                _deny("OWNED_DEDICATED_INSTALLER_PIN_REFUSED")

            def stopped_storage_owner(*, audit_package=True):
                guard()
                if audit_package:
                    package()
                require_disabled_unit(_UNIT, inactive=True)
                require_disabled_unit(_OWNED_WAL_DOMAIN, inactive=True)
                if pending_placement:
                    prepared_resources()
                else:
                    with _owned_layout_locked(root, state, recovering=False) as layout:
                        state_dir, nginx, public, check_layout = layout
                        check_layout()
                        _no_conflicting_owned_wal_pending(state_dir)
                        _owned_check_stages_absent(state_dir, nginx, public)
                        if _read_owned_resources(state_dir, nginx, public) != old:
                            _deny("OWNED_LIVE_RESOURCE_DRIFT")
                        check_layout()
                guard()

            stopped_storage_owner()
            stopped = inspect_signed_owned_namespace_unit(https_port=port, active=False)
            if stopped.get("main_pid_observed") != 0:
                _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")

            def storage_owner(*, audit_package=True):
                stopped_storage_owner(audit_package=audit_package)
                if inspect_signed_owned_namespace_unit(https_port=port, active=False) != stopped:
                    _deny("OWNED_DEDICATED_RECOVERY_SERVICE_REFUSED")
                stopped_storage_owner(audit_package=audit_package)

            def storage_policy():
                options = dict(distribution="almalinux", worker_uid=pwd.getpwnam("nginx").pw_uid,
                               namespace_identity=namespace_identity,
                               profile_receipt_sha256=pins["profile_receipt_sha256"],
                               executable_receipt_sha256=pins["executable_receipt_sha256"])
                if pending_placement:
                    result = _verify_owned_prepared_wal_boot_egress_locked(
                        root, state, **options, expected_wal=wal, recheck_stopped_owner=storage_owner)
                else:
                    result = _prepare_owned_committed_boot_egress_locked(
                        root, state, **options, recheck_namespace_owner=storage_owner, allow_prepare=False)
                if (result.get("receipt_sha256") != pins["boot_receipt_sha256"]
                        or result.get("generation_manifest_sha256") != pins["generation_manifest_sha256"]
                        or (not pending_placement and result.get("committed_resources_verified") is not True)
                        or (pending_placement and (
                            result.get("prior_resources_verified") is not True
                            or result.get("wal_sha256") != pins["wal_sha256"]
                            or result.get("catalog_withdrawn") is not True
                            or result.get("recovery_required") is not True
                            or "committed_resources_verified" in result))
                        or result.get("authorizes_nginx_activation") is not False
                        or result.get("authorizes_catalog_publication") is not False):
                    _deny("OWNED_DEDICATED_INSTALLER_BOOT_REFUSED")
                return result

            before = storage_policy()
            storage_owner()
            report_pins = {key: pins[key] for key in (
                "generation_manifest_sha256", "boot_receipt_sha256",
                "profile_receipt_sha256", "executable_receipt_sha256")}
            if pending_placement:
                report_pins.update(wal_sha256=pins["wal_sha256"], catalog_withdrawn=True,
                                   recovery_required=True)
            if prepare_runtime:
                # Persistent dedicated storage must already exist. Never
                # create or migrate it as a side effect of runtime placement.
                existing = prepare_dedicated_candidate_storage("almalinux", doc, allow_create=False)
                if not _closed_committed_dedicated_storage_report(existing):
                    _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
                storage_owner()
                scratch = _prepare_owned_dedicated_runtime_locked(
                    root, recheck_owned=lambda: storage_owner(audit_package=False))
                storage_owner()
                readback = prepare_dedicated_candidate_storage("almalinux", doc, allow_create=False)
                if (not _closed_committed_dedicated_storage_report(readback)
                        or readback != existing or storage_policy() != before
                        or _owned_alma_runtime_temps(root, dedicated=True, inactive=True) != scratch
                        or len(scratch[1]) != 5):
                    _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
                storage_owner()
                return {"status": ("OWNED_DEDICATED_PREPARED_WAL_RUNTIME_PREPARED" if pending_placement
                                   else "OWNED_DEDICATED_COMMITTED_RUNTIME_PREPARED"),
                        "scratch_count": 5, "storage": readback, **report_pins,
                        "authorizes_systemctl": False, "authorizes_nginx_activation": False,
                        "authorizes_catalog_publication": False}
            created = prepare_dedicated_candidate_storage("almalinux", doc, allow_create=True)
            storage_owner()
            if not _closed_committed_dedicated_storage_report(created):
                _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
            readback = prepare_dedicated_candidate_storage("almalinux", doc, allow_create=False)
            if (not _closed_committed_dedicated_storage_report(readback)
                    or readback != created or storage_policy() != before):
                _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
            storage_owner()
            return {"status": ("OWNED_DEDICATED_PREPARED_WAL_STORAGE_PREPARED" if pending_placement
                               else "OWNED_DEDICATED_COMMITTED_STORAGE_PREPARED"),
                    "storage": created, **report_pins,
                    "authorizes_systemctl": False, "authorizes_nginx_activation": False,
                    "authorizes_catalog_publication": False}

        if start:
            def committed_owner():
                guard()
                require_disabled_unit(_UNIT, inactive=True)
                require_disabled_unit(_OWNED_WAL_DOMAIN, inactive=False)
                prepared_resources()
                guard()

            committed_owner()
            entry = (_start_owned_prepared_wal_dedicated_locked if pending_start else
                     _start_or_verify_owned_committed_dedicated_locked if active_repeat else
                     _start_owned_committed_dedicated_locked)
            result = entry(
                root, state, namespace_identity=namespace_identity,
                **({"expected_wal": wal} if pending_start else {}),
                executable_identity=executable_before["executable_identity"][:2],
                profile_receipt_sha256=pins["profile_receipt_sha256"],
                executable_receipt_sha256=pins["executable_receipt_sha256"],
                recheck_authenticated_owner=committed_owner)
            committed_owner()
            package()
            committed_owner()
            accepted_status = ({"OWNED_DEDICATED_PREPARED_WAL_START_OBSERVED"} if pending_start
                               else {"OWNED_DEDICATED_COMMITTED_START_OBSERVED"})
            if active_repeat:
                accepted_status.add("OWNED_DEDICATED_COMMITTED_ACTIVE_VERIFIED")
            if (result.get("status") not in accepted_status
                    or result.get("generation") != snapshot["state_generation"]
                    or result.get("catalog_observed") is not (not pending_start)
                    or (pending_start and (result.get("wal_sha256") != pins["wal_sha256"]
                                           or result.get("catalog_withdrawn") is not True
                                           or result.get("recovery_required") is not True))
                    or result.get("service_storage_mounts_verified") is not True
                    or result.get("service_scratch_mounts_verified") is not True
                    or result.get("enablement_changed") is not False):
                _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
            return {**result, "generation_manifest_sha256": pins["generation_manifest_sha256"],
                    "boot_receipt_sha256": pins["boot_receipt_sha256"]}

        guard()
        result = _recover_owned_prepared_dedicated_locked(
            root, state, namespace_identity=namespace_identity,
            executable_identity=executable_before["executable_identity"][:2],
            profile_receipt_sha256=pins["profile_receipt_sha256"],
            executable_receipt_sha256=pins["executable_receipt_sha256"],
            expected_wal=wal, recheck_authenticated_owner=guard)
        guard()
        package()
        if (_read_file(state, _OWNED_WAL, 0, _MAX_WAL) is not None
                or result.get("status") != "OWNED_DEDICATED_WAL_ROLLBACK_OBSERVED"
                or result.get("wal_sha256") != pins["wal_sha256"]
                or result.get("recovery_required") is not False
                or result.get("catalog_observed") is not True):
            _deny("OWNED_DEDICATED_INSTALLER_RESULT_REFUSED")
        return result


def _owned_live_wait_generation(root_fd: int, identity: tuple, context: tuple) -> None:
    """A graceful reload is asynchronous; bounded retries cannot change authority."""
    deadline = time.monotonic() + 12
    # A fast guest can complete all three old probes before the graceful
    # reload has activated the new workers. Poll the exact generation until
    # the existing deadline, but never extend retries for authority failures.
    for attempt in range(61):
        if _owned_live_observe(root_fd) != identity:
            _deny("OWNED_LIVE_UNIT_CHANGED")
        try:
            _owned_live_health_bound(root_fd, identity, context, None, publish=False)
            return
        except (NativeV2TransactionError, EffectiveNginxUnitError) as exc:
            stale = (type(exc) is NativeV2TransactionError
                     and exc.args == ("NATIVE_V2_OWNED_LIVE_GENERATION_UNVERIFIED",))
            remaining = deadline - time.monotonic()
            if attempt == 60 or remaining <= 0 or (not stale and attempt >= 2):
                raise
            time.sleep(min(0.2, remaining))


def _owned_live_guard(state_fd: int, nginx_fd: int, public_fd: int,
                      check_layout, wal: bytes, expected: dict) -> None:
    check_layout()
    _owned_require_exact_wal(state_fd, wal)
    if _read_owned_resources(state_fd, nginx_fd, public_fd) != expected:
        _deny("OWNED_LIVE_RESOURCE_DRIFT")


def _owned_live_write(state_fd: int, nginx_fd: int, public_fd: int,
                      check_layout, wal: bytes, expected: dict,
                      name: str, after: bytes | None, *, dedicated_catalog: bool = False) -> None:
    _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
    if dedicated_catalog:
        _owned_write_resource(state_fd, nginx_fd, public_fd, name, expected[name], after,
                              dedicated_catalog=True)
    else:
        _owned_write_resource(state_fd, nginx_fd, public_fd, name, expected[name], after)
    expected[name] = after
    _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)


def _write_owned_initial_dedicated_config_locked(
        root_fd: int, state_fd: int, nginx_fd: int, public_fd: int,
        check_layout, wal: bytes, expected: dict, name: str,
        after: bytes | None) -> None:
    """Initial-generation label-preserving forward/rollback writer.

    Detached rehearsal only. Use the existing v3 WAL and exact resources,
    never adopt a committed or catalog-exposed generation. Retain the WAL
    on uncertainty; no service, public catalog, or host operation.
    """
    _refuse_actual_root_fixture_write(root_fd)
    code = "OWNED_INITIAL_DEDICATED_WRITE_REFUSED"
    if name not in (_OWNED_MAIN, _INCLUDE):
        _deny(code)
    old, hashes = _decode_owned_wal(wal, distribution="almalinux")
    if (_json(wal, limit=_MAX_WAL)["version"] != 3
            or _validate_owned_resources(old, distribution="almalinux") is not None
            or expected[_CATALOG] is not None or expected[_OWNED_MANIFEST] is not None
            or _hash(after) not in (_hash(old[name]), hashes[name])):
        _deny(code)
    if ((name == _OWNED_MAIN and after != old[name]
            and _hash(expected[_INCLUDE]) != hashes[_INCLUDE])
            or (name == _INCLUDE and after is None
                and expected[_OWNED_MAIN] != old[_OWNED_MAIN])):
        _deny(code)
    labels = _Labels("almalinux", dedicated=True)

    def boundary():
        _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
        _owned_wal_resource_drift(old, hashes, expected, unpublished=False)
        labels.finish()

    def proof(*, allow_stage=False):
        # Require a closed namespace even with both managed config leaves.
        # The optional fixed stage may exist only during our guarded write.
        if not allow_stage:
            _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
        return _dedicated_readonly_config_labels(
            nginx_fd, public_fd, catalog_present=False,
            bootstrap=expected[_INCLUDE] is None,
            allowed_stage=_OWNED_STAGES[name])

    def unchanged(proven):
        parents, mounts, files = proven
        # Creation of our own regular staging file may change the NGINX
        # directory size/times, but never its inode, links, owner or mount.
        return (parents[0][:6], parents[1], mounts, files)

    boundary()
    _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
    before = proof()
    if expected[name] == after:
        return

    def guard():
        boundary()
        for other in _OWNED_ORDER:
            if other != name:
                parent = _owned_resource_parent(other, state_fd, nginx_fd, public_fd)
                _owned_require_absent(parent, _OWNED_STAGES[other])
        if unchanged(proof(allow_stage=True)) != unchanged(before):
            _deny(code)

    _write_dedicated_public_leaf(nginx_fd, name, expected[name], after, recheck=guard)
    expected[name] = after
    boundary()
    _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
    final = proof()
    if unchanged(final)[:3] != unchanged(before)[:3]:
        _deny(code)
    # Main is always first in the proof. The unaffected config leaf must
    # keep its complete identity across the operation, not merely its bytes.
    if name == _INCLUDE and final[2][0] != before[2][0]:
        _deny(code)
    if name == _OWNED_MAIN and final[2][1:] != before[2][1:]:
        _deny(code)


def _owned_live_finish(state_fd: int, nginx_fd: int, public_fd: int,
                       check_layout, wal: bytes, expected: dict) -> None:
    _owned_live_guard(state_fd, nginx_fd, public_fd, check_layout, wal, expected)
    _validate_owned_resources(expected)
    _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
    _owned_require_exact_wal(state_fd, wal)
    _unlink_known(state_fd, _OWNED_WAL, wal, 0, _MAX_WAL)


def _prepare_owned_inactive_wal_rollback_locked(
    state_fd: int, nginx_fd: int, public_fd: int, check_layout, *,
    distribution: str, expected_wal: bytes, recheck_stopped_owner,
) -> dict:
    """Restore prior bytes while the authenticated owned service is stopped.

    Only a trusted lifecycle caller retaining the original root/state lock
    and fixed layout may invoke this internal preparation. A published v3
    WAL remains the recovery authority, and the catalog stays withdrawn.
    No process, namespace, enablement, syntax or publication operation is
    performed. Active-route predecessors and unpublished WALs are refused.
    """
    if (type(distribution) is not str or distribution not in _CA
            or type(expected_wal) is not bytes
            or not 1 <= len(expected_wal) <= _MAX_WAL
            or not callable(recheck_stopped_owner)):
        _deny("OWNED_INACTIVE_WAL_INPUT_INVALID")

    def stopped_layout():
        check_layout()
        _owned_require_exact_wal(state_fd, expected_wal)
        recheck_stopped_owner()
        check_layout()
        _owned_require_exact_wal(state_fd, expected_wal)

    stopped_layout()
    old, hashes = _decode_owned_wal(expected_wal, distribution=distribution)
    if _json(expected_wal, limit=_MAX_WAL)["version"] != 3:
        _deny("OWNED_LIVE_WAL_REQUIRED")
    snapshot = _validate_owned_resources(old, distribution=distribution)
    _owned_socket_require_inactive_routes(snapshot)
    expected = _read_owned_resources(state_fd, nginx_fd, public_fd)
    _owned_wal_resource_drift(old, hashes, expected, unpublished=False,
                              catalog_withdrawal=True)
    _owned_live_guard(state_fd, nginx_fd, public_fd, stopped_layout,
                      expected_wal, expected)
    _owned_cleanup_stages(state_fd, nginx_fd, public_fd, old, hashes)
    # Cleanup may only remove WAL-owned stages; it must not change targets.
    _owned_live_guard(state_fd, nginx_fd, public_fd, stopped_layout,
                      expected_wal, expected)
    for name, after in ((_CATALOG, None), (_OWNED_MAIN, old[_OWNED_MAIN]),
                        (_INCLUDE, old[_INCLUDE]), (V2_STATE, old[V2_STATE]),
                        (_OWNED_MANIFEST, old[_OWNED_MANIFEST])):
        _owned_live_write(state_fd, nginx_fd, public_fd, stopped_layout,
                          expected_wal, expected, name, after)
    prior_withdrawn = {**old, _CATALOG: None}
    if expected != prior_withdrawn:
        _deny("OWNED_INACTIVE_WAL_RESTORE_DRIFT")
    _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
    _owned_live_guard(state_fd, nginx_fd, public_fd, stopped_layout,
                      expected_wal, prior_withdrawn)
    return {
        "status": "OWNED_INACTIVE_WAL_PRIOR_BYTES_PREPARED",
        "wal_sha256": hashlib.sha256(expected_wal).hexdigest(),
        "prior_generation": None if snapshot is None else snapshot["state_generation"],
        "catalog_withdrawn": True,
        "recovery_required": True,
        "runtime_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
    }


def _finish_owned_inactive_wal_rollback_locked(
    root_fd: int, state_fd: int, nginx_fd: int, public_fd: int, check_layout, *,
    distribution: str, expected_wal: bytes, expected_unit: bytes,
    recheck_active_owner,
) -> dict:
    """Finalize prepared prior bytes only after an authenticated start.

    The trusted signed installer retains the same state lock, layout and
    unit identity. No start/stop or reload is performed here. Publication
    follows proof of the prior generation, exact listener and TLS leaf;
    an uncertain WAL unlink is never reported as completed recovery.
    """
    if (type(distribution) is not str or distribution not in _CA
            or type(expected_wal) is not bytes
            or not 1 <= len(expected_wal) <= _MAX_WAL
            or type(expected_unit) is not bytes or not expected_unit
            or not callable(recheck_active_owner)):
        _deny("OWNED_INACTIVE_WAL_INPUT_INVALID")
    _owned_require_exact_wal(state_fd, expected_wal)
    old, _ = _decode_owned_wal(expected_wal, distribution=distribution)
    if _json(expected_wal, limit=_MAX_WAL)["version"] != 3:
        _deny("OWNED_LIVE_WAL_REQUIRED")
    snapshot = _validate_owned_resources(old, distribution=distribution)
    _owned_socket_require_inactive_routes(snapshot)
    expected = {**old, _CATALOG: None}

    def active_layout():
        check_layout()
        _owned_require_exact_wal(state_fd, expected_wal)
        recheck_active_owner()
        check_layout()
        _owned_require_exact_wal(state_fd, expected_wal)

    _owned_live_guard(state_fd, nginx_fd, public_fd, active_layout,
                      expected_wal, expected)
    _owned_check_stages_absent(state_fd, nginx_fd, public_fd)
    identity = _owned_live_observe(root_fd, expected_unit=expected_unit)
    context = _owned_live_validate(root_fd, state_fd, old)
    _owned_live_health_bound(root_fd, identity, context, None,
                            publish=False, expected_unit=expected_unit)
    _owned_live_guard(state_fd, nginx_fd, public_fd, active_layout,
                      expected_wal, expected)
    try:
        _owned_live_write(state_fd, nginx_fd, public_fd, active_layout,
                          expected_wal, expected, _CATALOG, old[_CATALOG])
        _owned_live_health_bound(root_fd, identity, context, old[_CATALOG],
                                publish=True, expected_unit=expected_unit)
        if (expected != old
                or _owned_live_observe(root_fd, expected_unit=expected_unit) != identity
                or _owned_live_validate(root_fd, state_fd, old) != context):
            _deny("OWNED_LIVE_RECOVERY_DRIFT")
        _owned_live_finish(state_fd, nginx_fd, public_fd, active_layout,
                           expected_wal, expected)
    except Exception:
        # A write may have completed before a post-write guard failed.
        # Withdraw only the exact prior catalog under the same still
        # published WAL and unchanged non-catalog resources; a missing
        # or changed journal cannot authorize any compensating effect.
        current_wal = _read_file(state_fd, _OWNED_WAL, 0, _MAX_WAL)
        if current_wal == expected_wal:
            current = _read_owned_resources(state_fd, nginx_fd, public_fd)
            if current == old:
                _owned_live_write(state_fd, nginx_fd, public_fd, check_layout,
                                  expected_wal, current, _CATALOG, None)
        raise
    return {
        "status": "OWNED_INACTIVE_WAL_ROLLBACK_OBSERVED",
        "prior_generation": None if snapshot is None else snapshot["state_generation"],
        "recovery_required": False,
    }


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
                                         distribution: str, *,
                                         expected_intake: tuple[dict, bytes] | None = None
                                         ) -> tuple[dict, dict, dict]:
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
    if expected_intake is not None and (report, candidate) != expected_intake:
        _deny("CANDIDATE_CHANGED")
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


def _prepare_owned_initial_dedicated_candidate_locked(
        root_fd: int, state_fd: int, nginx_fd: int, public_fd: int,
        check_layout, distribution: str) -> tuple[dict, dict, dict]:
    """Read-only generation-one preflight; never authorize a WAL or service.

    The enforcing AlmaLinux path requires exact inert labelled configuration
    and operator TLS identities on both sides of deterministic CAS rendering.
    The caller must retain the authenticated lock and independently prove
    installed policy, service and storage authority before any future effect.
    """
    code = "OWNED_INITIAL_DEDICATED_CANDIDATE_REFUSED"
    if distribution != "almalinux":
        _deny(code)
    labels = _Labels("almalinux", dedicated=True)
    check_layout()
    config = _dedicated_readonly_config_labels(
        nginx_fd, public_fd, catalog_present=False, bootstrap=True)
    old = _read_owned_resources(state_fd, nginx_fd, public_fd)
    if _validate_owned_resources(old, distribution=distribution) is not None:
        _deny(code)
    report, candidate = _load_private_under_root(root_fd, owner_uid=0, owner_gid=0)
    if report["expected_generation"] != 0 or report["expected_state_sha256"] is not None:
        _deny("STATE_STALE")
    snapshot = _json(candidate, limit=_LIMIT[V2_STATE])
    _owned_socket_require_inactive_routes(snapshot)
    document = parse_install_bytes(
        base64.b64decode(snapshot["configuration_base64"], validate=True),
        for_apply=True,
    )
    tls = _dedicated_readonly_tls_labels(root_fd, document)
    previous, new, prepared = _prepare_owned_live_candidate_locked(
        root_fd, state_fd, nginx_fd, public_fd, distribution,
        expected_intake=(report, candidate))
    labels.finish()
    check_layout()
    again, raw = _load_private_under_root(root_fd, owner_uid=0, owner_gid=0)
    if (previous != old or prepared != report or new[V2_STATE] != candidate
            or again != report or raw != candidate
            or _read_owned_resources(state_fd, nginx_fd, public_fd) != old
            or _dedicated_readonly_config_labels(
                nginx_fd, public_fd, catalog_present=False, bootstrap=True) != config
            or _dedicated_readonly_tls_labels(root_fd, document) != tls):
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
    identity = _reload_native(distribution)
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
        generation = prior_state["state_generation"]
        _wait_native_generation(prior_doc, generation, distribution, identity,
                                stale_generation=generation + 1)
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
    except NativeV2TransactionError as exc:
        _audit_native_failure(exc)
        raise
    except (OSError, ValueError, TypeError) as exc:
        _audit_native_failure(exc)
        _deny("HOST_OPERATION_REFUSED")
    finally:
        os.close(fd)
