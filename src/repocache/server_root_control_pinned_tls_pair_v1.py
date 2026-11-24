"""Purely observational, private opened-FD TLS certificate/key pair preflight.

A future installed root broker MUST obtain pinned FDs from its *own*
authenticated, root-owned state-v2/NGINX transaction. This module is NOT
connected to the socket worker, takes no path or administrator request,
never grants a service reload. The optional in-memory handshake verifies
TLS trust/name/expiry without opening a listener; neither mode proves ownership of path ancestors, ACLs, labels or live HTTPS exposure.

Stock AlmaLinux 10 nginx -t has been observed accepting a missing or
mismatched TLS key. A real independent load of the exact cert/key pair is
required before any future NGINX reload. This prerequisite validates an already-opened descriptor pair with
OpenSSL through Python ssl, optionally including its trusted server identity.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import ssl
import stat
from typing import Any

_MAX_PEM_BYTES = 128 * 1024


class PinnedTLSPairError(ValueError):
    """Static redacted errors: no key material, paths or OpenSSL messages."""


def _deny(code: str) -> None:
    raise PinnedTLSPairError("PINNED_TLS_PAIR_" + code)


def _metadata(fd: int, *, uid: int, private: bool) -> tuple[int, ...]:
    try:
        info = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    except (OSError, ValueError, TypeError):
        _deny("FD_UNAVAILABLE")
    if (not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_nlink != 1
            or not 0 < info.st_size <= _MAX_PEM_BYTES
            or flags & os.O_ACCMODE != os.O_RDONLY
            or flags & getattr(os, "O_PATH", 0)
            or descriptor_flags & fcntl.FD_CLOEXEC == 0
            or stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022)):
        _deny("FD_UNTRUSTED")
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _digest_fd(fd: int) -> bytes:
    """Pin content with bounded pread; never return the content or digest."""
    try:
        h = hashlib.sha256()
        offset = 0
        while offset <= _MAX_PEM_BYTES:
            chunk = os.pread(fd, min(16384, _MAX_PEM_BYTES + 1 - offset), offset)
            if not chunk:
                break
            h.update(chunk)
            offset += len(chunk)
        if not 0 < offset <= _MAX_PEM_BYTES:
            _deny("FD_CHANGED")
        return h.digest()
    except PinnedTLSPairError:
        raise
    except (OSError, TypeError, ValueError):
        _deny("FD_UNAVAILABLE")


def _verify_tls_identity_in_memory(server_context: ssl.SSLContext,
                                   hostname: str) -> str:
    """Verify the actual cert chain, name and validity without a listener.

    The client uses the same OS default trust as the future live HTTPS
    probe. The caller must supply the name from independently validated
    root-owned configuration, not from the socket peer. No test CA or
    caller-provided TLS context is accepted in the production API.
    """
    if (type(hostname) is not str or not 1 <= len(hostname) <= 253
            or not hostname.isascii()
            or any(ord(ch) <= 32 or ord(ch) == 127 for ch in hostname)):
        _deny("HOSTNAME_REFUSED")
    try:
        client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if (client_context.verify_mode != ssl.CERT_REQUIRED
                or not client_context.check_hostname):
            _deny("CLIENT_TRUST_REFUSED")
        client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_context.wrap_bio(
            client_in, client_out, server_hostname=hostname,
        )
        server = server_context.wrap_bio(
            server_in, server_out, server_side=True,
        )
        client_done = server_done = False
        transmitted = 0
        # MemoryBIO handshakes never access the network. Bound both the
        # number of steps and transferred TLS records for defensive limits.
        for _ in range(32):
            if not client_done:
                try:
                    client.do_handshake()
                    client_done = True
                except ssl.SSLWantReadError:
                    pass
            if client_out.pending:
                transmitted += client_out.pending
                if transmitted > 1024 * 1024:
                    _deny("TLS_IDENTITY_HANDSHAKE_LIMIT")
                server_in.write(client_out.read())
            if not server_done:
                try:
                    server.do_handshake()
                    server_done = True
                except ssl.SSLWantReadError:
                    pass
            if server_out.pending:
                transmitted += server_out.pending
                if transmitted > 1024 * 1024:
                    _deny("TLS_IDENTITY_HANDSHAKE_LIMIT")
                client_in.write(server_out.read())
            if client_done and server_done:
                leaf = client.getpeercert(binary_form=True)
                if type(leaf) is not bytes or not leaf:
                    _deny("TLS_IDENTITY_PEER_MISSING")
                return hashlib.sha256(leaf).hexdigest()
        _deny("TLS_IDENTITY_HANDSHAKE_LIMIT")
    except PinnedTLSPairError:
        raise
    except (ssl.SSLError, OSError, ValueError, TypeError):
        _deny("TLS_IDENTITY_UNVERIFIED")


def _inspect_pinned_tls_pair_for_future_transaction(
    certificate_fd: int, private_key_fd: int, *, expected_owner_uid: int,
    expected_hostname: str | None = None,
) -> dict[str, Any]:
    """PRIVATE test seam; NOT a standalone trusted-root file reader.

    The trusted caller (NOT IMPLEMENTED) must itself prove installed source,
    OS-root, authenticated operator, path/dirfd ancestry, mount/ACL/SELinux,
    immutable state generation and ownership while holding the transaction
    lock. Never let clients, the socket peer or an untrusted document select
    descriptors or expected_owner_uid. This helper does not accept paths.
    """
    if (type(certificate_fd) is not int or certificate_fd < 0
            or type(private_key_fd) is not int or private_key_fd < 0
            or certificate_fd == private_key_fd
            or type(expected_owner_uid) is not int
            or expected_owner_uid < 0):
        _deny("ARGUMENTS_REFUSED")
    cert_before = _metadata(
        certificate_fd, uid=expected_owner_uid, private=False,
    )
    key_before = _metadata(
        private_key_fd, uid=expected_owner_uid, private=True,
    )
    if cert_before[:2] == key_before[:2]:
        _deny("CERT_KEY_COLLIDE")
    cert_digest = _digest_fd(certificate_fd)
    key_digest = _digest_fd(private_key_fd)
    try:
        # /proc/self/fd pins already validated open file descriptions;
        # no caller-provided path is passed to OpenSSL or interpolated into
        # shell/subprocess arguments. Explicit empty password forbids an
        # interactive prompt for encrypted operator keys.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile="/proc/self/fd/" + str(certificate_fd),
            keyfile="/proc/self/fd/" + str(private_key_fd),
            password="",
        )
    except (ssl.SSLError, OSError, ValueError, TypeError):
        _deny("CERT_KEY_LOAD_FAILED")
    peer_sha = (None if expected_hostname is None
                else _verify_tls_identity_in_memory(context, expected_hostname))
    if (_metadata(certificate_fd, uid=expected_owner_uid, private=False)
            != cert_before
            or _metadata(private_key_fd, uid=expected_owner_uid, private=True)
            != key_before
            or _digest_fd(certificate_fd) != cert_digest
            or _digest_fd(private_key_fd) != key_digest):
        _deny("FILES_CHANGED")
    return {
        "schema_version": 1,
        "status": "PINNED_OPEN_FD_CERT_KEY_PAIR_ONLY",
        "private_key_pair_load_observed": True,
        "pinned_opened_file_descriptions_observed": True,
        "trusted_path_ancestry_verified": False,
        "acl_mount_selinux_labels_verified": False,
        "certificate_issuer_hostname_expiry_verified": peer_sha is not None,
        "private_verified_leaf_der_sha256": peer_sha,
        "installed_signed_code_verified": False,
        "operator_authorization_verified": False,
        "host_root_provenance_verified": False,
        "managed_candidate_verified": False,
        "native_nginx_reloaded": False,
        "active_exposure_verified": False,
        "authorizes_host_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }
