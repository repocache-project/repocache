"""Pinned native TLS key-pair validation under a caller-owned fixture root (#30).

This is not an authenticated host-root helper or an installed NGINX action.
All errors are fixed codes, with no private key or operator path disclosure.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
import re
import ssl
import stat
from typing import Any

from repocache.server_install_v1 import validate_install_document

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_REG = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_PARENT = ("etc", "repocache", "tls")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z", re.ASCII)
_MAX = 1_048_576


class NativeTLSMaterialProbeError(ValueError):
    """Fixed-code refusal without untrusted path or OpenSSL output."""


def _deny(code: str) -> None:
    raise NativeTLSMaterialProbeError("TLS_MATERIAL_" + code)


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _directory(fd: int, uid: int) -> os.stat_result:
    st = os.fstat(fd)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != uid
            or stat.S_IMODE(st.st_mode) & 0o022):
        _deny("DIRECTORY_UNTRUSTED")
    return st


def _reject_unreviewed_attributes(fd: int) -> None:
    try:
        if os.listxattr(fd):
            _deny("XATTR_OR_SELINUX_UNVERIFIED")
    except OSError:
        _deny("XATTR_OR_SELINUX_UNVERIFIED")


def inspect_native_tls_pair_under_root(
    root_fd: int, *, owner_uid: int, document: dict[str, Any],
) -> dict[str, Any]:
    """Open/verify fixed-subtree cert+key FDs, then load pair via OpenSSL.

    /proc/self/fd paths reference already pinned descriptors, not a second
    read of untrusted source paths. Host root/UID provenance, SAN/chain/expiry
    and enforcing SELinux are explicitly outside this private fixture seam.
    """
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or not 0 <= owner_uid <= 2**32-2):
        _deny("ARGUMENT_INVALID")
    try:
        doc = validate_install_document(document, for_apply=True)
        tls = doc["deployment"]["tls"]
        names = []
        prefix = "/" + "/".join(_PARENT) + "/"
        for field in ("certificate_file", "private_key_file"):
            path = tls[field]
            if (type(path) is not str or not path.startswith(prefix)
                    or _NAME.fullmatch(path[len(prefix):]) is None):
                _deny("PATH_UNSUPPORTED")
            names.append(path[len(prefix):])
        if names[0] == names[1]:
            _deny("SAME_INODE")
    except NativeTLSMaterialProbeError:
        raise
    except (KeyError, ValueError, TypeError, RecursionError):
        _deny("DOCUMENT_INVALID")

    try:
        with ExitStack() as stack:
            root = _directory(root_fd, owner_uid)
            current = root_fd
            chain = []
            for segment in _PARENT:
                parent = _directory(current, owner_uid)
                named = os.stat(segment, dir_fd=current, follow_symlinks=False)
                opened = os.open(segment, _DIR, dir_fd=current)
                stack.callback(os.close, opened)
                st = _directory(opened, owner_uid)
                if (_identity(named) != _identity(st)
                        or st.st_dev != parent.st_dev):
                    _deny("DIRECTORY_CHANGED")
                _reject_unreviewed_attributes(opened)
                chain.append((current, segment, opened, _identity(st)))
                current = opened
            leaf_fds = []
            leaf_snapshots = []
            for i, name in enumerate(names):
                named = os.stat(name, dir_fd=current, follow_symlinks=False)
                opened = os.open(name, _REG, dir_fd=current)
                stack.callback(os.close, opened)
                st = os.fstat(opened)
                mode = stat.S_IMODE(st.st_mode)
                if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                        or st.st_uid != owner_uid or st.st_dev != root.st_dev
                        or mode not in ((0o600, 0o644) if i == 0 else (0o600,))
                        or not 1 <= st.st_size <= _MAX
                        or _identity(named) != _identity(st)):
                    _deny("FILE_UNTRUSTED")
                _reject_unreviewed_attributes(opened)
                leaf_fds.append(opened)
                leaf_snapshots.append((name, _identity(st)))
            if leaf_snapshots[0][1][:2] == leaf_snapshots[1][1][:2]:
                _deny("SAME_INODE")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(
                certfile="/proc/self/fd/" + str(leaf_fds[0]),
                keyfile="/proc/self/fd/" + str(leaf_fds[1]),
            )
            for (name, snapshot), fd in zip(leaf_snapshots, leaf_fds):
                if (_identity(os.fstat(fd)) != snapshot
                        or _identity(os.stat(name, dir_fd=current,
                                             follow_symlinks=False)) != snapshot):
                    _deny("FILE_CHANGED")
            for parent, name, fd, snapshot in chain:
                if (_identity(os.fstat(fd)) != snapshot
                        or _identity(os.stat(name, dir_fd=parent,
                                             follow_symlinks=False)) != snapshot):
                    _deny("DIRECTORY_CHANGED")
            if _identity(os.fstat(root_fd)) != _identity(root):
                _deny("DIRECTORY_CHANGED")
    except NativeTLSMaterialProbeError:
        raise
    except (OSError, ssl.SSLError, ValueError, TypeError):
        _deny("TLS_PAIR_OR_INODE_UNVERIFIED")
    return {
        "schema_version": 1,
        "status": "PINNED_NATIVE_TLS_PAIR_FIXTURE_ONLY",
        "openssl_matching_pair_verified": True,
        "certificate_chain_verified": False,
        "certificate_hostname_verified": False,
        "certificate_expiry_verified": False,
        "host_root_authenticated": False,
        "operator_identity_verified": False,
        "selinux_context_verified": False,
        "authorizes_nginx_reload": False,
        "authorizes_firewall_change": False,
    }
