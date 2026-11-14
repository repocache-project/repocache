"""Linux-only, non-activating fixed-operation root control boundary (#64).

A future *installed and reviewed* root-owned broker can use this primitive
after systemd has established a protected AF_UNIX SOCK_SEQPACKET socket.
It only authenticates kernel peer credentials and selects a fixed operation.
It does NOT call nginx/systemctl, write host state, confer a privileged token,
or attest the mount namespace. Never expose a general executable/argument,
pathname, shell, or arbitrary JSON-command dispatch through this protocol.
"""
from __future__ import annotations

import grp
import os
import pwd
import socket
import struct
from typing import Any

_ALLOWED = {
    b"apply-v2\n": "APPLY_V2",
    b"recover-v2\n": "RECOVER_V2",
}
_MAX_PACKET = 32
_MAX_GROUP_BYTES = 1024
_ADMIN_GROUP = "repocache-admin"
_SERVICE_USER = "repocache"
# Linux uapi: SO_PEERGROUPS. Python may not export the constant.
_SO_PEERGROUPS = getattr(socket, "SO_PEERGROUPS", 59)


class FixedRootControlError(ValueError):
    """Public errors contain only static diagnostic codes."""


def _refuse(code: str) -> None:
    raise FixedRootControlError(code)


def _valid_id(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**32 - 2


def _decide_peer(
    *, peer_uid: int, peer_gid: int, peer_groups: tuple[int, ...],
    admin_gid: int, service_uid: int,
) -> None:
    """Pure check; all identities must be obtained independently from OS."""
    if (not _valid_id(peer_uid) or not _valid_id(peer_gid)
            or not _valid_id(admin_gid) or admin_gid == 0
            or not _valid_id(service_uid) or service_uid == 0
            or type(peer_groups) is not tuple
            or len(peer_groups) > _MAX_GROUP_BYTES // struct.calcsize("i")
            or any(not _valid_id(gid) for gid in peer_groups)):
        _refuse("IDENTITY_INVALID")
    # Deny the service identity even if accidentally assigned the admin group.
    if peer_uid == service_uid:
        _refuse("SERVICE_IDENTITY_DENIED")
    if peer_uid != 0 and admin_gid not in (peer_gid, *peer_groups):
        _refuse("ADMIN_GROUP_REQUIRED")


def _root_worker() -> None:
    """Root UID is necessary but never sufficient host-root provenance."""
    try:
        if (os.getuid() != 0 or os.geteuid() != 0
                or os.getresuid() != (0, 0, 0)):
            _refuse("ROOT_WORKER_REQUIRED")
    except AttributeError:
        _refuse("LINUX_ROOT_CREDENTIALS_UNAVAILABLE")


def _peer_credentials(conn: socket.socket) -> tuple[int, int, tuple[int, ...]]:
    """Read unforgeable kernel socket peer IDs; never accept claimed JSON IDs."""
    if conn.family != socket.AF_UNIX or conn.type & 0xF != socket.SOCK_SEQPACKET:
        _refuse("SOCKET_TYPE_INVALID")
    try:
        raw = conn.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        if len(raw) != struct.calcsize("3i"):
            _refuse("PEER_CREDENTIALS_INVALID")
        pid, uid, gid = struct.unpack("3i", raw)
        if pid <= 0 or not _valid_id(uid) or not _valid_id(gid):
            _refuse("PEER_CREDENTIALS_INVALID")
        raw_groups = conn.getsockopt(
            socket.SOL_SOCKET, _SO_PEERGROUPS, _MAX_GROUP_BYTES
        )
        if len(raw_groups) % struct.calcsize("i"):
            _refuse("PEER_GROUPS_INVALID")
        groups = struct.unpack(
            f"{len(raw_groups) // struct.calcsize('i')}i", raw_groups
        )
        if any(not _valid_id(member_gid) for member_gid in groups):
            _refuse("PEER_GROUPS_INVALID")
        return uid, gid, groups
    except (OSError, ValueError, struct.error):
        _refuse("PEER_CREDENTIALS_UNAVAILABLE")


def _trusted_local_ids() -> tuple[int, int]:
    """Fail closed if either administrator or service identity is unprovisioned."""
    try:
        admin_gid = grp.getgrnam(_ADMIN_GROUP).gr_gid
        service_uid = pwd.getpwnam(_SERVICE_USER).pw_uid
    except (KeyError, OSError, ValueError):
        _refuse("LOCAL_IDENTITIES_UNAVAILABLE")
    if not _valid_id(admin_gid) or not _valid_id(service_uid):
        _refuse("LOCAL_IDENTITIES_INVALID")
    return admin_gid, service_uid


def authorize_fixed_root_request(conn: socket.socket) -> dict[str, Any]:
    """Select exactly one command using kernel creds, not input approvals.

    The socket must have been accepted by a separately secured root-owned
    systemd broker. This function performs no privileged action. In particular
    its output is NOT a write/reload capability, nor is root-in-container
    evidence of a trusted host. A worker must close conn after this one packet.
    """
    _root_worker()
    uid, gid, groups = _peer_credentials(conn)
    admin_gid, service_uid = _trusted_local_ids()
    _decide_peer(
        peer_uid=uid, peer_gid=gid, peer_groups=groups,
        admin_gid=admin_gid, service_uid=service_uid,
    )
    try:
        conn.settimeout(3.0)
        payload, _ancillary, flags, _address = conn.recvmsg(_MAX_PACKET + 1)
    except (OSError, TimeoutError):
        _refuse("FIXED_REQUEST_UNAVAILABLE")
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        _refuse("FIXED_REQUEST_TRUNCATED")
    operation = _ALLOWED.get(payload)
    if operation is None:
        _refuse("FIXED_OPERATION_REFUSED")
    return {
        "schema_version": 1,
        "status": "KERNEL_PEER_FIXED_OPERATION_SELECTED_ONLY",
        "operation": operation,
        "peer_uid": uid,
        "kernel_peer_credentials_checked": True,
        "authorizes_nginx_reload": False,
        "authorizes_state_write": False,
        "authorizes_catalog_publication": False,
        "host_root_provenance_verified": False,
        "managed_unit_verified": False,
        "operator_action_executed": False,
    }
