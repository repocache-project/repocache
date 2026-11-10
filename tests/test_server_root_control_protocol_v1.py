"""Negative authorization and exact Linux socket protocol tests (#64).

Container root is not evidence of a booted, trusted host or an installed
systemd broker; mocks below are deliberately only protocol unit tests.
"""
from __future__ import annotations

import os
import socket
import struct

import pytest

import repocache.server_root_control_protocol_v1 as protocol
from repocache.server_root_control_protocol_v1 import (
    FixedRootControlError, _decide_peer, _peer_credentials,
    authorize_fixed_root_request,
)


def pair():
    return socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)


@pytest.mark.parametrize("uid,gid,groups,admin,service", [
    (1000, 2000, (), 3000, 900),
    (1000, 2000, (2001,), 3000, 900),
    (900, 3000, (3000,), 3000, 900),
    (900, 2000, (3000,), 3000, 900),
])
def test_unauthorized_or_service_uid_cannot_cross_boundary(
    uid, gid, groups, admin, service,
):
    with pytest.raises(FixedRootControlError, match="DENIED|REQUIRED"):
        _decide_peer(
            peer_uid=uid, peer_gid=gid, peer_groups=groups,
            admin_gid=admin, service_uid=service,
        )


@pytest.mark.parametrize("uid,gid,groups", [
    (0, 0, ()),
    (1000, 3000, ()),
    (1000, 2000, (3000,)),
])
def test_root_or_member_of_exact_admin_group_passes_pure_policy(uid, gid, groups):
    assert _decide_peer(
        peer_uid=uid, peer_gid=gid, peer_groups=groups,
        admin_gid=3000, service_uid=900,
    ) is None


@pytest.mark.parametrize("bad", [
    True, -1, "3000", None, 2**32 - 1,
])
def test_invalid_peer_identity_refused(bad):
    with pytest.raises(FixedRootControlError, match="IDENTITY_INVALID"):
        _decide_peer(
            peer_uid=bad, peer_gid=100, peer_groups=(),
            admin_gid=3000, service_uid=900,
        )


@pytest.mark.parametrize("bad", [
    0, -1, True, 2**32 - 1, "900",
])
def test_invalid_service_identity_never_grants_authority(bad):
    with pytest.raises(FixedRootControlError, match="IDENTITY_INVALID"):
        _decide_peer(
            peer_uid=0, peer_gid=0, peer_groups=(),
            admin_gid=3000, service_uid=bad,
        )


def test_actual_linux_kernel_peer_credentials_read_without_claims():
    a, b = pair()
    try:
        uid, gid, groups = _peer_credentials(a)
        assert uid == os.getuid()
        assert gid == os.getgid()
        assert isinstance(groups, tuple)
        assert all(type(value) is int for value in groups)
    finally:
        a.close()
        b.close()


def test_stream_socket_cannot_pass_even_when_connection_is_local():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(FixedRootControlError, match="SOCKET_TYPE_INVALID"):
            _peer_credentials(a)
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("raw", [
    b"", b"apply-v2", b"apply-v2\r\n", b"reload\n", b"nginx -t\n",
    b"apply-v2\nmore", b"recover-v2 --path /tmp\n",
    b'{"operation":"apply-v2"}', b"apply-v2\n" + b"x" * 40,
])
def test_unapproved_messages_are_rejected_before_effects(monkeypatch, raw):
    a, b = pair()
    try:
        monkeypatch.setattr(protocol, "_root_worker", lambda: None)
        monkeypatch.setattr(protocol, "_peer_credentials",
                            lambda _: (1001, 3000, ()))
        monkeypatch.setattr(protocol, "_trusted_local_ids",
                            lambda: (3000, 900))
        if raw:
            b.send(raw)
        else:
            b.shutdown(socket.SHUT_WR)
        with pytest.raises(FixedRootControlError,
                           match="FIXED_OPERATION_REFUSED|TRUNCATED"):
            authorize_fixed_root_request(a)
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("message,operation", [
    (b"apply-v2\n", "APPLY_V2"),
    (b"recover-v2\n", "RECOVER_V2"),
])
def test_fixed_command_selection_never_confers_host_authority(
    monkeypatch, message, operation,
):
    a, b = pair()
    try:
        monkeypatch.setattr(protocol, "_root_worker", lambda: None)
        monkeypatch.setattr(protocol, "_peer_credentials",
                            lambda _: (1001, 3000, ()))
        monkeypatch.setattr(protocol, "_trusted_local_ids",
                            lambda: (3000, 900))
        b.send(message)
        result = authorize_fixed_root_request(a)
        assert result["operation"] == operation
        assert result["kernel_peer_credentials_checked"] is True
        assert result["peer_uid"] == 1001
        assert all(result[k] is False for k in (
            "authorizes_nginx_reload", "authorizes_state_write",
            "authorizes_catalog_publication", "host_root_provenance_verified",
            "managed_unit_verified", "operator_action_executed",
        ))
    finally:
        a.close()
        b.close()


def test_service_identity_denied_even_if_socket_filesystem_was_permissive(
    monkeypatch,
):
    a, b = pair()
    try:
        monkeypatch.setattr(protocol, "_root_worker", lambda: None)
        monkeypatch.setattr(protocol, "_peer_credentials",
                            lambda _: (900, 3000, (3000,)))
        monkeypatch.setattr(protocol, "_trusted_local_ids",
                            lambda: (3000, 900))
        b.send(b"apply-v2\n")
        with pytest.raises(FixedRootControlError, match="SERVICE_IDENTITY_DENIED"):
            authorize_fixed_root_request(a)
    finally:
        a.close()
        b.close()


def test_missing_local_identity_refused_even_for_root(monkeypatch):
    a, b = pair()
    try:
        monkeypatch.setattr(protocol, "_root_worker", lambda: None)
        monkeypatch.setattr(protocol, "_peer_credentials", lambda _: (0, 0, ()))
        monkeypatch.setattr(protocol.grp, "getgrnam", lambda _: (_ for _ in ()).throw(KeyError()))
        b.send(b"apply-v2\n")
        with pytest.raises(FixedRootControlError, match="LOCAL_IDENTITIES_UNAVAILABLE"):
            authorize_fixed_root_request(a)
    finally:
        a.close()
        b.close()


def test_non_root_worker_denied_even_if_peer_claims_to_be_admin(monkeypatch):
    a, b = pair()
    try:
        monkeypatch.setattr(protocol.os, "getuid", lambda: 1000)
        monkeypatch.setattr(protocol.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(protocol.os, "getresuid", lambda: (1000, 1000, 1000))
        b.send(b"apply-v2\n")
        with pytest.raises(FixedRootControlError, match="ROOT_WORKER_REQUIRED"):
            authorize_fixed_root_request(a)
    finally:
        a.close()
        b.close()


def test_invalid_packet_does_not_execute_filesystem_or_subprocess(monkeypatch):
    def forbidden(*_a, **_k):
        raise AssertionError("protocol must not perform host I/O")
    monkeypatch.setattr(protocol.os, "system", forbidden)
    monkeypatch.setattr(protocol.os, "replace", forbidden)
    monkeypatch.setattr(protocol.os, "remove", forbidden)
    a, b = pair()
    try:
        monkeypatch.setattr(protocol, "_root_worker", lambda: None)
        monkeypatch.setattr(protocol, "_peer_credentials", lambda _: (0, 0, ()))
        monkeypatch.setattr(protocol, "_trusted_local_ids", lambda: (3000, 900))
        b.send(b"apply-v2\n")
        assert authorize_fixed_root_request(a)["operator_action_executed"] is False
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("case", [
    "truncated-credentials", "invalid-pid", "missing-groups",
    "bad-group-width", "negative-gid",
])
def test_kernel_credential_metadata_errors_fail_closed(case):
    class Peer:
        family = socket.AF_UNIX
        type = socket.SOCK_SEQPACKET

        def getsockopt(self, _level, option, _size):
            if option == socket.SO_PEERCRED:
                if case == "truncated-credentials":
                    return b"0"
                return struct.pack(
                    "3i", 0 if case == "invalid-pid" else 100,
                    1001, -1 if case == "negative-gid" else 3000,
                )
            if case == "missing-groups":
                raise OSError("kernel groups unavailable")
            if case == "bad-group-width":
                return b"x"
            return struct.pack("i", 3000)
    with pytest.raises(FixedRootControlError,
                       match="PEER_CREDENTIALS|PEER_GROUPS"):
        uid, gid, groups = _peer_credentials(Peer())
        # Kernel payload parsing and pure identity policy remain separate,
        # so the invalid primary gid is rejected at this independent stage.
        _decide_peer(
            peer_uid=uid, peer_gid=gid, peer_groups=groups,
            admin_gid=3000, service_uid=900,
        )


def test_too_many_groups_never_bypass_identity_validation():
    with pytest.raises(FixedRootControlError, match="IDENTITY_INVALID"):
        _decide_peer(
            peer_uid=1001, peer_gid=3000, peer_groups=(3000,) * 257,
            admin_gid=3000, service_uid=900,
        )


@pytest.mark.skipif(
    os.geteuid() != 0 or not hasattr(os, "fork"),
    reason="requires disposable root-owned Linux container",
)
def test_actual_kernel_peer_groups_deny_service_and_allow_explicit_admin():
    """Real fork/UID/GID kernel evidence, never an installed broker."""
    import shutil
    import tempfile

    directory = tempfile.mkdtemp(prefix="repocache-peer-", dir="/tmp")
    os.chmod(directory, 0o755)
    admin_gid = 49999
    service_uid = 65534
    cases = (
        (65534, [admin_gid], "SERVICE_IDENTITY_DENIED"),
        (65533, [], "ADMIN_GROUP_REQUIRED"),
        (65532, [admin_gid], None),
    )
    try:
        for index, (uid, groups, expected_error) in enumerate(cases):
            target = os.path.join(directory, f"peer-{index}.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
                server.settimeout(5.0)
                server.bind(target)
                os.chmod(target, 0o666)  # intentionally permissive test socket
                server.listen(1)
                child = os.fork()
                if child == 0:
                    try:
                        server.close()
                        os.setgroups(groups)
                        os.setgid(uid)
                        os.setuid(uid)
                        with socket.socket(
                            socket.AF_UNIX, socket.SOCK_SEQPACKET
                        ) as client:
                            client.settimeout(5.0)
                            client.connect(target)
                            client.sendall(b"apply-v2\n")
                        os._exit(0)
                    except BaseException:
                        os._exit(70)
                try:
                    with server.accept()[0] as conn:
                        peer_uid, peer_gid, peer_groups = _peer_credentials(conn)
                        assert peer_uid == uid
                        assert peer_gid == uid
                        assert set(peer_groups) == set(groups)
                        if expected_error:
                            with pytest.raises(
                                FixedRootControlError, match=expected_error,
                            ):
                                _decide_peer(
                                    peer_uid=peer_uid,
                                    peer_gid=peer_gid,
                                    peer_groups=peer_groups,
                                    admin_gid=admin_gid,
                                    service_uid=service_uid,
                                )
                        else:
                            _decide_peer(
                                peer_uid=peer_uid,
                                peer_gid=peer_gid,
                                peer_groups=peer_groups,
                                admin_gid=admin_gid,
                                service_uid=service_uid,
                            )
                finally:
                    ended, status = os.waitpid(child, 0)
                    assert ended == child
                    assert os.waitstatus_to_exitcode(status) == 0
    finally:
        shutil.rmtree(directory)
