"""Fixed native root dispatcher positive and negative kernel-socket tests.

Native host effects are intentionally stubbed in ordinary pytest; OS-root,
systemd/SELinux, genuine exposure and signer acceptance require final VMs.
"""
from __future__ import annotations

import json
import socket

import pytest

import repocache.server_native_root_control_entrypoint_v1 as worker
from repocache.server_root_control_protocol_v1 import FixedRootControlError


class Server:
    def __init__(self, accepted):
        self.conn = accepted
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False
    def settimeout(self, seconds):
        assert seconds == 3.0
    def accept(self):
        return self.conn, None


def valid(operation):
    return {
        "status": "KERNEL_PEER_FIXED_OPERATION_SELECTED_ONLY",
        "kernel_peer_credentials_checked": True,
        "host_root_provenance_verified": False,
        "authorizes_nginx_reload": False,
        "operation": operation,
    }


@pytest.mark.parametrize("operation,result,status", [
    ("APPLY_V2", {"status": "NATIVE_V2_COMMITTED",
                  "state_generation": 2}, "APPLIED"),
    ("APPLY_V2", {"status": "NATIVE_V2_NO_CHANGE",
                  "state_generation": 1}, "UNCHANGED"),
    ("RECOVER_V2", {"status": "NATIVE_V2_ROLLED_BACK"}, "RECOVERED"),
    ("RECOVER_V2", {"status": "NATIVE_V2_CLEAN"}, "CLEAN"),
    ("RECOVER_V2",
     {"status": "NATIVE_V2_UNPUBLISHED_WAL_DISCARDED"}, "RECOVERED"),
])
def test_fixed_kernel_operation_dispatch_positive(monkeypatch, operation, result, status):
    client, accepted = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, accepted:
        monkeypatch.setattr(worker, "_systemd_listener", lambda: Server(accepted))
        monkeypatch.setattr(worker, "authorize_fixed_root_request",
                            lambda conn: valid(operation))
        monkeypatch.setattr(worker, "_native_distro", lambda: "debian")
        effects = []

        def execute(op, distro):
            effects.append((op, distro))
            return result

        monkeypatch.setattr(worker, "execute_native_fixed_v2_transaction", execute)
        response = worker.serve_one_native_fixed_request()
        received = client.recv(1024)
        assert received == (json.dumps(
            response, sort_keys=True, separators=(",", ":"),
        ) + "\n").encode("ascii")
        assert response["status"] == status
        assert response["requested_operation"] == operation
        assert response["transaction_completed"] is True
        assert effects == [(operation, "debian")]
        assert "command" not in response and "path" not in response


@pytest.mark.parametrize("claims", [
    {"kernel_peer_credentials_checked": False},
    {"authorizes_nginx_reload": True},
    {"host_root_provenance_verified": True},
    {"status": "UNTRUSTED"},
    {"operation": "ARBITRARY_COMMAND"},
])
def test_forged_peer_metadata_never_dispatches(monkeypatch, claims):
    client, accepted = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, accepted:
        monkeypatch.setattr(worker, "_systemd_listener", lambda: Server(accepted))
        fake = {**valid("APPLY_V2"), **claims}
        monkeypatch.setattr(worker, "authorize_fixed_root_request",
                            lambda conn: fake)
        monkeypatch.setattr(worker, "_native_distro",
                            lambda: pytest.fail("distro must not be read"))
        monkeypatch.setattr(worker, "execute_native_fixed_v2_transaction",
                            lambda *_: pytest.fail("unauthorized dispatcher"))
        with pytest.raises(worker.NativeControlDispatchError):
            worker.serve_one_native_fixed_request()
        assert client.recv(1024) == b""


def test_kernel_refusal_has_no_reply_or_effects(monkeypatch):
    client, accepted = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, accepted:
        monkeypatch.setattr(worker, "_systemd_listener", lambda: Server(accepted))
        monkeypatch.setattr(worker, "authorize_fixed_root_request",
                            lambda conn: (_ for _ in ()).throw(
                                FixedRootControlError("ADMIN_GROUP_REQUIRED")))
        monkeypatch.setattr(worker, "execute_native_fixed_v2_transaction",
                            lambda *_: pytest.fail("unauthorized dispatcher"))
        with pytest.raises(FixedRootControlError, match="ADMIN_GROUP_REQUIRED"):
            worker.serve_one_native_fixed_request()
        assert client.recv(1024) == b""


def test_transaction_failure_is_single_redacted_non_success_packet(monkeypatch):
    client, accepted = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, accepted:
        monkeypatch.setattr(worker, "_systemd_listener", lambda: Server(accepted))
        monkeypatch.setattr(worker, "authorize_fixed_root_request",
                            lambda conn: valid("APPLY_V2"))
        monkeypatch.setattr(worker, "_native_distro", lambda: "almalinux")

        def fail(*args):
            raise worker.NativeV2TransactionError(
                "PRIVATE_TLS_PATH_AND_ROOT_INTERNAL_DETAILS",
            )

        monkeypatch.setattr(worker, "execute_native_fixed_v2_transaction", fail)
        result = worker.serve_one_native_fixed_request()
        raw = client.recv(1024)
        assert json.loads(raw) == result
        assert result == {
            "schema_version": 1, "status": "DENIED",
            "requested_operation": "APPLY_V2",
            "code": "NATIVE_V2_OPERATION_REFUSED",
            "transaction_completed": False,
        }
        assert b"PRIVATE" not in raw


@pytest.mark.parametrize("bad", [
    {"status": "NATIVE_V2_COMMITTED"},
    {"status": "NATIVE_V2_COMMITTED", "state_generation": True},
    {"status": "NATIVE_V2_CLEAN", "state_generation": 1},
    {"status": "UNKNOWN"},
])
def test_forged_transaction_result_never_reports_success(monkeypatch, bad):
    client, accepted = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, accepted:
        monkeypatch.setattr(worker, "_systemd_listener", lambda: Server(accepted))
        monkeypatch.setattr(worker, "authorize_fixed_root_request",
                            lambda conn: valid("APPLY_V2"))
        monkeypatch.setattr(worker, "_native_distro", lambda: "debian")
        monkeypatch.setattr(worker, "execute_native_fixed_v2_transaction",
                            lambda *_: bad)
        result = worker.serve_one_native_fixed_request()
        assert result["status"] == "DENIED"
        assert result["transaction_completed"] is False


def test_main_rejects_arguments_before_socket_or_root(monkeypatch, capsys):
    monkeypatch.setattr(worker.sys, "argv",
                        ["native-worker", "--unit=ssh.service"])
    monkeypatch.setattr(worker, "serve_one_native_fixed_request",
                        lambda: pytest.fail("not allowed"))
    assert worker.main() == 2
    assert "ARGUMENTS_REFUSED" in capsys.readouterr().out


def test_real_native_wrapper_is_not_the_inert_protocol_skeleton():
    from repocache.server_root_control_worker_v1 import serve_one_fixed_request
    from inspect import getsource
    assert "ROOT_TRANSACTION_NOT_IMPLEMENTED" in getsource(serve_one_fixed_request)
    assert "execute_native_fixed_v2_transaction" in getsource(
        worker.serve_one_native_fixed_request,
    )
