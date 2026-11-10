"""Non-installed Unix control client: bounded, root-peer, fail-closed replies."""
from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

import pytest

import repocache.server_root_control_client_v1 as client
from repocache.server_root_control_client_v1 import (
    FixedControlClientError, _parse_response,
    request_fixed_inert_operation,
)

_DENIAL = {
    "schema_version": 1,
    "status": "ROOT_TRANSACTION_NOT_IMPLEMENTED",
    "requested_operation": "APPLY_V2",
    "authorizes_nginx_reload": False,
    "authorizes_state_write": False,
    "authorizes_catalog_publication": False,
    "operator_action_executed": False,
}


def packet(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def test_closed_denial_response_is_not_an_authorization():
    result = _parse_response(packet(_DENIAL), operation="APPLY_V2")
    assert result == _DENIAL
    assert not result["operator_action_executed"]


@pytest.mark.parametrize("mutate", [
    lambda d: {**d, "operator_action_executed": True},
    lambda d: {**d, "authorizes_state_write": True},
    lambda d: {**d, "authorizes_catalog_publication": True},
    lambda d: {**d, "status": "SUCCESS"},
    lambda d: {**d, "requested_operation": "RECOVER_V2"},
    lambda d: {**d, "extra": "injection"},
    lambda d: {**d, "schema_version": True},
    lambda d: {**d, "authorizes_nginx_reload": 0},
])
def test_client_refuses_modified_or_success_claiming_response(mutate):
    with pytest.raises(FixedControlClientError,
                       match="RESPONSE_UNEXPECTED"):
        _parse_response(packet(mutate(_DENIAL)), operation="APPLY_V2")


@pytest.mark.parametrize("wire", [
    b"", b"not-json\n", b"{}\n", b"\xff\n", b"{}\r\n",
    b"{}\n{}\n", b"x" * 1025, b"{}\x00\n", packet(_DENIAL)[:-1],
])
def test_invalid_or_unterminated_response_fails_closed(wire):
    with pytest.raises(FixedControlClientError):
        _parse_response(wire, operation="APPLY_V2")


@pytest.mark.parametrize("operation", [
    "", "reload", "apply-v2\n", "RECOVER_V2\n", "RELOAD", None,
    0, {}, True,
])
def test_unknown_operation_is_refused_before_path_or_socket_access(
    monkeypatch, operation,
):
    monkeypatch.setattr(client, "_validate_parent_and_socket",
                        lambda: pytest.fail("must not inspect host paths"))
    with pytest.raises(FixedControlClientError,
                       match="OPERATION_REFUSED"):
        request_fixed_inert_operation(operation)


@pytest.mark.skipif(os.geteuid() != 0,
                    reason="root-owned disposable socket fixture required")
@pytest.mark.parametrize("operation", ["APPLY_V2", "RECOVER_V2"])
def test_linux_kernel_seqpacket_roundtrip_from_fixed_local_socket(
    tmp_path: Path, monkeypatch, operation,
):
    """A real root-peer Unix socket may report denial but never success."""
    socket_path = tmp_path / "root-control.sock"
    os.chown(tmp_path, 0, 0)
    os.chmod(tmp_path, 0o755)
    monkeypatch.setattr(client, "_PARENT", str(tmp_path))
    monkeypatch.setattr(client, "_SOCKET", str(socket_path))
    expected_request = (b"apply-v2\n" if operation == "APPLY_V2"
                        else b"recover-v2\n")
    served = []
    reply = {**_DENIAL, "requested_operation": operation}

    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
        server.bind(str(socket_path))
        os.chown(socket_path, 0, 0)
        os.chmod(socket_path, 0o660)
        server.listen(1)

        def serve():
            try:
                with server.accept()[0] as conn:
                    conn.settimeout(3)
                    received = conn.recv(256)
                    served.append(received)
                    conn.send(packet(reply))
            except OSError as exc:
                served.append(type(exc).__name__)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        result = request_fixed_inert_operation(operation)
        worker.join(timeout=3)
        assert not worker.is_alive()
        assert served == [expected_request]
        assert result == reply
        assert all(result[key] is False for key in (
            "authorizes_nginx_reload", "authorizes_state_write",
            "authorizes_catalog_publication", "operator_action_executed",
        ))


@pytest.mark.skipif(os.geteuid() != 0,
                    reason="root-owned disposable socket fixture required")
@pytest.mark.parametrize("bad", ["symlink", "writable", "wrong-owner-socket"])
def test_client_rejects_unsafe_local_socket_path_before_connect(
    tmp_path: Path, monkeypatch, bad,
):
    socket_path = tmp_path / "root-control.sock"
    os.chown(tmp_path, 0, 0)
    os.chmod(tmp_path, 0o755)
    monkeypatch.setattr(client, "_PARENT", str(tmp_path))
    monkeypatch.setattr(client, "_SOCKET", str(socket_path))
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
        server.bind(str(socket_path))
        os.chown(socket_path, 0, 0)
        os.chmod(socket_path, 0o660)
        server.listen(1)
        if bad == "symlink":
            socket_path.unlink()
            socket_path.symlink_to("/etc/passwd")
        elif bad == "writable":
            os.chmod(tmp_path, 0o777)
        else:
            os.chown(socket_path, 65534, 65534)
        with pytest.raises(FixedControlClientError,
                           match="SOCKET_UNSAFE"):
            request_fixed_inert_operation("APPLY_V2")


@pytest.mark.parametrize("extra_wire", [
    lambda good: good.replace(
        b'"status":"ROOT_TRANSACTION_NOT_IMPLEMENTED"',
        b'"status":"FAIL","status":"ROOT_TRANSACTION_NOT_IMPLEMENTED"',
    ),
    lambda good: good.replace(b'"schema_version":1', b'"schema_version":1.0'),
    lambda good: good.replace(b',"status":', b', "status":'),
    lambda good: good.replace(b'"requested_operation":"APPLY_V2"',
                              b'"requested_operation":"\u0041PPLY_V2"'),
    lambda good: good.replace(b'"schema_version":1',
                              b'"schema_version":NaN,"schema_version":1'),
])
def test_ambiguous_or_noncanonical_fixed_denial_is_never_accepted(extra_wire):
    altered = extra_wire(packet(_DENIAL))
    assert altered != packet(_DENIAL)
    with pytest.raises(FixedControlClientError,
                       match="RESPONSE_INVALID|RESPONSE_NONCANONICAL"):
        _parse_response(altered, operation="APPLY_V2")
