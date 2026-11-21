"""Fixed native root dispatcher positive and negative kernel-socket tests.

Native host effects are intentionally stubbed in ordinary pytest; OS-root,
systemd/SELinux, genuine exposure and signer acceptance require final VMs.
"""
from __future__ import annotations

import json
import os
import socket
import stat
from types import SimpleNamespace

import pytest

import repocache.server_native_root_control_entrypoint_v1 as worker
import repocache.server_native_v2_transaction_v1 as transaction
from repocache.server_root_control_protocol_v1 import FixedRootControlError
from test_server_proposed_state_v2_store import document


@pytest.mark.parametrize("release,version,machine,native,venv,expected", [
    ("ID=debian\nVERSION_ID=13\n", (3, 13), "x86_64", True, False, "debian"),
    ("ID=almalinux\nVERSION_ID=10\n", (3, 12), "x86_64", True, False, "almalinux"),
    ("ID=debian\nVERSION_ID=12\n", (3, 12), "x86_64", True, False, None),
    ("ID=almalinux\nVERSION_ID=9\n", (3, 12), "x86_64", True, False, None),
    ("ID=debian\nVERSION_ID=13\n", (3, 12), "x86_64", True, False, None),
    ("ID=debian\nVERSION_ID=13\n", (3, 13), "aarch64", True, False, None),
    ("ID=debian\nVERSION_ID=13\n", (3, 13), "x86_64", False, False, None),
    ("ID=debian\nVERSION_ID=13\n", (3, 13), "x86_64", None, False, None),
    ("ID=debian\nVERSION_ID=13\n", (3, 13), "x86_64", True, True, None),
])
def test_native_root_target_gate(tmp_path, monkeypatch, release, version, machine, native, venv, expected):
    path = tmp_path / "os-release"
    path.write_text(release, encoding="ascii")
    monkeypatch.setattr(worker, "_RELEASE_ID", str(path))
    real_lstat = os.lstat
    def owned_metadata(name, *args, **kwargs):
        if str(name) == "/usr/lib":
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        value = real_lstat(name, *args, **kwargs)
        if str(name) == str(path):
            return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0,
                                   st_nlink=value.st_nlink, st_size=value.st_size,
                                   st_dev=value.st_dev, st_ino=value.st_ino)
        return value
    monkeypatch.setattr(worker.os, "lstat", owned_metadata)
    monkeypatch.setattr(worker, "sys", SimpleNamespace(version_info=version,
        prefix="/tmp/venv" if venv else "/usr", base_prefix="/usr"))
    monkeypatch.setattr(worker.platform, "machine", lambda: machine)
    monkeypatch.setattr(worker, "_native_python_identity", lambda _: native)
    if expected is None:
        with pytest.raises(worker.NativeControlDispatchError):
            worker._native_distro()
    else:
        assert worker._native_distro() == expected


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
    ("RELOAD_V2", {"status": "NATIVE_V2_RELOADED",
                   "state_generation": 3}, "RELOADED"),
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
        if status == "RELOADED":
            assert response["nginx_reload_and_exposure_observed"] is True
            assert response["active_catalog_published"] is False
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


def test_real_transaction_checks_service_mount_view_before_nginx(monkeypatch):
    def refuse():
        raise worker.NativeHostPreflightError("NATIVE_HOST_SERVICE_MOUNT_VIEW_DIFFERENT")

    monkeypatch.setattr(transaction, "require_socket_worker_host_preconditions", refuse)
    monkeypatch.setattr(transaction, "inspect_effective_native_nginx_unit",
                        lambda _distro: pytest.fail("NGINX inspection after mount refusal"))
    with pytest.raises(worker.NativeHostPreflightError, match="SERVICE_MOUNT_VIEW_DIFFERENT"):
        transaction.execute_native_fixed_v2_transaction("APPLY_V2", "debian")


def test_native_pin_resolution_drops_privilege_and_bounds_total_wait(monkeypatch):
    config = document(count=2)
    repository = config["repositories"][0]
    repository["desired_state"] = "active"
    calls = []
    times = iter((100.0, 144.0))
    # Replace the transaction's binding rather than mutating the test
    # process's global time.monotonic.
    from types import SimpleNamespace
    monkeypatch.setattr(transaction, "time", SimpleNamespace(monotonic=lambda: next(times)))

    def resolve(host, port, **options):
        calls.append((host, port, options))
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                 "", ("8.8.8.8", port))]

    monkeypatch.setattr(transaction, "bounded_getaddrinfo", resolve)
    host, = repository["upstream"]["allowed_hosts"]
    assert transaction._resolve_pins(config) == {"repo-0": {host: ["8.8.8.8"]}}
    assert len(calls) == 1
    assert calls[0][:2] == (host, 443)
    assert calls[0][2]["timeout_seconds"] == 1.0
    assert calls[0][2]["run_as_uid"] == calls[0][2]["run_as_gid"] == 65534


def test_native_pin_resolution_refuses_mismatched_sockaddr(monkeypatch):
    config = document(count=1)
    config["repositories"][0]["desired_state"] = "active"
    monkeypatch.setattr(transaction, "bounded_getaddrinfo", lambda *_a, **_kw: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 80)),
    ])
    with pytest.raises(transaction.NativeV2TransactionError, match="DNS_UNVERIFIED"):
        transaction._resolve_pins(config)
