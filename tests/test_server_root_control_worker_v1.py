"""Fail-closed noninstalled socket worker skeleton tests (#64)."""
from __future__ import annotations

import json
import os
import socket
import stat
from types import SimpleNamespace

import pytest

import repocache.server_root_control_worker_v1 as worker
from repocache.server_root_control_worker_v1 import (
    RootControlWorkerError, _validate_layout, _validate_listener,
)


def meta(kind, mode, uid=0, gid=3000, dev=3, links=1):
    return SimpleNamespace(
        st_mode=kind | mode, st_uid=uid, st_gid=gid,
        st_dev=dev, st_nlink=links,
    )


def test_fixed_socket_metadata_is_strict_and_has_no_effects():
    _validate_layout(
        meta(stat.S_IFDIR, 0o750),
        meta(stat.S_IFSOCK, 0o660), admin_gid=3000,
    )


@pytest.mark.parametrize("which,change", [
    ("dir", {"st_mode": stat.S_IFDIR | 0o770}),
    ("dir", {"st_uid": 1000}),
    ("dir", {"st_gid": 7000}),
    ("dir", {"st_mode": stat.S_IFLNK | 0o750}),
    ("sock", {"st_mode": stat.S_IFREG | 0o660}),
    ("sock", {"st_mode": stat.S_IFSOCK | 0o666}),
    ("sock", {"st_uid": 1000}),
    ("sock", {"st_gid": 7000}),
    ("sock", {"st_dev": 5}),
    ("sock", {"st_nlink": 2}),
])
def test_unsafe_socket_layout_fails_closed(which, change):
    directory = meta(stat.S_IFDIR, 0o750)
    listener = meta(stat.S_IFSOCK, 0o660)
    for field, value in change.items():
        setattr(directory if which == "dir" else listener, field, value)
    with pytest.raises(RootControlWorkerError,
                       match="ROOT_CONTROL_SOCKET_OWNERSHIP_REFUSED"):
        _validate_layout(directory, listener, admin_gid=3000)


def test_abstract_listener_rejected_without_filesystem_access():
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
        server.bind("\0repocache-test-private-abstract")
        server.listen(1)
        with pytest.raises(RootControlWorkerError,
                           match="ROOT_CONTROL_LISTENER_REFUSED"):
            _validate_listener(server)


def test_stream_listener_never_accepted():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind("\0repocache-test-private-stream")
        server.listen(1)
        with pytest.raises(RootControlWorkerError,
                           match="ROOT_CONTROL_LISTENER_REFUSED"):
            _validate_listener(server)


def test_worker_requires_systemd_fd_metadata_before_reading_fd3(monkeypatch):
    monkeypatch.setattr(worker, "_root_worker", lambda: None)
    monkeypatch.delenv("LISTEN_PID", raising=False)
    monkeypatch.delenv("LISTEN_FDS", raising=False)
    with pytest.raises(RootControlWorkerError,
                       match="ROOT_CONTROL_SOCKET_ACTIVATION_REQUIRED"):
        worker._systemd_listener()


def test_no_ambient_fd3_fallback_when_systemd_fd_missing(monkeypatch):
    monkeypatch.setattr(worker, "_root_worker", lambda: None)
    monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
    monkeypatch.setenv("LISTEN_FDS", "1")

    def unavailable(_fd):
        raise OSError("not a trusted activation fd")

    monkeypatch.setattr(worker.os, "dup", unavailable)
    with pytest.raises(RootControlWorkerError,
                       match="ROOT_CONTROL_SOCKET_FD_INVALID"):
        worker._systemd_listener()


def test_accepted_admin_operation_still_refuses_all_mutations(monkeypatch):
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Server:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, timeout):
            assert timeout == 3.0

        def accept(self):
            return Connection(), "untrusted caller-supplied address"

    monkeypatch.setattr(worker, "_systemd_listener", Server)
    monkeypatch.setattr(worker, "authorize_fixed_root_request",
                        lambda _conn: {"operation": "APPLY_V2"})
    result = worker.serve_one_fixed_request()
    assert result["status"] == "ROOT_TRANSACTION_NOT_IMPLEMENTED"
    assert result["requested_operation"] == "APPLY_V2"
    assert all(result[field] is False for field in (
        "authorizes_nginx_reload", "authorizes_state_write",
        "authorizes_catalog_publication", "operator_action_executed",
    ))


def test_main_returns_failure_even_for_valid_authenticated_request(
    monkeypatch, capsys,
):
    monkeypatch.setattr(worker.sys, "argv", ["server-control-worker"])
    monkeypatch.setattr(
        worker, "serve_one_fixed_request",
        lambda: {"schema_version": 1, "status": "ROOT_TRANSACTION_NOT_IMPLEMENTED"},
    )
    assert worker.main() == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "ROOT_TRANSACTION_NOT_IMPLEMENTED"


def test_main_refuses_external_arguments_before_root_or_socket_access(
    monkeypatch, capsys,
):
    monkeypatch.setattr(worker.sys, "argv",
                        ["server-control-worker", "--unit", "ssh.service"])
    monkeypatch.setattr(worker, "serve_one_fixed_request",
                        lambda: pytest.fail("must reject caller arguments"))
    assert worker.main() == 2
    assert json.loads(capsys.readouterr().out) == {
        "code": "ROOT_CONTROL_ARGUMENTS_REFUSED",
    }


def test_main_redacts_host_errors(monkeypatch, capsys):
    monkeypatch.setattr(worker.sys, "argv", ["server-control-worker"])

    def unsafe():
        raise OSError("host secret /etc/ssl/private/do-not-expose")

    monkeypatch.setattr(worker, "serve_one_fixed_request", unsafe)
    assert worker.main() == 2
    report = json.loads(capsys.readouterr().out)
    assert report == {"status": "DENIED", "code": "ROOT_CONTROL_UNAVAILABLE"}
    assert "private" not in capsys.readouterr().out
