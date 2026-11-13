"""Actual Linux procfs TCP collision evidence in disposable CI (#26).

The tested preflight is read-only: the *test* owns the temporary loopback
socket and never alters real NGINX configuration or an installed service.
Linux /proc/net/tcp{,6} belongs to the current network namespace; this
does not prove a later privileged installer can safely claim a port.
"""
from __future__ import annotations

import os
import socket

import pytest

from repocache.server_host_checks_v1 import HostInspectionSpec, _port_check
from repocache.server_preflight_v1 import PreflightStatus


_FIXED_CONFIG = (
    "/etc/nginx",
    "/etc/nginx/conf.d/repocache-managed.conf",
    "/var/lib/repocache/server",
    "/var/cache/nginx/repocache-managed",
    "/var/log/nginx/repocache-managed",
)


def _metadata_snapshot():
    observed = []
    for path in _FIXED_CONFIG:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            observed.append(None)
        else:
            observed.append((
                info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                info.st_gid, info.st_size, info.st_ctime_ns, info.st_mtime_ns,
            ))
    return tuple(observed)


def _spec(port: int) -> HostInspectionSpec:
    return HostInspectionSpec(
        bind_address="127.0.0.1", https_port=port,
        state_root="/var/lib/repocache/server",
        cache_root="/var/cache/nginx/repocache-managed",
        log_root="/var/log/nginx/repocache-managed",
        generated_include="/etc/nginx/conf.d/repocache-managed.conf",
        tls_certificate_file="/etc/repocache/tls/test-chain.pem",
        tls_private_key_file="/etc/repocache/tls/test-key.pem",
        warning_free_bytes=2_000, critical_free_bytes=1_000,
    )


@pytest.mark.parametrize("family,host", [
    (socket.AF_INET, "127.0.0.1"),
    (socket.AF_INET6, "::1"),
])
def test_real_kernel_listen_port_denied_read_only_and_repeatable(family, host):
    """Require an actual kernel LISTEN row, not a mocked procfs table."""
    try:
        listener = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((host, 0))
        listener.listen(1)
    except OSError:
        if family == socket.AF_INET6:
            pytest.skip("CI network namespace has no enabled IPv6 loopback")
        raise
    try:
        port = listener.getsockname()[1]
        assert type(port) is int and 0 < port < 65536
        before = _metadata_snapshot()
        for _ in range(2):
            result = _port_check(_spec(port))
            assert (result.name, result.status, result.code) == (
                "listen_port_conflicts",
                PreflightStatus.FAIL,
                "HTTPS_PORT_ALREADY_LISTENING",
            )
        assert _metadata_snapshot() == before
        assert listener.getsockname()[1] == port
        assert listener.fileno() >= 0
    finally:
        listener.close()


def test_kernel_tcp_snapshot_preserves_multiple_listener_observations():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as first:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as second:
            for item in (first, second):
                item.bind(("127.0.0.1", 0))
                item.listen(1)
            ports = (first.getsockname()[1], second.getsockname()[1])
            assert ports[0] != ports[1]
            before = _metadata_snapshot()
            for port in ports:
                result = _port_check(_spec(port))
                assert result.status is PreflightStatus.FAIL
                assert result.code == "HTTPS_PORT_ALREADY_LISTENING"
            assert _metadata_snapshot() == before
