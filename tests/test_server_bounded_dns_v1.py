"""Bounded subprocess DNS tests; no live upstream or activation."""
from __future__ import annotations

import json
import socket
import subprocess
from types import SimpleNamespace

import pytest

from repocache.server_bounded_dns_v1 import (
    DEFAULT_DNS_SECONDS,
    MAX_DNS_SECONDS,
    bounded_getaddrinfo,
)

HOST = "mirror.example.invalid"
FAMILY = dict(family=socket.AF_UNSPEC,
              type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)


def resolve(**kwargs):
    return bounded_getaddrinfo(HOST, 443, **FAMILY, **kwargs)


def wire(*, addr="8.8.8.8", port=443):
    return json.dumps([
        [socket.AF_INET, socket.SOCK_STREAM,
         socket.IPPROTO_TCP, "", [addr, port]],
    ]).encode("ascii")


def test_dns_worker_uses_isolated_process_with_hard_timeout(monkeypatch):
    observed = []

    def fake_run(argv, **kwargs):
        observed.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=wire())

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert resolve() == [
        (socket.AF_INET, socket.SOCK_STREAM,
         socket.IPPROTO_TCP, "", ("8.8.8.8", 443)),
    ]
    argv, opts = observed[0]
    assert argv[1:3] == ["-I", "-c"]
    assert argv[-2:] == [HOST, "443"]
    assert isinstance(argv, list)
    assert opts["timeout"] == DEFAULT_DNS_SECONDS
    assert opts["close_fds"] is True
    assert opts["start_new_session"] is True
    assert opts["cwd"] == "/"
    assert opts["stdin"] == subprocess.DEVNULL
    assert opts["stderr"] == subprocess.DEVNULL
    assert opts["env"] == {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
    }
    assert opts["check"] is False
    assert opts.get("shell", False) is False
    assert "getaddrinfo" in argv[3]


@pytest.mark.parametrize("bad", [
    {"host": ""}, {"host": "a" * 254},
    {"host": "bad\nhostname"}, {"host": "høst.invalid"},
    {"port": 0}, {"port": 65536}, {"port": True},
    {"timeout_seconds": 0}, {"timeout_seconds": 16},
    {"timeout_seconds": True}, {"timeout_seconds": float("inf")},
    {"timeout_seconds": float("nan")},
    {"family": socket.AF_INET}, {"type": socket.SOCK_DGRAM},
    {"proto": socket.IPPROTO_UDP},
])
def test_bad_call_refused_before_child(monkeypatch, bad):
    monkeypatch.setattr(subprocess, "run",
                        lambda *_a, **_kw: pytest.fail("child executed"))
    payload = dict(host=HOST, port=443, **FAMILY)
    payload.update(bad)
    with pytest.raises(socket.gaierror, match="invalid request"):
        bounded_getaddrinfo(**payload)


@pytest.mark.parametrize("result", [
    SimpleNamespace(returncode=1, stdout=b""),
    SimpleNamespace(returncode=0, stdout=b"not-json"),
    SimpleNamespace(returncode=0, stdout=b"[]"),
    SimpleNamespace(returncode=0, stdout=b"null"),
    SimpleNamespace(returncode=0, stdout=b"*" * 16385),
    SimpleNamespace(returncode=0, stdout=json.dumps(
        [[2, 1, 6, "", ["8.8.8.8", 443]]] * 33).encode()),
    SimpleNamespace(returncode=0, stdout=b'[[2,1,6,{},["8.8.8.8",443]]]'),
    SimpleNamespace(returncode=0, stdout=b'[[2,1,6,"",["8.8.8.8"]]]'),
])
def test_invalid_worker_responses_fail_closed(monkeypatch, result):
    monkeypatch.setattr(subprocess, "run",
                        lambda *_a, **_kw: result)
    with pytest.raises(socket.gaierror, match="lookup failed"):
        resolve()


def test_worker_timeout_and_os_errors_are_redacted(monkeypatch):
    for error in [
        subprocess.TimeoutExpired(["never log hostname"], timeout=0.2),
        FileNotFoundError(HOST),
    ]:
        def fail(*_args, **_kw):
            raise error
        monkeypatch.setattr(subprocess, "run", fail)
        with pytest.raises(socket.gaierror, match="lookup failed") as exc:
            resolve()
        assert HOST not in str(exc.value)
        assert "never log hostname" not in str(exc.value)


def test_real_child_resolves_localhost_but_never_creates_a_proxy():
    # A local OS resolver test; not an approved repo pin or global-IP PASS.
    answer = bounded_getaddrinfo(
        "localhost", 443, **FAMILY, timeout_seconds=MAX_DNS_SECONDS,
    )
    assert 1 <= len(answer) <= 32
    assert all(isinstance(record[4], tuple) for record in answer)
    assert all(record[1] == socket.SOCK_STREAM for record in answer)


def test_bounded_resolver_cannot_override_public_destination_policy(monkeypatch):
    from repocache.server_upstream_rotation_v1 import (
        UpstreamRotationError, propose_automatic_upstream_refresh,
    )
    import json
    from pathlib import Path
    doc = json.loads((
        Path(__file__).resolve().parents[1]
        / "docs/examples/server-install-v1.json"
    ).read_text())
    doc["repositories"][0]["desired_state"] = "active"
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw:
                        SimpleNamespace(returncode=0, stdout=wire(addr="127.0.0.1")))
    with pytest.raises(UpstreamRotationError, match="unsafe"):
        propose_automatic_upstream_refresh(
            doc, repository_id="debian-trixie-main",
            current_generation=0, previous_pins_by_host=None,
            resolver=bounded_getaddrinfo,
        )
