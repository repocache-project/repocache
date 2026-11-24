"""Signed unit consistency and bootstrap health prerequisites for #27."""
import io
import os
from pathlib import Path
import zipfile

import pytest

from repocache import server_native_nginx_effective_unit_v1 as unit
from scripts import build_native_root_worker


_ROOT = Path(__file__).resolve().parents[1]
_UNIT_SOURCE = _ROOT / "docs/examples/systemd/repocache-nginx.service"


def test_worker_embeds_exact_authenticated_source_unit():
    raw = build_native_root_worker.build(_ROOT)
    assert raw == build_native_root_worker.build(_ROOT)
    with zipfile.ZipFile(io.BytesIO(raw)) as worker:
        assert worker.namelist().count(unit._SIGNED_UNIT_MEMBER) == 1
        assert worker.read(unit._SIGNED_UNIT_MEMBER) == _UNIT_SOURCE.read_bytes()


def test_source_import_cannot_claim_installed_worker_unit():
    with pytest.raises(unit.EffectiveNginxUnitError, match="SIGNED_OWN_UNIT_SOURCE_REQUIRED"):
        unit._signed_owned_unit_bytes()


@pytest.mark.parametrize("fault", [None, "changed", "symlink", "hardlink", "mode", "fifo"])
def test_exact_unit_file_is_pinned_and_not_adopted(tmp_path, fault):
    directory = tmp_path / "etc/systemd/system"
    directory.mkdir(parents=True)
    target = directory / "repocache-nginx.service"
    expected = _UNIT_SOURCE.read_bytes()
    target.write_bytes(expected)
    target.chmod(0o644)
    if fault == "changed":
        target.write_bytes(b"X" + expected[1:])
    elif fault == "symlink":
        other = directory / "other.service"
        target.rename(other)
        target.symlink_to(other.name)
    elif fault == "hardlink":
        os.link(target, directory / "other.service")
    elif fault == "mode":
        target.chmod(0o664)
    elif fault == "fifo":
        target.unlink()
        os.mkfifo(target)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if fault is None:
            assert unit._read_exact_owned_unit_at(
                fd, expected, owner_uid=os.getuid(), owner_gid=os.getgid()
            )[1] == target.stat().st_ino
        else:
            with pytest.raises(unit.EffectiveNginxUnitError):
                unit._read_exact_owned_unit_at(
                    fd, expected, owner_uid=os.getuid(), owner_gid=os.getgid()
                )
    finally:
        os.close(fd)


@pytest.mark.parametrize("drift", [False, True])
def test_signed_observer_requires_same_unit_identity(monkeypatch, drift):
    monkeypatch.setattr(unit, "_signed_owned_unit_bytes", lambda: b"signed")
    reads = iter([(1, 2), (1, 3) if drift else (1, 2)])
    monkeypatch.setattr(unit, "_read_exact_owned_unit_at", lambda *a, **kw: next(reads))
    monkeypatch.setattr(unit, "inspect_effective_owned_nginx_unit", lambda **kw: {
        "unit_name": "repocache-nginx.service", "main_pid_observed": 77,
        "authorizes_nginx_reload": False, "authorizes_systemctl": False,
    })
    if drift:
        with pytest.raises(unit.EffectiveNginxUnitError, match="SIGNED_OWN_UNIT_CHANGED"):
            unit.inspect_signed_owned_nginx_unit()
    else:
        report = unit.inspect_signed_owned_nginx_unit()
        assert report["signed_worker_unit_bytes_match"] is True
        assert report["authorizes_nginx_reload"] is False
        assert report["authorizes_systemctl"] is False


@pytest.mark.parametrize("raw", [
    b"HTTP/1.1 200 OK\r\n\r\n",
    b"HTTP/1.1 302 Found\r\nLocation: https://example.org/\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\n\r\nbody",
    b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\n malformed\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\n",
    b"x" * 8193,
])
def test_bootstrap_health_refuses_invalid_response(raw):
    with pytest.raises(unit.EffectiveNginxUnitError, match="BOOTSTRAP_HEALTH_UNVERIFIED"):
        unit._require_bootstrap_response(raw)


def test_bootstrap_probe_uses_only_fixed_loopback(monkeypatch):
    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, seconds):
            assert 0 < seconds <= 4

        def sendall(self, raw):
            assert raw == (b"GET /__repocache/private HTTP/1.1\r\n"
                           b"Host: localhost\r\nConnection: close\r\n\r\n")

        chunks = iter([b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n", b""])

        def recv(self, maximum):
            assert 0 < maximum <= 4096
            return next(self.chunks)

    def connect(address, *, timeout):
        assert address == ("127.0.0.1", 8008)
        assert timeout == 4
        return Stream()

    monkeypatch.setattr(unit.socket, "create_connection", connect)
    assert unit.require_owned_bootstrap_health() is None
