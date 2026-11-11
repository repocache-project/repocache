"""No-follow root-owned installed HTTPS-origin config preflight (#24/UC-10).

These tests never read or write a real host /etc; explicit --server overrides
the optional config only for nonprivileged, nonmutating client operations.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "client_config_boundary", ROOT / "client/repocache_client.py"
)
assert spec is not None and spec.loader is not None
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)

ORIGIN = "https://cache.example.invalid"


@pytest.fixture
def installed(tmp_path):
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    etc = root / "etc"
    etc.mkdir(mode=0o755)
    folder = etc / "repocache-client"
    folder.mkdir(mode=0o755)
    config = folder / "config.json"
    config.write_text(json.dumps({"server": ORIGIN}) + "\n")
    config.chmod(0o644)
    return root, etc, folder, config


def test_pinned_installed_config_works_without_root_and_never_writes(installed):
    root, _etc, _folder, config = installed
    before = config.stat()
    assert client._installed_server_config(root) == ORIGIN
    after = config.stat()
    assert (before.st_dev, before.st_ino, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_mtime_ns,
    )
    assert config.read_text() == json.dumps({"server": ORIGIN}) + "\n"


def test_missing_configuration_never_selects_a_default(installed):
    root, _etc, folder, config = installed
    config.unlink()
    assert client._installed_server_config(root) == ""
    folder.rmdir()
    assert client._installed_server_config(root) == ""
    assert client._installed_server_config(root / "missing") == ""


@pytest.mark.parametrize("unsafe", [
    "link-config", "hardlink-config", "world-writable-file",
    "group-writable-directory", "symlink-directory", "symlink-etc",
    "symlink-root",
])
def test_unsafe_installed_configuration_refused_without_following(
    installed, unsafe, tmp_path,
):
    root, etc, folder, config = installed
    outside = tmp_path / "outside"
    outside.write_text('{"server":"https://attacker.example.invalid"}')
    outside.chmod(0o644)
    if unsafe == "link-config":
        config.unlink()
        config.symlink_to(outside)
    elif unsafe == "hardlink-config":
        os.link(config, folder / "other.json")
    elif unsafe == "world-writable-file":
        config.chmod(0o666)
    elif unsafe == "group-writable-directory":
        folder.chmod(0o775)
    elif unsafe == "symlink-directory":
        folder.rename(etc / "saved")
        folder.symlink_to(etc / "saved", target_is_directory=True)
    elif unsafe == "symlink-etc":
        etc.rename(root / "saved")
        etc.symlink_to(root / "saved", target_is_directory=True)
    else:
        other = tmp_path / "alias"
        other.symlink_to(root, target_is_directory=True)
        root = other
    with pytest.raises(client.ClientError, match="Unsafe installed client configuration"):
        client._installed_server_config(root)
    assert outside.read_text() == '{"server":"https://attacker.example.invalid"}'


@pytest.mark.parametrize("content", [
    b'{"server":"https://cache.example.invalid","server":"https://evil.example.invalid"}',
    b'{"server":"https://cache.example.invalid","extra":true}',
    b'{"server":true}',
    b'{"server":null}',
    b'{"server":5}',
    b'["https://cache.example.invalid"]',
    b'{"server":"unterminated',
    b'\xff\xfe',
    b' ' * 4097,
])
def test_noncanonical_or_oversized_config_is_not_a_discovery_authority(
    installed, content,
):
    root, _etc, _folder, config = installed
    config.write_bytes(content)
    config.chmod(0o644)
    with pytest.raises(client.ClientError):
        client._installed_server_config(root)


def test_installed_origin_never_implicitly_touches_a_source(installed, monkeypatch):
    root, _etc, _folder, _config = installed
    monkeypatch.setattr(client, "discover",
                        lambda *_: [])
    monkeypatch.setattr(client, "_distro",
                        lambda *_: {"id": "debian", "version_id": "13"})
    monkeypatch.setattr(client, "_catalog",
                        lambda *_: pytest.fail("read-only list must not call catalog"))
    assert client.run(["repos", "list", "--json"], root=root) == 0


def test_explicit_origin_bypasses_config_and_keeps_readonly_cli(
    installed, monkeypatch, capsys,
):
    root, _etc, folder, config = installed
    config.unlink()
    config.symlink_to("/etc/shadow")
    monkeypatch.setattr(client, "_installed_server_config",
                        lambda *_: pytest.fail("explicit --server must bypass config"))
    monkeypatch.setattr(client, "discover", lambda *_: [])
    monkeypatch.setattr(client, "_distro",
                        lambda *_: {"id": "debian", "version_id": "13"})
    result = client.run(
        ["--server", ORIGIN, "repos", "list", "--json"], root=root,
    )
    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["server"] == ORIGIN
    assert payload["repositories"] == []


def test_unreadable_foreign_config_does_not_reveal_its_contents(installed):
    root, _etc, _folder, config = installed
    secret = "credential:private:must-not-appear"
    config.write_text(secret)
    config.chmod(0o600)
    try:
        client._installed_server_config(root)
    except client.ClientError as err:
        assert secret not in str(err)
    else:
        pytest.fail("malformed untrusted config unexpectedly selected")
