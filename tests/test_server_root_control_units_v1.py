"""Strict static, non-installed systemd socket/worker reference checks (#64)."""
from __future__ import annotations

import configparser
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1] / "docs/examples/systemd"


def parse(name):
    config = configparser.ConfigParser(interpolation=None, strict=True)
    config.optionxform = str
    text = (_ROOT / name).read_text(encoding="utf-8")
    assert "NON-INSTALLED REFERENCE ONLY" in text
    config.read_string(text)
    assert "Install" not in config
    return config


def test_fixed_systemd_socket_reference_never_grants_directory_write():
    unit = parse("repocache-control.socket")
    assert list(unit) == ["DEFAULT", "Unit", "Socket"]
    assert dict(unit["Socket"]) == {
        "ListenSequentialPacket": "/run/repocache/server-control.sock",
        "SocketUser": "root",
        "SocketGroup": "repocache-admin",
        "SocketMode": "0660",
        "DirectoryMode": "0755",
        "Accept": "no",
        "RemoveOnStop": "yes",
        "Service": "repocache-control.service",
    }
    assert not any(key.startswith("ListenStream") for key in unit["Socket"])
    assert not any(key.startswith("ListenDatagram") for key in unit["Socket"])


def test_systemd_worker_reference_is_inert_and_has_no_write_exemption():
    unit = parse("repocache-control.service")
    assert list(unit) == ["DEFAULT", "Unit", "Service"]
    assert dict(unit["Unit"]) == {
        "Description": "REPOCACHE inert root-control worker (non-installed reference)",
        "Requires": "repocache-control.socket",
        "After": "repocache-control.socket",
        "ConditionPathIsExecutable": "/usr/libexec/repocache/server-control-worker",
    }
    assert dict(unit["Service"]) == {
        "Type": "oneshot",
        "User": "root",
        "Group": "root",
        "ExecStart": "/usr/libexec/repocache/server-control-worker",
        "NoNewPrivileges": "yes",
        "PrivateTmp": "yes",
        "PrivateDevices": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes",
        "ProtectControlGroups": "yes",
        "RestrictAddressFamilies": "AF_UNIX",
        "LockPersonality": "yes",
        "MemoryDenyWriteExecute": "yes",
        "SystemCallArchitectures": "native",
        "UMask": "0077",
        "TimeoutStartSec": "10s",
        "StandardInput": "null",
        "StandardOutput": "journal",
        "StandardError": "journal",
    }
    assert not (_ROOT / "repocache-control-worker").exists()
