"""QEMU signed APT/DNF guest guard and non-destructive selection (#24).

No root, package manager, systemd or host sources are touched by these tests.
Full booted guest signed metadata and fallback MUST be observed in VM CI.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/ci_v06_vm_signed_client_guest.py"
spec = importlib.util.spec_from_file_location("repocache_vm_signed_client_test", SCRIPT)
assert spec and spec.loader
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


@pytest.mark.parametrize("platform", ["debian13", "almalinux10", "unexpected", ""])
def test_native_guest_guard_never_accepts_ci_container_or_unknown_platform(platform):
    # Pure, fail-closed: the caller cannot reuse the root fixture on CI or
    # a non-disposable OS. This test must not open a package manager.
    with pytest.raises(AssertionError):
        guest.guarded_native_guest(platform)


@pytest.mark.parametrize("platform,expected", [
    ("debian13", ("apt", True, False, True)),
    ("almalinux10", ("dnf", True, True, False)),
])
def test_native_manager_selection_preserves_sources_and_packages(
    platform, expected, monkeypatch, capsys,
):
    calls = []
    monkeypatch.setattr(guest, "guarded_native_guest", lambda _: None)
    monkeypatch.setattr(guest, "installed_sources", lambda _: ("unchanged",))
    monkeypatch.setattr(guest, "installed_packages", lambda _: ("unchanged",))
    if platform == "almalinux10":
        monkeypatch.setattr(
            guest, "command",
            lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="Enforcing"),
        )
    monkeypatch.setitem(sys.modules, "ci_client_native_fallback",
                        SimpleNamespace(
                            probe=lambda manager, **k: calls.append((
                                manager, k["tls"], k["signed_dnf"],
                                k["package_transfer"],
                            )),
                        ))
    guest.main(platform)
    assert calls == [expected]
    assert "PASS: booted-native-real-manager-signed-fallback" in capsys.readouterr().out


def test_native_manager_detects_system_source_drift(monkeypatch):
    snapshots = iter([("before",), ("after",)])
    monkeypatch.setattr(guest, "guarded_native_guest", lambda _: None)
    monkeypatch.setattr(guest, "installed_sources", lambda _: next(snapshots))
    monkeypatch.setattr(guest, "installed_packages", lambda _: ("unchanged",))
    monkeypatch.setitem(sys.modules, "ci_client_native_fallback",
                        SimpleNamespace(probe=lambda *args, **kw: None))
    with pytest.raises(AssertionError, match="source files were modified"):
        guest.main("debian13")


def test_native_manager_detects_installed_package_change(monkeypatch):
    installed = iter([("before",), ("after",)])
    monkeypatch.setattr(guest, "guarded_native_guest", lambda _: None)
    monkeypatch.setattr(guest, "installed_sources", lambda _: ("same",))
    monkeypatch.setattr(guest, "installed_packages", lambda _: next(installed))
    monkeypatch.setitem(sys.modules, "ci_client_native_fallback",
                        SimpleNamespace(probe=lambda *args, **kw: None))
    with pytest.raises(AssertionError, match="installed package inventory changed"):
        guest.main("debian13")


def test_native_guest_rejects_non_root_before_system_checks(monkeypatch):
    monkeypatch.setattr(guest.os, "getresuid", lambda: (1000, 1000, 1000))
    with pytest.raises(AssertionError, match="root-only"):
        guest.guarded_native_guest("debian13")
