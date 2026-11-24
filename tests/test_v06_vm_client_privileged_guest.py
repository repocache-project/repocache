"""Booted privileged fixture must refuse before IO when the VM guard fails."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci_v06_vm_client_privileged_guest as guest


@pytest.mark.parametrize("platform", ["debian13", "almalinux10", "unknown"])
def test_guest_refuses_before_inspecting_sources_when_native_guard_fails(monkeypatch, platform):
    def denied(_):
        raise AssertionError("guard")
    monkeypatch.setattr(guest, "guarded_native_guest", denied)
    monkeypatch.setattr(guest, "installed_sources", lambda *_:
                        pytest.fail("source inventory reached before guard"))
    with pytest.raises(AssertionError, match="guard"):
        guest.main(platform)
