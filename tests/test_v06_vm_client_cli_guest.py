"""Native read-only CLI evidence must refuse malformed outcomes and source drift."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci_v06_vm_client_cli_guest as guest


@pytest.mark.parametrize("platform", ["debian13", "almalinux10", "unknown"])
def test_vm_guard_precedes_source_inventory(monkeypatch, platform):
    def denied(_):
        raise AssertionError("guard")
    monkeypatch.setattr(guest, "native_guard", denied)
    monkeypatch.setattr(guest, "source_snapshot", lambda *_:
                        pytest.fail("source inventory before native guard"))
    with pytest.raises(AssertionError, match="guard"):
        guest.main(platform)


def test_readonly_observation_requires_exact_snapshot(monkeypatch):
    monkeypatch.setattr(guest, "run", lambda *_a, **_kw:
                        SimpleNamespace(returncode=0, stderr="",
                                        stdout='{"schema_version":1,"ok":true}'))
    monkeypatch.setattr(guest, "source_snapshot", lambda *_: ("changed",))
    with pytest.raises(AssertionError, match="inventory changed"):
        guest.checked_readonly_call("debian13", ("original",), ["check"],
                                    Path("/fixture"), (0,))


@pytest.mark.parametrize("code,stderr,payload", [
    (1, "", {"schema_version": 1, "ok": False}),
    (0, "unexpected", {"schema_version": 1, "ok": True}),
    (0, "", {"schema_version": 2, "ok": True}),
    (0, "", {"schema_version": 1, "ok": False}),
    (0, "", {"schema_version": 1, "ok": 1}),
    (0, "", []),
])
def test_readonly_observation_rejects_wrong_contract(monkeypatch, code, stderr, payload):
    monkeypatch.setattr(guest, "run", lambda *_a, **_kw:
                        SimpleNamespace(returncode=code, stderr=stderr,
                                        stdout=json.dumps(payload)))
    monkeypatch.setattr(guest, "source_snapshot", lambda *_: ("original",))
    with pytest.raises(AssertionError):
        guest.checked_readonly_call("debian13", ("original",), ["check"],
                                    Path("/fixture"), (0,))


def test_readonly_observation_accepts_exact_success(monkeypatch):
    monkeypatch.setattr(guest, "run", lambda *_a, **_kw:
                        SimpleNamespace(returncode=0, stderr="",
                                        stdout='{"schema_version":1,"ok":true}'))
    monkeypatch.setattr(guest, "source_snapshot", lambda *_: ("original",))
    payload, code = guest.checked_readonly_call(
        "debian13", ("original",), ["check"], Path("/fixture"), (0,))
    assert code == 0 and payload["ok"] is True
