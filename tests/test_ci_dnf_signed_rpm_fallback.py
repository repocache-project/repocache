"""Safety boundaries of disposable RPM transfer test harness (#24)."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ci_dnf_signed_rpm_fallback as rpm_probe


def test_signed_rpm_test_harness_refuses_unprivileged_or_unmarked_execution(
    monkeypatch,
):
    monkeypatch.setattr(rpm_probe.os, "geteuid", lambda: 1000)
    with pytest.raises(RuntimeError, match="disposable CI Docker"):
        rpm_probe._only_in_disposable_root()
    monkeypatch.setattr(rpm_probe.os, "geteuid", lambda: 0)
    monkeypatch.delenv("REPOCACHE_DISPOSABLE_NATIVE_CI", raising=False)
    with pytest.raises(RuntimeError, match="disposable CI Docker"):
        rpm_probe._only_in_disposable_root()


def test_dnf_fetch_only_uses_download_and_scoped_destination(monkeypatch, tmp_path):
    argv = [
        "/usr/bin/dnf5", "--assumeyes",
        "--config=/tmp/disposable.conf", "--refresh", "makecache",
    ]
    calls = []

    def recorder(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(rpm_probe.subprocess, "run", recorder)
    destination = tmp_path / "packages"
    result = rpm_probe._download_dnf(argv, destination)
    assert result.returncode == 0
    assert destination.is_dir()
    assert len(calls) == 1
    actual, opts = calls[0]
    assert actual == [
        "/usr/bin/dnf5", "--assumeyes",
        "--config=/tmp/disposable.conf", "--refresh",
        "download", rpm_probe._PACKAGE,
        "--destdir=" + str(destination),
    ]
    assert "install" not in actual
    assert opts["timeout"] <= 120
    assert opts["check"] is False


def test_synthetic_rpm_has_no_execution_install_or_scriptlet_sections():
    spec = rpm_probe._SPEC
    assert "%install" in spec  # rpmbuild's staging operation only
    for forbidden in ("%post", "%preun", "%postun", "%pretrans",
                      "%posttrans", "Requires:", "BuildRequires:"):
        assert forbidden not in spec
    assert "BuildArch: noarch" in spec
    assert rpm_probe._RPM_NAME.endswith(".noarch.rpm")



@pytest.mark.parametrize("rpm_output", [
    "", "foo.rpm: digests OK\n", "foo.rpm: Header SHA256 digest: OK\n",
    "foo.rpm: signatures NOKEY\n", "foo.rpm: signatures NOT OK\n",
    "foo.rpm: BAD signature\n", "foo.rpm: no signature\n",
    1234,
])
def test_native_verification_cannot_accept_unsigned_or_untrusted_rpm(rpm_output):
    assert not rpm_probe._rpm_signature_verified(rpm_output)


@pytest.mark.parametrize("signed_output", [
    "foo.rpm: digests signatures OK\n",
    "foo.rpm:\n    Header V4 RSA/SHA256 Signature, key ID 12345678: OK\n"
    "    Payload SHA256 digest: OK\n",
])
def test_native_verification_requires_real_signature_ok(signed_output):
    assert rpm_probe._rpm_signature_verified(signed_output)


def test_booted_rpm_probe_requires_native_guard_before_fixture(monkeypatch):
    from types import SimpleNamespace

    def deny(platform):
        assert platform == "almalinux10"
        raise AssertionError("not a disposable enforcing VM")

    monkeypatch.setitem(sys.modules, "ci_v06_vm_signed_client_guest",
                        SimpleNamespace(guarded_native_guest=deny))
    monkeypatch.setattr(rpm_probe, "_probe_signed_rpm",
                        lambda: pytest.fail("fixture reached before VM guard"))
    with pytest.raises(AssertionError, match="not a disposable enforcing VM"):
        rpm_probe.probe_booted_vm()


def test_booted_rpm_probe_calls_fixture_after_guard(monkeypatch):
    from types import SimpleNamespace

    calls = []
    monkeypatch.setitem(sys.modules, "ci_v06_vm_signed_client_guest",
                        SimpleNamespace(guarded_native_guest=lambda platform:
                                        calls.append(platform)))
    monkeypatch.setattr(rpm_probe, "_probe_signed_rpm",
                        lambda *, booted_vm=False: calls.append(("fixture", booted_vm)))
    rpm_probe.probe_booted_vm()
    assert calls == ["almalinux10", ("fixture", True)]


def test_isolated_rpmdb_label_refuses_host_database_before_commands(monkeypatch):
    monkeypatch.setattr(rpm_probe, "_run", lambda *_:
                        pytest.fail("unsafe label target reached command"))
    with pytest.raises(RuntimeError, match="Unsafe isolated"):
        rpm_probe._label_isolated_rpmdb(Path("/usr/lib/sysimage/rpm"))
