"""Negative tests for foreign NGINX refusal before any v0.6 package effects (#27).

A local synthetic gate test complements the real two-distro disposable
APT/DNF-userspace job. Neither is a booted systemd/SELinux acceptance test.
"""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "scripts"))
import ci_v06_journaled_native_server_install as native_install


@pytest.mark.parametrize("foreign_path", [
    "/etc/nginx",
    "/usr/sbin/nginx",
    "/lib/systemd/system/nginx.service",
    "/var/lib/repocache",
])
def test_foreign_nginx_or_state_refused_before_any_mutation(
    monkeypatch: pytest.MonkeyPatch, foreign_path: str,
) -> None:
    monkeypatch.setenv(
        "REPOCACHE_NATIVE_TEST_CONTAINER", "CONFIRMED_DISPOSABLE_DOCKER_ONLY",
    )
    monkeypatch.setattr(native_install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        native_install.Path, "is_file",
        lambda self: str(self) == "/.dockerenv",
    )
    monkeypatch.setattr(
        native_install.Path, "read_text",
        lambda self, **kwargs: (
            "sh\n" if str(self) == "/proc/1/comm"
            else "ID=debian\nVERSION_ID=13\n"
        ),
    )
    monkeypatch.setattr(
        native_install, "validate_os_identity", lambda *_args: "debian",
    )
    monkeypatch.setattr(
        native_install, "validate_server_architecture", lambda *_args: None,
    )
    monkeypatch.setattr(
        native_install.os.path, "lexists", lambda path: path == foreign_path,
    )
    def forbidden(*_args, **_kwargs):
        pytest.fail("CI driver passed the foreign-footprint safety gate")

    monkeypatch.setattr(native_install, "_verify_readonly_preflight", forbidden)
    monkeypatch.setattr(
        native_install, "bootstrap_protected_namespace_under_root", forbidden,
    )
    monkeypatch.setattr(native_install, "run_rehearsal", forbidden)
    with pytest.raises(
        native_install.NativeIntegrationError,
        match="^DISPOSABLE_HOST_NOT_FRESH$",
    ):
        native_install.run()


def test_foreign_nginx_real_distro_ci_is_explicitly_mandatory() -> None:
    """Prevent accidental deletion of the separate real-filesystem guard."""
    source = (
        _ROOT / ".github/workflows/server-v06-journaled-native-package.yml"
    ).read_text(encoding="utf-8")
    negative = source.split(
        "- name: Refuse foreign NGINX footprints before native package effects",
        1,
    )
    assert len(negative) == 2
    step = negative[1]
    for required in (
        "foreign-config foreign-binary",
        "DISPOSABLE_HOST_NOT_FRESH",
        'test ! -e /var/lib/repocache',
        'test ! -e /var/log/nginx',
        "sha256sum",
        "stat -c",
        "target=/workspace,readonly",
        "REPOCACHE_NATIVE_TEST_CONTAINER=CONFIRMED_DISPOSABLE_DOCKER_ONLY",
        "authorizes_host_installation",
    ):
        assert required in step
    assert 'platform: debian13' in source
    assert 'platform: almalinux10' in source
    assert 'merge_group:' in source
