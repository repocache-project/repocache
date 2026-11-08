"""Fail-closed, nonauthorizing vendor nginx.service unit inventory (#27)."""
from __future__ import annotations

import hashlib

import pytest

from repocache import server_native_nginx_service_unit_v1 as unit


DEBIAN = b"""[Unit]
Description=NGINX HTTP server
After=network.target
[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
[Install]
WantedBy=multi-user.target
"""

ALMA = b"""[Unit]
Description=NGINX HTTP server
After=network-online.target
[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/bin/rm -f /run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecReload=/usr/sbin/nginx -s reload
KillSignal=SIGQUIT
[Install]
WantedBy=multi-user.target
"""


@pytest.mark.parametrize("contents", [DEBIAN, ALMA])
def test_native_vendor_unit_layout_supported_but_never_authorizing(
    monkeypatch, contents,
):
    assert unit._unit_layout_supported(contents)
    monkeypatch.setattr(unit, "_shadows_present", lambda: False)
    monkeypatch.setattr(unit, "_read_vendor", lambda: (
        "VENDOR_NGINX_UNIT_OBSERVED", contents,
    ))
    result = unit.inspect_native_nginx_unit("debian").to_dict()
    assert result["status"] == "PASS"
    assert result["vendor_unit_sha256"] == hashlib.sha256(contents).hexdigest()
    for field in (
        "native_package_file_ownership_verified",
        "systemd_pid1_and_active_service_verified",
        "selinux_enforcing_service_verified",
        "authorizes_systemctl", "authorizes_nginx_reload",
        "authorizes_native_package_installation", "can_install",
    ):
        assert result[field] is False
    assert result["vendor_unit_bounded_and_owned"]
    assert result["known_unit_shadows_absent"]


@pytest.mark.parametrize("bad", [
    b"",
    DEBIAN + b"\x00",
    b"\xff" + DEBIAN,
    DEBIAN + b"\r\n",
    DEBIAN + b"#" * 65536,
    DEBIAN.replace(b"/usr/sbin/nginx", b"/bin/sh", 1),
    DEBIAN.replace(b"ExecStart=/usr/sbin/nginx", b"ExecStart=/bin/bash", 1),
    DEBIAN.replace(b"ExecReload=/usr/sbin/nginx", b"ExecReload=/tmp/helper", 1),
    DEBIAN.replace(b"Type=forking", b"Type=oneshot"),
    DEBIAN.replace(b"PIDFile=/run/nginx.pid", b"PIDFile=/tmp/nginx.pid"),
    DEBIAN.replace(b"WantedBy=multi-user.target", b"WantedBy=malicious.target"),
    DEBIAN.replace(b"[Install]", b"[Install]\n[Install]"),
    DEBIAN.replace(b"[Service]", b"[Service]\nUser=repocache"),
    DEBIAN.replace(b"[Service]", b"[Service]\nEnvironmentFile=/tmp/evil"),
    DEBIAN.replace(b"[Service]", b"[Service]\nExecStartPost=/bin/sh -c id"),
    DEBIAN.replace(b"[Service]", b"[Service]\nExecCondition=/bin/sh -c id"),
    DEBIAN.replace(b"[Service]", b"[Service]\nRootDirectory=/tmp/evil"),
    DEBIAN.replace(b"[Service]", b"[Service]\nExecStart=\n"),
    DEBIAN.replace(b"ExecStart=/usr/sbin/nginx", b"ExecStart=/usr/sbin/nginx \\"),
])
def test_vendor_unit_signal_only_reload_is_never_sufficient():
    assert not unit._unit_layout_supported(
        ALMA.replace(b"ExecReload=/usr/sbin/nginx -s reload\n", b"")
    )


def test_duplicate_or_unrecognized_vendor_reload_is_refused():
    assert not unit._unit_layout_supported(
        ALMA.replace(
            b"ExecReload=/usr/sbin/nginx -s reload\n",
            b"ExecReload=/usr/sbin/nginx -s reload\n"
            b"ExecReload=/usr/sbin/nginx -s reload\n",
        )
    )
    assert not unit._unit_layout_supported(
        ALMA.replace(
            b"ExecReload=/usr/sbin/nginx -s reload",
            b"ExecReload=/usr/bin/systemctl restart arbitrary.service",
        )
    )


def test_unexpected_or_ambiguous_systemd_unit_contents_refused(bad):
    assert not unit._unit_layout_supported(bad)


def test_disallowed_distribution_fails_before_any_host_observation(monkeypatch):
    monkeypatch.setattr(
        unit, "_shadows_present",
        lambda: pytest.fail("foreign distro must not inspect host"),
    )
    with pytest.raises(
        unit.NginxServiceUnitInspectionError,
        match="^NGINX_UNIT_DISTRIBUTION_INVALID$",
    ):
        unit.inspect_native_nginx_unit("ubuntu")


@pytest.mark.parametrize("code,expected", [
    ("VENDOR_NGINX_UNIT_MISSING", "NOT VERIFIED"),
    ("VENDOR_NGINX_UNIT_UNSAFE", "FAIL"),
    ("VENDOR_NGINX_PARENT_UNSAFE", "FAIL"),
    ("VENDOR_NGINX_UNIT_CHANGED", "NOT VERIFIED"),
    ("VENDOR_NGINX_UNIT_UNAVAILABLE", "NOT VERIFIED"),
])
def test_missing_unsafe_or_raced_vendor_unit_never_authorizes(
    monkeypatch, code, expected,
):
    monkeypatch.setattr(unit, "_shadows_present", lambda: False)
    monkeypatch.setattr(unit, "_read_vendor", lambda: (code, None))
    result = unit.inspect_native_nginx_unit("almalinux").to_dict()
    assert result["status"] == expected
    assert result["vendor_unit_sha256"] is None
    assert not result["authorizes_systemctl"]


def test_external_unit_overlay_refused_before_any_vendor_read(monkeypatch):
    monkeypatch.setattr(unit, "_shadows_present", lambda: True)
    monkeypatch.setattr(
        unit, "_read_vendor",
        lambda: pytest.fail("shadowed service must not be considered vendor-owned"),
    )
    result = unit.inspect_native_nginx_unit("debian").to_dict()
    assert result["code"] == "VENDOR_NGINX_SHADOW_REFUSED"
    assert result["status"] == "FAIL"


def test_external_overlay_race_after_read_is_refused(monkeypatch):
    visits = iter((False, True))
    monkeypatch.setattr(unit, "_shadows_present", lambda: next(visits))
    monkeypatch.setattr(unit, "_read_vendor", lambda: (
        "VENDOR_NGINX_UNIT_OBSERVED", ALMA,
    ))
    result = unit.inspect_native_nginx_unit("almalinux").to_dict()
    assert result["code"] == "VENDOR_NGINX_SHADOW_REFUSED"
    assert result["vendor_unit_sha256"] is None


def test_unsupported_unit_does_not_claim_package_or_service_trust(monkeypatch):
    monkeypatch.setattr(unit, "_shadows_present", lambda: False)
    monkeypatch.setattr(unit, "_read_vendor", lambda: (
        "VENDOR_NGINX_UNIT_OBSERVED", b"evil-secret-xyz",
    ))
    result = unit.inspect_native_nginx_unit("almalinux").to_dict()
    assert result["code"] == "VENDOR_NGINX_UNIT_UNSUPPORTED"
    assert result["status"] == "NOT VERIFIED"
    assert "evil-secret" not in str(result)


@pytest.mark.parametrize("code,digest", [
    ("FORGED_PASS", "a" * 64),
    ("VENDOR_NGINX_UNIT_OBSERVED", None),
    ("VENDOR_NGINX_UNIT_UNSAFE", "a" * 64),
    ("VENDOR_NGINX_UNIT_OBSERVED", "A" * 64),
])
def test_evidence_codes_and_sha256_are_strictly_coherent(code, digest):
    with pytest.raises(ValueError):
        unit.NativeNginxUnitObservation(code, digest)
