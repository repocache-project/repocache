"""Fail-closed, nonauthorizing vendor nginx.service unit inventory (#27)."""
from __future__ import annotations

import hashlib

import pytest

from repocache import server_native_nginx_service_unit_v1 as unit


DEBIAN = b"""[Unit]
Description=NGINX HTTP server
After=network.target
ConditionFileIsExecutable=/usr/sbin/nginx
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
    DEBIAN.replace(
        b"ConditionFileIsExecutable=/usr/sbin/nginx",
        b"ConditionFileIsExecutable=/tmp/foreign",
    ),
    DEBIAN.replace(b"WantedBy=multi-user.target", b"WantedBy=malicious.target"),
    DEBIAN.replace(b"[Install]", b"[Install]\n[Install]"),
    DEBIAN.replace(b"[Service]", b"[Service]\nUser=repocache"),
    DEBIAN.replace(b"[Service]", b"[Service]\nEnvironmentFile=/tmp/evil"),
    DEBIAN.replace(b"[Service]", b"[Service]\nExecStartPost=/bin/sh -c id"),
    DEBIAN.replace(b"[Service]", b"[Service]\nExecCondition=/bin/sh -c id"),
    DEBIAN.replace(b"[Service]", b"[Service]\nRootDirectory=/tmp/evil"),
    DEBIAN.replace(b"[Service]", b"[Service]\nEnvironment=LD_PRELOAD=/tmp/evil.so"),
    DEBIAN.replace(b"ExecStop=-/sbin/start-stop-daemon", b"ExecStop=/bin/sh -c id"),
    DEBIAN.replace(b"ExecStartPre=/usr/sbin/nginx -t", b"ExecStartPre=/usr/sbin/nginx -t\nExecStartPre=/usr/sbin/nginx -t"),
    DEBIAN.replace(b"[Service]", b"[Service]\nExecStart=\n"),
    DEBIAN.replace(b"ExecStart=/usr/sbin/nginx", b"ExecStart=/usr/sbin/nginx \\"),
])
def test_unexpected_or_ambiguous_systemd_unit_contents_refused(bad):
    assert not unit._unit_layout_supported(bad)



@pytest.mark.parametrize("injection", [
    b"[Service]\nBindPaths=/etc/shadow:/tmp/stolen\n",
    b"[Service]\nReadWritePaths=/root\n",
    b"[Service]\nNoNewPrivileges=false\n",
    b"[Service]\nWorkingDirectory=/tmp/untrusted\n",
    b"[Service]\nImportCredential=secret\n",
    b"[Service]\nProtectSystem=false\n",
    b"[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN\n",
    b"[Unit]\nRequires=unrelated.service\n",
    b"[Unit]\nBefore=unrelated.service\n",
    b"[Unit]\nWants=unrelated.service\n",
    b"[Install]\nAlias=nginx-shadow.service\n",
    b"[Custom]\nDescription=ignored-extension\n",
])
def test_systemd_extra_privilege_dependency_and_unknown_keys_fail_closed(injection):
    section = injection.split(b"\n", 1)[0]
    mutated = (
        DEBIAN.replace(section, injection.rstrip(b"\n"), 1)
        if section in DEBIAN
        else DEBIAN + injection
    )
    assert mutated != DEBIAN
    assert not unit._unit_layout_supported(mutated)


@pytest.mark.parametrize("original,substituted", [
    (b"After=network.target", b"After=malicious.service"),
    (b"Description=NGINX HTTP server", b"Description="),
    (b"Type=forking", b"Type=forking\nPrivateTmp=false"),
    (b"Type=forking", b"Type=forking\nKillSignal=SIGKILL"),
    (b"Type=forking", b"Type=forking\nTimeoutStopSec=infinity"),
    (b"Type=forking", b"Type=forking\nKillMode=process"),
    (b"WantedBy=multi-user.target", b"WantedBy=multi-user.target\nAlias=nginx.service"),
])
def test_known_directive_values_cannot_change_native_service_side_effects(
    original, substituted,
):
    assert original in DEBIAN
    assert not unit._unit_layout_supported(DEBIAN.replace(original, substituted, 1))


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


# The systemd --system load path includes control, transient, generator and
# administrator roots; name-specific and type-wide drop-ins are also effective
# even if the distro's vendor nginx.service bytes remain completely unchanged.
_SYSTEMD_SHADOW_ROOTS = (
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/run/systemd/generator.late",
)


@pytest.mark.parametrize("root", _SYSTEMD_SHADOW_ROOTS)
@pytest.mark.parametrize("entry", (
    "nginx.service", "nginx.service.d", "service.d",
    "nginx.service.wants", "nginx.service.requires",
    "nginx.service.upholds",
))
def test_effective_systemd_shadow_roots_refused(
    root, entry, tmp_path, monkeypatch,
):
    assert root + "/" + entry in unit._SHADOW_PATHS
    fixture = tmp_path / entry
    if entry.endswith(".d"):
        fixture.mkdir()
        (fixture / "override.conf").write_text(
            "[Service]\nExecStart=\nExecStart=/tmp/untrusted\n",
            encoding="utf-8",
        )
    elif entry.endswith((".wants", ".requires", ".upholds")):
        fixture.mkdir()
        (fixture / "untrusted.service").symlink_to("/tmp/untrusted.service")
    else:
        fixture.write_text("[Service]\nExecStart=/tmp/untrusted\n", encoding="utf-8")
    monkeypatch.setattr(unit, "_SHADOW_PATHS", (str(fixture),))
    assert unit._shadows_present()


@pytest.mark.parametrize("entry", (
    "nginx.service.d", "service.d",
    "nginx.service.wants", "nginx.service.requires", "nginx.service.upholds",
))
def test_vendor_dropins_and_implicit_dependencies_are_checked(entry):
    assert "/usr/lib/systemd/system/" + entry in unit._SHADOW_PATHS
    assert "/usr/lib/systemd/system/nginx.service" not in unit._SHADOW_PATHS


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


def test_package_created_empty_dropin_is_not_an_effective_systemd_override(
    tmp_path, monkeypatch,
):
    """Isolated fixture: bypass root-UID requirement, but exercise real dirfd syscalls."""
    directory = tmp_path / "nginx.service.d"
    directory.mkdir()
    monkeypatch.setattr(
        unit, "_metadata",
        lambda info, *, directory: True if directory else False,
    )
    before = unit.os.lstat(directory)
    assert unit._empty_safe_dropin_directory(str(directory), before)
    monkeypatch.setattr(unit, "_SHADOW_PATHS", (str(directory),))
    assert not unit._shadows_present()

    # Any file, including a malicious hidden entry, reverses the refusal.
    (directory / ".secret-override.conf").write_text(
        "[Service]\nExecStart=/tmp/evil\n", encoding="utf-8",
    )
    assert unit._shadows_present()


def test_symlinked_or_nonempty_dropin_never_passes_snapshot(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(
        unit, "_metadata",
        lambda info, *, directory: True if directory else False,
    )
    directory = tmp_path / "real-service.d"
    directory.mkdir()
    (directory / "override.conf").write_text("[Service]\n")
    before = unit.os.lstat(directory)
    assert not unit._empty_safe_dropin_directory(str(directory), before)
    link = tmp_path / "nginx.service.d"
    link.symlink_to(directory, target_is_directory=True)
    assert not unit._empty_safe_dropin_directory(
        str(link), unit.os.lstat(link)
    )


def test_ordinary_unprivileged_dropin_is_not_accepted_as_vendor_owned(tmp_path):
    directory = tmp_path / "nginx.service.d"
    directory.mkdir()
    before = unit.os.lstat(directory)
    if unit.os.geteuid() != 0:
        assert not unit._empty_safe_dropin_directory(str(directory), before)


def test_postscan_new_entry_never_becomes_approved_empty_snapshot(
    tmp_path, monkeypatch,
):
    directory = tmp_path / "nginx.service.d"
    directory.mkdir()
    before = unit.os.lstat(directory)
    monkeypatch.setattr(
        unit, "_metadata",
        lambda info, *, directory: True if directory else False,
    )
    real_scandir = unit.os.scandir

    class AlterAfterScan:
        def __enter__(self):
            return iter(())

        def __exit__(self, *_args):
            (directory / "new-dropin.conf").write_text("[Service]\n")

    monkeypatch.setattr(unit.os, "scandir", lambda fd: AlterAfterScan())
    try:
        assert not unit._empty_safe_dropin_directory(str(directory), before)
    finally:
        monkeypatch.setattr(unit.os, "scandir", real_scandir)
