"""Strict non-authorizing nginx.service effective PID1 snapshot negatives."""
from __future__ import annotations

import stat
import subprocess
from types import SimpleNamespace

import pytest

import repocache.server_native_nginx_effective_unit_v1 as unit
from repocache.server_native_nginx_effective_unit_v1 import (
    EffectiveNginxUnitError, inspect_effective_native_nginx_unit,
)


def _stat(directory):
    return SimpleNamespace(
        st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | 0o755,
        st_uid=0, st_gid=0, st_nlink=2 if directory else 1,
    )


def _response(**changes):
    values = {
        "Id": "nginx.service",
        "Names": "nginx.service",
        "FragmentPath": "/usr/lib/systemd/system/nginx.service",
        "DropInPaths": "",
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "MainPID": "1450",
        "CanReload": "yes",
        "NeedDaemonReload": "no",
    }
    values.update(changes)
    return "".join(f"{key}={value}\n" for key, value in values.items())


def _fake_native(monkeypatch, *, response=None, vendor=True, unsafe=None,
                 returncode=0, failure=None):
    events = []
    monkeypatch.setattr(
        unit, "inspect_native_nginx_unit",
        lambda dist: SimpleNamespace(
            code=("VENDOR_NGINX_UNIT_OBSERVED" if vendor
                  else "VENDOR_NGINX_UNIT_UNSAFE"),
            digest="a" * 64 if vendor else None,
        ),
    )

    def fake_lstat(path):
        events.append(("lstat", path))
        if path == unsafe:
            return SimpleNamespace(
                st_mode=stat.S_IFLNK | 0o777,
                st_uid=1000, st_gid=1000, st_nlink=1,
            )
        return _stat(path != unit._SYSTEMCTL)

    monkeypatch.setattr(unit, "os", SimpleNamespace(lstat=fake_lstat))

    def run(args, **kwargs):
        events.append(("run", args))
        assert tuple(args) == unit._FIXED_ARGS
        assert kwargs == {
            "shell": False, "check": False, "capture_output": True,
            "text": True, "timeout": 5, "cwd": "/",
            "stdin": subprocess.DEVNULL,
            "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            "start_new_session": True,
        }
        if failure:
            raise subprocess.TimeoutExpired("systemctl", 5)
        return SimpleNamespace(
            returncode=returncode, stdout=(
                _response() if response is None else response
            ), stderr="",
        )

    monkeypatch.setattr(unit, "subprocess", SimpleNamespace(
        DEVNULL=subprocess.DEVNULL,
        TimeoutExpired=subprocess.TimeoutExpired,
        run=run,
    ))
    return events


def test_exact_effective_running_unit_is_observation_only(monkeypatch):
    events = _fake_native(monkeypatch)
    result = inspect_effective_native_nginx_unit("debian")
    assert result["status"] == "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION"
    assert result["main_pid_observed"] == 1450
    assert result["vendor_unit_sha256"] == "a" * 64
    assert result["effective_unit_shape_observed"] is True
    assert all(result[key] is False for key in (
        "distro_package_owner_verified", "real_pid1_and_nginx_process_verified",
        "host_root_and_selinux_verified", "authorizes_systemctl",
        "authorizes_nginx_reload", "authorizes_nginx_install",
    ))
    assert [e for e in events if e[0] == "run"] == [
        ("run", unit._FIXED_ARGS),
    ]


@pytest.mark.parametrize("bad_changes", [
    {"Id": "other.service"},
    {"Names": "nginx.service other.service"},
    {"FragmentPath": "/etc/systemd/system/nginx.service"},
    {"DropInPaths": "/etc/systemd/system/nginx.service.d/override.conf"},
    {"LoadState": "masked"},
    {"ActiveState": "inactive"},
    {"ActiveState": "failed"},
    {"SubState": "dead"},
    {"CanReload": "no"},
    {"NeedDaemonReload": "yes"},
])
def test_effective_unit_shadows_inactive_or_stale_refused(
    monkeypatch, bad_changes,
):
    _fake_native(monkeypatch, response=_response(**bad_changes))
    with pytest.raises(EffectiveNginxUnitError,
                       match="FOREIGN_OR_INACTIVE_UNIT"):
        inspect_effective_native_nginx_unit("almalinux")


@pytest.mark.parametrize("pid", [
    "0", "-1", "1.0", "18446744073709551615", "", "abc", "True",
])
def test_invalid_or_forged_mainpid_refused(monkeypatch,pid):
    _fake_native(monkeypatch, response=_response(MainPID=pid))
    with pytest.raises(EffectiveNginxUnitError,
                       match="INVALID_MAIN_PID"):
        inspect_effective_native_nginx_unit("debian")


@pytest.mark.parametrize("response", [
    "", "garbage", "Id=nginx.service\n", "Id=x\nId=y\n",
    _response() + "ExecStart=/bin/sh -c attacker\n",
    _response() + "Id=nginx.service\n",
    _response().replace("Names=nginx.service\n", ""),
    _response().replace("CanReload=yes\n", "CanReload=yes\r\n"),
    "x" * 8200,
])
def test_malformed_systemctl_output_refused_without_mutation(
    monkeypatch,response,
):
    _fake_native(monkeypatch, response=response)
    with pytest.raises(EffectiveNginxUnitError):
        inspect_effective_native_nginx_unit("debian")


def test_vendor_inventory_must_pass_before_systemctl(monkeypatch):
    events = _fake_native(monkeypatch, vendor=False)
    with pytest.raises(EffectiveNginxUnitError,
                       match="VENDOR_UNIT_UNVERIFIED"):
        inspect_effective_native_nginx_unit("almalinux")
    assert not any(kind == "run" for kind, _ in events)


def test_foreign_systemctl_binary_or_parent_denied(monkeypatch):
    events = _fake_native(monkeypatch, unsafe="/usr/bin/systemctl")
    with pytest.raises(EffectiveNginxUnitError,
                       match="EXECUTABLE_UNSAFE"):
        inspect_effective_native_nginx_unit("debian")
    assert not any(kind == "run" for kind, _ in events)


@pytest.mark.parametrize("dist", ["", "ubuntu", None, True, "almalinux:10"])
def test_wrong_distribution_cannot_dispatch_command(monkeypatch,dist):
    events = _fake_native(monkeypatch)
    with pytest.raises(EffectiveNginxUnitError,
                       match="DISTRIBUTION_INVALID"):
        inspect_effective_native_nginx_unit(dist)
    assert events == []


@pytest.mark.parametrize("failure,returncode", [
    (True, 0), (False, 1), (False, 127),
])
def test_systemctl_timeout_and_nonzero_result_fail_closed(
    monkeypatch,failure,returncode,
):
    events = _fake_native(monkeypatch, failure=failure,returncode=returncode)
    with pytest.raises(EffectiveNginxUnitError,
                       match="SYSTEMCTL_UNAVAILABLE|SYSTEMCTL_FAILED"):
        inspect_effective_native_nginx_unit("debian")
    assert len([x for x in events if x[0] == "run"]) == 1


def test_negative_results_do_not_echo_untrusted_systemctl_text(monkeypatch):
    text = _response(DropInPaths="/etc/ssl/private/UNSAFE_SECRET")
    _fake_native(monkeypatch, response=text)
    with pytest.raises(EffectiveNginxUnitError) as caught:
        inspect_effective_native_nginx_unit("debian")
    assert "UNSAFE_SECRET" not in str(caught.value)
