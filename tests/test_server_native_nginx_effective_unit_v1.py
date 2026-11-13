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


    monkeypatch.setattr(unit, "_observe_systemd_pid1",
                        lambda: events.append(("pid1", "systemd")))
    monkeypatch.setattr(
        unit, "_observe_nginx_master_kernel",
        lambda pid: events.append(("kernel", pid)),
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
    assert result["kernel_nginx_master_executable_inode_observed"] is True
    assert ("kernel", 1450) in events
    assert result["vendor_unit_sha256"] == "a" * 64
    assert result["effective_unit_shape_observed"] is True
    assert result["kernel_systemd_pid1_comm_observed"] is True
    assert ("pid1", "systemd") in events
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
    "0", "1", "-1", "1.0", "18446744073709551615", "", "abc", "True",
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


@pytest.mark.parametrize("field", [
    "wrong_binary_inode", "foreign_binary", "foreign_process",
    "wrong_comm", "changed_pid_inode", "changed_exe_inode",
    "missing_proc", "symlink_binary", "nonexecutable_binary",
    "replaced_binary",
])
def test_kernel_nginx_master_identity_fails_closed(monkeypatch, field):
    """Only read kernel fixed-name observations; no process action."""
    dev, inode = 7, 120
    binary = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0,
                             st_gid=0, st_nlink=1, st_dev=dev, st_ino=inode)
    process = SimpleNamespace(st_mode=stat.S_IFDIR | 0o555, st_uid=0,
                              st_dev=9, st_ino=1450)
    executing = SimpleNamespace(st_dev=dev, st_ino=inode)
    count = {"process": 0, "exe": 0}
    closed = []
    seen_binary = {"calls": 0}
    def lstat(path):
        assert path == "/usr/sbin/nginx"
        seen_binary["calls"] += 1
        if field == "replaced_binary" and seen_binary["calls"] == 2:
            return SimpleNamespace(**{**vars(binary), "st_ino": inode + 2})
        if field == "nonexecutable_binary":
            return SimpleNamespace(**{**vars(binary), "st_mode": stat.S_IFREG | 0o600})
        if field == "foreign_binary":
            return SimpleNamespace(**{**vars(binary), "st_uid": 2000})
        if field == "symlink_binary":
            return SimpleNamespace(**{**vars(binary), "st_mode": stat.S_IFLNK | 0o777})
        return binary
    def observe(path):
        if field == "missing_proc":
            raise FileNotFoundError("missing")
        if path == "/proc/1450":
            count["process"] += 1
            if field == "foreign_process":
                return SimpleNamespace(**{**vars(process), "st_uid": 2000})
            if field == "changed_pid_inode" and count["process"] == 2:
                return SimpleNamespace(**{**vars(process), "st_ino": 1451})
            return process
        if path == "/proc/1450/exe":
            count["exe"] += 1
            if field == "wrong_binary_inode" or (
                field == "changed_exe_inode" and count["exe"] == 2
            ):
                return SimpleNamespace(st_dev=dev, st_ino=inode + 1)
            return executing
        raise AssertionError(path)
    fake_os = SimpleNamespace(
        lstat=lstat, stat=observe, O_RDONLY=0, O_NOFOLLOW=0, O_CLOEXEC=0,
        open=lambda path, flags: 33,
        fstat=lambda fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0),
        read=lambda fd, size: b"worker\n" if field == "wrong_comm" else b"nginx\n",
        close=lambda fd: closed.append(fd),
    )
    monkeypatch.setattr(unit, "os", fake_os)
    with pytest.raises(EffectiveNginxUnitError,
                       match="NGINX_MASTER_IDENTITY_"):
        unit._observe_nginx_master_kernel(1450)
    if field in ("wrong_comm", "changed_pid_inode", "changed_exe_inode"):
        assert closed == [33]


def test_kernel_nginx_master_positive_is_only_inert_inode_observation(monkeypatch):
    observed = []
    binary = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0,
                             st_gid=0, st_nlink=1, st_dev=7, st_ino=120)
    process = SimpleNamespace(st_mode=stat.S_IFDIR | 0o555,
                              st_uid=0, st_dev=9, st_ino=1450)
    monkeypatch.setattr(unit, "os", SimpleNamespace(
        lstat=lambda path: binary,
        stat=lambda path: observed.append(path) or (
            process if path == "/proc/1450" else binary),
        O_RDONLY=0, O_NOFOLLOW=0, O_CLOEXEC=0,
        open=lambda path, flags: 33,
        fstat=lambda fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0),
        read=lambda fd, size: b"nginx\n",
        close=lambda fd: None,
    ))
    assert unit._observe_nginx_master_kernel(1450) is None
    assert observed == [
        "/proc/1450", "/proc/1450/exe",
        "/proc/1450", "/proc/1450/exe",
    ]


def test_kernel_master_invalid_pid_refused_before_proc_access(monkeypatch):
    monkeypatch.setattr(unit, "os", SimpleNamespace(
        lstat=lambda *_: pytest.fail("must refuse PID 1"),
    ))
    with pytest.raises(EffectiveNginxUnitError, match="INVALID_MAIN_PID"):
        unit._observe_nginx_master_kernel(1)

@pytest.mark.parametrize("case", [
    "positive", "not_systemd", "foreign_pid1", "writable_pid1",
    "missing_pid1", "missing_comm", "foreign_comm", "changed_pid1",
])
def test_kernel_pid1_precondition_is_readonly_and_fail_closed(monkeypatch, case):
    events = []
    proc = SimpleNamespace(
        st_mode=stat.S_IFDIR | (0o777 if case == "writable_pid1" else 0o555),
        st_uid=2000 if case == "foreign_pid1" else 0,
        st_dev=7, st_ino=31,
    )
    comm = SimpleNamespace(st_mode=stat.S_IFREG | 0o444,
                           st_uid=2000 if case == "foreign_comm" else 0)
    def lstat(path):
        events.append(("lstat", path))
        assert path == "/proc/1"
        if case == "missing_pid1":
            raise FileNotFoundError("not present")
        if case == "changed_pid1" and events.count(("lstat", path)) == 2:
            return SimpleNamespace(**{**vars(proc), "st_ino": 32})
        return proc
    def open_comm(path, flags):
        events.append(("open", path, flags))
        assert path == "/proc/1/comm"
        if case == "missing_comm":
            raise FileNotFoundError("not present")
        return 41
    fake_os = SimpleNamespace(
        lstat=lstat, open=open_comm, fstat=lambda fd: comm,
        read=lambda fd, count: b"nginx\n" if case == "not_systemd"
        else b"systemd\n",
        close=lambda fd: events.append(("close", fd)),
        O_RDONLY=0, O_NOFOLLOW=0x20000, O_NONBLOCK=0x800,
        O_CLOEXEC=0x80000,
    )
    monkeypatch.setattr(unit, "os", fake_os)
    if case == "positive":
        unit._observe_systemd_pid1()
        assert events.count(("lstat", "/proc/1")) == 2
        assert ("close", 41) in events
        assert [e for e in events if e[0] == "open"] == [
            ("open", "/proc/1/comm", 0x20000 | 0x800 | 0x80000),
        ]
    else:
        with pytest.raises(EffectiveNginxUnitError,
                           match="PID1_IDENTITY_REFUSED|PID1_UNAVAILABLE"):
            unit._observe_systemd_pid1()
        assert all(e[0] in ("lstat", "open", "close") for e in events)
        if case not in ("foreign_pid1", "writable_pid1", "missing_pid1",
                        "missing_comm"):
            assert ("close", 41) in events


def test_non_systemd_pid1_never_invokes_systemctl(monkeypatch):
    events = _fake_native(monkeypatch)
    def refuse_pid1():
        events.append(("pid1", "refused"))
        raise EffectiveNginxUnitError("NATIVE_NGINX_EFFECTIVE_PID1_IDENTITY_REFUSED")
    monkeypatch.setattr(unit, "_observe_systemd_pid1", refuse_pid1)
    with pytest.raises(EffectiveNginxUnitError, match="PID1_IDENTITY_REFUSED"):
        inspect_effective_native_nginx_unit("debian")
    assert not any(item[0] == "run" for item in events)
