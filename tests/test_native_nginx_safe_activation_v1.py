"""Contract tests for the REPOCACHE-owned native NGINX service (#27).

Host operations are mocked here: native booted Debian/AlmaLinux and SELinux
require separately executed QEMU evidence.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts import install_native_root_worker as host
from scripts import stage_native_root_worker as stage


def _setup(monkeypatch):
    state = {
        "active": False, "enabled": False, "vendor_queries": 0,
        "commands": [], "package_audits": 0, "config_checks": 0, "runtime_preps": 0,
    }
    def audit(*args, **kwargs):
        state["package_audits"] += 1
    monkeypatch.setattr(host, "_require_audited_native_package_for_activation", audit)
    monkeypatch.setattr(host, "_no_conflicting_pending", lambda _fd: None)
    monkeypatch.setattr(host, "_read_v2", lambda _fd, _owner: (None, None))
    monkeypatch.setattr(host, "_nginx_inactive_vendor_service",
                        lambda _d: None)
    def vendor_status(command):
        state["vendor_queries"] += 1
        return (1, b"disabled\n") if command == "is-enabled" else (
            3, b"inactive\n"
        )
    monkeypatch.setattr(host, "_nginx_systemctl", vendor_status)
    monkeypatch.setattr(host, "_place_signed_private_config",
                        lambda _bytes: state.__setitem__(
                            "config_checks", state["config_checks"] + 1))
    monkeypatch.setattr(host, "_require_private_nginx_listeners",
                        lambda: state.__setitem__(
                            "config_checks", state["config_checks"] + 1))
    monkeypatch.setattr(host, "_private_config_present",
                        lambda: state.__setitem__(
                            "config_checks", state["config_checks"] + 1))
    monkeypatch.setattr(host, "_prepare_own_runtime_directory",
                        lambda: state.__setitem__(
                            "runtime_preps", state["runtime_preps"] + 1))
    def own_status(command):
        return ((0, b"enabled\n") if state["enabled"] else
                (1, b"disabled\n")) if command == "is-enabled" else (
                (0, b"active\n") if state["active"] else (3, b"inactive\n"))
    monkeypatch.setattr(host, "_own_systemctl", own_status)
    def effective(*, active):
        assert active == state["active"]
        return {"status": "NATIVE_REPOCACHE_NGINX_SERVICE_VERIFIED",
                "unit_name": "repocache-nginx.service",
                "main_pid_observed": 1234 if active else 0}
    monkeypatch.setattr(host, "_own_service_observation", effective)
    def command(action):
        state["commands"].append(action)
        if action == "start":
            state["active"] = True
        if action == "enable":
            state["enabled"] = True
        if action == "stop":
            state["active"] = False
        if action == "disable":
            state["enabled"] = False
    monkeypatch.setattr(host, "_nginx_activation_command", command)
    return state


def test_explicit_signed_own_service_is_idempotent(monkeypatch):
    state = _setup(monkeypatch)
    first = host._activate_audited_native_nginx_under_lock(
        11, "debian", host._BOOTSTRAP_CONFIG)
    assert first["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ACTIVE"
    assert state["commands"] == ["daemon-reload", "start", "enable"]
    assert state["config_checks"] == 4
    assert state["runtime_preps"] == 1
    again = host._activate_audited_native_nginx_under_lock(
        11, "debian", host._BOOTSTRAP_CONFIG)
    assert again["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ALREADY_ACTIVE"
    assert state["commands"] == ["daemon-reload", "start", "enable"]
    assert state["package_audits"] == 3


def test_explicit_activation_refuses_vendor_active(monkeypatch):
    state = _setup(monkeypatch)
    monkeypatch.setattr(host, "_nginx_systemctl", lambda action: (
        (0, b"active\n") if action == "is-active" else
        (1, b"disabled\n")))
    with pytest.raises(stage.WorkerStageError, match="NATIVE_ACTIVATION_VENDOR_SERVICE_STATE"):
        host._activate_audited_native_nginx_under_lock(
            11, "debian", host._BOOTSTRAP_CONFIG)
    assert state["commands"] == []


def test_stale_managed_generation_refuses_before_install(monkeypatch):
    state = _setup(monkeypatch)
    monkeypatch.setattr(host, "_read_v2",
                        lambda *_: ({"state_generation": 1}, b"owned"))
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_MANAGED_STATE_REFUSED"):
        host._activate_audited_native_nginx_under_lock(
            11, "almalinux", host._BOOTSTRAP_CONFIG)
    assert state["commands"] == []


def test_foreign_state_of_own_service_refuses(monkeypatch):
    state = _setup(monkeypatch)
    state["enabled"] = True
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_FOREIGN_SERVICE_STATE"):
        host._activate_audited_native_nginx_under_lock(
            11, "debian", host._BOOTSTRAP_CONFIG)
    assert state["commands"] == []


def test_unexpected_signed_config_bytes_refused_without_writes(monkeypatch):
    def forbidden(*_a, **_kw):
        pytest.fail("host touched for unexpected configuration")
    monkeypatch.setattr(host.os, "open", forbidden)
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_SIGNED_CONFIG_UNEXPECTED"):
        host._place_signed_private_config(b"http { listen 80; }")


def test_failed_enable_stops_only_own_service(monkeypatch):
    state = _setup(monkeypatch)
    def fault(action):
        state["commands"].append(action)
        if action == "start":
            state["active"] = True
        if action == "enable":
            raise stage.WorkerStageError("WORKER_PLACEMENT_INJECTED_FAILURE")
        if action == "stop":
            state["active"] = False
        if action == "disable":
            state["enabled"] = False
    monkeypatch.setattr(host, "_nginx_activation_command", fault)
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_FAILED_ROLLED_BACK"):
        host._activate_audited_native_nginx_under_lock(
            11, "almalinux", host._BOOTSTRAP_CONFIG)
    assert state["commands"] == ["daemon-reload", "start", "enable", "stop", "disable"]
    assert not state["active"] and not state["enabled"]


def test_failed_start_after_spawning_is_stopped(monkeypatch):
    state = _setup(monkeypatch)
    def fault(action):
        state["commands"].append(action)
        if action == "start":
            state["active"] = True
            raise stage.WorkerStageError("WORKER_PLACEMENT_START_TIMEOUT")
        if action == "stop":
            state["active"] = False
        if action == "disable":
            state["enabled"] = False
    monkeypatch.setattr(host, "_nginx_activation_command", fault)
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_FAILED_ROLLED_BACK"):
        host._activate_audited_native_nginx_under_lock(
            11, "debian", host._BOOTSTRAP_CONFIG)
    assert state["commands"] == ["daemon-reload", "start", "stop", "disable"]


def test_unknown_master_on_failed_start_is_never_killed(monkeypatch):
    state = _setup(monkeypatch)
    def fault(action):
        state["commands"].append(action)
        if action == "start":
            state["active"] = True
            raise stage.WorkerStageError("WORKER_PLACEMENT_START_UNCERTAIN")
    monkeypatch.setattr(host, "_nginx_activation_command", fault)
    # The first observer checks the initially inactive unit. Make only the
    # post-start active observation foreign; otherwise the test would fail
    # before the fault-injected start and never cover recovery safety.
    inactive_observation = host._own_service_observation
    observed_states = []

    def foreign_only_after_start(*, active):
        observed_states.append(active)
        if active:
            raise stage.WorkerStageError("WORKER_PLACEMENT_FOREIGN_RUNTIME")
        return inactive_observation(active=active)

    monkeypatch.setattr(host, "_own_service_observation", foreign_only_after_start)
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_RECOVERY_REQUIRED"):
        host._activate_audited_native_nginx_under_lock(
            11, "debian", host._BOOTSTRAP_CONFIG)
    assert state["commands"] == ["daemon-reload", "start"]
    assert observed_states == [False, True, True]


def test_pid_cleanup_refuses_symlink_without_unlink(tmp_path):
    import os
    (tmp_path / "nginx.pid").symlink_to("/etc/passwd")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(stage.WorkerStageError,
                           match="NATIVE_RUNTIME_PID_FOREIGN"):
            host._unlink_inert_nginx_syntax_pid(fd)
        assert (tmp_path / "nginx.pid").is_symlink()
    finally:
        os.close(fd)


def test_pid_cleanup_refuses_nonempty_foreign_file(tmp_path):
    import os
    (tmp_path / "nginx.pid").write_text("1234")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(stage.WorkerStageError,
                           match="NATIVE_RUNTIME_PID_FOREIGN"):
            host._unlink_inert_nginx_syntax_pid(fd)
        assert (tmp_path / "nginx.pid").read_text() == "1234"
    finally:
        os.close(fd)


def test_fixed_service_command_never_touches_vendor(monkeypatch):
    monkeypatch.setattr(host, "_safe_native_systemctl", lambda: None)
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(host.subprocess, "run", run)
    for action in ("daemon-reload", "start", "enable", "stop", "disable"):
        host._nginx_activation_command(action)
    assert calls[0][0][-1] == "daemon-reload"
    for argv, kwargs in calls[1:]:
        assert argv[-1] == "repocache-nginx.service"
        assert "nginx.service" not in argv
        assert kwargs["timeout"] == 30 and kwargs["stdin"] == host.subprocess.DEVNULL


@pytest.mark.parametrize("value", ["", "not found", "/etc/systemd/system/nginx.service", "foreign"])
def test_own_service_observation_refuses_foreign_unit(monkeypatch, value):
    from repocache import server_native_nginx_effective_unit_v1 as effective
    monkeypatch.setattr(host, "_observe_systemd_pid1", lambda: None)
    monkeypatch.setattr(host, "_safe_native_systemctl", lambda: None)
    monkeypatch.setattr(effective, "_observe_nginx_master_kernel", lambda _pid: None)
    keys = {
        "Id": "repocache-nginx.service", "Names": "repocache-nginx.service",
        "FragmentPath": value, "DropInPaths": "", "LoadState": "loaded",
        "ActiveState": "active", "SubState": "running", "MainPID": "1234",
        "CanReload": "yes", "NeedDaemonReload": "no",
    }
    monkeypatch.setattr(host.subprocess, "run",
                        lambda *_a, **_kw: SimpleNamespace(
                            returncode=0, stdout="".join(
                                f"{k}={v}\n" for k, v in keys.items()), stderr=""))
    with pytest.raises(stage.WorkerStageError, match="NATIVE_OWN_UNIT_UNVERIFIED"):
        host._own_service_observation(active=True)


def test_own_service_observation_accepts_exact_unit(monkeypatch):
    from repocache import server_native_nginx_effective_unit_v1 as effective
    seen = []
    monkeypatch.setattr(host, "_observe_systemd_pid1", lambda: None)
    monkeypatch.setattr(host, "_safe_native_systemctl", lambda: None)
    monkeypatch.setattr(effective, "_observe_nginx_master_kernel",
                        lambda pid: seen.append(pid))
    keys = {
        "Id": "repocache-nginx.service", "Names": "repocache-nginx.service",
        "FragmentPath": "/etc/systemd/system/repocache-nginx.service",
        "DropInPaths": "", "LoadState": "loaded",
        "ActiveState": "active", "SubState": "running", "MainPID": "1234",
        "CanReload": "yes", "NeedDaemonReload": "no",
    }
    monkeypatch.setattr(host.subprocess, "run",
                        lambda argv, **_kw: (
                            SimpleNamespace(returncode=0,
                                stdout="".join(f"{k}={v}\n" for k, v in keys.items()),
                                stderr="")))
    assert host._own_service_observation(active=True)[
        "unit_name"] == "repocache-nginx.service"
    assert seen == [1234, 1234]


def test_no_signed_worker_refuses_before_root(monkeypatch, tmp_path):
    monkeypatch.setattr(host, "_native_distro", lambda: "debian")
    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(stage, "verify_installed_worker", lambda *_a, **_kw: {
        "status": "AUTHENTICATED_WORKER_FILES_MATCH",
        "source_sha": "a" * 40, "archive_sha256": "b" * 64,
        "authorizes_host_installation": False,
        "authorizes_service_activation": True,
    })
    monkeypatch.setattr(host.os, "open", lambda *_a, **_kw: pytest.fail(
        "root opened before signed-worker identity verification"))
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_SIGNED_WORKER_AUDIT_UNVERIFIED"):
        host.activate_authenticated_native_nginx(
            tmp_path, commit="a" * 40, archive_sha256="b" * 64)
