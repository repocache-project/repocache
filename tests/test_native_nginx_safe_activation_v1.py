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
        "storage_preps": [], "storage_mounts": [],
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
                        lambda _bytes, _fd: state.__setitem__(
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
    def storage(distribution, *, allow_create):
        state["storage_preps"].append((distribution, allow_create))
        return {"cache_root_verified": True, "log_root_verified": True,
                "actual_service_write_verified": False}
    monkeypatch.setattr(host, "prepare_installed_storage", storage)
    monkeypatch.setattr(host, "verify_service_storage_mounts",
                        lambda pid: state["storage_mounts"].append(pid))
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
    assert state["storage_preps"] == [("debian", True), ("debian", False), ("debian", False)]
    assert state["storage_mounts"] == [1234, 1234, 1234]
    assert first["service_storage_mounts_verified"] is True
    assert again["storage"]["actual_service_write_verified"] is False


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
        host._place_signed_private_config(b"http { listen 80; }", 11)


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
    assert observed_states == [False, True]


def test_owned_config_intent_refuses_even_exact_foreign_bytes(tmp_path):
    import os

    state = tmp_path / "state"
    nginx = tmp_path / "nginx"
    state.mkdir()
    nginx.mkdir()
    (nginx / stage.CONFIG).write_bytes(host._BOOTSTRAP_CONFIG)
    state_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    nginx_fd = os.open(nginx, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(stage.WorkerStageError,
                           match="NATIVE_PRIVATE_CONFIG_FOREIGN_COLLISION"):
            host._require_owned_private_config_intent(state_fd, nginx_fd)
        assert list(state.iterdir()) == []
        assert (nginx / stage.CONFIG).read_bytes() == host._BOOTSTRAP_CONFIG
    finally:
        os.close(nginx_fd)
        os.close(state_fd)


def test_owned_config_intent_rejects_another_owner_marker(tmp_path):
    import os

    state = tmp_path / "state"
    nginx = tmp_path / "nginx"
    state.mkdir()
    nginx.mkdir()
    (state / (host._CONFIG_MARKER_PREFIX + "unrecognized")).write_bytes(b"")
    state_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    nginx_fd = os.open(nginx, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(stage.WorkerStageError,
                           match="NATIVE_PRIVATE_CONFIG_MARKER_CONFLICT"):
            host._require_owned_private_config_intent(state_fd, nginx_fd)
        assert not (nginx / stage.CONFIG).exists()
    finally:
        os.close(nginx_fd)
        os.close(state_fd)


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
    monkeypatch.setattr(effective, "_observe_systemd_pid1", lambda: None)
    monkeypatch.setattr(effective, "_safe_native_systemctl", lambda: None)
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
    monkeypatch.setattr(effective, "_observe_systemd_pid1", lambda: None)
    monkeypatch.setattr(effective, "_safe_native_systemctl", lambda: None)
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
    report = effective.inspect_effective_owned_nginx_unit(active=True)
    assert report["main_pid_observed"] == 1234
    assert report["authorizes_systemctl"] is False
    assert report["authorizes_nginx_reload"] is False
    assert report["authorizes_nginx_install"] is False


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


@pytest.mark.parametrize("change", [
    {"Names": "repocache-nginx.service nginx.service"},
    {"DropInPaths": "/etc/systemd/system/repocache-nginx.service.d/override.conf"},
    {"NeedDaemonReload": "yes"},
    {"MainPID": "99999999999999999999"},
    {"MainPID": "5678"},
])
def test_shared_owned_observer_refuses_changed_or_foreign_runtime(monkeypatch, change):
    from repocache import server_native_nginx_effective_unit_v1 as effective
    monkeypatch.setattr(effective, "_observe_systemd_pid1", lambda: None)
    monkeypatch.setattr(effective, "_safe_native_systemctl", lambda: None)
    monkeypatch.setattr(effective, "_observe_nginx_master_kernel", lambda _pid: None)
    original = {
        "Id": "repocache-nginx.service", "Names": "repocache-nginx.service",
        "FragmentPath": "/etc/systemd/system/repocache-nginx.service",
        "DropInPaths": "", "LoadState": "loaded", "ActiveState": "active",
        "SubState": "running", "MainPID": "1234", "CanReload": "yes",
        "NeedDaemonReload": "no",
    }
    observations = iter((original, dict(original, **change)))

    def run(argv, **_kwargs):
        assert argv[-1] == "repocache-nginx.service"
        return SimpleNamespace(returncode=0, stderr="", stdout="".join(
            f"{k}={v}\n" for k, v in next(observations).items()
        ))

    monkeypatch.setattr(effective.subprocess, "run", run)
    with pytest.raises(effective.EffectiveNginxUnitError, match="OWN_UNIT_"):
        effective.inspect_effective_owned_nginx_unit(active=True)

def test_storage_refusal_blocks_service_start(monkeypatch):
    state = _setup(monkeypatch)
    from repocache.server_native_installed_storage_v1 import InstalledStorageError
    def refuse(*args, **kwargs):
        raise InstalledStorageError("INSTALLED_NGINX_STORAGE_PARTIAL_OR_FOREIGN_ROOT")
    monkeypatch.setattr(host, "prepare_installed_storage", refuse)
    with pytest.raises(InstalledStorageError, match="PARTIAL_OR_FOREIGN_ROOT"):
        host._activate_audited_native_nginx_under_lock(11, "debian", host._BOOTSTRAP_CONFIG)
    assert state["commands"] == []


def test_mount_refusal_compensates_owned_start(monkeypatch):
    state = _setup(monkeypatch)
    from repocache.server_native_installed_storage_v1 import InstalledStorageError
    def refuse(_pid):
        raise InstalledStorageError("INSTALLED_NGINX_STORAGE_SERVICE_PARENT_WRITABLE")
    monkeypatch.setattr(host, "verify_service_storage_mounts", refuse)
    with pytest.raises(stage.WorkerStageError, match="NATIVE_ACTIVATION_FAILED_ROLLED_BACK"):
        host._activate_audited_native_nginx_under_lock(11, "debian", host._BOOTSTRAP_CONFIG)
    assert state["commands"] == ["daemon-reload", "start", "stop", "disable"]
    assert not state["active"] and not state["enabled"]


def test_managed_installer_refuses_inactive_without_effects(monkeypatch):
    state = _setup(monkeypatch)
    monkeypatch.setattr(host, "_read_v2", lambda *_: ({"state_generation": 1}, b"owned"))
    with pytest.raises(stage.WorkerStageError, match="NATIVE_ACTIVATION_MANAGED_STATE_REFUSED"):
        host._activate_audited_native_nginx_under_lock(
            11, "debian", host._BOOTSTRAP_CONFIG, root_fd=10, unit_bytes=b"signed")
    assert state["commands"] == [] and state["config_checks"] == 0
    assert state["storage_preps"] == []


def test_managed_installer_reuses_verified_generation_without_bootstrap(monkeypatch):
    from contextlib import contextmanager

    state = _setup(monkeypatch)
    state["enabled"] = state["active"] = True
    monkeypatch.setattr(host, "_read_v2", lambda *_: ({"state_generation": 1}, b"owned"))
    @contextmanager
    def layout(root, fd, *, recovering):
        assert (root, fd, recovering) == (10, 11, False)
        yield (11, 12, 13, lambda: None)
    monkeypatch.setattr(host, "_owned_layout_locked", layout)
    resources = {"catalog.json": b"catalog"}
    monkeypatch.setattr(host, "_read_owned_resources", lambda *_: resources)
    monkeypatch.setattr(host, "_validate_owned_resources", lambda *_a, **_kw: {"state_generation": 1})
    monkeypatch.setattr(host, "_owned_socket_require_inactive_routes", lambda _: None)
    monkeypatch.setattr(host, "_no_conflicting_owned_wal_pending", lambda _: None)
    def observe(root, *, expected_unit):
        assert (root, expected_unit) == (10, b"signed")
        return (1234, (1, 2))
    monkeypatch.setattr(host, "_owned_live_observe", observe)
    monkeypatch.setattr(host, "_owned_live_validate", lambda *_: (None, 1, None))
    def health(*args, **kwargs):
        assert kwargs == {"publish": True, "expected_unit": b"signed"}
        assert args[-1] == b"catalog"
    monkeypatch.setattr(host, "_owned_live_health_bound", health)
    report = host._activate_audited_native_nginx_under_lock(
        11, "debian", host._BOOTSTRAP_CONFIG, root_fd=10, unit_bytes=b"signed")
    assert report["state_generation"] == 1
    assert report["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ALREADY_ACTIVE"
    assert state["commands"] == [] and state["config_checks"] == 0
    assert state["storage_preps"] == [("debian", False), ("debian", False)]
    assert state["storage_mounts"] == [1234, 1234]

def _inactive_managed(monkeypatch):
    from contextlib import contextmanager

    state = _setup(monkeypatch)
    state["enabled"] = True
    monkeypatch.setattr(host, "_read_v2", lambda *_: ({"state_generation": 1}, b"owned"))
    @contextmanager
    def layout(root, fd, *, recovering):
        assert (root, fd, recovering) == (10, 11, False)
        yield (11, 12, 13, lambda: None)
    monkeypatch.setattr(host, "_owned_layout_locked", layout)
    monkeypatch.setattr(host, "_read_owned_resources", lambda *_: {"catalog.json": b"catalog"})
    monkeypatch.setattr(host, "_validate_owned_resources", lambda *_a, **_kw: {"state_generation": 1})
    monkeypatch.setattr(host, "_owned_socket_require_inactive_routes", lambda _: None)
    monkeypatch.setattr(host, "_no_conflicting_owned_wal_pending", lambda _: None)
    monkeypatch.setattr(host, "_read_exact_owned_unit_at",
                        lambda *a, **kw: (1, 2))
    def observe(root, *, expected_unit):
        assert state["active"] and (root, expected_unit) == (10, b"signed")
        return (1234, (1, 2))
    monkeypatch.setattr(host, "_owned_live_observe", observe)
    monkeypatch.setattr(host, "_owned_live_validate", lambda *_: (None, 1, None))
    monkeypatch.setattr(host, "_owned_live_health_bound", lambda *a, **kw: None)
    monkeypatch.setattr(host, "_cleanup_own_nginx_syntax_pid", lambda: None)
    return state


def test_enabled_inactive_managed_restart_preserves_generation_and_enablement(monkeypatch):
    state = _inactive_managed(monkeypatch)
    result = host._activate_audited_native_nginx_under_lock(
        11, "debian", host._BOOTSTRAP_CONFIG, root_fd=10, unit_bytes=b"signed")
    assert result["status"] == "AUTHENTICATED_REPOCACHE_NGINX_ACTIVE"
    assert result["state_generation"] == 1
    assert state["commands"] == ["start"]
    assert state["active"] and state["enabled"] and state["config_checks"] == 0
    assert state["runtime_preps"] == 1
    assert all(not create for _, create in state["storage_preps"])


def test_enabled_inactive_managed_restart_compensates_post_start_failure(monkeypatch):
    state = _inactive_managed(monkeypatch)
    from repocache.server_native_installed_storage_v1 import InstalledStorageError
    def refuse(_pid):
        raise InstalledStorageError("INSTALLED_NGINX_STORAGE_SERVICE_PARENT_WRITABLE")
    monkeypatch.setattr(host, "verify_service_storage_mounts", refuse)
    with pytest.raises(stage.WorkerStageError, match="NATIVE_ACTIVATION_FAILED_ROLLED_BACK"):
        host._activate_audited_native_nginx_under_lock(
            11, "debian", host._BOOTSTRAP_CONFIG, root_fd=10, unit_bytes=b"signed")
    assert state["commands"] == ["start", "stop"]
    assert not state["active"] and state["enabled"] and state["config_checks"] == 0


def test_enabled_inactive_managed_restart_never_stops_unverified_master(monkeypatch):
    state = _inactive_managed(monkeypatch)
    def refuse(*a, **kw):
        raise host.NativeV2TransactionError("NATIVE_V2_OWNED_LIVE_UNIT_UNVERIFIED")
    monkeypatch.setattr(host, "_owned_live_observe", refuse)
    with pytest.raises(stage.WorkerStageError, match="NATIVE_ACTIVATION_RECOVERY_REQUIRED"):
        host._activate_audited_native_nginx_under_lock(
            11, "debian", host._BOOTSTRAP_CONFIG, root_fd=10, unit_bytes=b"signed")
    assert state["commands"] == ["start"]
    assert state["enabled"]


def test_enabled_inactive_managed_pending_refused_before_start(monkeypatch):
    state = _inactive_managed(monkeypatch)
    def pending(_fd):
        raise host.NativeV2TransactionError("NATIVE_V2_OWNED_WAL_DOMAIN_REQUIRED")
    monkeypatch.setattr(host, "_no_conflicting_owned_wal_pending", pending)
    with pytest.raises(stage.WorkerStageError, match="NATIVE_ACTIVATION_MANAGED_STATE_REFUSED"):
        host._activate_audited_native_nginx_under_lock(
            11, "debian", host._BOOTSTRAP_CONFIG, root_fd=10, unit_bytes=b"signed")
    assert state["commands"] == [] and state["runtime_preps"] == 0

def test_enabled_inactive_managed_restart_never_stops_replaced_master(monkeypatch):
    state = _inactive_managed(monkeypatch)
    from repocache.server_native_installed_storage_v1 import InstalledStorageError
    observed = iter(((1234, (1, 2)), (1235, (1, 2))))
    monkeypatch.setattr(host, "_owned_live_observe", lambda *a, **kw: next(observed))
    def refuse(_pid):
        raise InstalledStorageError("INSTALLED_NGINX_STORAGE_SERVICE_PARENT_WRITABLE")
    monkeypatch.setattr(host, "verify_service_storage_mounts", refuse)
    with pytest.raises(stage.WorkerStageError, match="NATIVE_ACTIVATION_RECOVERY_REQUIRED"):
        host._activate_audited_native_nginx_under_lock(
            11, "debian", host._BOOTSTRAP_CONFIG, root_fd=10, unit_bytes=b"signed")
    assert state["commands"] == ["start"]
    assert state["enabled"]
