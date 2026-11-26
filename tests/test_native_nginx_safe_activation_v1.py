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
                        lambda **_kwargs: state.__setitem__(
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


def test_fixture_selinux_connect_denied_matches_only_current_enforcing_worker():
    from scripts.ci_native_nginx_activate_guest import fixture_selinux_connect_denied

    record = ('type=AVC msg=audit(1.0:1): avc:  denied  { name_connect } '
              'for pid=123 comm="nginx" dest=8008 '
              'scontext=system_u:system_r:httpd_t:s0 '
              'tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket '
              'permissive=0')
    assert fixture_selinux_connect_denied(record, {123})
    assert fixture_selinux_connect_denied(
        "audit: " + record.replace("type=AVC", "type=1400"), {123})
    assert not fixture_selinux_connect_denied(record.replace("type=AVC", "type=1300"), {123})
    assert not fixture_selinux_connect_denied(record, {124})
    assert not fixture_selinux_connect_denied(record, set())
    for old, new in (
        ("type=AVC", "type=SYSCALL"),
        ("name_connect", "name_bind"),
        ('comm="nginx"', 'comm="python"'),
        ("dest=8008", "dest=8009"),
        (":httpd_t:", ":unconfined_t:"),
        ("tclass=tcp_socket", "tclass=udp_socket"),
        ("permissive=0", "permissive=1"),
    ):
        assert not fixture_selinux_connect_denied(record.replace(old, new), {123})
    assert not fixture_selinux_connect_denied("x" * (1024 * 1024 + 1) + record, {123})
    assert not fixture_selinux_connect_denied(record.replace(" dest=8008", "\n dest=8008"), {123})


def test_fixture_policy_port_context_matches_kernel_first_tcp_interval():
    from types import SimpleNamespace
    from scripts.ci_native_nginx_activate_guest import fixture_port_context

    def rule(protocol, low, high, context):
        return SimpleNamespace(protocol=protocol,
                               ports=SimpleNamespace(low=low, high=high),
                               context=context)
    label = "system_u:object_r:http_port_t:s0"
    foreign = "system_u:object_r:unreserved_port_t:s0"
    rules = [rule("tcp", 443, 443, label), rule("tcp", 8008, 8009, label),
             rule("udp", 8008, 8008, foreign)]
    assert fixture_port_context(rules, 443) == label
    assert fixture_port_context(rules, 8008) == label
    assert fixture_port_context(rules, 8009) is None
    assert fixture_port_context([rule("tcp", 8009, 8010, label)], 8008) is None
    # The actual kernel lookup follows policy order even when intervals overlap.
    assert fixture_port_context(rules + [rule("tcp", 1024, 65535, foreign)], 8008) == label
    assert fixture_port_context([rule("tcp", 1024, 65535, foreign)] + rules, 8008) == foreign
    assert fixture_port_context([rule("tcp", 1, 511, foreign)] + rules, 443) == foreign
    assert fixture_port_context([rule("tcp", 8008, 8008, "unsafe label")] + rules, 8008) is None
    assert fixture_port_context([rule("tcp", 8008, 8008, "unsafe label")], 8008) is None


def test_fixture_upstream_eacces_matches_current_worker_and_exact_endpoint():
    from scripts.ci_native_nginx_activate_guest import fixture_upstream_connect_eacces

    record = ("2026/11/25 18:00:00 [crit] 123#123: *7 "
              "connect() to 127.0.0.1:8008 failed (13: Permission denied) "
              "while connecting to upstream, client: fixture")
    assert fixture_upstream_connect_eacces(record, {123})
    assert not fixture_upstream_connect_eacces(record, {124})
    assert not fixture_upstream_connect_eacces(record, set())
    for old, new in (
        ("127.0.0.1:8008", "127.0.0.1:443"),
        ("127.0.0.1:8008", "127.0.0.1:80080"),
        ("13: Permission denied", "111: Connection refused"),
        ("connect()", "open()"),
        ("while connecting to upstream", "while reading upstream"),
    ):
        assert not fixture_upstream_connect_eacces(record.replace(old, new), {123})
    assert not fixture_upstream_connect_eacces("x" * (1024 * 1024 + 1) + record, {123})


def test_fixture_control_worker_waits_for_clean_exit(monkeypatch):
    from scripts import ci_native_nginx_activate_guest as guest

    def state(active, sub, pid):
        return SimpleNamespace(returncode=0, stdout=(
            f"LoadState=loaded\nActiveState={active}\nSubState={sub}\n"
            f"Result=success\nMainPID={pid}\nControlPID=0\nExecMainStatus=0\n"))
    observations = iter([state("activating", "start", 123),
                         state("inactive", "dead", 0)])
    calls = []
    def run(*args):
        calls.append(args)
        return next(observations)
    monkeypatch.setattr(guest, "run", run)
    monkeypatch.setattr(guest.time, "sleep", lambda _: None)
    guest.require_control_worker_idle()
    assert len(calls) == 2
    assert all(call[:3] == ("/usr/bin/systemctl", "show",
                            "repocache-control.service") for call in calls)


@pytest.mark.parametrize("change", [
    "ActiveState=failed", "Result=exit-code", "ExecMainStatus=1",
    "MainPID=123", "ControlPID=123", "SubState=exited",
    "ActiveState=active", "ActiveState=activating", "LoadState=not-found",
    "missing", "duplicate", "command-failed",
])
def test_fixture_control_worker_refuses_unclean_or_unavailable_state(monkeypatch, change):
    from scripts import ci_native_nginx_activate_guest as guest

    fields = dict(LoadState="loaded", ActiveState="inactive", SubState="dead",
                  Result="success", MainPID="0", ControlPID="0", ExecMainStatus="0")
    if "=" in change:
        key, value = change.split("=")
        fields[key] = value
    elif change == "missing":
        del fields["Result"]
    raw = "\n".join(f"{key}={value}" for key, value in fields.items())
    if change == "duplicate":
        raw += "\nResult=success"
    monkeypatch.setattr(guest, "run", lambda *args: SimpleNamespace(
        returncode=1 if change == "command-failed" else 0, stdout=raw))
    with pytest.raises(AssertionError):
        guest.require_control_worker_idle(timeout=0)


def test_isolated_selinux_egress_rules_have_exact_default_and_separate_negative_probe():
    from scripts import ci_selinux_nginx_egress_guest as guest
    normal = guest.nft_rules(987)
    negative = guest.nft_rules(987, negative_port_probe=True)
    assert "ip daddr 127.0.0.1 tcp dport 443 accept" in normal
    assert "5432" not in normal
    assert negative.replace("{443,5432}", "443") == normal
    assert "meta skuid 987 counter name denied reject" in normal
    for invalid in (0, -1, True, "987", 2**31):
        with pytest.raises(AssertionError):
            guest.nft_rules(invalid)


def test_isolated_selinux_egress_guard_precedes_policy_and_network(monkeypatch):
    from scripts import ci_selinux_nginx_egress_guest as guest
    def refuse():
        raise AssertionError("not the authorized VM")
    monkeypatch.setattr(guest, "guard", refuse)
    monkeypatch.setattr(guest, "command", lambda *_a, **_kw:
                        pytest.fail("mutation before native guard"))
    with pytest.raises(AssertionError, match="authorized VM"):
        guest.probe()



def test_isolated_derived_unit_preserves_signed_contract_and_private_paths():
    from pathlib import Path
    from scripts import ci_selinux_nginx_egress_guest as guest

    signed = (Path(__file__).resolve().parents[1] /
              "docs/examples/systemd/repocache-nginx.service").read_bytes()
    root = Path("/var/lib/repocache-ci-selinux-test")
    derived = guest.derive_signed_unit(signed, root).decode("ascii")
    import configparser
    parsed = configparser.ConfigParser(interpolation=None, strict=True)
    parsed.optionxform = str
    parsed.read_string(derived)
    assert parsed.sections() == ["Unit", "Service"]
    assert parsed["Unit"]["Description"] == "REPOCACHE CI derived signed unit"
    assert parsed["Service"]["Type"] == "forking"
    assert parsed["Service"]["CapabilityBoundingSet"] == ""
    assert "Type=forking" in derived and "NoNewPrivileges=yes" in derived
    assert "User=nginx" in derived and "Group=nginx" in derived
    assert "CapabilityBoundingSet=\n" in derived
    assert "ProtectHome=yes" in derived and "ProtectSystem=strict" in derived
    assert "ExecStartPre=" + str(root / "nginx") in derived
    assert "ExecReload=" + str(root / "nginx") in derived
    assert "ExecStop=" + str(root / "nginx") in derived
    assert "/usr/sbin/nginx" not in derived and "/etc/nginx/" not in derived
    assert "RuntimeDirectory=" not in derived and "[Install]" not in derived
    for bad in (signed.replace(b"Type=forking", b"Type=exec"),
                signed.replace(b"NoNewPrivileges=yes", b"NoNewPrivileges=no"),
                signed.replace(b"KillMode=mixed", b"KillMode=mixed\nExecStartPost=/bin/false")):
        with pytest.raises(AssertionError):
            guest.derive_signed_unit(bad, root)
    with pytest.raises(AssertionError):
        guest.derive_signed_unit(signed, Path("/"))


def test_isolated_derived_root_uses_implicit_identity_and_same_four_caps():
    import configparser
    from pathlib import Path
    from scripts import ci_selinux_nginx_egress_guest as guest

    signed = (Path(__file__).resolve().parents[1] /
              "docs/examples/systemd/repocache-nginx.service").read_bytes()
    root = Path("/var/lib/repocache-ci-selinux-test")
    parsed = configparser.ConfigParser(interpolation=None, strict=True)
    parsed.optionxform = str
    parsed.read_string(guest.derive_signed_unit(signed, root, root_master=True).decode("ascii"))
    svc = parsed["Service"]
    assert "User" not in svc and "Group" not in svc
    assert svc["CapabilityBoundingSet"].split() == ["CAP_CHOWN", "CAP_KILL", "CAP_SETGID", "CAP_SETUID"]
    assert "AmbientCapabilities" not in svc
    assert svc["NoNewPrivileges"] == "yes"
    assert svc["RestrictAddressFamilies"] == "AF_UNIX AF_INET"
    assert svc["ProtectSystem"] == "strict" and svc["ProtectHome"] == "yes"
    assert svc["Type"] == "forking"
    assert parsed.sections() == ["Unit", "Service"]


def test_isolated_selinux_guard_rejects_optimized_python_before_io():
    import subprocess
    import sys
    from pathlib import Path

    scripts = Path(__file__).resolve().parents[1] / "scripts"
    code = """
import sys
sys.path.insert(0, sys.argv[1])
import ci_selinux_nginx_egress_guest as guest
try:
    guest.guard()
except AssertionError as exc:
    if str(exc) == "Native isolated fixture requires assertions enabled":
        raise SystemExit(0)
raise SystemExit(91)
"""
    result = subprocess.run([sys.executable, "-I", "-O", "-c", code, str(scripts)],
                            capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr


def test_isolated_remote_egress_is_root_only_and_exact_tuple_bound():
    from scripts import ci_selinux_nginx_egress_guest as guest

    first = guest.nft_rules(987, root_master=True, remote=True)
    both = guest.nft_rules(987, root_master=True, remote=True, custom_https=True)
    assert "policy drop" in first
    assert "meta skuid 0 ip daddr 127.0.0.1 tcp dport 8443 accept" in first
    assert "meta skuid 987 ip daddr 192.0.2.2 tcp dport 443 accept" in first
    assert "192.0.2.3" not in first
    assert "meta skuid 987 ip daddr 192.0.2.3 tcp dport 8008 accept" in both
    assert "meta skuid 987 ip daddr 192.0.2.2 tcp dport 8008 accept" not in both
    assert "meta skuid 987 ip daddr 192.0.2.3 tcp dport 443 accept" not in both
    assert "meta skuid 987 ip daddr 127.0.0.1" not in both
    assert "meta skuid 0 ip daddr 192.0.2." not in both
    assert "5432" not in both
    with pytest.raises(AssertionError):
        guest.nft_rules(987, remote=True)
    with pytest.raises(AssertionError):
        guest.nft_rules(987, root_master=True, remote=True, negative_port_probe=True)
    with pytest.raises(AssertionError):
        guest.nft_rules(987, root_master=True, remote=1)


def test_peer_denial_counter_requires_exact_named_kernel_counter():
    from scripts.ci_selinux_nginx_egress_guest import parse_denied_packets
    data = {"nftables": [{"metainfo": {}}, {"counter": {"family": "inet",
             "table": "repocache_egress", "name": "denied", "packets": 4}}]}
    assert parse_denied_packets(data) == 4
    for field, value in (("family", "ip"), ("table", "foreign"),
                         ("name", "other"), ("packets", True), ("packets", -1)):
        bad = {"nftables": [{"counter": {**data["nftables"][1]["counter"], field: value}}]}
        with pytest.raises(AssertionError):
            parse_denied_packets(bad)
