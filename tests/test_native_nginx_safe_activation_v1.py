"""Fixed signed-worker NGINX activation guards (#27).

These are no-host-effect unit tests. Native PID1/systemd/SELinux acceptance
requires actual disposable booted Debian 13 and AlmaLinux 10 VMs.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts import install_native_root_worker as native
from scripts import stage_native_root_worker as stage


def _private_dump() -> bytes:
    return (b"# configuration file /etc/nginx/nginx.conf:\n"
            b"http {\n"
            b"    server {\n"
            b"        listen 127.0.0.1:8080;\n"
            b"        location / { return 204; }\n"
            b"    }\n"
            b"}\n")


def test_private_loopback_listener_candidate_only(monkeypatch):
    checked = []
    monkeypatch.setattr(native, "_native_syntax_check",
                        lambda: checked.append("syntax"))
    monkeypatch.setattr(native, "_capture_default_nginx_dump_private",
                        _private_dump)
    native._require_private_nginx_listeners()
    assert checked == ["syntax"]


@pytest.mark.parametrize("dump", [
    b"http { server { listen 127.0.0.1:8080; } }\n",
    b"http {\n server {\n listen 80;\n }\n}\n",
    b"http {\n server {\n listen 0.0.0.0:80;\n }\n}\n",
    b"http {\n server {\n listen [::]:443 ssl;\n }\n}\n",
    b"http {\n server {\n listen 127.0.0.1:0;\n }\n}\n",
    b"http {\n server {\n listen 127.0.0.1:65536;\n }\n}\n",
    b"http {\n server {\n }\n}\n",
    b"http {\n server { listen 127.0.0.1:8080;\n }\n}\n",
    b"http {\n server {\n listen 127.0.0.1:8080; listen 80;\n }\n}\n",
    b"",
    b"\xff",
])
def test_public_implicit_or_ambiguous_listeners_refused(monkeypatch, dump):
    monkeypatch.setattr(native, "_native_syntax_check", lambda: None)
    monkeypatch.setattr(native, "_capture_default_nginx_dump_private",
                        lambda: dump)
    with pytest.raises(stage.WorkerStageError,
                       match="^WORKER_PLACEMENT_NATIVE_LISTENERS_UNVERIFIED$"):
        native._require_private_nginx_listeners()


def test_inactive_vendor_systemd_shape_requires_exact_match(monkeypatch):
    monkeypatch.setattr(native, "_observe_systemd_pid1", lambda: None)
    monkeypatch.setattr(native, "_safe_native_systemctl", lambda: None)
    monkeypatch.setattr(native, "inspect_native_nginx_unit",
                        lambda _d: SimpleNamespace(to_dict=lambda: {
                            "code": "VENDOR_NGINX_UNIT_OBSERVED",
                            "vendor_unit_bounded_and_owned": True,
                            "vendor_unit_sha256": "a" * 64,
                        }))
    fixed = {
        "Id": "nginx.service", "Names": "nginx.service",
        "FragmentPath": "/usr/lib/systemd/system/nginx.service",
        "DropInPaths": "", "LoadState": "loaded", "ActiveState": "inactive",
        "SubState": "dead", "MainPID": "0", "CanReload": "yes",
        "NeedDaemonReload": "no",
    }
    seen = []
    def run(argv, **kwargs):
        seen.append((argv, kwargs))
        assert argv == native._EFFECTIVE_SYSTEMCTL_ARGS
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 5
        assert kwargs["stdin"] == native.subprocess.DEVNULL
        return SimpleNamespace(returncode=0, stdout="".join(
            f"{k}={v}\n" for k, v in fixed.items()
        ), stderr="")
    monkeypatch.setattr(native.subprocess, "run", run)
    native._nginx_inactive_vendor_service("debian")
    assert len(seen) == 1
    fixed["FragmentPath"] = "/etc/systemd/system/nginx.service"
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_INACTIVE_UNIT_UNVERIFIED"):
        native._nginx_inactive_vendor_service("debian")


def _setup_activation(monkeypatch):
    state = {"active": False, "enabled": False, "commands": [],
             "integrity_checked": 0, "preflight_checked": 0}
    def verified(*_args, **_kwargs):
        state["integrity_checked"] += 1
    monkeypatch.setattr(native, "_require_audited_native_package_for_activation",
                        verified)
    monkeypatch.setattr(native, "_no_conflicting_pending", lambda _fd: None)
    monkeypatch.setattr(native, "_read_v2", lambda _fd, _owner: (None, None))
    def systemctl(action):
        return ((0, b"enabled\n") if state["enabled"] else
                (1, b"disabled\n")) if action == "is-enabled" else (
                (0, b"active\n") if state["active"] else (3, b"inactive\n"))
    monkeypatch.setattr(native, "_nginx_systemctl", systemctl)
    def preflight(_distribution):
        state["preflight_checked"] += 1
    monkeypatch.setattr(native, "_nginx_inactive_vendor_service", preflight)
    monkeypatch.setattr(native, "_require_private_nginx_listeners",
                        lambda: state.__setitem__(
                            "preflight_checked", state["preflight_checked"] + 1))
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
    monkeypatch.setattr(native, "_nginx_activation_command", command)
    monkeypatch.setattr(native, "inspect_effective_native_nginx_unit",
                        lambda _d: {
                            "status": "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION",
                            "vendor_unit_sha256": "a" * 64,
                            "main_pid_observed": 1234,
                            "authorizes_systemctl": False,
                        })
    return state


def test_explicit_activation_is_idempotent_and_does_not_reinstall(monkeypatch):
    state = _setup_activation(monkeypatch)
    result = native._activate_audited_native_nginx_under_lock(11, "debian")
    assert result["status"] == "AUTHENTICATED_NATIVE_NGINX_ACTIVE"
    assert state["commands"] == ["start", "enable"]
    assert state["integrity_checked"] == 2
    assert state["preflight_checked"] == 2
    again = native._activate_audited_native_nginx_under_lock(11, "debian")
    assert again["status"] == "AUTHENTICATED_NATIVE_NGINX_ALREADY_ACTIVE"
    assert state["commands"] == ["start", "enable"]



def test_idempotent_request_never_certifies_existing_public_http(monkeypatch):
    state = _setup_activation(monkeypatch)
    state["active"] = True
    state["enabled"] = True
    def public():
        raise stage.WorkerStageError("WORKER_PLACEMENT_NATIVE_LISTENERS_UNVERIFIED")
    monkeypatch.setattr(native, "_require_private_nginx_listeners", public)
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_LISTENERS_UNVERIFIED"):
        native._activate_audited_native_nginx_under_lock(11, "debian")
    assert state["commands"] == []
    assert state["integrity_checked"] == 1


def test_existing_managed_generation_blocks_first_service_start(monkeypatch):
    state = _setup_activation(monkeypatch)
    monkeypatch.setattr(native, "_read_v2",
                        lambda _fd, _owner: ({"state_generation": 1}, b"raw"))
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_MANAGED_STATE_REFUSED"):
        native._activate_audited_native_nginx_under_lock(11, "almalinux")
    assert state["commands"] == []


def test_stopped_but_enabled_or_foreign_service_refused(monkeypatch):
    state = _setup_activation(monkeypatch)
    state["enabled"] = True
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_FOREIGN_SERVICE_STATE"):
        native._activate_audited_native_nginx_under_lock(11, "debian")
    assert state["commands"] == []


def test_prestart_listener_refusal_performs_no_systemctl_write(monkeypatch):
    state = _setup_activation(monkeypatch)
    def refuse():
        raise stage.WorkerStageError("WORKER_PLACEMENT_NATIVE_LISTENERS_UNVERIFIED")
    monkeypatch.setattr(native, "_require_private_nginx_listeners", refuse)
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_LISTENERS_UNVERIFIED"):
        native._activate_audited_native_nginx_under_lock(11, "debian")
    assert state["commands"] == []


def test_poststart_failed_enable_stops_own_unit_and_disables(monkeypatch):
    state = _setup_activation(monkeypatch)
    def failed_enable(action):
        state["commands"].append(action)
        if action == "start":
            state["active"] = True
        if action == "enable":
            raise stage.WorkerStageError("WORKER_PLACEMENT_NGINX_ENABLE_FAILED")
        if action == "stop":
            state["active"] = False
        if action == "disable":
            state["enabled"] = False
    monkeypatch.setattr(native, "_nginx_activation_command", failed_enable)
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_FAILED_ROLLED_BACK"):
        native._activate_audited_native_nginx_under_lock(11, "debian")
    assert state["commands"] == ["start", "enable", "stop", "disable"]
    assert state["active"] is False and state["enabled"] is False



def test_systemctl_start_error_after_service_started_is_compensated(monkeypatch):
    state = _setup_activation(monkeypatch)
    def partial_start(action):
        state["commands"].append(action)
        if action == "start":
            state["active"] = True
            raise stage.WorkerStageError(
                "WORKER_PLACEMENT_NATIVE_ACTIVATION_COMMAND_FAILED"
            )
        if action == "stop":
            state["active"] = False
        if action == "disable":
            state["enabled"] = False
    monkeypatch.setattr(native, "_nginx_activation_command", partial_start)
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_FAILED_ROLLED_BACK"):
        native._activate_audited_native_nginx_under_lock(11, "debian")
    assert state["commands"] == ["start", "stop", "disable"]
    assert not state["active"] and not state["enabled"]


def test_start_error_with_unknown_runtime_does_not_kill_foreign_service(monkeypatch):
    state = _setup_activation(monkeypatch)
    def ambiguous_start(action):
        state["commands"].append(action)
        if action == "start":
            state["active"] = True
            raise stage.WorkerStageError("WORKER_PLACEMENT_START_AMBIGUOUS")
    monkeypatch.setattr(native, "_nginx_activation_command", ambiguous_start)
    def foreign(_distribution):
        raise ValueError("foreign runtime")
    monkeypatch.setattr(native, "inspect_effective_native_nginx_unit", foreign)
    with pytest.raises(stage.WorkerStageError,
                       match="NATIVE_ACTIVATION_RECOVERY_REQUIRED"):
        native._activate_audited_native_nginx_under_lock(11, "almalinux")
    assert state["commands"] == ["start"]


def test_foreign_replacement_after_start_not_stopped(monkeypatch):
    state = _setup_activation(monkeypatch)
    observed = 0
    def foreign(_distribution):
        nonlocal observed
        observed += 1
        raise ValueError("foreign systemd runtime " + "/private/path")
    monkeypatch.setattr(native, "inspect_effective_native_nginx_unit", foreign)
    with pytest.raises(stage.WorkerStageError) as exc:
        native._activate_audited_native_nginx_under_lock(11, "debian")
    assert str(exc.value) == "WORKER_PLACEMENT_NATIVE_ACTIVATION_RECOVERY_REQUIRED"
    assert "/private/path" not in str(exc.value)
    assert state["commands"] == ["start"]
    assert observed == 2


def test_no_signed_worker_refuses_before_root_or_service_access(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "_native_distro", lambda: "debian")
    monkeypatch.setattr(native, "require_native_host_preconditions", lambda: None)
    def untrusted(*_args, **_kwargs):
        raise stage.WorkerStageError("WORKER_STAGE_INVALID_SIGNED_WORKER")
    monkeypatch.setattr(stage, "verify_installed_worker", untrusted)
    def forbidden(*_args, **_kwargs):
        pytest.fail("must not open protected root or contact systemctl")
    monkeypatch.setattr(native.os, "open", forbidden)
    with pytest.raises(stage.WorkerStageError, match="INVALID_SIGNED_WORKER"):
        native.activate_authenticated_native_nginx(
            tmp_path, commit="a" * 40, archive_sha256="b" * 64)
