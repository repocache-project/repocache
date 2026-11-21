"""Static refusals and exact argv for the non-deployable NGINX syntax gate."""
from __future__ import annotations

import os
import stat
import subprocess
from types import SimpleNamespace

import pytest

import repocache.server_root_control_native_syntax_v1 as gate


def meta(*, mode=0o755, kind=stat.S_IFREG, uid=0, gid=0, links=1,
         ino=32, dev=4):
    return SimpleNamespace(
        st_mode=kind | mode, st_uid=uid, st_gid=gid, st_nlink=links,
        st_dev=dev, st_ino=ino, st_size=32, st_mtime_ns=1, st_ctime_ns=2,
    )


def valid_layout(monkeypatch):
    paths = {name: meta(kind=stat.S_IFDIR, ino=i) for i, name in
             enumerate(gate._PARENTS, 1)}
    paths[gate._NGINX] = meta(ino=101)
    paths[gate._CONF] = meta(ino=102, mode=0o644)
    monkeypatch.setattr(gate.os, "lstat", lambda name: paths[name])
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0)
    return paths


def test_strict_fixed_native_command_and_no_authority(monkeypatch):
    valid_layout(monkeypatch)
    seen = []
    def run(argv, **kwargs):
        seen.append((argv, kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(gate.subprocess, "run", run)
    result = gate.inspect_installed_default_nginx_syntax_only()
    assert len(seen) == 1
    argv, kwargs = seen[0]
    assert argv == ("/usr/sbin/nginx", "-t", "-c", "/etc/nginx/nginx.conf")
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 10
    assert kwargs["cwd"] == "/"
    assert kwargs["env"] == {
        "PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C",
    }
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stdout"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs["start_new_session"] is True
    assert kwargs["close_fds"] is True
    assert result["fixed_native_command_executed"] is True
    assert result["managed_candidate_staged_and_verified"] is False
    assert all(value is False for key, value in result.items()
               if key.startswith("authorizes_"))
    assert all(result[key] is False for key in (
        "native_host_root_provenance_verified",
        "installed_binary_package_provenance_verified",
        "operator_authorization_verified",
        "effective_systemd_unit_verified",
    ))


def test_nonroot_refuses_before_path_and_process_access(monkeypatch):
    monkeypatch.setattr(gate.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(gate.os, "lstat",
                        lambda name: pytest.fail("should not lstat"))
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, **k: pytest.fail("should not run"))
    with pytest.raises(gate.FixedNginxSyntaxError, match="ROOT_REQUIRED"):
        gate.inspect_installed_default_nginx_syntax_only()


@pytest.mark.parametrize("path,changes", [
    ("/usr/sbin/nginx", {"st_mode": stat.S_IFLNK | 0o777}),
    ("/usr/sbin/nginx", {"st_mode": stat.S_IFREG | 0o777}),
    ("/usr/sbin/nginx", {"st_uid": 1000}),
    ("/usr/sbin/nginx", {"st_gid": 1000}),
    ("/usr/sbin/nginx", {"st_nlink": 2}),
    ("/etc/nginx/nginx.conf", {"st_mode": stat.S_IFLNK | 0o777}),
    ("/etc/nginx/nginx.conf", {"st_mode": stat.S_IFREG | 0o666}),
    ("/etc/nginx/nginx.conf", {"st_uid": 65534}),
    ("/etc/nginx/nginx.conf", {"st_nlink": 2}),
    ("/etc/nginx", {"st_mode": stat.S_IFLNK | 0o777}),
    ("/etc", {"st_mode": stat.S_IFDIR | 0o777}),
    ("/usr/sbin", {"st_uid": 1000}),
])
def test_unsafe_native_files_refused_before_execution(monkeypatch, path,
                                                       changes):
    paths = valid_layout(monkeypatch)
    for key, value in changes.items():
        setattr(paths[path], key, value)
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, **k: pytest.fail("must not run"))
    with pytest.raises(gate.FixedNginxSyntaxError, match="UNSAFE_PATH"):
        gate.inspect_installed_default_nginx_syntax_only()


@pytest.mark.parametrize("failure,code", [
    ("syntax", "CHECK_FAILED"),
    ("status-bool", "CHECK_FAILED"),
    ("timeout", "CHECK_TIMEOUT"),
    ("oserror", "CHECK_UNAVAILABLE"),
    ("subprocess-error", "CHECK_UNAVAILABLE"),
])
def test_failed_native_validation_redacts_output(monkeypatch, failure, code):
    valid_layout(monkeypatch)
    def runner(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args[0], 10, output=b"private config")
        if failure == "oserror":
            raise OSError("private TLS key /etc/ssl/private")
        if failure == "subprocess-error":
            raise subprocess.SubprocessError("private TLS key")
        return SimpleNamespace(returncode=True if failure == "status-bool" else 1)
    monkeypatch.setattr(gate.subprocess, "run", runner)
    with pytest.raises(gate.FixedNginxSyntaxError,
                       match="NATIVE_NGINX_SYNTAX_" + code) as caught:
        gate.inspect_installed_default_nginx_syntax_only()
    assert "private" not in str(caught.value)


@pytest.mark.parametrize("name", ["/usr/sbin/nginx", "/etc/nginx/nginx.conf"])
def test_changed_executable_or_config_refused_after_subprocess(monkeypatch,
                                                               name):
    paths = valid_layout(monkeypatch)
    def mutate(*args, **kwargs):
        paths[name].st_ino += 1
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(gate.subprocess, "run", mutate)
    with pytest.raises(gate.FixedNginxSyntaxError, match="FILES_CHANGED"):
        gate.inspect_installed_default_nginx_syntax_only()


def test_not_a_service_or_worker_dispatcher(monkeypatch):
    assert not hasattr(gate, "reload_nginx")
    assert not hasattr(gate, "publish_catalog")
    # Do not assume the systemd worker has ever called this module.
    import inspect
    import repocache.server_root_control_worker_v1 as worker
    source = inspect.getsource(worker.serve_one_fixed_request)
    assert "inspect_installed_default_nginx_syntax_only" not in source
    assert "ROOT_TRANSACTION_NOT_IMPLEMENTED" in source
