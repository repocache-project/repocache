"""Native fixed NGINX -T bounded private observation, no service reload."""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys

import pytest

import repocache.server_root_control_full_context_v1 as observed


def _mock_root_and_files(monkeypatch):
    monkeypatch.setattr(observed.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        observed, "_trusted_fixed_files", lambda: ((1, 2), (3, 4)),
    )


def _child_with_output(monkeypatch, code: str):
    actual = subprocess.Popen
    calls = []
    def process(argv, **kwargs):
        calls.append((argv, kwargs))
        return actual([sys.executable, "-c", code], **kwargs)
    monkeypatch.setattr(observed.subprocess, "Popen", process)
    return calls


def test_exact_nginx_t_command_bounded_hash_never_exposes_dump(monkeypatch):
    _mock_root_and_files(monkeypatch)
    calls = _child_with_output(
        monkeypatch, "import sys;sys.stdout.buffer.write(b'private-config')",
    )
    report = observed.inspect_installed_default_nginx_full_context_only()
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == (
        "/usr/sbin/nginx", "-T", "-c", "/etc/nginx/nginx.conf",
    )
    assert kwargs["shell"] is False
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stdout"] == subprocess.PIPE
    assert kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs["cwd"] == "/"
    assert kwargs["env"] == {"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"}
    assert kwargs["start_new_session"] is True
    assert kwargs["close_fds"] is True
    assert report["full_context_sha256"] == hashlib.sha256(
        b"private-config",
    ).hexdigest()
    assert report["dump_size_bytes"] == len(b"private-config")
    assert "private-config" not in str(report)
    assert all(value is False for key, value in report.items()
               if key.startswith("authorizes_") or key.endswith("_verified")
               or key == "preflight_remains_valid_after_return")


@pytest.mark.parametrize("code,expected", [
    ("import sys;sys.exit(1)", "CHECK_FAILED"),
    ("", "CHECK_FAILED"),
    ("import sys;sys.stdout.buffer.write(b'x'*4194305)", "OUTPUT_TOO_LARGE"),
    ("import time;time.sleep(2)", "CHECK_TIMEOUT"),
])
def test_bad_native_dump_denied_and_never_echoed(monkeypatch, code, expected):
    _mock_root_and_files(monkeypatch)
    # Tight test timeout; real source retains 10-second bound.
    monkeypatch.setattr(observed, "_TIMEOUT_SECONDS", 0.35)
    _child_with_output(monkeypatch, code)
    with pytest.raises(observed.FixedNginxFullContextError,
                       match="NATIVE_NGINX_FULL_CONTEXT_" + expected) as err:
        observed.inspect_installed_default_nginx_full_context_only()
    assert "private" not in str(err.value)


def test_nonroot_refuses_before_filesystem_and_subprocess(monkeypatch):
    monkeypatch.setattr(observed.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        observed, "_trusted_fixed_files",
        lambda: pytest.fail("must not inspect native files"),
    )
    monkeypatch.setattr(
        observed.subprocess, "Popen",
        lambda *a, **k: pytest.fail("must not execute nginx"),
    )
    with pytest.raises(observed.FixedNginxFullContextError,
                       match="ROOT_REQUIRED"):
        observed.inspect_installed_default_nginx_full_context_only()


def test_untrusted_executable_denied_before_command(monkeypatch):
    _mock_root_and_files(monkeypatch)
    def decline():
        from repocache.server_root_control_native_syntax_v1 import (
            FixedNginxSyntaxError,
        )
        raise FixedNginxSyntaxError("NATIVE_NGINX_SYNTAX_UNSAFE_PATH")
    monkeypatch.setattr(observed, "_trusted_fixed_files", decline)
    monkeypatch.setattr(
        observed.subprocess, "Popen",
        lambda *a, **k: pytest.fail("must not run nginx"),
    )
    with pytest.raises(observed.FixedNginxFullContextError,
                       match="FIXED_FILES_UNVERIFIED"):
        observed.inspect_installed_default_nginx_full_context_only()


def test_binary_or_conf_identity_changed_refused_after_command(monkeypatch):
    _mock_root_and_files(monkeypatch)
    reads = []
    def change():
        reads.append(1)
        return ((1,), (2 if len(reads) == 1 else 3,))
    monkeypatch.setattr(observed, "_trusted_fixed_files", change)
    _child_with_output(monkeypatch, "print('one')")
    with pytest.raises(observed.FixedNginxFullContextError,
                       match="FIXED_FILES_CHANGED"):
        observed.inspect_installed_default_nginx_full_context_only()


def test_private_dump_not_wired_into_worker():
    import inspect
    from repocache.server_root_control_worker_v1 import serve_one_fixed_request
    assert "_capture_default_nginx_dump_private" not in inspect.getsource(
        serve_one_fixed_request,
    )
    assert "ROOT_TRANSACTION_NOT_IMPLEMENTED" in inspect.getsource(
        serve_one_fixed_request,
    )

@pytest.mark.parametrize("managed", [False, True])
def test_owned_context_uses_only_fixed_private_command(monkeypatch, managed):
    monkeypatch.setattr(observed.os, "geteuid", lambda: 0)
    seen = []
    monkeypatch.setattr(observed, "_trusted_owned_fixed_files",
                        lambda selected: seen.append(selected) or ((1,), (2,)))
    monkeypatch.setattr(observed, "_trusted_fixed_files",
                        lambda: pytest.fail("vendor probe selected"))
    calls = _child_with_output(monkeypatch, "print('private-context')")
    assert observed._capture_owned_nginx_dump_private(managed=managed) == b"private-context\n"
    assert seen == [managed, managed]
    assert calls[0][0] == (
        "/usr/sbin/nginx", "-T", "-c", "/etc/nginx/repocache.d/repocache.conf",
    )
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["stderr"] == subprocess.DEVNULL


@pytest.mark.parametrize("managed", [False, True])
def test_owned_context_refuses_file_identity_drift(monkeypatch, managed):
    monkeypatch.setattr(observed.os, "geteuid", lambda: 0)
    reads = iter(((1,), (2,)))
    monkeypatch.setattr(observed, "_trusted_owned_fixed_files",
                        lambda selected: next(reads))
    _child_with_output(monkeypatch, "print('private-context')")
    with pytest.raises(observed.FixedNginxFullContextError,
                       match="FIXED_FILES_CHANGED"):
        observed._capture_owned_nginx_dump_private(managed=managed)


def test_owned_context_bootstrap_refuses_even_dangling_include(monkeypatch):
    import stat
    from types import SimpleNamespace

    def meta(mode, ino):
        return SimpleNamespace(st_mode=mode, st_uid=0, st_gid=0,
                               st_nlink=1, st_dev=4, st_ino=ino,
                               st_size=32, st_mtime_ns=1, st_ctime_ns=2)

    paths = {path: meta(stat.S_IFDIR | 0o755, i)
             for i, path in enumerate(observed._PARENTS, 1)}
    paths[observed._NGINX] = meta(stat.S_IFREG | 0o755, 101)
    paths[observed._OWNED_MAIN_PATH] = meta(stat.S_IFREG | 0o644, 102)

    def lookup(path):
        if path not in paths:
            raise FileNotFoundError(path)
        return paths[path]

    monkeypatch.setattr(observed.os, "lstat", lookup)
    assert observed._trusted_owned_fixed_files(False)[1][-1] is None
    with pytest.raises(observed.FixedNginxFullContextError,
                       match="FIXED_FILES_UNVERIFIED"):
        observed._trusted_owned_fixed_files(True)
    paths[observed._OWNED_INCLUDE_PATH] = meta(stat.S_IFLNK | 0o777, 103)
    for managed in (False, True):
        with pytest.raises(observed.FixedNginxFullContextError,
                           match="FIXED_FILES_UNVERIFIED"):
            observed._trusted_owned_fixed_files(managed)
    paths[observed._OWNED_INCLUDE_PATH] = meta(stat.S_IFREG | 0o644, 104)
    assert observed._trusted_owned_fixed_files(True)[1][-1] is not None
    with pytest.raises(observed.FixedNginxFullContextError,
                       match="FIXED_FILES_UNVERIFIED"):
        observed._trusted_owned_fixed_files(False)
