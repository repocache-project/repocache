"""Adversarial native distro package ownership observation regressions."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import stat
import subprocess
from unittest import mock

import pytest

from repocache import server_stock_nginx_package_owner_v1 as p


@pytest.mark.parametrize("raw,platform", [
    ('ID=debian\nVERSION_ID="13"\n', "debian13"),
    ('ID=almalinux\nVERSION_ID=10\n', "almalinux10"),
    ('ID="almalinux"\nVERSION_ID="10.0"\n', "almalinux10"),
    ('NAME="AlmaLinux"\nID=almalinux\nVERSION_ID="10.1"\n', "almalinux10"),
])
def test_exact_supported_platforms(raw, platform):
    assert p._platform(raw) == platform


@pytest.mark.parametrize("raw", [
    "", "ID=ubuntu\nVERSION_ID=24.04\n",
    "ID=debian\nVERSION_ID=12\n",
    "ID=almalinux\nVERSION_ID=9\n",
    "ID=debian\nVERSION_ID=13\nVERSION_ID=13\n",
    "ID=debian\nVERSION_ID=13;ignored\n",
    "ID=almalinux\nVERSION_ID=10.0.1\n",
    "ID=almalinux\nVERSION_ID=100\n",
])
def test_foreign_and_forged_platforms_refused(raw):
    with pytest.raises(p.StockNginxPackageOwnerError, match="NATIVE_NGINX_OWNER_"):
        p._platform(raw)


@pytest.mark.parametrize("distro,output,expected", [
    ("debian13", "nginx: /usr/sbin/nginx\n", "nginx"),
    ("debian13", "nginx:amd64: /usr/sbin/nginx\n", "nginx"),
    ("almalinux10", "nginx\n", "nginx"),
])
def test_package_owner_contract(distro, output, expected):
    assert p._owner(distro, output) == expected


@pytest.mark.parametrize("distro,output", [
    ("debian13", "nginx-common: /usr/sbin/nginx\n"),
    ("debian13", "nginx: /etc/nginx/nginx.conf\n"),
    ("debian13", "nginx: /usr/sbin/nginx\nnginx: /usr/sbin/nginx\n"),
    ("almalinux10", "nginx-custom\n"),
    ("almalinux10", "nginx\nother\n"),
    ("almalinux10", "nginx: valid\n"),
])
def test_foreign_or_ambiguous_package_owner_refused(distro, output):
    with pytest.raises(p.StockNginxPackageOwnerError):
        p._owner(distro, output)


def test_live_probe_observes_only_fixed_binary_and_manager():
    info = SimpleNamespace(
        st_dev=2, st_ino=19, st_mode=stat.S_IFREG | 0o755,
        st_uid=0, st_gid=0, st_nlink=1, st_size=345678,
        st_mtime_ns=5, st_ctime_ns=5,
    )
    run_result = subprocess.CompletedProcess([], 0, stdout="nginx\n", stderr="")
    with mock.patch.object(Path, "read_text", return_value='ID=almalinux\nVERSION_ID="10"\n'), \
         mock.patch.object(p.os, "lstat", return_value=info) as lstat, \
         mock.patch.object(p.subprocess, "run", return_value=run_result) as call:
        observed = p.inspect_stock_nginx_package_owner()
    assert observed["platform"] == "almalinux10"
    assert observed["package_name"] == "nginx"
    assert not observed["authorizes_nginx_adoption"]
    assert lstat.call_count == 2
    assert all(c.args == ("/usr/sbin/nginx",) for c in lstat.call_args_list)
    args, kwargs = call.call_args
    assert args[0] == p._MANAGERS["almalinux10"]
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs["cwd"] == "/"
    assert kwargs["timeout"] <= 12
    assert kwargs["check"] is False
    assert "shell" not in kwargs


def test_package_manager_failure_never_claims_identity():
    info = SimpleNamespace(st_dev=2, st_ino=19, st_mode=stat.S_IFREG | 0o755,
         st_uid=0, st_gid=0, st_nlink=1, st_size=345678,
         st_mtime_ns=5, st_ctime_ns=5)
    with mock.patch.object(Path, "read_text", return_value="ID=debian\nVERSION_ID=13\n"), \
         mock.patch.object(p.os, "lstat", return_value=info), \
         mock.patch.object(p.subprocess, "run",
             return_value=subprocess.CompletedProcess([], 1, stdout="nginx: /usr/sbin/nginx")):
        with pytest.raises(p.StockNginxPackageOwnerError):
            p.inspect_stock_nginx_package_owner()


def test_changed_binary_inode_refused():
    good = SimpleNamespace(st_dev=2, st_ino=19, st_mode=stat.S_IFREG | 0o755,
         st_uid=0, st_gid=0, st_nlink=1, st_size=345678,
         st_mtime_ns=5, st_ctime_ns=5)
    changed = SimpleNamespace(**{**vars(good), "st_ino": 21})
    with mock.patch.object(Path, "read_text", return_value="ID=almalinux\nVERSION_ID=10\n"), \
         mock.patch.object(p.os, "lstat", side_effect=[good, changed]), \
         mock.patch.object(p.subprocess, "run",
             return_value=subprocess.CompletedProcess([], 0, stdout="nginx\n")):
        with pytest.raises(p.StockNginxPackageOwnerError, match="BINARY_CHANGED"):
            p.inspect_stock_nginx_package_owner()


@pytest.mark.parametrize("mode,uid,links,size", [
    (stat.S_IFLNK | 0o777, 0, 1, 100000),
    (stat.S_IFREG | 0o777, 0, 1, 100000),
    (stat.S_IFREG | 0o755, 1000, 1, 100000),
    (stat.S_IFREG | 0o755, 0, 2, 100000),
    (stat.S_IFREG | 0o755, 0, 1, 10),
])
def test_unsafe_binary_metadata_refused(mode, uid, links, size):
    info = SimpleNamespace(st_dev=2, st_ino=19, st_mode=mode, st_uid=uid,
         st_gid=0, st_nlink=links, st_size=size, st_mtime_ns=1, st_ctime_ns=1)
    with mock.patch.object(p.os, "lstat", return_value=info):
        with pytest.raises(p.StockNginxPackageOwnerError):
            p._safe_binary()
