"""Native root preflight is a necessary *refusal* gate, never authority."""
from __future__ import annotations

import os
import socket
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import repocache.server_root_control_host_preflight_v1 as gate
from repocache.server_root_control_host_preflight_v1 import (
    NativeHostPreflightError, require_native_host_preconditions,
)


def _dir(mode=0o755, uid=0, gid=0):
    return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid, st_gid=gid)


def _prepared(monkeypatch, *, pid1=b"systemd\n", mapping=None,
              runtime=None, process_uid=0, process_gid=0):
    if mapping is None:
        mapping = gate._INITIAL_UID_MAP
    if runtime is None:
        runtime = {
            "/run": _dir(), "/run/systemd": _dir(),
            "/run/systemd/system": _dir(),
        }
    monkeypatch.setattr(gate.os, "getuid", lambda: process_uid)
    monkeypatch.setattr(gate.os, "geteuid", lambda: process_uid)
    monkeypatch.setattr(gate.os, "getresuid",
                        lambda: (process_uid,) * 3)
    monkeypatch.setattr(gate.os, "getgid", lambda: process_gid)
    monkeypatch.setattr(gate.os, "getegid", lambda: process_gid)
    monkeypatch.setattr(gate.os, "getresgid",
                        lambda: (process_gid,) * 3)
    monkeypatch.setattr(
        gate, "_read_proc",
        lambda path: {
            "/proc/1/comm": pid1,
            "/proc/self/uid_map": mapping,
        }[path],
    )
    monkeypatch.setattr(gate, "_same_namespace", lambda kind: None)
    monkeypatch.setattr(gate.os, "lstat", lambda path: runtime[path])


def test_all_synthetic_native_preconditions_are_only_observations(monkeypatch):
    _prepared(monkeypatch)
    result = require_native_host_preconditions()
    assert result["status"] == "NATIVE_HOST_NECESSARY_PRECONDITIONS_ONLY"
    assert all(result[n] is False for n in (
        "signed_installed_binary_verified",
        "effective_systemd_unit_verified",
        "selinux_acl_mount_ownership_verified",
        "host_root_provenance_verified",
        "authorizes_host_write", "authorizes_nginx_reload",
        "authorizes_catalog_publication",
    ))


@pytest.mark.parametrize("uid,gid", [(1, 0), (0, 1), (1000, 1000)])
def test_unprivileged_worker_denied_prior_to_any_procfs_claim(
    monkeypatch, uid, gid,
):
    _prepared(monkeypatch, process_uid=uid, process_gid=gid)
    with pytest.raises(NativeHostPreflightError,
                       match="INITIAL_ROOT_REQUIRED"):
        require_native_host_preconditions()


@pytest.mark.parametrize("pid1", [b"bash\n", b"init\n", b"systemd", b""])
def test_non_systemd_pid1_fails_closed(monkeypatch, pid1):
    _prepared(monkeypatch, pid1=pid1)
    with pytest.raises(NativeHostPreflightError,
                       match="SYSTEMD_PID1_REQUIRED"):
        require_native_host_preconditions()


@pytest.mark.parametrize("mapping", [
    b"         0     100000      65536\n",
    b"         0          0      65536\n",
    b"0 0 4294967295\n",
    b"",
])
def test_rootless_or_unrecognized_user_namespace_denied(monkeypatch, mapping):
    _prepared(monkeypatch, mapping=mapping)
    with pytest.raises(NativeHostPreflightError,
                       match="INITIAL_USER_NAMESPACE_REQUIRED"):
        require_native_host_preconditions()


@pytest.mark.parametrize("path,change", [
    ("/run", {"st_mode": stat.S_IFDIR | 0o777}),
    ("/run/systemd", {"st_uid": 1000}),
    ("/run/systemd/system", {"st_gid": 1000}),
    ("/run/systemd/system", {"st_mode": stat.S_IFLNK | 0o755}),
])
def test_foreign_or_writable_systemd_runtime_refused(monkeypatch,path,change):
    runtime = {"/run": _dir(), "/run/systemd": _dir(),
               "/run/systemd/system": _dir()}
    for key, value in change.items():
        setattr(runtime[path], key, value)
    _prepared(monkeypatch, runtime=runtime)
    with pytest.raises(NativeHostPreflightError,
                       match="SYSTEMD_RUNTIME_UNSAFE"):
        require_native_host_preconditions()


@pytest.mark.parametrize("kind", ["mnt", "user", "pid"])
def test_kernel_namespace_identity_mismatch_is_detected(monkeypatch,kind):
    def fake_stat(path):
        identity = 100 if path.startswith("/proc/1/") else 200
        return SimpleNamespace(
            st_mode=stat.S_IFREG | 0o444, st_dev=1, st_ino=identity,
        )
    monkeypatch.setattr(gate, "os", SimpleNamespace(stat=fake_stat))
    with pytest.raises(NativeHostPreflightError,
                       match="NAMESPACE_DIFFERENT"):
        gate._same_namespace(kind)


def test_invalid_namespace_kind_refused_before_syscalls(monkeypatch):
    monkeypatch.setattr(gate,"os",SimpleNamespace(
        stat=lambda _:pytest.fail("no stat"),
    ))
    with pytest.raises(NativeHostPreflightError,
                       match="NAMESPACE_KIND_REFUSED"):
        gate._same_namespace("../net")


def test_private_mount_namespace_requires_matching_service_view(monkeypatch):
    _prepared(monkeypatch)
    observed = []
    monkeypatch.setattr(gate, "_namespace_pair", lambda kind: ((1, 10), (1, 20)))
    monkeypatch.setattr(gate, "_matching_service_mount_view", lambda: observed.append(True))
    report = gate.require_socket_worker_host_preconditions()
    assert observed == [True]
    assert report["private_mount_and_fixed_service_view_observed"] is True
    assert report["pid1_systemd_and_matching_namespaces_observed"] is False
    assert report["signed_installed_binary_verified"] is False
    assert report["authorizes_nginx_reload"] is False


def test_standalone_observation_still_refuses_a_private_mount_namespace(monkeypatch):
    _prepared(monkeypatch)

    def same(kind):
        if kind == "mnt":
            raise NativeHostPreflightError("NATIVE_HOST_NAMESPACE_DIFFERENT")

    monkeypatch.setattr(gate, "_same_namespace", same)
    monkeypatch.setattr(gate, "_matching_service_mount_view",
                        lambda: pytest.fail("standalone probe must remain strict"))
    with pytest.raises(NativeHostPreflightError, match="NAMESPACE_DIFFERENT"):
        require_native_host_preconditions()


def test_mount_namespace_drift_remains_a_refusal(monkeypatch):
    _prepared(monkeypatch)
    views = iter((((1, 10), (1, 20)), ((1, 10), (1, 21))))
    monkeypatch.setattr(gate, "_namespace_pair", lambda kind: next(views))
    monkeypatch.setattr(gate, "_matching_service_mount_view", lambda: None)
    with pytest.raises(NativeHostPreflightError, match="NAMESPACE_CHANGED"):
        gate.require_socket_worker_host_preconditions()


def test_service_view_compares_real_rooted_socket_inodes_and_refuses_substitutions(
    monkeypatch, tmp_path,
):
    here = tmp_path / "worker"
    there = tmp_path / "pid1"
    here.mkdir()
    there.mkdir()
    # Start two real sockets in temporary directories; tools never query
    # PID 1 or a real control socket for this regression.
    for root in (here, there):
        (root / "run").mkdir()
        (root / "worker").write_text("marker", encoding="ascii")
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as first, \
            socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as second:
        # Use relative addresses to stay inside Linux sun_path limits.
        monkeypatch.chdir(tmp_path)
        first.bind("worker/s")
        second.bind("pid1/s")
        native_open = os.open
        roots = {"/": here, "/proc/1/root": here}

        def open_fixed(path, *args, **kwargs):
            return native_open(roots.get(path, path), *args, **kwargs)

        monkeypatch.setattr(os, "open", open_fixed)
        monkeypatch.setattr(gate, "_SERVICE_DIRECTORIES", ("/run",))
        monkeypatch.setattr(gate, "_SERVICE_FILES", ("/worker",))
        monkeypatch.setattr(gate, "_SERVICE_SOCKETS", ("/s",))
        gate._matching_service_mount_view()
        roots["/proc/1/root"] = there
        with pytest.raises(NativeHostPreflightError, match="SERVICE_MOUNT_VIEW_DIFFERENT"):
            gate._matching_service_mount_view()
        roots["/proc/1/root"] = here
        (here / "worker").rename(here / "worker-real")
        (here / "worker").symlink_to(Path("worker-real"))
        with pytest.raises(NativeHostPreflightError, match="SERVICE_MOUNT_VIEW_UNSAFE"):
            gate._matching_service_mount_view()


def test_unsafe_proc_data_is_redacted_and_size_limited(monkeypatch):
    class ProcFd:
        descriptor = 8

    # Replace only the module's os reference. Patching global os.fstat
    # would break pytest capture/context manager internals during the test.
    monkeypatch.setattr(gate, "os", SimpleNamespace(
        O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW,
        O_NONBLOCK=os.O_NONBLOCK, O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
        open=lambda *_a, **_kw: 8,
        fstat=lambda _fd: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o444, st_uid=0,
        ),
        read=lambda *_a: b"SECRET" * 100,
        close=lambda _fd: None,
    ))
    with pytest.raises(NativeHostPreflightError,match="PROC_INVALID") as exc:
        gate._read_proc("/proc/1/comm")
    assert "SECRET" not in str(exc.value)


def test_proc_file_symlink_and_untrusted_uid_refusal(monkeypatch):
    monkeypatch.setattr(gate, "os", SimpleNamespace(
        O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW,
        O_NONBLOCK=os.O_NONBLOCK, O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
        open=lambda *_a, **_kw: 9,
        fstat=lambda _fd: SimpleNamespace(
            st_mode=stat.S_IFLNK | 0o777, st_uid=1000,
        ),
        close=lambda _fd: None,
    ))
    with pytest.raises(NativeHostPreflightError,match="PROC_UNTRUSTED"):
        gate._read_proc("/proc/self/uid_map")


def test_actual_disposable_userspace_cannot_claim_host_attestation():
    # Positive authority is *always* false, even if root/systemd is observed.
    # Some CI runners are not root, some use a non-systemd PID1, and this
    # test intentionally does not assume an actual booted Linux host.
    try:
        result = require_native_host_preconditions()
    except NativeHostPreflightError:
        return
    assert result["host_root_provenance_verified"] is False
    assert result["authorizes_nginx_reload"] is False
    assert result["signed_installed_binary_verified"] is False
