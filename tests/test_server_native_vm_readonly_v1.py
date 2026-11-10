"""Fixed read-only VM probe negatives and simulated booted observations."""
from __future__ import annotations

import os
import stat
from types import SimpleNamespace

import pytest
import repocache.server_native_vm_readonly_v1 as vm


def prepared(monkeypatch, *, distro="debian", root=True, container=False,
             pid1=b"systemd\n", runtime=True, enforcing=b"1\n", nginx=True):
    calls = []
    monkeypatch.setattr(vm, "validate_os_identity", lambda *_: distro)
    monkeypatch.setattr(vm.os, "geteuid", lambda: 0 if root else 1000)
    monkeypatch.setattr(vm.os.path, "lexists", lambda p: container)
    monkeypatch.setattr(vm, "_booted_pid1_shape", lambda: runtime)
    def read(path, size):
        calls.append(("read", path))
        return {
            "/etc/os-release": b"ID=debian\nVERSION_ID=13\n",
            "/proc/1/comm": pid1,
            "/sys/fs/selinux/enforce": enforcing,
        }[path]
    monkeypatch.setattr(vm, "_read_fixed", read)
    def effective(d):
        calls.append(("nginx", d))
        if not nginx:
            raise vm.EffectiveNginxUnitError("MISSING")
        return {
            "status": "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION",
            "kernel_nginx_master_executable_inode_observed": True,
            "effective_unit_shape_observed": True,
            "authorizes_nginx_reload": False,
        }
    monkeypatch.setattr(vm, "inspect_effective_native_nginx_unit", effective)
    return calls


@pytest.mark.parametrize("distro", ["debian", "almalinux"])
def test_synthetic_positive_never_authenticates_or_authorizes(monkeypatch, distro):
    calls = prepared(monkeypatch, distro=distro)
    result = vm.inspect_booted_vm_nginx_readonly()
    assert result["status"] == "READ_ONLY_PREREQUISITES_OBSERVED"
    assert result["code"] == "OBSERVATION_ONLY_NO_HOST_AUTHORITY"
    assert ("nginx", distro) in calls
    assert all(v is False for k, v in result.items()
               if k.startswith("authorizes_"))
    assert result["host_root_attested"] is False
    assert result["complete_server_acceptance_passed"] is False


@pytest.mark.parametrize("setting,code", [
    ("root", "ROOT_READ_ONLY_PROBE_REQUIRED"),
    ("container", "CONTAINER_CONTEXT_REFUSED"),
    ("pid1", "SYSTEMD_PID1_NOT_OBSERVED"),
    ("runtime", "SYSTEMD_NAMESPACE_OR_RUNTIME_NOT_OBSERVED"),
    ("nginx", "EFFECTIVE_NGINX_NOT_OBSERVED"),
])
def test_denials_never_return_native_acceptance(monkeypatch, setting, code):
    calls = prepared(
        monkeypatch, root=setting != "root", container=setting == "container",
        pid1=b"bash\n" if setting == "pid1" else b"systemd\n",
        runtime=setting != "runtime", nginx=setting != "nginx",
    )
    result = vm.inspect_booted_vm_nginx_readonly()
    assert result["code"] == code
    assert result["status"] == "NOT VERIFIED"
    assert result["authorizes_host_write"] is False
    if setting != "nginx":
        assert not any(x[0] == "nginx" for x in calls)


@pytest.mark.parametrize("mode", [b"0\n", b"", b"2\n", b"permissive"])
def test_almalinux_selinux_enforcing_required_before_nginx(monkeypatch, mode):
    calls = prepared(monkeypatch, distro="almalinux", enforcing=mode)
    result = vm.inspect_booted_vm_nginx_readonly()
    assert result["code"] == "ALMALINUX_SELINUX_ENFORCING_NOT_OBSERVED"
    assert not any(x[0] == "nginx" for x in calls)


def test_invalid_os_refused_before_any_nginx_probe(monkeypatch):
    calls = prepared(monkeypatch)
    def reject(*_):
        raise ValueError("private details not leaked")
    monkeypatch.setattr(vm, "validate_os_identity", reject)
    result = vm.inspect_booted_vm_nginx_readonly()
    assert result["code"] == "SUPPORTED_OS_NOT_OBSERVED"
    assert result["distribution"] is None
    assert calls == [("read", "/etc/os-release")]


@pytest.mark.parametrize("response", [
    {},
    {"status": "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION"},
    {"status": "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION",
     "kernel_nginx_master_executable_inode_observed": True,
     "effective_unit_shape_observed": True, "authorizes_nginx_reload": True},
])
def test_malformed_unit_report_is_not_accepted(monkeypatch, response):
    prepared(monkeypatch)
    monkeypatch.setattr(vm, "inspect_effective_native_nginx_unit",
                        lambda d: response)
    result = vm.inspect_booted_vm_nginx_readonly()
    assert result["code"] == "EFFECTIVE_NGINX_NOT_OBSERVED"


def test_fixed_file_reader_rejects_nonregular_before_bytes(monkeypatch):
    calls = []
    monkeypatch.setattr(vm, "os", SimpleNamespace(
        O_RDONLY=os.O_RDONLY, O_NONBLOCK=os.O_NONBLOCK,
        O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
        open=lambda p, flags: calls.append(("open", p)) or 99,
        fstat=lambda fd: SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755, st_size=0,
        ),
        read=lambda *_: pytest.fail("not a regular file"),
        close=lambda fd: calls.append(("close", fd)),
    ))
    with pytest.raises(vm.NativeVMReadOnlyError, match="FIXED_READ_UNSAFE"):
        vm._read_fixed("/etc/os-release", 8192)
    assert calls == [("open", "/etc/os-release"), ("close", 99)]


def test_actual_docker_userspace_cannot_claim_complete_host_acceptance():
    result = vm.inspect_booted_vm_nginx_readonly()
    assert result["complete_server_acceptance_passed"] is False
    assert result["host_root_attested"] is False
    assert result["authorizes_nginx_reload"] is False


def test_sysfs_virtual_attribute_size_does_not_mask_enforcing_status(monkeypatch):
    # sysfs regular attrs can have st_size=4096 but return b"1\\n".
    events = []
    monkeypatch.setattr(vm, "os", SimpleNamespace(
        O_RDONLY=os.O_RDONLY, O_NONBLOCK=os.O_NONBLOCK,
        O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
        open=lambda *_: 83,
        fstat=lambda _: SimpleNamespace(st_mode=stat.S_IFREG | 0o444,
                                        st_size=4096),
        read=lambda fd, size: b"1\\n",
        close=lambda fd: events.append(fd),
    ))
    assert vm._read_fixed("/sys/fs/selinux/enforce", 32) == b"1\\n"
    assert events == [83]
