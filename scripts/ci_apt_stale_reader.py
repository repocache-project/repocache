#!/usr/bin/env python3
"""Disposable booted Debian fixture: a parsed APT source can outlive rollback.

Trace only our own apt-get child until entry to its real lists-lock syscall.
No installed source writer, host edits, ptrace setting or signature bypass.
"""
from __future__ import annotations

import ctypes
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from ci_client_native_fallback import HTTPBackend, apt_repository, temporary_tls_identity
from ci_v06_vm_signed_client_guest import guarded_native_guest
import native_package_lock_observation as locks

# Linux PTRACE_GET_SYSCALL_INFO entry layout and x86-64 syscall ABI. This
# fixture is part of the existing x86-64 QEMU campaign, not product code.
class _SyscallEntry(ctypes.Structure):
    _fields_ = [("op", ctypes.c_uint8), ("pad", ctypes.c_uint8 * 3),
                ("arch", ctypes.c_uint32), ("ip", ctypes.c_uint64),
                ("sp", ctypes.c_uint64), ("nr", ctypes.c_uint64),
                ("args", ctypes.c_uint64 * 6)]


def _ptrace(request, pid, address=0, data=0):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    libc.ptrace.restype = ctypes.c_long
    result = libc.ptrace(request, pid, address, data)
    if result == -1:
        raise OSError(ctypes.get_errno(), "Disposable child ptrace failed")
    return result


# Fixed child wrapper; never attach to an existing PID or run a shell.
_TRACE_CHILD = r"""
import ctypes, os, signal
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
libc.ptrace.restype = ctypes.c_long
if libc.ptrace(0, 0, 0, 0) != 0:
    raise SystemExit('PTRACE_TRACEME failed')
os.kill(os.getpid(), signal.SIGSTOP)
os.execve('/usr/bin/apt-get', ['apt-get', 'update'], dict(os.environ))
"""


def _wait_stop(child, deadline):
    while time.monotonic() < deadline:
        pid, status = os.waitpid(child.pid, os.WNOHANG | os.WUNTRACED)
        if pid:
            if not os.WIFSTOPPED(status):
                child.returncode = os.waitstatus_to_exitcode(status)
                raise AssertionError("APT exited before native lists-lock barrier")
            return os.WSTOPSIG(status)
        time.sleep(0.0005)
    raise TimeoutError("APT lists-lock barrier timed out")


def _at_lists_lock(child, lock: Path):
    deadline = time.monotonic() + 45
    assert _wait_stop(child, deadline) == signal.SIGSTOP
    _ptrace(0x4200, child.pid, 0, 0x100001)  # TRACESYSGOOD | EXITKILL
    deliver = 0
    for _ in range(20000):
        _ptrace(24, child.pid, 0, deliver)  # PTRACE_SYSCALL
        stopped = _wait_stop(child, deadline)
        deliver = 0
        if stopped == (signal.SIGTRAP | 0x80):
            entry = _SyscallEntry()
            size = _ptrace(0x420e, child.pid, ctypes.sizeof(entry), ctypes.addressof(entry))
            if entry.op != 1:
                continue
            assert size >= ctypes.sizeof(entry) and entry.arch == 0xc000003e
            if entry.nr == 72 and entry.args[1] == fcntl.F_SETLK:
                try:
                    actual = os.readlink(f"/proc/{child.pid}/fd/{entry.args[0]}")
                except FileNotFoundError:
                    continue
                if actual == str(lock):
                    return
        elif stopped != signal.SIGTRAP:
            deliver = stopped
    raise AssertionError("APT did not enter the exact native lists-lock syscall")


def _replace_fixture(path: Path, content: str):
    stage = path.with_name(path.name + ".next")
    with stage.open("x", encoding="ascii") as handle:
        handle.write(content)
        os.fchmod(handle.fileno(), 0o644)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(stage, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _cycle(root, primary, upstream, keyring, ca, mode):
    assert mode in ("retained", "removed", "upstream-only") and root.name == mode
    assert root.parent.parent == Path("/tmp")
    assert root.parent.name.startswith("repocache-booted-apt-reader-")
    assert root.parent.resolve(strict=True) == root.parent and root.parent.stat().st_uid == 0
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    etc = root / "etc/apt"
    lists = root / "var/lib/apt/lists"
    for directory in (lists / "partial", root / "var/cache/apt/archives/partial",
                      root / "var/log/apt", etc / "empty-parts", etc / "apt.conf.d"):
        directory.mkdir(mode=0o700, parents=True)
    etc.parent.chmod(0o755)
    etc.chmod(0o755)
    for relative in locks.APT:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(mode=0o600, exist_ok=False)
    status = root / "var/lib/dpkg/status"
    status.touch(exist_ok=False)
    (etc / "apt.conf").touch(exist_ok=False)
    source = etc / "fixture.list"
    mirror = etc / "mirror.list"
    original = f"deb [signed-by={keyring}] {upstream.origin} stable main\n"
    source.write_text(f"deb [signed-by={keyring}] mirror+file:{mirror} stable main\n", encoding="ascii")
    mirror.write_text(primary.origin + "\tpriority:1\n" + upstream.origin + "\tpriority:2\n",
                      encoding="ascii")
    source.chmod(0o644)
    mirror.chmod(0o644)
    config = etc / "fixture.conf"
    config.write_text(
        f'Dir "{root}/";\n'
        'Dir::Etc "etc/apt";\nDir::Etc::main "apt.conf";\n'
        'Dir::Etc::parts "apt.conf.d";\nDir::Etc::sourcelist "fixture.list";\n'
        'Dir::Etc::sourceparts "empty-parts";\nDir::State "var/lib/apt";\n'
        f'Dir::State::status "{status}";\nDir::Cache "var/cache/apt";\n'
        'Dir::Log "var/log/apt";\nAPT::Update::Error-Mode "any";\n'
        'Acquire::Retries "0";\nAcquire::Languages "none";\n'
        f'Acquire::https::CaInfo "{ca}";\n'
        'Acquire::https::Verify-Peer "true";\nAcquire::https::Verify-Host "true";\n',
        encoding="ascii")
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "APT_CONFIG": str(config)}
    primary.hits.clear()
    upstream.hits.clear()
    log = root / "output.txt"
    with log.open("xb") as output:
        child = subprocess.Popen([sys.executable, "-I", "-c", _TRACE_CHILD], env=env,
                                 stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            _at_lists_lock(child, lists / "lock")
            # The actual APT reader has not acquired its lists lock yet.
            # Simulate only the fixture's source/companion rollback under
            # the real REPOCACHE lock primitive, release, then resume it.
            with locks.hold_existing_native_package_locks(
                    "apt", root=root, revalidation=True) as recheck:
                if mode == "upstream-only":
                    _replace_fixture(mirror, upstream.origin + "\tpriority:1\n")
                    recheck()
                _replace_fixture(source, original)
                recheck()
                if mode == "removed":
                    mirror.unlink()
                recheck()
            _ptrace(17, child.pid)  # PTRACE_DETACH and resume
            result = child.wait(timeout=45)
        finally:
            if child.returncode is None:
                os.killpg(child.pid, signal.SIGKILL)
                _, stopped = os.waitpid(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(stopped)
    assert source.read_text(encoding="ascii") == original
    assert status.read_bytes() == b""
    assert log.stat().st_size <= 1024 * 1024
    observed = log.read_text(encoding="utf-8")
    if mode == "removed":
        assert result == 100 and str(mirror) in observed
        assert "File not found" in observed and "Downloading mirror file failed" in observed
        assert not primary.hits and not upstream.hits
    elif mode == "retained":
        assert result == 0 and primary.hits and not upstream.hits, observed[-1000:]
    elif mode == "upstream-only":
        assert result == 0 and upstream.hits and not primary.hits, observed[-1000:]
    print("PASS: actual APT stale source reader, companion " + mode, flush=True)


def probe():
    guarded_native_guest("debian13")
    assert os.uname().machine == "x86_64"
    with tempfile.TemporaryDirectory(prefix="repocache-booted-apt-reader-", dir="/tmp") as work:
        base = Path(work)
        base.chmod(0o755)  # Public fixture metadata/key only; private keys remain 0600.
        keyring = apt_repository(base)
        ca, private = temporary_tls_identity(base, "stale-source")
        primary = HTTPBackend(base / "www", certificate=ca, key=private)
        try:
            upstream = HTTPBackend(base / "www", certificate=ca, key=private)
            try:
                for mode in ("retained", "removed", "upstream-only"):
                    _cycle(base / mode, primary, upstream, keyring, ca, mode)
            finally:
                upstream.close()
        finally:
            primary.close()
        print("PASS: upstream-only companion preserves signed HTTPS fallback for an earlier reader; "
              "not a production lifecycle or revocation proof", flush=True)
