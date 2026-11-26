#!/usr/bin/env python3
"""Disposable booted Debian fixture: a parsed APT source can outlive rollback.

Trace only our own apt-get child until entry to its real lists-lock syscall.
No installed source writer, host edits, ptrace setting or signature bypass.
"""
from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import ssl
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


def _at_lists_lock(child, lock: Path, *, namespace_alias=False):
    expected = lock.stat()
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
                if namespace_alias:
                    # Only the traced child can hold this exact private inode.
                    # The path is different inside its mount namespace.
                    observed = os.stat(f"/proc/{child.pid}/fd/{entry.args[0]}")
                    if (observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino):
                        return
                elif actual == str(lock):
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


# Mounts exist only in the new child namespace; no host path is created,
# relabelled, or unmounted. The parent retains its original namespace.
_NAMESPACE_TRACE_CHILD = r"""
import os, sys, subprocess
from pathlib import Path
root, view = map(Path, sys.argv[1:3])
assert os.getresuid() == (0, 0, 0)
assert root.name == 'transaction' and view == root.parent / 'view'
assert root.parent.name == 'journal'
assert root.parent.parent.name.startswith('repocache-booted-apt-reader-')
assert root.resolve(strict=True) == root and view.resolve(strict=True) == view
assert os.readlink('/proc/self/ns/mnt') != sys.argv[3]
assert (root / '.repocache-recoverable-pair-test').is_file()
subprocess.run(['/usr/bin/mount', '--bind', str(root / 'etc/apt'), '/etc/apt'],
               check=True, timeout=10)
subprocess.run(['/usr/bin/mount', '--bind', str(root / 'var'), str(view)],
               check=True, timeout=10)
assert os.stat('/etc/apt').st_ino == (root / 'etc/apt').stat().st_ino
assert view.stat().st_ino == (root / 'var').stat().st_ino
""" + _TRACE_CHILD


def _journal_cycle(case, primary, upstream, keyring, ca):
    """Prove actual journal recovery, not a manual simulation, for a stale APT reader."""
    from smoke_client_recoverable_pair import build
    import recoverable_fallback_pair_lab as pair
    import root_source_boundary as boundary

    assert case.name == "journal" and case.parent.parent == Path("/tmp")
    assert case.parent.name.startswith("repocache-booted-apt-reader-")
    case.mkdir(mode=0o755)
    case.chmod(0o755)
    root, view = case / "transaction", case / "view"
    root.mkdir(mode=0o700)
    view.mkdir(mode=0o755)
    source, _, _, state = build(root, "apt")
    etc = root / "etc/apt"
    keys = etc / "keyrings"
    keys.mkdir(mode=0o755)
    shutil.copyfile(keyring, keys / "repocache-ci.gpg")
    (keys / "repocache-ci.gpg").chmod(0o644)
    original = (f"deb [signed-by=/etc/apt/keyrings/repocache-ci.gpg] "
                f"{upstream.origin} stable main\n").encode("ascii")
    source.write_bytes(original)
    for name in ("apt.conf.d", "empty-parts"):
        (etc / name).mkdir(mode=0o755)
    (etc / "apt.conf").touch(mode=0o644, exist_ok=False)
    for relative in ("var/lib/apt/lists/partial", "var/cache/apt/archives/partial",
                     "var/log/apt"):
        (root / relative).mkdir(parents=True, mode=0o755)
    status = root / "var/lib/dpkg/status"
    status.touch(mode=0o644, exist_ok=False)
    (root / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    config = root / "etc/repocache-client"
    config.mkdir(mode=0o755)
    server = primary.origin.removesuffix("/repo/")
    route = server + "/__repocache/repos/approved/"
    (config / "config.json").write_text(json.dumps({"server": server}))
    (config / "config.json").chmod(0o644)
    catalog = case.parent / "www/.well-known/repocache/catalog.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(json.dumps({"schema": 1, "repositories": [
        {"upstream": upstream.origin, "cache": route}]}))
    (state / ("candidate-" + "a" * 32 + ".json")).unlink()
    digest = hashlib.sha256(original).hexdigest()
    old_context = boundary._native_tls_context
    trusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trusted.load_verify_locations(cafile=str(ca))
    try:
        boundary._native_tls_context = lambda: trusted
        prepared = boundary.prepare_current_candidate(digest, digest, _test_root=root)
        ident = prepared["managed_id"]
        review = boundary.review_current_candidate(ident, _test_root=root)
        assert review["upstream"] == upstream.origin and review["cache"] == route
        approved = boundary.approve_current_candidate(
            ident, review["route_sha256"], _test_root=root)
        assert approved["status"] == "approved"
        pid = os.fork()
        if pid == 0:
            def kill_at(active, phase):
                if active == phase:
                    os.kill(os.getpid(), signal.SIGKILL)
            pair._crash = kill_at
            pair.apply_retaining_apt_companion_sandbox(root, ident, crash="source")
            os._exit(77)
        _, killed = os.waitpid(pid, 0)
        assert os.WIFSIGNALED(killed) and os.WTERMSIG(killed) == signal.SIGKILL
    finally:
        boundary._native_tls_context = old_context
    mirror = etc / "mirrors" / ("repocache-" + ident + ".list")
    assert source.read_bytes() != original and mirror.read_bytes().startswith(route.encode())
    primary.hits.clear()
    upstream.hits.clear()
    primary.mode = "unavailable"
    config_file = case / "fixture.conf"
    config_file.write_text(
        'Dir::Etc "/etc/apt";\nDir::Etc::main "apt.conf";\n'
        'Dir::Etc::parts "apt.conf.d";\nDir::Etc::sourcelist "sources.list.d/base.list";\n'
        'Dir::Etc::sourceparts "empty-parts";\n'
        f'Dir::State "{view}/lib/apt";\nDir::State::status "{view}/lib/dpkg/status";\n'
        f'Dir::Cache "{view}/cache/apt";\nDir::Log "{view}/log/apt";\n'
        'APT::Update::Error-Mode "any";\nAcquire::Retries "0";\nAcquire::Languages "none";\n'
        f'Acquire::https::CaInfo "{ca}";\n'
        'Acquire::https::Verify-Peer "true";\nAcquire::https::Verify-Host "true";\n',
        encoding="ascii")
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "APT_CONFIG": str(config_file)}
    parent_ns = os.readlink("/proc/self/ns/mnt")
    host_apt = Path("/etc/apt").stat()
    log = case / "output.txt"
    try:
        with log.open("xb") as output:
            child = subprocess.Popen(
                ["/usr/bin/unshare", "--mount", "--propagation", "private",
                 sys.executable, "-I", "-c", _NAMESPACE_TRACE_CHILD,
                 str(root), str(view), parent_ns],
                env=env, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.STDOUT, start_new_session=True)
            try:
                _at_lists_lock(child, root / "var/lib/apt/lists/lock",
                               namespace_alias=True)
                assert os.readlink(f"/proc/{child.pid}/ns/mnt") != parent_ns
                assert pair.recover_sandbox(root, ident)["status"] == "restored"
                assert source.read_bytes() == original
                assert mirror.read_bytes() == (upstream.origin + "\tpriority:1\n").encode()
                retained_inode = mirror.stat().st_ino
                _ptrace(17, child.pid)
                result = child.wait(timeout=45)
            finally:
                if child.returncode is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    _, stopped = os.waitpid(child.pid, 0)
                    child.returncode = os.waitstatus_to_exitcode(stopped)
        assert result == 0, log.read_text(errors="replace")[-3000:]
        assert upstream.hits and not primary.hits
        assert "Download is performed unsandboxed as root" not in log.read_text()
        assert status.read_bytes() == b""
        assert pair.recover_sandbox(root, ident)["status"] == "restored"
        assert mirror.stat().st_ino == retained_inode
        assert source.read_bytes() == original
        assert not list(view.iterdir())  # the mount never propagated to the parent
        assert os.readlink("/proc/self/ns/mnt") == parent_ns
        now = Path("/etc/apt").stat()
        assert (now.st_dev, now.st_ino) == (host_apt.st_dev, host_apt.st_ino)
        print("PASS: actual journal SIGKILL recovery preserves a previously parsed "
              "APT source in a private mount namespace; signed HTTPS metadata "
              "from upstream only, no cache or host source mutation", flush=True)
    finally:
        primary.mode = "healthy"


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
                _journal_cycle(base / "journal", primary, upstream, keyring, ca)
            finally:
                upstream.close()
        finally:
            primary.close()
        print("PASS: upstream-only companion preserves signed HTTPS fallback for an earlier reader; "
              "not a production lifecycle or revocation proof", flush=True)
