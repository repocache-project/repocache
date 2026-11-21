#!/usr/bin/env python3
"""PR237: interrupt an ACTUAL signed-distro APT/DNF process in a disposable VM.

Synthetic release keys only. This script never executes on the runner host.
It does not pretend that native package side effects are atomically reversible.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

FIXTURE = Path("/root/pr237-synthetic-fixture")
STATE = Path("/var/lib/repocache/server")
SOURCE = Path("/home/pr237ci/combined")
RECORD = FIXTURE / "native-manager-interrupted.json"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, capture_output=True, text=True, check=False, timeout=25,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL,
    )


def facts(distribution: str) -> None:
    assert distribution in ("debian", "almalinux")
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert run("/usr/bin/systemd-detect-virt", "--vm").returncode == 0
    if distribution == "almalinux":
        assert run("/usr/sbin/getenforce").stdout.strip() == "Enforcing"
    assert STATE.is_dir()
    assert not RECORD.exists() or RECORD.stat().st_uid == 0


def pending() -> tuple[bytes, os.stat_result]:
    from repocache.server_native_nginx_package_journal_v1 import (
        NATIVE_PENDING_NAME, NATIVE_TMP_NAME, NATIVE_COMPLETE_NAME,
    )
    marker = STATE / NATIVE_PENDING_NAME
    info = marker.lstat()
    assert stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
    assert info.st_uid == 0 and info.st_gid == 0 and info.st_nlink == 1
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert not (STATE / NATIVE_TMP_NAME).exists()
    assert not (STATE / NATIVE_COMPLETE_NAME).exists()
    raw = marker.read_bytes()
    assert 0 < len(raw) < 2048
    return raw, info


def direct_manager(installer_pid: int, distribution: str) -> int | None:
    """Identify an actual pinned OS APT/DNF program, owned by our installer.

    DNF4 on AlmaLinux may exec an OS Python interpreter and refer to the
    distribution DNF script via a *different symlink name*. Compare the
    script's native inode with the trusted fixed executable, never merely
    match the untrusted argv basename. This test does not log proc content.
    """
    os_manager = "/usr/bin/apt-get" if distribution == "debian" else "/usr/bin/dnf"
    trusted = os.stat(os_manager)
    expected_inode = trusted.st_dev, trusted.st_ino
    with os.scandir("/proc") as processes:
        for entry in processes:
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            pid = int(entry.name)
            if pid <= 1 or pid == installer_pid:
                continue
            try:
                status = (Path("/proc") / entry.name / "status").read_bytes()[:4096]
                ppid_lines = [
                    line for line in status.splitlines() if line.startswith(b"PPid:")
                ]
                if len(ppid_lines) != 1 or int(ppid_lines[0].split()[1]) != installer_pid:
                    continue
                path = Path("/proc") / entry.name / "cmdline"
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    raw = os.read(fd, 1024)
                finally:
                    os.close(fd)
                args = raw.rstrip(b"\0").split(b"\0")
                if not args or not args[0]:
                    continue

                def same_manager(token: bytes) -> bool:
                    if not token.startswith((b"/usr/bin/", b"/usr/libexec/")):
                        return False
                    try:
                        path_stat = os.stat(os.fsdecode(token))
                    except (OSError, ValueError, UnicodeError):
                        return False
                    return (path_stat.st_dev, path_stat.st_ino) == expected_inode

                if same_manager(args[0]):
                    return pid
                # A DNF4 executable may be a shebang script. Its Python
                # interpreter is the first argv; the signed OS script may
                # appear after -s or a canonicalized dnf-3 name.
                executable = args[0]
                interpreter = (
                    executable in (b"/usr/libexec/platform-python", b"/usr/bin/python3")
                    or executable.startswith(b"/usr/bin/python3.")
                )
                if (distribution == "almalinux" and interpreter
                        and any(same_manager(arg) for arg in args[1:5])):
                    return pid
            except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
                continue
    return None

def interrupt(distribution: str) -> None:
    from repocache.server_native_nginx_package_journal_v1 import (
        NATIVE_PENDING_NAME, NATIVE_COMPLETE_NAME,
    )
    from scripts import install_native_root_worker, stage_native_root_worker
    pins = json.loads((FIXTURE / "pins.json").read_bytes())
    assert set(pins) == {"commit", "archive_sha256"}
    assets = FIXTURE / "assets"
    assert stage_native_root_worker.verify_installed_worker(
        assets, **pins,
    )["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    assert not Path("/usr/sbin/nginx").exists()
    assert not Path("/etc/nginx").exists()
    assert not (STATE / NATIVE_PENDING_NAME).exists()
    assert not (STATE / NATIVE_COMPLETE_NAME).exists()
    assert not RECORD.exists()
    raw = (SOURCE / "docs/examples/server-install-v1.json").read_bytes()
    doc = FIXTURE / "reviewed-install.json"
    fd = os.open(doc, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    digest = hashlib.sha256(raw).hexdigest()

    installer_pid = os.fork()
    if installer_pid == 0:
        # A separate OS process runs the actual authenticated native
        # installer and its unmodified subprocess.run APT/DNF command.
        try:
            install_native_root_worker.install_authenticated_native_nginx(
                assets, doc, digest, **pins,
            )
        except Exception as exc:
            # Keep native exception details PRIVATE; only a fixed class
            # and an uppercase redacted code may leave the child.
            code = str(exc)
            if re.fullmatch(r"[A-Z][A-Z0-9_]{3,120}", code) is None:
                code = "REDACTED"
            classification = (
                "CHILD_EXCEPTION_CLASS=" + type(exc).__name__ + "\n"
                + "CHILD_EXCEPTION_CODE=" + code + "\n"
            )
            diagnostic = FIXTURE / "native-interrupt-child-status.txt"
            try:
                fd = os.open(
                    diagnostic, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(fd, "w", encoding="ascii") as record:
                    record.write(classification)
                    record.flush()
                    os.fsync(record.fileno())
            except OSError:
                pass
            os._exit(44)
        os._exit(0)

    observed_manager = False
    deadline = time.monotonic() + 150
    try:
        while time.monotonic() < deadline:
            ended, status = os.waitpid(installer_pid, os.WNOHANG)
            if ended:
                # A fast finish must not be misclassified as having killed
                # the actual manager. Expose only fixed diagnostic codes.
                reason = FIXTURE / "native-interrupt-child-status.txt"
                if reason.exists():
                    lines = reason.read_text(encoding="ascii").splitlines()
                    for line in lines:
                        if re.fullmatch(r"CHILD_EXCEPTION_(?:CLASS|CODE)=[A-Za-z0-9_]+", line):
                            print("DIAGNOSTIC: " + line, flush=True)
                print(
                    "DIAGNOSTIC: native installer exited with "
                    + str(os.waitstatus_to_exitcode(status)),
                    flush=True,
                )
                raise AssertionError("Native installer ended before manager interruption")
            manager_pid = direct_manager(installer_pid, distribution)
            if manager_pid is not None:
                # Pin the kernel task identity BEFORE a destructive signal.
                # A numerical PID may be recycled after a /proc scan; a
                # pidfd cannot silently retarget another process.
                try:
                    pidfd = os.pidfd_open(manager_pid, 0)
                except ProcessLookupError:
                    continue
                try:
                    if direct_manager(installer_pid, distribution) != manager_pid:
                        continue
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    observed_manager = True
                    break
                except ProcessLookupError:
                    pass
                finally:
                    os.close(pidfd)
            time.sleep(0.02)
        if not observed_manager:
            raise AssertionError("No actual direct APT/DNF manager was observed and killed")
        # The installer must fail from the real killed native subprocess.
        child_end = time.monotonic() + 35
        while time.monotonic() < child_end:
            ended, result = os.waitpid(installer_pid, os.WNOHANG)
            if ended:
                assert os.waitstatus_to_exitcode(result) == 44
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Native installer did not reject killed package manager")
    finally:
        # Do not leave any unexpected process running in this disposable VM.
        try:
            os.kill(installer_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(installer_pid, os.WNOHANG)
        except ChildProcessError:
            pass

    original, info = pending()
    assert run("/usr/bin/systemctl", "is-enabled", "nginx.service").stdout.strip() == "masked"
    assert run("/usr/bin/systemctl", "is-active", "nginx.service").returncode != 0
    record = {
        "distribution": distribution,
        "manager": "apt" if distribution == "debian" else "dnf",
        "actual_manager_process_sigkill_observed": True,
        "synthetic_journal_only": False,
        "journal_sha256": hashlib.sha256(original).hexdigest(),
        "journal_inode": info.st_ino,
        "journal_mtime_ns": info.st_mtime_ns,
    }
    result = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    fd = os.open(RECORD, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(result)
        output.flush()
        os.fsync(output.fileno())
    print("PASS: actual apt/dnf subprocess SIGKILL during authenticated native install", flush=True)
    print("PASS: real interrupted manager retained durable root-owned pending journal and service mask", flush=True)


def after(distribution: str) -> None:
    from repocache.server_native_nginx_package_journal_v1 import (
        NativePackageJournalError, _prepare_native_journal_under_root,
    )
    from scripts import stage_native_root_worker
    record = json.loads(RECORD.read_bytes())
    assert record["distribution"] == distribution
    assert record["actual_manager_process_sigkill_observed"] is True
    assert record["synthetic_journal_only"] is False
    raw, info = pending()
    assert hashlib.sha256(raw).hexdigest() == record["journal_sha256"]
    assert (info.st_ino, info.st_mtime_ns) == (
        record["journal_inode"], record["journal_mtime_ns"],
    )
    assert run("/usr/bin/systemctl", "is-enabled", "nginx.service").stdout.strip() == "masked"
    assert run("/usr/bin/systemctl", "is-active", "nginx.service").returncode != 0
    pins = json.loads((FIXTURE / "pins.json").read_bytes())
    assert stage_native_root_worker.verify_installed_worker(
        FIXTURE / "assets", **pins,
    )["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    rootfd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for _ in (1, 2):
            try:
                _prepare_native_journal_under_root(
                    rootfd, owner_uid=0, distribution=distribution,
                )
            except NativePackageJournalError as error:
                assert str(error) == "NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED"
            else:
                raise AssertionError("Unsafe reentry after real package manager interruption")
            assert pending()[0] == raw
            later = pending()[1]
            assert (later.st_ino, later.st_mtime_ns) == (info.st_ino, info.st_mtime_ns)
    finally:
        os.close(rootfd)
    for unit in ("repocache-control.service", "repocache-control.socket"):
        assert run("/usr/bin/systemctl", "is-active", unit).returncode != 0
    print("PASS: real kernel reboot retained interrupted APT/DNF journal and NGINX mask", flush=True)
    print("PASS: repeated package-manager retry denied; no auto-reinstall or control service activation", flush=True)
    print("NOT VERIFIED: automatic native package side-effect rollback; requires explicit reconciliation", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("debian", "almalinux"):
        raise SystemExit("Usage: ci_pr237_native_package_interrupt_guest.py distribution interrupt|after")
    sys.path[:0] = [str(SOURCE / "src"), str(SOURCE)]
    platform, stage = sys.argv[1:]
    facts(platform)
    if stage == "interrupt":
        interrupt(platform)
    elif stage == "after":
        after(platform)
    else:
        raise SystemExit("Invalid interrupt stage")
