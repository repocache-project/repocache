#!/usr/bin/env python3
"""Native DNF signed-RPM download/fallback regression, disposable CI only (#24).

Builds and signs a noarch fixture RPM under an isolated temporary directory,
then checks actual DNF HTTPS preference/fallback and signed metadata. It
NEVER installs a test package, touches a host source, or uses publisher keys.
A production client writer remains disabled and #24 host gates remain OPEN.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_client_native_fallback as native


_PACKAGE = "repocache-ci-rpm-probe"
_RPM_NAME = _PACKAGE + "-0.0.1-1.noarch.rpm"
_SPEC = """Name: repocache-ci-rpm-probe
Version: 0.0.1
Release: 1
Summary: Disposable REPOCACHE CI RPM, NEVER install
License: MIT
BuildArch: noarch

%description
Synthetic signed native package transport fixture for disposable CI.

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/doc/repocache-ci-rpm-probe
printf 'CI ONLY. NEVER INSTALL.\\n' > %{buildroot}/usr/share/doc/repocache-ci-rpm-probe/README

%files
/usr/share/doc/repocache-ci-rpm-probe/README
"""


def _only_in_disposable_root() -> None:
    if (os.geteuid() != 0
            or not Path("/.dockerenv").is_file()
            or os.environ.get("REPOCACHE_DISPOSABLE_NATIVE_CI") != "1"
            or not Path("/workspace/scripts/ci_client_native_fallback.py").is_file()):
        raise RuntimeError("Refuse signed RPM test outside explicitly disposable CI Docker")


def _run(argv: list[str], *, cwd: Path | None = None,
         env: dict[str, str] | None = None) -> str:
    process = subprocess.run(
        argv, cwd=cwd, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=120, check=False,
    )
    if process.returncode != 0:
        # No key bytes or commands containing secrets are emitted.
        raise RuntimeError("Disposable native RPM fixture command failed: " + argv[0])
    return process.stdout


def _rpm_signature_verified(output: str) -> bool:
    """Require a positive trusted RPM signature, not just a valid digest.

    rpm -Kv can return success for a digest-valid *unsigned* RPM. A test
    acceptance must contain at least one signed result ending in OK, and
    no NOKEY, BAD or failed signature status.
    """
    if type(output) is not str or len(output) > 8192:
        return False
    lower = output.lower()
    if any(marker in lower for marker in (
        "nokey", "not ok", "bad signature", "not signed", "no signature",
    )):
        return False
    return any(
        "signature" in line.lower()
        and line.strip().lower().endswith((" ok", ": ok"))
        for line in output.splitlines()
    )


def _label_isolated_rpmdb(rpmdb: Path) -> None:
    """Apply the distro's RPMDB label to the empty disposable DB only.

    In an enforcing guest rpm runs in its confined domain and cannot create
    a transaction lock in an ordinary tmp_t directory. Use the actual
    distro RPMDB directory as a label reference, not as a database.
    Never relabel a host path or disable enforcement.
    """
    if (rpmdb.parent != Path("/var/lib")
            or not rpmdb.name.startswith("repocache-ci-rpmdb-") or rpmdb.resolve(strict=True) != rpmdb
            or rpmdb.stat().st_uid != 0 or any(rpmdb.iterdir())):
        raise RuntimeError("Unsafe isolated RPMDB label target")
    _apply_disposable_rpmdb_label(rpmdb)


def _apply_disposable_rpmdb_label(rpmdb: Path) -> None:
    """Private label operation, called only after the disposable path guard."""
    if _run(["getenforce"]).strip() != "Enforcing":
        raise RuntimeError("Booted RPM fixture requires SELinux Enforcing")
    reference = Path("/usr/lib/sysimage/rpm")
    if not reference.is_dir():
        raise RuntimeError("Native RPMDB label reference missing")
    expected = os.getxattr(reference, "security.selinux")
    if expected.split(b":")[2] != b"rpm_var_lib_t":
        raise RuntimeError("Unexpected native RPMDB label type")
    _run(["chcon", "--reference=" + str(reference), str(rpmdb)])
    if os.getxattr(rpmdb, "security.selinux") != expected:
        raise RuntimeError("Isolated RPMDB label verification failed")


def _rpm_waiter(table: str, pid: int, info: os.stat_result) -> bool:
    """Require a kernel-reported POSIX waiter on the exact RPMDB lock."""
    if len(table) > 1_000_000:
        raise RuntimeError("Unexpected native lock table size")
    expected = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
    for line in table.splitlines():
        parts = line.split()
        if (len(parts) != 9 or parts[1:4] != ["->", "POSIX", "ADVISORY"]
                or parts[4] not in ("READ", "WRITE") or parts[5] != str(pid)):
            continue
        try:
            major, minor, inode = parts[6].split(":")
            identity = (int(major, 16), int(minor, 16), int(inode))
        except ValueError:
            continue
        if identity == expected:
            return True
    return False


def _import_under_native_lock(rpmdb: Path, public_key: Path) -> None:
    """Exercise real RPM contention only against the isolated booted-VM DB.

    No host DB, no package installation, no change to system trust. The
    positive import happens only after our two kernel locks are released.
    """
    from ci_v06_vm_signed_client_guest import guarded_native_guest

    guarded_native_guest("almalinux10")
    if (rpmdb.parent != Path("/var/lib")
            or not rpmdb.name.startswith("repocache-ci-rpmdb-")
            or rpmdb.resolve(strict=True) != rpmdb
            or rpmdb.stat().st_uid != 0
            or rpmdb.stat().st_mode & 0o077):
        raise RuntimeError("Unsafe isolated RPMDB contention target")
    lock = rpmdb / ".rpm.lock"
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        named = lock.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != 0 or info.st_mode & 0o022
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise RuntimeError("Unsafe isolated RPMDB lock inode")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        argv = ["/usr/bin/rpm", "--dbpath", str(rpmdb), "--import", str(public_key)]
        with subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        ) as child:
            try:
                deadline = time.monotonic() + 10
                observed_wait = False
                while child.poll() is None and time.monotonic() < deadline:
                    with Path("/proc/locks").open(encoding="ascii") as table:
                        observed_wait = _rpm_waiter(table.read(1_000_001), child.pid, info)
                    if observed_wait:
                        break
                    time.sleep(0.05)
                if not observed_wait:
                    if child.poll() is None:
                        raise RuntimeError("RPM blocking reason not proven by kernel lock table")
                    output, _ = child.communicate(timeout=2)
                    if (child.returncode == 0 or "transaction lock" not in output.lower()
                            or str(lock) not in output
                            or "resource temporarily unavailable" not in output.lower()):
                        raise RuntimeError("RPM did not refuse the exact held transaction lock")
                # If it waits, terminate and reap it BEFORE releasing our
                # lock; no positive import may be inferred from a timeout.
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)
        named = lock.lstat()
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise RuntimeError("RPMDB lock pathname changed during contention")
    finally:
        os.close(fd)
    _run(argv, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    print("PASS: real RPM import excluded by held isolated RPMDB lock; succeeds after release",
          flush=True)


def _native_dnf_transaction_variant() -> tuple[str, str]:
    """Select the installed distro command, never install a test dependency."""
    if Path("/usr/bin/dnf5").is_file():
        return "/usr/bin/dnf5", "dnf5"
    if Path("/usr/bin/dnf").is_file():
        version = _run(["/usr/bin/dnf", "--version"]).splitlines()
        if version and version[0].strip().startswith("4."):
            return "/usr/bin/dnf", "dnf4"
    raise RuntimeError("Unsupported native DNF executable/version")


def _dnf_transaction_test_command(root: Path, package: Path) -> list[str]:
    """Only the fixed local signed fixture, with RPM transaction TEST mode."""
    if (root.parent != Path("/var/lib")
            or not root.name.startswith("repocache-ci-dnf-root-")
            or root.resolve(strict=True) != root
            or root.stat().st_uid != 0 or root.stat().st_mode & 0o077
            or package.name != _RPM_NAME or not package.is_file()
            or package.is_symlink()):
        raise RuntimeError("Unsafe isolated DNF transaction test")
    executable, variant = _native_dnf_transaction_variant()
    disable = "--disable-repo=*" if variant == "dnf5" else "--disablerepo=*"
    lock_options = [] if variant == "dnf5" else ["--setopt=exit_on_lock=1"]
    return [
        executable, "--installroot=" + str(root), "--releasever=10",
        "--config=" + str(root / "etc/dnf/dnf.conf"),
        "--setopt=plugins=0", disable, *lock_options,
        "--setopt=localpkg_gpgcheck=1",
        "--setopt=tsflags=test,noscripts,notriggers,noplugins",
        "--assumeyes", "install", str(package),
    ]


@contextlib.contextmanager
def _private_dnf4_claim(root: Path):
    """Reuse the marked-root journal lab's guarded DNF4 lock protocol."""
    from ci_v06_vm_signed_client_guest import guarded_native_guest
    guarded_native_guest("almalinux10")
    assert _native_dnf_transaction_variant() == ("/usr/bin/dnf", "dnf4")
    assert root.parent == Path("/var/lib") and root.name.startswith("repocache-ci-dnf-root-")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
    import recoverable_fallback_pair_lab as pair
    with pair._dnf4_private_claim(root) as recheck:
        yield recheck


def _probe_private_dnf4_claim(root, argv, lock, env):
    """Exercise the real DNF4 PID protocol, including interrupted ownership."""
    # Existing foreign or stale records must not be rewritten by our helper.
    lock.write_bytes(b"99999999")
    lock.chmod(0o600)
    foreign = lock.stat()
    try:
        with _private_dnf4_claim(root):
            raise AssertionError("Foreign PID was claimed")
    except FileExistsError:
        pass
    assert lock.stat().st_ino == foreign.st_ino and lock.read_bytes() == b"99999999"
    lock.unlink()  # only our just-created negative-control fixture

    with _private_dnf4_claim(root) as recheck:
        info = lock.stat()
        refused = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, env=env, timeout=90, check=False)
        assert refused.returncode == 200 and (
            f"rpmdb already locked by {os.getpid()}" in refused.stdout.lower()), refused.stdout[-1800:]
        recheck()
        assert lock.stat().st_ino == info.st_ino
        # Real DNF reads repository definitions despite the RPM transaction
        # lock. No origin access: disabled local canary + cache-only command.
        repo = root / "etc/yum.repos.d/repocache-lock-reader.repo"
        repo.write_text("[repocache-lock-reader]\nname=Private read canary\n"
                        "baseurl=https://127.0.0.1:9/repo/\nenabled=0\n"
                        "gpgcheck=1\nrepo_gpgcheck=1\n", encoding="ascii")
        # Use only the existing isolated installroot, config and no-plugin
        # options. Never run against the installed source directory.
        prefix = argv[:argv.index("--assumeyes")]
        read = subprocess.run([*prefix, "--cacheonly", "repolist", "--all"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, env=env,
                              timeout=30, check=False)
        assert read.returncode == 0 and "repocache-lock-reader" in read.stdout, read.stdout[-1800:]
        recheck()
        repo.unlink()
    assert not os.path.lexists(lock)
    # Losing a POSIX lock in this process does not remove its PID claim
    # or change the RPMDB lock inode. The exact kernel witness must refuse.
    import native_package_lock_observation as held_locks
    rpm_lock = root / "usr/lib/sysimage/rpm/.rpm.lock"
    before = rpm_lock.stat()
    try:
        with _private_dnf4_claim(root) as recheck:
            os.close(os.open(rpm_lock, os.O_RDONLY | os.O_CLOEXEC))
            assert rpm_lock.stat() == before
            assert lock.read_bytes() == str(os.getpid()).encode("ascii")
            recheck()
    except held_locks.LockInspectionRefused as exc:
        assert "kernel lock scope drift" in str(exc)
    else:
        raise AssertionError("Lost private DNF4 POSIX lock was accepted")
    assert not os.path.lexists(lock)
    with _private_dnf4_claim(root) as recheck:
        recheck()
    assert not os.path.lexists(lock)
    print("PASS: native DNF4 detects lost RPMDB POSIX lock despite exact PID and unchanged inode", flush=True)
    print("PASS: DNF4 atomic private live-PID claim and RPMDB locks; real "
          "transaction refused while repository config remained readable", flush=True)

    # An interrupted owner leaves exact evidence. Native DNF4 may recover
    # dead PIDs; REPOCACHE's guarded lab must never silently take them over.
    child = os.fork()
    if child == 0:
        with _private_dnf4_claim(root):
            os.kill(os.getpid(), signal.SIGKILL)
        os._exit(77)
    _, status = os.waitpid(child, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    stale = lock.stat()
    assert lock.read_bytes() == str(child).encode("ascii")
    try:
        with _private_dnf4_claim(root):
            raise AssertionError("Interrupted DNF4 ownership silently reused")
    except FileExistsError:
        pass
    assert lock.stat().st_ino == stale.st_ino and lock.read_bytes() == str(child).encode("ascii")
    # Test harness cleanup of its own positively identified dead child only;
    # not a production recovery policy and never a host lock removal.
    lock.unlink()
    print("PASS: interrupted private DNF4 claim preserved and refused; no stale takeover", flush=True)


def _probe_dnf_transaction_lock(package: Path, public_key: Path) -> None:
    """Actual installed DNF transaction TEST; isolated RPMDB, no install.

    DNF4 uses a live-PID ProcessLock under persistdir; DNF5 uses a
    separate kernel transaction lock. Neither demonstrates exclusion of
    earlier repository/config reads. Never claim the wrong lock family.
    """
    from ci_v06_vm_signed_client_guest import guarded_native_guest

    guarded_native_guest("almalinux10")
    if _run(["rpm", "--eval", "%{_dbpath}"]).strip() != "/usr/lib/sysimage/rpm":
        raise RuntimeError("Unexpected native RPMDB layout")
    with tempfile.TemporaryDirectory(prefix="repocache-ci-dnf-root-", dir="/var/lib") as folder:
        root = Path(folder)
        argv = _dnf_transaction_test_command(root, package)
        variant = "dnf5" if argv[0] == "/usr/bin/dnf5" else "dnf4"
        # Only new, private installroot paths. No host config or package
        # store is used; the fixture's exact key is imported in this DB.
        db = root / "usr/lib/sysimage/rpm"
        db.mkdir(parents=True, mode=0o700)
        _apply_disposable_rpmdb_label(db)
        rpm = ["/usr/bin/rpm", "--dbpath", str(db)]
        _run(rpm + ["--initdb"])
        _run(rpm + ["--import", str(public_key)])
        if not _rpm_signature_verified(_run(rpm + ["-Kv", str(package)])):
            raise RuntimeError("Isolated DNF transaction fixture is not signed")
        baseline = _run(rpm + ["-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\\n"])
        conf = root / "etc/dnf/dnf.conf"
        conf.parent.mkdir(parents=True)
        (root / "etc/yum.repos.d").mkdir()
        conf.write_text("[main]\nreposdir=/etc/yum.repos.d\nplugins=0\n"
                        "localpkg_gpgcheck=1\npersistdir=/var/lib/dnf\n"
                        "cachedir=/var/cache/dnf\nlogdir=/var/log\n",
                        encoding="ascii")
        lock = root / ("run/dnf/rpmtransaction.lock" if variant == "dnf5"
                       else "var/lib/dnf/rpmdb_lock.pid")
        lock.parent.mkdir(parents=True, mode=0o700)
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if variant == "dnf5":
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                # DNF4 uses a live PID under a short-lived flock; holding
                # flock indefinitely would test a different protocol.
                pid_bytes = str(os.getpid()).encode("ascii")
                assert os.write(fd, pid_bytes) == len(pid_bytes)
                os.fsync(fd)
            refused = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, env=env, timeout=90, check=False)
            output = refused.stdout.lower()
            if variant == "dnf5":
                denied = (refused.returncode != 0 and "rpm transaction lock" in output
                          and "another transaction is in progress" in output)
            else:
                denied = (refused.returncode == 200
                          and f"rpmdb already locked by {os.getpid()}" in output
                          and os.pread(fd, 32, 0) == pid_bytes)
            if not denied:
                raise RuntimeError("Native " + variant + " lock-specific refusal not proven: "
                                   + refused.stdout[-1800:])
            named = lock.lstat()
            if ((named.st_dev, named.st_ino, named.st_nlink)
                    != (info.st_dev, info.st_ino, 1)):
                raise RuntimeError("DNF replaced a held native transaction lock")
            if variant == "dnf4":
                # Release only our private PID record after the child
                # exits and exact inode and bytes have been rechecked.
                lock.unlink()
        finally:
            os.close(fd)
        if variant == "dnf4":
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
            import recoverable_fallback_pair_lab as pair
            marker = root / pair.DNF4_MARKER
            with marker.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(pair.DNF4_MAGIC)
            _probe_private_dnf4_claim(root, argv, lock, env)
        positive = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, env=env, timeout=90, check=False)
        if positive.returncode != 0:
            raise RuntimeError("Native DNF TEST transaction failed after release: "
                               + positive.stdout[-1800:])
        if (_run(rpm + ["-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\\n"]) != baseline
                or (root / "usr/share/doc/repocache-ci-rpm-probe").exists()):
            raise RuntimeError("DNF TEST unexpectedly changed isolated packages")
        if os.path.lexists(lock):
            named = lock.lstat()
            lifecycle = ("retained" if (named.st_dev, named.st_ino)
                         == (info.st_dev, info.st_ino) else "replaced")
        else:
            lifecycle = "removed"
        print("PASS: actual " + variant + " TEST transaction excluded by private "
              + lock.name + "; succeeds after release; lock lifecycle="
              + lifecycle, flush=True)
        print("DNF fixture version: " + _run([argv[0], "--version"]).splitlines()[0],
              flush=True)


def _signed_fixture(base: Path, *, isolated_rpmdb: Path | None = None) -> tuple[Path, Path, bytes, Path]:
    """Build no-script RPM, sign with *ephemeral CI* key, sign generated repodata."""
    public_key = native.dnf_repository(base, signed=True)
    assert public_key is not None
    topdir = base / "rpmbuild"
    for directory in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (topdir / directory).mkdir(parents=True)
    spec = topdir / "SPECS" / "fixture.spec"
    spec.write_text(_SPEC, encoding="ascii")
    _run([
        "rpmbuild", "-bb", "--define", "_topdir " + str(topdir),
        "--define", "debug_package %{nil}", str(spec),
    ])
    built = topdir / "RPMS" / "noarch" / _RPM_NAME
    if not built.is_file() or built.stat().st_size > 1024 * 1024:
        raise RuntimeError("Unexpected disposable RPM package artifact")
    gpg_home = base / "dnf-gnupg"
    gpg_name = "REPOCACHE DNF Fixture <metadata-ci@repocache.invalid>"
    _run([
        "rpmsign", "--addsign",
        "--define", "_gpg_name " + gpg_name,
        "--define", "_gpg_path " + str(gpg_home),
        "--define", "__gpg /usr/bin/gpg", str(built),
    ])
    package = base / "www" / "repo" / _RPM_NAME
    shutil.copyfile(built, package)
    signed_original = package.read_bytes()
    _run(["createrepo_c", "--quiet", "--update", str(package.parent)])
    repomd = package.parent / "repodata" / "repomd.xml"
    signature = repomd.with_name("repomd.xml.asc")
    signature.unlink(missing_ok=True)
    gpg = [
        "gpg", "--homedir", str(gpg_home), "--batch", "--yes",
        "--pinentry-mode", "loopback", "--passphrase", "",
    ]
    _run(gpg + [
        "--armor", "--detach-sign", "--output", str(signature), str(repomd),
    ])

    # No host RPMDB: only a temporary, disposable trust store is used for
    # native RPM's own signature check after each successful download.
    rpmdb = isolated_rpmdb if isolated_rpmdb is not None else base / "rpmdb"
    if isolated_rpmdb is None:
        rpmdb.mkdir(mode=0o700)
    else:
        _label_isolated_rpmdb(rpmdb)
    # Preserve a bounded native diagnostic for this disposable operation.
    # No trust-store relaxation, SELinux change or host RPMDB fallback.
    init = subprocess.run(
        ["rpm", "--dbpath", str(rpmdb), "--initdb"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=120, check=False,
    )
    if init.returncode != 0:
        diagnostic = subprocess.run(
            ["ls", "-Zd", str(rpmdb.parent), str(rpmdb)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=10, check=False,
        )
        raise RuntimeError(
            "Isolated RPMDB initialization failed; exit=" + str(init.returncode)
            + "; output=" + init.stdout[-2000:]
            + "; directory contexts=" + diagnostic.stdout[-1000:]
        )
    if isolated_rpmdb is not None:
        _import_under_native_lock(rpmdb, public_key)
    else:
        _run(["rpm", "--dbpath", str(rpmdb), "--import", str(public_key)])
    check = _run(["rpm", "--dbpath", str(rpmdb), "-Kv", str(package)])
    if not _rpm_signature_verified(check):
        raise RuntimeError("Signed RPM fixture is not trusted by isolated RPMDB")
    return public_key, package, signed_original, rpmdb


def _download_dnf(argv: list[str], target: Path) -> subprocess.CompletedProcess:
    """Force a fresh native DNF package transfer, NEVER execute install."""
    target.mkdir()
    return subprocess.run(
        [*argv[:-1], "download", _PACKAGE, "--destdir=" + str(target)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=120, check=False,
    )


def probe() -> None:
    _only_in_disposable_root()
    _probe_signed_rpm()


def probe_booted_vm() -> None:
    """Use the same fixture only inside the fixed enforcing AlmaLinux guest."""
    from ci_v06_vm_signed_client_guest import guarded_native_guest

    guarded_native_guest("almalinux10")
    _probe_signed_rpm(booted_vm=True)


# Only a private mount namespace may resolve the compiled absolute key URI.
# The child reads the real .repo before the parent's recovery, then uses the
# same native DNF Base/Repo objects to fetch signed metadata and RPM bytes.
_STALE_DNF4_READER = r"""
import dnf, dnf.conf, json, os, shutil, subprocess, sys
from pathlib import Path

root, work, ca, expected, host_mnt = sys.argv[1:]
root, work, ca = map(Path, (root, work, ca))
assert os.getresuid() == (0, 0, 0)
assert root.parent == Path("/var/tmp") and root.name.startswith("repocache-booted-dnf4-")
assert root.resolve(strict=True) == root and work.parent == root
assert os.stat("/proc/self/ns/mnt").st_ino != int(host_mnt)
assert (root / ".repocache-dnf4-lock-test").read_bytes() == b"REPOCACHE_DNF4_PRIVATE_LOCK_LAB_V1\n"
keydir = root / "etc/pki/rpm-gpg"
assert keydir.resolve(strict=True) == keydir
assert sorted(p.name for p in keydir.iterdir()) == ["repocache-ci-fixture"]
target = "/etc/pki/rpm-gpg"
env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
subprocess.run(["/usr/bin/mount", "--bind", str(keydir), target],
               env=env, check=True, timeout=15)
subprocess.run(["/usr/bin/mount", "-o", "remount,bind,ro", target],
               env=env, check=True, timeout=15)
assert (Path(target) / "repocache-ci-fixture").read_bytes() == (keydir / "repocache-ci-fixture").read_bytes()
expected = json.loads(expected)
conf = dnf.conf.Conf()
conf.installroot = str(root)
conf.config_file_path = str(work / "dnf.conf")
conf.reposdir = [str(root / "etc/yum.repos.d")]
conf.cachedir = str(work / "cache")
conf.persistdir = str(work / "persist")
conf.logdir = str(work / "logs")
conf.destdir = str(work / "downloads")
conf.substitutions["releasever"] = "10"
conf.substitutions["basearch"] = "x86_64"
conf.module_platform_id = "platform:el10"
conf.plugins = False
conf.assumeyes = True
conf.keepcache = True
conf.sslverify = True
conf.sslcacert = str(ca)
conf.gpgkey_dns_verification = False
conf.skip_if_unavailable = False
conf.fastestmirror = False
with dnf.Base(conf) as base:
    base.read_all_repos()
    repos = list(base.repos.iter_enabled())
    assert len(repos) == 1
    repo = repos[0]
    assert repo.id == "baseos" and list(repo.baseurl) == expected
    assert repo.gpgcheck and repo.repo_gpgcheck and repo.sslverify
    assert repo.sslcacert == str(ca)
    assert list(repo.gpgkey) == ["file:///etc/pki/rpm-gpg/repocache-ci-fixture"]
    print("DNF4_READER_READY", flush=True)
    assert sys.stdin.readline() == "go\n"
    base.fill_sack(load_system_repo=False)
    pkgs = list(base.sack.query().available().filter(name="repocache-ci-rpm-probe"))
    assert len(pkgs) == 1
    base.download_packages(pkgs)
    path = Path(pkgs[0].localPkg())
    assert path.is_file() and path.resolve(strict=True).is_relative_to(work)
    shutil.copyfile(path, work / "verified-transfer.rpm")
    print("DNF4_READER_TRANSFERRED", flush=True)
"""


@contextlib.contextmanager
def _stale_dnf4_reader(root, label, ca, urls):
    """Start one bounded actual reader; no network before the ready barrier."""
    from ci_v06_vm_signed_client_guest import guarded_native_guest
    import recoverable_fallback_pair_lab as pair
    guarded_native_guest("almalinux10")
    assert pair._is_dnf4_pair_root(root)
    assert label in ("stale-offline", "stale-online", "fresh")
    work = root / label
    work.mkdir(mode=0o700)
    for name in ("cache", "persist", "logs", "downloads"):
        (work / name).mkdir(mode=0o700)
    (work / "dnf.conf").write_text("[main]\n", encoding="ascii")
    host_mnt = str(os.stat("/proc/self/ns/mnt").st_ino)
    argv = ["/usr/bin/unshare", "--mount", "--propagation", "private", "--",
            "/usr/bin/python3", "-I", "-B", "-c", _STALE_DNF4_READER,
            str(root), str(work), str(ca), json.dumps(urls), host_mnt]
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    with (work / "reader.stderr").open("w+") as errors:
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=errors, text=True, env=env)
        try:
            ready, _, _ = select.select([child.stdout], [], [], 25)
            if not ready or child.stdout.readline().strip() != "DNF4_READER_READY":
                errors.seek(0)
                raise AssertionError("Native DNF4 reader did not parse source: " + errors.read()[-1500:])
            assert child.poll() is None
            assert os.stat(f"/proc/{child.pid}/ns/mnt").st_ino != int(host_mnt)
            yield child, work, errors
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            child.stdin.close()
            child.stdout.close()


def _complete_stale_dnf4_reader(reader, expected_bytes, rpmdb):
    child, work, errors = reader
    output, _ = child.communicate(input="go\n", timeout=120)
    errors.seek(0)
    assert child.returncode == 0 and "DNF4_READER_TRANSFERRED" in output, errors.read()[-2500:]
    payload = work / "verified-transfer.rpm"
    assert hashlib.sha256(payload.read_bytes()).digest() == hashlib.sha256(expected_bytes).digest()
    assert _rpm_signature_verified(_run(["/usr/bin/rpm", "--dbpath", str(rpmdb), "-Kv", str(payload)]))


def _probe_dnf4_catalog_stale_reader(base, key, certificate, foreign, primary,
                                    upstream, expected_bytes, rpmdb):
    """Real TLS catalog consent + marked DNF4 journal + pre-parsed native readers."""
    from ci_v06_vm_signed_client_guest import guarded_native_guest, installed_sources, installed_packages
    from ci_v06_vm_client_privileged_guest import _alma_fixture_file_context, _private_dnf4_setup, _snapshot
    from smoke_client_recoverable_pair import build, IDENT, sha
    import root_source_boundary as boundary
    import recoverable_fallback_pair_lab as pair

    guarded_native_guest("almalinux10")
    assert _native_dnf_transaction_variant() == ("/usr/bin/dnf", "dnf4")
    before_sources = installed_sources("almalinux10")
    before_packages = installed_packages("almalinux10")
    original_context = boundary._native_tls_context
    origin = primary.origin.removesuffix("/repo/")
    route = origin + "/__repocache/repos/approved/"
    www = base / "www"
    mapped = www / "__repocache/repos/approved"
    assert not mapped.exists()
    shutil.copytree(www / "repo", mapped)
    catalog = www / ".well-known/repocache/catalog.json"
    catalog.parent.mkdir(parents=True)
    def publish(mappings):
        catalog.write_text(json.dumps({"schema": 1, "repositories": mappings}), encoding="ascii")
    active = [{"upstream": upstream.origin, "cache": route}]
    def exercise(withdrawal):
        publish(active)
        with tempfile.TemporaryDirectory(prefix="repocache-booted-dnf4-", dir="/var/tmp") as folder:
            root = Path(folder)
            with _alma_fixture_file_context(root):
                source, _, _, state = build(root, "dnf")
                (state / ("candidate-" + IDENT + ".json")).unlink()
                raw = ("[baseos]\nname=Private signed DNF fixture\nbaseurl=" + upstream.origin
                       + "\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"
                       "gpgkey=file:///etc/pki/rpm-gpg/repocache-ci-fixture\n").encode("ascii")
                source.write_bytes(raw)
                (root / "etc/os-release").write_text('ID=almalinux\nVERSION_ID="10"\n')
                cfg = root / "etc/repocache-client"
                cfg.mkdir(mode=0o755)
                (cfg / "config.json").write_text(json.dumps({"server": origin}), encoding="ascii")
                (cfg / "config.json").chmod(0o644)
                keydir = root / "etc/pki/rpm-gpg"
                keydir.mkdir(parents=True)
                shutil.copyfile(key, keydir / "repocache-ci-fixture")
                (keydir / "repocache-ci-fixture").chmod(0o644)
                _run(["/usr/sbin/restorecon", "-RF", str(root)])
                _private_dnf4_setup(root)
                os.setxattr(source, "user.repocache-ci", b"preserve")
                baseline = _snapshot(source)
                digest = sha(raw)
                with boundary.metadata.native_metadata_scope(root):
                    wrong = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    wrong.load_verify_locations(cafile=str(foreign))
                    boundary._native_tls_context = lambda: wrong
                    primary.hits.clear()
                    try:
                        boundary.prepare_current_candidate(digest, digest, _test_root=root)
                    except boundary.BoundaryRefused:
                        pass
                    else:
                        raise AssertionError("Foreign catalog CA accepted")
                    assert not primary.hits and not list(state.glob("pending-*.json"))
                    trusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    trusted.load_verify_locations(cafile=str(certificate))
                    boundary._native_tls_context = lambda: trusted
                    prepared = boundary.prepare_current_candidate(digest, digest, _test_root=root)
                    ident = prepared["managed_id"]
                    assert prepared["route_sha256"] == sha(route.encode("ascii"))
                    approved = boundary.approve_current_candidate(
                        ident, prepared["route_sha256"], _test_root=root)
                    assert approved["status"] == "approved" and not approved["write_eligible"]
                    assert _snapshot(source) == baseline
                    # Withdrawn/changed catalog must refuse while native
                    # DNF4 scope is acquired, before any journal intent.
                    for mappings in ([], [{"upstream": upstream.origin,
                                            "cache": origin + "/__repocache/repos/changed/"}]):
                        publish(mappings)
                        try:
                            pair.apply_catalog_bound_sandbox(root, ident)
                        except pair.PairRefused:
                            pass
                        else:
                            raise AssertionError("Withdrawn/changed catalog permitted DNF4 apply")
                        assert _snapshot(source) == baseline
                        assert not list(state.glob("pair-*.json"))
                    publish(active)
                    if withdrawal is not None:
                        # The real HTTPS catalog changes while the private
                        # DNF4 owner and native-created RPM lock are held.
                        from recovery_journal_v1 import inspect_local_recovery_record
                        original_crash = pair._crash
                        seen = []
                        claim = root / "var/lib/dnf/rpmdb_lock.pid"
                        def withdraw_at(active, phase):
                            if phase == withdrawal:
                                assert claim.read_bytes() == str(os.getpid()).encode("ascii")
                                seen.append(_snapshot(source))
                                publish([])
                        pair._crash = withdraw_at
                        try:
                            try:
                                pair.apply_catalog_bound_sandbox(root, ident)
                            except pair.PairRefused as exc:
                                assert "exact local transaction restored" in str(exc), exc
                            else:
                                raise AssertionError("Mid-transaction DNF4 withdrawal committed")
                        finally:
                            pair._crash = original_crash
                        assert len(seen) == 1
                        assert (seen[0][0] != baseline[0]) == (withdrawal == "source")
                        restored = _snapshot(source)
                        assert restored[0] == baseline[0]
                        assert restored[3:6] == baseline[3:6] and restored[-1] == baseline[-1]
                        if withdrawal == "armed":
                            assert restored[1:3] == baseline[1:3]
                        assert not os.path.lexists(claim)
                        assert not list(root.rglob(".repocache-atomic-*"))
                        report = inspect_local_recovery_record(ident, _test_root=root)
                        assert report["phase"] == "restored"
                        assert report["source_state"] in (
                            ("original",) if withdrawal == "armed"
                            else ("restored", "original-or-restored"))
                        assert report["companion_state"] == "not-applicable"
                        assert report["journal_record_verified"]
                        assert not any(report[k] for k in (
                            "local_rollback_verified", "route_revocation_verified",
                            "native_exclusion_verified", "write_eligible"))
                        # Recovery remains offline and idempotent even with
                        # a healthy former cache and a withdrawn catalog.
                        primary.hits.clear()
                        upstream.hits.clear()
                        assert pair.recover_sandbox(root, ident)["status"] == "restored"
                        assert not primary.hits and not upstream.hits
                        assert not os.path.lexists(claim)
                        with _stale_dnf4_reader(root, "fresh",
                                                certificate, [upstream.origin]) as fresh:
                            _complete_stale_dnf4_reader(fresh, expected_bytes, rpmdb)
                        assert not primary.hits and any(_RPM_NAME in hit for hit in upstream.hits)
                        assert _snapshot(source) == restored
                        print("PASS: real DNF4 HTTPS catalog withdrawal at " + withdrawal
                              + " compensated under native private locks; signed upstream only",
                              flush=True)
                        return
                    pid = os.fork()
                    if pid == 0:
                        def kill_at(active, phase):
                            if active == phase:
                                os.kill(os.getpid(), signal.SIGKILL)
                        pair._crash = kill_at
                        pair.apply_catalog_bound_sandbox(root, ident, crash="source")
                        os._exit(77)
                    _, status = os.waitpid(pid, 0)
                    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
                    changed = _snapshot(source)
                    assert changed[0] != baseline[0] and changed[-1] == baseline[-1]
                    primary.hits.clear()
                    upstream.hits.clear()
                    # Both children parse the actual published managed entry
                    # before recovery. Neither reads metadata at the barrier.
                    with _stale_dnf4_reader(root, "stale-offline", certificate, [route, upstream.origin]) as offline:
                        with _stale_dnf4_reader(root, "stale-online", certificate, [route, upstream.origin]) as online:
                            assert not primary.hits and not upstream.hits
                            stale = root / "var/lib/dnf/rpmdb_lock.pid"
                            proof = stale.lstat()
                            assert stale.read_bytes() == str(pid).encode("ascii")
                            journal = state / ("pair-" + ident + ".json")
                            journal_before = journal.read_bytes()
                            primary.mode = "unavailable"
                            try:
                                pair.recover_sandbox(root, ident)
                            except pair.PairRefused:
                                pass
                            else:
                                raise AssertionError("Stale DNF4 PID silently taken over")
                            assert _snapshot(source) == changed and journal.read_bytes() == journal_before
                            assert stale.lstat().st_ino == proof.st_ino
                            assert stale.read_bytes() == str(pid).encode("ascii")
                            # Only the known reaped fixture child record.
                            stale.unlink()
                            fd = os.open(stale.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                            try:
                                os.fsync(fd)
                            finally:
                                os.close(fd)
                            assert pair.recover_sandbox(root, ident)["status"] == "restored"
                            restored = _snapshot(source)
                            assert restored[0] == baseline[0] and restored[3:6] == baseline[3:6]
                            assert restored[-1] == baseline[-1]
                            assert pair.recover_sandbox(root, ident)["status"] == "restored"
                            assert not primary.hits and not upstream.hits
                            _complete_stale_dnf4_reader(offline, expected_bytes, rpmdb)
                            assert primary.hits and upstream.hits
                            assert any(_RPM_NAME in hit for hit in upstream.hits)
                            print("PASS: DNF4 reader parsed journal-published entry before SIGKILL recovery; signed HTTPS RPM fallback after cache outage", flush=True)
                            # Recovery does not revoke already parsed inline
                            # DNF URLs if the former cache stays available.
                            primary.hits.clear()
                            upstream.hits.clear()
                            primary.mode = "healthy"
                            _complete_stale_dnf4_reader(online, expected_bytes, rpmdb)
                            assert any(_RPM_NAME in hit for hit in primary.hits) and not upstream.hits
                            print("OBSERVED: pre-parsed DNF4 reader still uses healthy former cache after source recovery; reader revocation NOT VERIFIED", flush=True)
                    primary.hits.clear()
                    upstream.hits.clear()
                    with _stale_dnf4_reader(root, "fresh", certificate, [upstream.origin]) as fresh:
                        _complete_stale_dnf4_reader(fresh, expected_bytes, rpmdb)
                    assert not primary.hits and any(_RPM_NAME in hit for hit in upstream.hits)
                    assert _snapshot(source) == restored
                    print("PASS: actual authenticated catalog-bound DNF4 labelled journal recovery; fresh native reader uses signed upstream only", flush=True)
    try:
        for withdrawal in ("armed", "source", None):
            exercise(withdrawal)
    finally:
        boundary._native_tls_context = original_context
        primary.mode = "healthy"
        upstream.mode = "healthy"
        primary.hits.clear()
        upstream.hits.clear()
    assert installed_sources("almalinux10") == before_sources
    assert installed_packages("almalinux10") == before_packages
    guarded_native_guest("almalinux10")


def _probe_signed_rpm(*, booted_vm: bool = False) -> None:
    with contextlib.ExitStack() as stack:
        folder = stack.enter_context(tempfile.TemporaryDirectory(
            prefix="repocache-dnf-signed-rpm-", dir="/tmp",
        ))
        # Avoid the temporary-directory SELinux traversal boundary: only
        # the database is relocated into a fresh private var_lib_t child.
        isolated_rpmdb = None
        if booted_vm:
            isolated_rpmdb = Path(stack.enter_context(tempfile.TemporaryDirectory(
                prefix="repocache-ci-rpmdb-", dir="/var/lib",
            )))
        base = Path(folder)
        (base / "www").mkdir()
        key, rpm_file, expected_bytes, rpmdb = _signed_fixture(base, isolated_rpmdb=isolated_rpmdb)
        if booted_vm:
            _probe_dnf_transaction_lock(rpm_file, key)
        certificate, private_key = native.temporary_tls_identity(base, "rpm")
        wrong_ca, _ = native.temporary_tls_identity(base, "foreign")
        primary = native.HTTPBackend(
            base / "www", certificate=certificate, key=private_key,
        )
        upstream = native.HTTPBackend(
            base / "www", certificate=certificate, key=private_key,
        )
        repomd_signature = base / "www" / "repo/repodata/repomd.xml.asc"
        original_signature = repomd_signature.read_bytes()
        try:
            if booted_vm and _native_dnf_transaction_variant() == ("/usr/bin/dnf", "dnf4"):
                _probe_dnf4_catalog_stale_reader(base, key, certificate, wrong_ca,
                                                 primary, upstream, expected_bytes, rpmdb)
            for cycle, mode1, mode2 in (
                ("preferred", "healthy", "healthy"),
                ("fallback", "unavailable", "healthy"),
                ("recovery", "healthy", "healthy"),
                ("both-failed", "unavailable", "unavailable"),
                ("wrong-ca", "healthy", "healthy"),
                ("tampered-metadata-signature", "healthy", "healthy"),
                ("tampered-rpm", "healthy", "healthy"),
            ):
                primary.mode, upstream.mode = mode1, mode2
                if cycle == "tampered-metadata-signature":
                    repomd_signature.write_bytes(b"not a valid signature\n")
                if cycle == "tampered-rpm":
                    rpm_file.write_bytes(b"tampered RPM after signed metadata generation\n")
                primary.hits.clear()
                upstream.hits.clear()
                ca = wrong_ca if cycle == "wrong-ca" else certificate
                argv = native.dnf_command(
                    base, primary, upstream, cycle,
                    ca_certificate=ca, metadata_key=key,
                )
                cache = subprocess.run(
                    argv, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=120, check=False,
                )
                downloaded = None
                checksum_ok = False
                rpm_signature_ok = False
                if cache.returncode == 0:
                    downloaded = _download_dnf(
                        argv, base / ("download-" + cycle),
                    )
                    fetched = base / ("download-" + cycle) / _RPM_NAME
                    checksum_ok = (
                        downloaded.returncode == 0 and fetched.is_file()
                        and hashlib.sha256(fetched.read_bytes()).digest()
                        == hashlib.sha256(expected_bytes).digest()
                    )
                    if checksum_ok:
                        verify = _run([
                            "rpm", "--dbpath", str(rpmdb), "-Kv", str(fetched),
                        ])
                        rpm_signature_ok = _rpm_signature_verified(verify)
                urls = primary.hits + upstream.hits
                requests_rpm = any(_RPM_NAME in hit for hit in urls)
                if cycle in ("preferred", "fallback", "recovery"):
                    accepted = (
                        cache.returncode == 0
                        and downloaded is not None and downloaded.returncode == 0
                        and checksum_ok and rpm_signature_ok and requests_rpm
                        and bool(primary.hits)
                        and (bool(upstream.hits) == (cycle == "fallback"))
                    )
                elif cycle == "both-failed":
                    accepted = cache.returncode != 0 and bool(primary.hits) and bool(upstream.hits)
                elif cycle == "wrong-ca":
                    accepted = cache.returncode != 0 and not primary.hits and not upstream.hits
                elif cycle == "tampered-metadata-signature":
                    accepted = cache.returncode != 0 and bool(primary.hits) and not requests_rpm
                else:
                    accepted = (
                        cache.returncode == 0
                        and downloaded is not None and downloaded.returncode != 0
                        and not checksum_ok and requests_rpm
                    )
                if not accepted:
                    raise RuntimeError(
                        "Signed DNF RPM scenario failed: " + cycle
                        + " cache_exit=" + str(cache.returncode)
                        + " download_exit=" + (
                            "N/A" if downloaded is None else str(downloaded.returncode)
                        )
                        + " cache_hits=" + str(len(primary.hits))
                        + " upstream_hits=" + str(len(upstream.hits))
                        + " hash_ok=" + str(checksum_ok)
                        + " rpm_sig_ok=" + str(rpm_signature_ok)
                        + " request_rpm=" + str(requests_rpm)
                        + " dnf_output=" + cache.stdout[-1500:]
                        + " download_output=" + (
                            "" if downloaded is None else downloaded.stdout[-1500:]
                        )
                    )
                print(
                    "PASS: DNF signed RPM (" + Path(argv[0]).name + ") "
                    + cycle
                    + " primary_hits=" + str(len(primary.hits))
                    + " upstream_hits=" + str(len(upstream.hits)),
                    flush=True,
                )
                if cycle == "tampered-metadata-signature":
                    repomd_signature.write_bytes(original_signature)
                if cycle == "tampered-rpm":
                    rpm_file.write_bytes(expected_bytes)
        finally:
            primary.close()
            upstream.close()


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("Signed DNF RPM fixture accepts no arguments")
    probe()
