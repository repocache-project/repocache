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
import os
from pathlib import Path
import shutil
import signal
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
