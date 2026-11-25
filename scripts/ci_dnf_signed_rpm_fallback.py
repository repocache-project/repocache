#!/usr/bin/env python3
"""Native DNF5 signed-RPM download/fallback regression, disposable CI only (#24).

Builds and signs a noarch fixture RPM under an isolated temporary directory,
then checks actual DNF5 HTTPS preference/fallback and signed metadata. It
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
    """Force a fresh DNF5 package transfer, NEVER execute install."""
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
                    "PASS: DNF5 signed RPM "
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
