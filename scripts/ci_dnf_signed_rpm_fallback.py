#!/usr/bin/env python3
"""Native DNF5 signed-RPM download/fallback regression, disposable CI only (#24).

Builds and signs a noarch fixture RPM under an isolated temporary directory,
then checks actual DNF5 HTTPS preference/fallback and signed metadata. It
NEVER installs a test package, touches a host source, or uses publisher keys.
A production client writer remains disabled and #24 host gates remain OPEN.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

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
printf 'CI ONLY. NEVER INSTALL.\n' > %{buildroot}/usr/share/doc/repocache-ci-rpm-probe/README

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


def _signed_fixture(base: Path) -> tuple[Path, Path, bytes, Path]:
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
    rpmdb = base / "rpmdb"
    rpmdb.mkdir()
    _run(["rpm", "--dbpath", str(rpmdb), "--initdb"])
    _run(["rpm", "--dbpath", str(rpmdb), "--import", str(public_key)])
    check = _run(["rpm", "--dbpath", str(rpmdb), "-Kv", str(package)])
    if "NOKEY" in check or "NOT OK" in check:
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
    with tempfile.TemporaryDirectory(prefix="repocache-dnf-signed-rpm-") as folder:
        base = Path(folder)
        (base / "www").mkdir()
        key, rpm_file, expected_bytes, rpmdb = _signed_fixture(base)
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
                        rpm_signature_ok = (
                            "NOKEY" not in verify and "NOT OK" not in verify
                        )
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
