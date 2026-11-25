#!/usr/bin/env python3
"""P0-3 booted VM: verify client fail-closed apply/CLI without altering sources."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from ci_v06_vm_nginx_cache_guest import native_guard

ROOT = Path("/home/pr237ci/source")
CLIENT = ROOT / "client/repocache_client.py"
MAX_SOURCE_BYTES = 1024 * 1024


def source_snapshot(platform: str) -> tuple[tuple, ...]:
    directory = (Path("/etc/apt/sources.list.d") if platform == "debian13"
                 else Path("/etc/yum.repos.d"))
    if not directory.is_dir() or directory.is_symlink():
        raise AssertionError("unsupported native package source directory")
    files = sorted(p for p in directory.iterdir() if p.suffix in (".list", ".sources", ".repo"))
    if platform == "debian13" and Path("/etc/apt/sources.list").exists():
        files.append(Path("/etc/apt/sources.list"))
    if not files:
        raise AssertionError("native package source inventory absent")
    if platform == "debian13":
        mirrors = Path("/etc/apt/mirrors")
        if os.path.lexists(mirrors):
            if mirrors.is_symlink() or not mirrors.is_dir():
                raise AssertionError("unsafe native APT mirror directory")
            files.extend(p for p in mirrors.iterdir()
                         if p.is_symlink() or not p.is_dir())
    if len(files) > 128:
        raise AssertionError("native package source inventory excessive")
    result = []

    def identity(meta):
        return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid,
                meta.st_gid, meta.st_nlink, meta.st_size, meta.st_mtime_ns,
                meta.st_ctime_ns)

    for p in files:
        meta = p.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_SOURCE_BYTES:
            raise AssertionError("unsupported or unsafe native package source inventory")
        blob = p.read_bytes()
        if len(blob) != meta.st_size or identity(p.lstat()) != identity(meta):
            raise AssertionError("native source changed during observation")
        result.append((str(p), *identity(meta), hashlib.sha256(blob).hexdigest()))
    return tuple(sorted(result))


def run(args: list[str], *, fixture_ca: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent",
           "PYTHONDONTWRITEBYTECODE": "1", "HTTP_PROXY": "", "HTTPS_PROXY": "", "NO_PROXY": "*"}
    if fixture_ca is not None:
        # Only the disposable child trust store; never import a CA on the host.
        env["SSL_CERT_FILE"] = str(fixture_ca)
    proc = subprocess.run(
        ["/usr/bin/python3", "-B", str(CLIENT), *args],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, text=True, timeout=15,
        env=env,
        check=False,
    )
    if len(proc.stdout) > 65536 or len(proc.stderr) > 65536:
        raise AssertionError("unbounded client CLI output")
    return proc


def checked_readonly_call(platform, before, args, ca, expected_codes):
    """Require actual JSON outcome and unchanged host sources after each call."""
    try:
        proc = run(args, fixture_ca=ca)
    finally:
        if source_snapshot(platform) != before:
            raise AssertionError("native source inventory changed during read-only operation")
    if proc.returncode not in expected_codes or proc.stderr:
        raise AssertionError("unexpected native read-only CLI outcome")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise AssertionError("invalid native read-only CLI JSON") from None
    if (type(payload) is not dict or type(payload.get("schema_version")) is not int
            or payload.get("schema_version") != 1
            or payload.get("ok") is not (proc.returncode == 0)):
        raise AssertionError("native read-only CLI JSON contract changed")
    return payload, proc.returncode


def verify_readonly_commands(platform: str, before) -> None:
    """Actual non-root client CLI, local authenticated catalog, no host edits."""
    from ci_client_native_fallback import HTTPBackend, temporary_tls_identity

    assert os.geteuid() != 0
    with tempfile.TemporaryDirectory(prefix="repocache-booted-readonly-") as work:
        root = Path(work)
        www = root / "www"
        catalog = www / ".well-known/repocache/catalog.json"
        catalog.parent.mkdir(parents=True)
        ca, key = temporary_tls_identity(root, "read-only")
        foreign, _ = temporary_tls_identity(root, "foreign")
        catalog.write_text('{"schema":1,"repositories":[]}', encoding="ascii")
        backend = HTTPBackend(www, certificate=ca, key=key)
        try:
            origin = backend.origin.removesuffix("/repo/")
            assert origin.startswith("https://127.0.0.1:")
            options = ["--server", origin, "--json"]

            def invoke(action, trust, codes):
                return checked_readonly_call(platform, before, options + action, trust, codes)

            def checks(payload):
                return {row["name"]: row["ok"] for row in payload["checks"]}

            def inventory(payload):
                return sorted((row["id"], row["source"], row["enabled"])
                              for row in payload["repositories"])

            listed, _ = invoke(["repos", "list"], ca, (0,))
            expected = inventory(listed)
            assert expected and not backend.hits
            checked, _ = invoke(["check"], ca, (0, 3))
            observed = checks(checked)
            assert all(observed.get(name) is True for name in ("dns", "https", "catalog"))
            assert inventory(checked) == expected and len(backend.hits) == 1
            planned, _ = invoke(["repos", "sync"], ca, (0,))
            assert planned["dry_run"] is True and planned["planned_changes"] == 0
            assert inventory(planned) == expected and len(backend.hits) == 2
            assert all(row["plan"]["action"] == "none"
                       and row["plan"]["apply_eligible"] is False
                       for row in planned["repositories"])

            # Catalog is optional for check, mandatory for sync. Foreign
            # TLS must fail before a catalog request reaches the server.
            catalog.write_text('{"schema":2,"repositories":[]}', encoding="ascii")
            rejected, _ = invoke(["check"], ca, (0, 3))
            assert checks(rejected).get("catalog") is False
            assert len(backend.hits) == 3
            refused, _ = invoke(["repos", "sync"], ca, (2,))
            assert refused["error"]["code"] == "OPERATION_FAILED"
            assert len(backend.hits) == 4
            catalog.write_text('{"schema":1,"repositories":[]}', encoding="ascii")
            rejected, _ = invoke(["check"], foreign, (1,))
            assert checks(rejected).get("https") is False
            assert rejected["error"]["code"] == "REQUIRED_CHECK_FAILED"
            refused, _ = invoke(["repos", "sync"], foreign, (2,))
            assert refused["error"]["code"] == "OPERATION_FAILED"
            assert len(backend.hits) == 4
            listed_again, _ = invoke(["repos", "list"], foreign, (0,))
            assert inventory(listed_again) == expected and len(backend.hits) == 4
        finally:
            backend.close()
    print("PASS: actual native check/list/default sync, valid/invalid catalog and foreign CA; "
          "source inventory unchanged after each operation", flush=True)


def main(platform: str) -> None:
    native_guard(platform)
    if not CLIENT.is_file() or CLIENT.is_symlink() or os.geteuid() == 0:
        raise AssertionError("native client test requires nonroot exact source")
    before = source_snapshot(platform)
    for args in (["--help"], ["repos", "--help"], ["repos", "list", "--help"],
                 ["repos", "sync", "--help"], ["check", "--help"]):
        proc = run(list(args))
        if proc.returncode != 0 or "usage:" not in proc.stdout.lower():
            raise AssertionError("native client parser/help failure")
    for args in (["--json", "repos", "sync", "--apply"],
                 ["repos", "sync", "--apply", "--json"]):
        proc = run(list(args))
        if proc.returncode != 2 or proc.stderr:
            raise AssertionError("native client apply refusal must be structured and noninteractive")
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError("invalid structured apply refusal") from exc
        if (payload.get("schema_version") != 1 or payload.get("ok") is not False
                or payload.get("error", {}).get("code") != "OPERATION_FAILED"
                or "Applying changes is disabled" not in payload["error"].get("message", "")):
            raise AssertionError("native client apply refusal contract changed")
    verify_readonly_commands(platform, before)
    after = source_snapshot(platform)
    if before != after:
        raise AssertionError("native APT/DNF sources changed during read-only CLI probe")
    # Root-bound approval/journal fixture in the same disposable guest.
    privileged_guest = ROOT / "scripts/ci_v06_vm_client_privileged_guest.py"
    if not privileged_guest.is_file() or privileged_guest.is_symlink():
        raise AssertionError("privileged client guest probe absent")
    privileged = subprocess.run(
        ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", str(privileged_guest), platform],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, text=True, timeout=180,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
             "PYTHONDONTWRITEBYTECODE": "1", "HTTP_PROXY": "", "HTTPS_PROXY": "",
             "NO_PROXY": "*"}, check=False,
    )
    if (privileged.returncode != 0 or
            "PASS: booted-native-client-privileged-fixture " + platform
            not in privileged.stdout):
        raise AssertionError("privileged client guest failed: "
                             + privileged.stdout[-3000:] + privileged.stderr[-9000:])
    print(privileged.stdout[-10000:], flush=True)
    if source_snapshot(platform) != before:
        raise AssertionError("native sources modified by privileged fixture")

    # Explicit privileged test-only real-manager probe in this disposable VM.
    # The probe uses isolated /tmp APT/DNF source+cache paths and independently
    # test-signed metadata through the native package manager, never --apply
    # or the production server service. The root guest probe itself performs
    # exact before/after host source and installed package inventories.
    guest = ROOT / "scripts/ci_v06_vm_signed_client_guest.py"
    if not guest.is_file() or guest.is_symlink():
        raise AssertionError("signed native client guest probe absent")
    signed = subprocess.run(
        ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", str(guest), platform],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, text=True, timeout=900,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
             "PYTHONDONTWRITEBYTECODE": "1", "HTTP_PROXY": "", "HTTPS_PROXY": "",
             "NO_PROXY": "*"}, check=False,
    )
    if (signed.returncode != 0 or
            "PASS: booted-native-real-manager-signed-fallback-and-host-sources-intact " +
            platform not in signed.stdout):
        raise AssertionError(
            "booted-native signed package-manager integrity probe failed: "
            + signed.stdout[-3000:] + signed.stderr[-1500:]
        )
    print(signed.stdout[-10000:], flush=True)
    if source_snapshot(platform) != before:
        raise AssertionError("native sources modified by real package-manager probe")
    print("PASS: booted native VM client CLI --apply refusal and APT/DNF source integrity")
    print("NOT VERIFIED: approved host source writer, production catalog, "
          "installed REPOCACHE cache route, actual repos sync --apply")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("debian13", "almalinux10"):
        raise SystemExit("Only the two fixed VM targets are supported")
    main(sys.argv[1])
