#!/usr/bin/env python3
"""Disposable native acceptance of an owner-signed first v0.6.0 installation.

The protected-main draft gate authenticates the final exact eight candidate
bytes before this fixture executes any archive code. The root bootstrap uses
only checked-out, reviewed sources independently matched to the signed TAR.
No historical v0.4.0 application, network redirect or migration is involved.
This is rootless application evidence in OS containers, NOT proof of a
booted server/NGINX/systemd/SELinux or production filesystem transaction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path("/repo")
CANDIDATE = Path("/candidate")
MANAGED = Path("/opt/repocache-cli/managed")


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise AssertionError(reason)
    print("PASS: " + reason, flush=True)


def run(*args: str, okay: bool = True, timeout: int = 90,
        env: dict | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                            env=env)
    if (result.returncode == 0) != okay:
        raise AssertionError(
            "Wrong exit status " + str(result.returncode) +
            " for " + " ".join(args[:4]) + " " +
            (result.stdout + result.stderr)[-1600:]
        )
    return result


def installed() -> tuple[str, bytes, dict]:
    active = os.readlink(MANAGED / "current")
    raw = (MANAGED / "installed.json").read_bytes()
    return active, raw, json.loads(raw)


def args_for(tag: str, folder: Path) -> tuple[str, ...]:
    bundle = folder / ("repocache-" + tag + ".tar.gz")
    return (
        "update", "--version", tag[1:],
        "--bundle", str(bundle),
        "--checksum", str(folder / (bundle.name + ".sha256")),
        "--manifest", str(folder / (bundle.name + ".manifest.json")),
        "--signature", str(folder / (bundle.name + ".manifest.json.sig")),
        "--wheelhouse", str(folder / (bundle.name + ".wheelhouse.tar.gz")),
        "--json",
    )


def sentinels() -> dict[str, bytes]:
    name = (
        "apt/sources.list.d/repocache-keep.sources"
        if Path("/etc/debian_version").exists()
        else "yum.repos.d/repocache-keep.repo"
    )
    names = (
        "/etc/nginx/nginx.conf", "/etc/ssl/repocache-test.key",
        "/var/cache/nginx/repocache-keep", "/etc/" + name,
    )
    return {p: Path(p).read_bytes() for p in names}


def run_as_service(
    script: str, *values: str, okay: bool = True,
) -> subprocess.CompletedProcess:
    return run(
        "/usr/sbin/runuser", "-u", "repocache", "--",
        str(MANAGED / "current/bin/python"), "-c", script, *values,
        okay=okay,
    )


def prepare_clean_candidate(tag: str) -> dict[str, bytes]:
    """Trust-boundary proof: no installed runtime, no old-version import."""
    need(
        not (MANAGED / "current").exists()
        and not (MANAGED / "installed.json").exists(),
        "clean OS has no REPOCACHE runtime or migration state",
    )
    source = CANDIDATE / ("repocache-" + tag + ".tar.gz")
    checked = {
        name: (ROOT / name).read_bytes()
        for name in (
            "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh",
            "src/repocache/recovery.py",
        )
    }
    with tarfile.open(source, "r:gz") as archive:
        members = archive.getmembers()
        prefix = "repocache-" + tag + "/"
        need(
            0 < len(members) < 150
            and all(
                m.isfile() and m.name.startswith(prefix)
                and ".." not in Path(m.name).parts
                and m.mode & 0o7000 == 0
                for m in members
            ),
            "authenticated first-install source archive has safe members",
        )
        for name, expected in checked.items():
            item = archive.getmember(prefix + name)
            stream = archive.extractfile(item)
            need(
                item.isfile() and item.size == len(expected)
                and stream is not None and stream.read(len(expected) + 1) == expected,
                "signed bootstrap member equals reviewed source: " + name,
            )

    name = (
        "apt/sources.list.d/repocache-keep.sources"
        if Path("/etc/debian_version").exists()
        else "yum.repos.d/repocache-keep.repo"
    )
    for original_path in (
        "/etc/nginx/nginx.conf", "/etc/ssl/repocache-test.key",
        "/var/cache/nginx/repocache-keep", "/etc/" + name,
    ):
        marker = Path(original_path)
        marker.parent.mkdir(parents=True, exist_ok=True)
        need(
            not marker.exists() and not marker.is_symlink(),
            "clean test preservation fixture was not preexisting",
        )
        marker.write_bytes(b"repocache-first-v06:DO-NOT-CHANGE\n")
    protected = sentinels()

    key_dir = Path("/etc/repocache/trust.d")
    key_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    public = key_dir / "repocache-2026-10.pem"
    need(
        not public.exists() and not public.is_symlink(),
        "independently provisioned publisher key is fresh",
    )
    public.write_bytes((ROOT / "keys/repocache-2026-10.pem").read_bytes())
    public.chmod(0o644)

    # Execute only reviewed checkout code as root and only after authenticating
    # the candidate and proving exact byte identity to the signed archive.
    run(
        "/bin/bash", str(ROOT / "scripts/bootstrap-rootless.sh"),
        "--launcher-sha256",
        hashlib.sha256(checked["scripts/repocache-launcher.sh"]).hexdigest(),
        "--recovery-sha256",
        hashlib.sha256(checked["src/repocache/recovery.py"]).hexdigest(),
    )
    need(
        (MANAGED.parent / ".updater.lock").is_file()
        and not (MANAGED / "current").exists(),
        "root-owned bootstrap has no installed release generation",
    )
    return protected


def install_first_signed_generation(tag: str, evidence: dict) -> None:
    """Run the supported CLI using only an offline, signed temporary wheelset."""
    archive = "repocache-" + tag + ".tar.gz"
    wheel = CANDIDATE / (archive + ".wheelhouse.tar.gz")
    wheel_sha = evidence["assets"][wheel.name]["sha256"]
    with tempfile.TemporaryDirectory(prefix="repocache-first-install-") as temp:
        base = Path(temp)
        base.chmod(0o755)
        sandbox = base / "sandbox"
        sandbox.mkdir(mode=0o700)
        uid = int(run("/usr/bin/id", "-u", "repocache").stdout.strip())
        gid = int(run("/usr/bin/id", "-g", "repocache").stdout.strip())
        os.chown(sandbox, uid, gid)
        wheels = sandbox / "wheels"
        venv = sandbox / "venv"
        bootstrap = (
            "import sys,subprocess; from pathlib import Path; "
            "from repocache import wheelhouse; "
            "a=Path(sys.argv[1]); "
            "lock=wheelhouse.verified_extract(a.read_bytes(),sys.argv[2],Path(sys.argv[3])); "
            "wheelhouse.verify_application_wheel(lock,sys.argv[5]); "
            "subprocess.run([sys.executable,'-m','venv',sys.argv[4]],check=True); "
            "subprocess.run([sys.argv[4]+'/bin/python','-m','pip','install',"
            "'--no-index','--require-hashes','-r',str(lock)],"
            "cwd=str(lock.parent),check=True)"
        )
        run(
            "/usr/sbin/runuser", "-u", "repocache", "--",
            "/usr/bin/env", "-i",
            "HOME=/var/lib/repocache", "PATH=/usr/local/bin:/usr/bin:/bin",
            "LANG=C.UTF-8", "PYTHONPATH=/repo/src",
            "PYTHONNOUSERSITE=1", "PYTHONSAFEPATH=1",
            "/usr/bin/python3", "-c", bootstrap,
            str(wheel), wheel_sha, str(wheels), str(venv), tag[1:],
            timeout=240,
        )
        need(
            (venv / "bin/repocache").is_file(),
            "temporary signed offline CLI exists for clean initialization",
        )
        first = run(
            "/usr/sbin/runuser", "-u", "repocache", "--",
            str(venv / "bin/repocache"), *args_for(tag, CANDIDATE),
            timeout=240,
        )
        need(
            json.loads(first.stdout).get("version") == tag[1:],
            "real user-facing signed local CLI initializes first v0.6 generation",
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", default="1")
    parser.add_argument("--release-id", required=True)
    args = parser.parse_args()

    need(
        os.geteuid() == 0 and Path("/.dockerenv").exists(),
        "only disposable distro-container root setup allowed",
    )
    run(
        "/usr/bin/python3", str(ROOT / "scripts/draft_release_gate.py"),
        "verify-local", "--tag", args.tag, "--commit", args.commit,
        "--run-id", args.run_id, "--run-attempt", args.run_attempt,
        "--release-id", args.release_id, "--dest", str(CANDIDATE),
        "--inventory", "/candidate-inventory/validated.json",
    )
    need(True, "owner-signed exact Draft authenticated before executing sources")

    preserved = prepare_clean_candidate(args.tag)
    evidence = json.loads(
        Path("/candidate-inventory/validated.json").read_text()
    )
    install_first_signed_generation(args.tag, evidence)
    link, raw, manifest = installed()
    archive = "repocache-" + args.tag + ".tar.gz"
    inventory = evidence["assets"]
    need(
        manifest["version"] == args.tag[1:]
        and manifest["archive_sha256"] == inventory[archive]["sha256"]
        and manifest["wheelhouse_sha256"]
        == inventory[archive + ".wheelhouse.tar.gz"]["sha256"]
        and manifest["release_commit"] == args.commit
        and manifest["publisher_key_id"] == "repocache-2026-10",
        "fresh installed generation matches signed release identities",
    )
    policy = manifest.get("release_policy")
    need(
        isinstance(policy, dict)
        and policy.get("compatible_from") == []
        and policy.get("downgrade_from") == [],
        "new release policy does not accept old installed versions",
    )

    cmd = ("/usr/local/bin/repocache", *args_for(args.tag, CANDIDATE))
    need(
        run("/usr/local/bin/repocache", "--version").stdout.strip().endswith(
            args.tag[1:]
        ),
        "root-protected launcher runs signed installed candidate",
    )
    run(
        str(MANAGED / "current/bin/python"), "-c",
        "from repocache.tui import RepoCacheApp; assert RepoCacheApp",
    )
    need(True, "installed signed candidate TUI import")
    repair = run(*cmd, timeout=240)
    next_link, next_raw, next_manifest = installed()
    need(
        json.loads(repair.stdout).get("version") == args.tag[1:]
        and next_link != link
        and next_manifest["archive_sha256"] == manifest["archive_sha256"],
        "same-version signed repair writes an independent valid generation",
    )

    with tempfile.TemporaryDirectory(prefix="repocache-negative-") as temp:
        scratch = Path(temp)
        scratch.chmod(0o755)
        for asset in CANDIDATE.iterdir():
            shutil.copyfile(asset, scratch / asset.name)
        (scratch / (archive + ".wheelhouse.tar.gz")).write_bytes(
            b"locally-tampered-wheel"
        )
        run(
            "/usr/local/bin/repocache", *args_for(args.tag, scratch),
            okay=False, timeout=120,
        )
        need(
            installed()[:2] == (next_link, next_raw),
            "tampered wheelset refused with no changed installed generation",
        )

        # The candidate is still a private Draft, never a public stable.
        run(
            "/usr/local/bin/repocache", "update", "--version", args.tag[1:],
            "--json", okay=False,
        )
        need(
            installed()[:2] == (next_link, next_raw),
            "unpublished Draft refused from public-update CLI",
        )

        # Check old -> new policy refusal without fetching or executing the
        # obsolete v0.4.0 application. No production migration is attempted.
        refusal = (
            "import json,sys; from repocache.upgrade import _policy; "
            "_policy(json.loads(sys.argv[1]),sys.argv[2],"
            "{'version':'0.4.0'},"
            "{'ID':sys.argv[3],'VERSION_ID':sys.argv[4]})"
        )
        debian = Path("/etc/debian_version").exists()
        run_as_service(
            refusal, json.dumps(policy), args.tag[1:],
            "debian" if debian else "almalinux",
            "13" if debian else "10", okay=False,
        )
        need(
            installed()[:2] == (next_link, next_raw),
            "unsupported historical upgrade refuses without state mutation",
        )

    failure = (
        "import sys; from pathlib import Path; "
        "from repocache import updater; from repocache.upgrade import upgrade; "
        "updater._write_manifest=lambda *_a: "
        "(_ for _ in ()).throw(updater.UpdateError('injected commit failure')); "
        "upgrade(selected=sys.argv[1],bundle=Path(sys.argv[2]),"
        "checksum=Path(sys.argv[3]))"
    )
    run_as_service(
        failure, args.tag[1:],
        str(CANDIDATE / archive),
        str(CANDIDATE / (archive + ".sha256")), okay=False,
    )
    need(
        installed()[:2] == (next_link, next_raw),
        "injected signed-application transaction failure preserves generation",
    )

    holder = subprocess.Popen(
        [
            "/usr/sbin/runuser", "-u", "repocache", "--", "/usr/bin/python3",
            "-u", "-c",
            "import fcntl,sys; f=open('/opt/repocache-cli/.updater.lock','rb'); "
            "fcntl.flock(f,fcntl.LOCK_EX); print('LOCKED',flush=True); "
            "sys.stdin.readline()",
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        need(holder.stdout is not None, "real service lock holder has stdout")
        ready, _, _ = select.select([holder.stdout], [], [], 10)
        need(
            bool(ready) and holder.stdout.readline().strip() == "LOCKED",
            "persistent protected updater lock acquired by service account",
        )
        busy = run(*cmd, okay=False, timeout=40)
        need(
            busy.returncode == 75 and installed()[:2] == (next_link, next_raw),
            "concurrent signed update refuses BUSY without state mutation",
        )
    finally:
        if holder.poll() is None and holder.stdin:
            try:
                holder.stdin.write("\n")
                holder.stdin.flush()
            except BrokenPipeError:
                pass
        try:
            holder.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder.communicate(timeout=5)

    need(
        all(Path(path).read_bytes() == content
            for path, content in preserved.items()),
        "NGINX, TLS, cache and client-source fixture bytes remain untouched",
    )
    print("PASS: real signed first-release candidate clean install, repair and rollback")
    print("NOT TESTED: booted systemd, SELinux enforcing or real power failure")


if __name__ == "__main__":
    try:
        main()
    except (
        AssertionError, OSError, ValueError, KeyError, tarfile.TarError,
        subprocess.TimeoutExpired,
    ) as exc:
        print("FAIL: signed first-install candidate: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
