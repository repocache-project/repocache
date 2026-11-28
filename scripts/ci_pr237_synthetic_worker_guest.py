#!/usr/bin/env python3
"""PR237-only synthetic Ed25519 -> ACTUAL native worker placement in a QEMU VM.

This tests real host-root paths, not publisher trust, deployment authorization
or service activation. #249 is combined read-only at a pinned exact SHA.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

def main() -> None:
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and
            sys.argv[3] != "--isolated-selinux-policy"):
        raise SystemExit("Require exact independently assembled source and SHA")
    isolated_policy = len(sys.argv) == 4
    source, combined_sha = Path(sys.argv[1]), sys.argv[2]
    assert source == Path("/home/pr237ci/combined")
    assert len(combined_sha) == 40 and all(x in "0123456789abcdef" for x in combined_sha)
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert subprocess.check_output(["/usr/bin/systemd-detect-virt", "--vm"], text=True).strip() in ("qemu", "kvm")
    assert not Path("/var/lib/repocache").exists()
    assert not Path("/etc/repocache").exists()
    assert not Path("/usr/libexec/repocache").exists()
    assert not Path("/etc/systemd/system/repocache-control.socket").exists()
    assert not Path("/etc/systemd/system/repocache-control.service").exists()
    sys.path[:0] = [str(source / "src"), str(source), str(source / "tests")]
    from repocache import signatures
    from scripts import build_release, install_native_root_worker, stage_native_root_worker
    from test_v06_release_source_inventory import _candidate_source
    from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions

    assert require_native_host_preconditions()["initial_root_credentials_observed"] is True
    assert signatures._parse((
        '{"archive":"repocache-v0.6.0.tar.gz","archive_sha256":"' + 'a'*64 +
        '","channel":"stable","commit":"' + combined_sha +
        '","expires_at":9999999999,"issued_at":1,"key_id":"pr237-synthetic",'
        '"policy_sha256":"' + 'b'*64 + '","repository":"repocache-project/repocache",'
        '"schema":1,"version":"0.6.0","wheelhouse_sha256":"' + 'c'*64 + '"}'
    ).encode())["repository"] == "repocache-project/repocache"
    print("PASS: exact pinned combined #249 v0.6 identity verifier observed")

    # All synthetic secrets stay inside this throwaway VM; never upload keys.
    private_root = Path("/root/pr237-synthetic-fixture")
    private_root.mkdir(mode=0o700)
    assets = private_root / "assets"
    original_root = build_release.ROOT
    try:
        source_tree = _candidate_source(private_root)
        build_release.ROOT = source_tree
        archive, _checksum = build_release.build_release(assets, "v0.6.0")
    finally:
        build_release.ROOT = original_root
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    now = int(time.time())
    manifest_obj = {
        "schema": 1, "repository": "repocache-project/repocache",
        "key_id": "pr237-synthetic", "channel": "stable", "version": "0.6.0",
        "commit": combined_sha, "archive": stage_native_root_worker.ARCHIVE,
        "archive_sha256": digest,
        "policy_sha256": hashlib.sha256((source_tree / "release-policy.json").read_bytes()).hexdigest(),
        "wheelhouse_sha256": "b" * 64,
        "issued_at": now - 30, "expires_at": now + 3600,
    }
    manifest = archive.with_name(archive.name + ".manifest.json")
    manifest.write_bytes((json.dumps(manifest_obj, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    private = private_root / "test-only-key.pem"
    trust_root = Path("/etc/repocache")
    trust_root.mkdir(mode=0o755)
    trust = trust_root / "trust.d"
    trust.mkdir(mode=0o755)
    public = trust / "pr237-synthetic.pem"
    subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519",
                    "-out", str(private)], check=True, timeout=20, capture_output=True)
    private.chmod(0o600)
    subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(private),
                    "-pubout", "-out", str(public)], check=True, timeout=20, capture_output=True)
    public.chmod(0o644)
    sig = manifest.with_name(manifest.name + ".sig")
    subprocess.run(["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey", str(private),
                    "-rawin", "-in", str(manifest), "-out", str(sig)],
                   check=True, timeout=20, capture_output=True)
    if isolated_policy:
        # Supplementary fixture-only envelope, NOT a release inventory member.
        # Bind the fixed policy source to the same synthetic signing identity,
        # archive, source and exact signed unit. Never ship the policy installer.
        from scripts.ci_selinux_nginx_egress_guest import guard, policy_manifest
        guard()
        # Only the policy bytes read from the independently assembled source
        # are authorized. The root-private copy is what the later probe uses.
        raw_policy = (source / "scripts/ci_selinux_nginx_egress_fixture.te").read_bytes()
        assert 0 < len(raw_policy) <= 16384
        policy = private_root / "isolated-policy.te"
        policy.write_bytes(raw_policy)
        policy.chmod(0o600)
        envelope = private_root / "isolated-policy.json"
        envelope.write_bytes(policy_manifest(
            combined_sha, digest, hashlib.sha256(manifest.read_bytes()).hexdigest(),
            hashlib.sha256((source_tree / stage_native_root_worker.UNIT_DIR /
                            "repocache-nginx.service").read_bytes()).hexdigest(),
            raw_policy))
        envelope.chmod(0o600)
        policy_sig = private_root / "isolated-policy.sig"
        subprocess.run(["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey", str(private),
                        "-rawin", "-in", str(envelope), "-out", str(policy_sig)],
                       check=True, timeout=20, capture_output=True)
        policy_sig.chmod(0o600)
        assert len(policy_sig.read_bytes()) == 64
    private.unlink()
    assert len(sig.read_bytes()) == 64
    pins = {"commit": combined_sha, "archive_sha256": digest}

    # A rejected synthetic detached signature MUST precede all host writes.
    signed = sig.read_bytes()
    sig.write_bytes(b"\x00" * 64)
    try:
        try:
            install_native_root_worker.install_authenticated_worker(assets, **pins)
        except (signatures.SignatureError, stage_native_root_worker.WorkerStageError):
            pass
        else:
            raise AssertionError("Invalid synthetic publisher signature installed a worker")
        assert not Path("/var/lib/repocache").exists()
        assert not Path("/usr/libexec/repocache").exists()
        print("PASS: actual root installer refused bad Ed25519 signature before worker/state placement")
    finally:
        sig.write_bytes(signed)

    result = install_native_root_worker.install_authenticated_worker(assets, **pins)
    assert result["status"] == "AUTHENTICATED_WORKER_FILES_PLACED"
    assert result["authorizes_service_activation"] is False
    assert stage_native_root_worker.verify_installed_worker(assets, **pins)["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    print("PASS: synthetic-signature authenticated real native worker+systemd units placed; exact readback")

    worker = Path("/usr/libexec/repocache/server-control-worker")
    units = [Path("/etc/systemd/system/repocache-control.service"),
             Path("/etc/systemd/system/repocache-control.socket")]
    tracked = [worker, *units]
    saved = [(p.stat().st_ino, p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest()) for p in tracked]
    second = install_native_root_worker.install_authenticated_worker(assets, **pins)
    assert second["status"] == "AUTHENTICATED_WORKER_FILES_PLACED"
    assert [(p.stat().st_ino, p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in tracked] == saved
    print("PASS: real repeated authenticated worker placement is byte/inode/mtime idempotent")

    # Test exact file integrity on real host, restoring the original bytes
    # before the later reboot/verification. No worker is ever started.
    unit = units[1]
    original = unit.read_bytes()
    try:
        unit.write_bytes(original + b"\n# pr237 synthetic drift\n")
        try:
            stage_native_root_worker.verify_installed_worker(assets, **pins)
        except stage_native_root_worker.WorkerStageError:
            pass
        else:
            raise AssertionError("Changed installed systemd unit was accepted")
        print("PASS: real root-installed unit-byte drift refused")
    finally:
        unit.write_bytes(original)
    assert stage_native_root_worker.verify_installed_worker(assets, **pins)["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"

    # Test actual installed executable path substitution, not only drift in
    # bytes. Preserve and restore the original inode inside this QEMU guest.
    backup = worker.with_name("server-control-worker.pr237-symlink-test-original")
    assert not os.path.lexists(backup) and not worker.is_symlink()
    worker_original = worker.lstat()
    os.rename(worker, backup)
    try:
        os.symlink(str(backup), str(worker))
        try:
            stage_native_root_worker.verify_installed_worker(assets, **pins)
        except stage_native_root_worker.WorkerStageError:
            pass
        else:
            raise AssertionError("Symlinked native root worker path was accepted")
    finally:
        if worker.is_symlink() and os.readlink(worker) == str(backup):
            worker.unlink()
        elif os.path.lexists(worker):
            raise AssertionError("Unexpected replacement at installed worker path")
        os.rename(backup, worker)
    worker_restored = worker.lstat()
    assert (worker_restored.st_dev, worker_restored.st_ino,
            worker_restored.st_mtime_ns) == (
                worker_original.st_dev, worker_original.st_ino,
                worker_original.st_mtime_ns)
    assert stage_native_root_worker.verify_installed_worker(assets, **pins)["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
    print("PASS: real installed root worker symlink substitution refused; original inode safely restored")

    subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True, timeout=30)
    for name in ("repocache-control.service", "repocache-control.socket"):
        active = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", name],
                                check=False, timeout=15)
        assert active.returncode != 0
    state = Path("/var/lib/repocache/server")
    assert state.is_dir()
    completed = list(state.glob(".native-worker-placement.complete-*"))
    assert len(completed) == 1 and completed[0].stat().st_size == 0
    with (private_root / "pins.json").open("w", encoding="ascii") as out:
        json.dump(pins, out, sort_keys=True)
    (private_root / "pins.json").chmod(0o600)
    print("PASS: real installed native worker signed-fixture audit, safe units unloaded/inactive")
    print("synthetic_archive_sha256=" + digest)
    print("combined_source_sha=" + combined_sha)
    print("NOT VERIFIED: real publisher-key signing, unit activation, SELinux worker denials")


if __name__ == "__main__":
    main()
