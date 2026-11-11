#!/usr/bin/env python3
"""Root-only, no-install privileged validation smoke on disposable native OS.

No APT/DNF installed-source writes, no root helper deployment, no network
trust claim. Fixture is a private 0700 directory under /tmp.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
import root_source_boundary as boundary

IDENT = "a" * 32
CACHE = "https://cache.example.org/__repocache/repos/baseos/"
APT = (b"deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] "
       b"https://deb.example.org/debian/ trixie main\n")
DNF = (b"[baseos]\nname=AlmaLinux\n"
       b"baseurl=https://rpm.example.org/alma/\n"
       b"enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"
       b"gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10\n")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def create(root: Path, *, manager: str):
    root.chmod(0o700)
    for marker, content in ((boundary.MARKER, boundary.MAGIC),
                            (".repocache-source-preflight-test",
                             b"REPOCACHE_SOURCE_PREFLIGHT_TEST_V1\n")):
        file = root / marker
        file.write_bytes(content)
        file.chmod(0o600)
    relative = ("etc/apt/sources.list.d/base.list" if manager == "apt"
                else "etc/yum.repos.d/base.repo")
    source = root / relative
    source.parent.mkdir(parents=True)
    raw = APT if manager == "apt" else DNF
    source.write_bytes(raw)
    source.chmod(0o644)
    state = root / "var/lib/repocache-client/approved-entries"
    state.mkdir(parents=True)
    (root / "var").chmod(0o755)
    (root / "var/lib").chmod(0o755)
    (root / "var/lib/repocache-client").chmod(0o700)
    state.chmod(0o700)
    lock = state / ".transaction.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    record = {
        "schema": 1, "id": IDENT, "source": relative,
        "source_sha256": sha(raw), "entry_sha256": sha(raw),
        "upstream": ("https://deb.example.org/debian/" if manager == "apt"
                     else "https://rpm.example.org/alma/"),
        "cache": CACHE, "route_sha256": sha(CACHE.encode("ascii")),
    }
    manifest = state / ("candidate-" + IDENT + ".json")
    manifest.write_text(json.dumps(record, sort_keys=True))
    manifest.chmod(0o600)
    return record, source, manifest, lock


def expect_reject(root: Path):
    try:
        boundary.validate(IDENT, _test_root=root)
    except boundary.BoundaryRefused:
        pass
    else:
        raise AssertionError("Root validation must reject corrupted source/state")


def smoke(manager: str):
    if os.geteuid() != 0 or not Path("/.dockerenv").exists():
        raise RuntimeError("Only native disposable Docker root accepts positive smoke")
    with tempfile.TemporaryDirectory(prefix="repocache-root-check-") as work:
        root = Path(work)
        record, source, manifest, lock = create(root, manager=manager)
        before = source.read_bytes()
        out = boundary.validate(IDENT, _test_root=root)
        assert out["status"] == "validated-read-only" and out["route_digest_matched"]
        assert not out["write_eligible"] and not out["installed"]
        assert not out["native_package_locks_verified"]
        assert source.read_bytes() == before
        print(f"{manager}: exact protected source/route PASS; no sources changed", flush=True)

        with lock.open("r+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            expect_reject(root)
            fcntl.flock(stream, fcntl.LOCK_UN)
        print(f"{manager}: competing global root transaction lock refusal PASS", flush=True)

        tampered = dict(record, cache="https://cache.example.org/other/")
        manifest.write_text(json.dumps(tampered))
        expect_reject(root)
        manifest.write_text(json.dumps(record))
        source.write_bytes(before + b"# external edit\n")
        expect_reject(root)
        source.write_bytes(before)
        # Corrupted foreign local approval ownership must not be followed.
        manifest.unlink()
        manifest.symlink_to("/etc/passwd")
        expect_reject(root)
        assert source.read_bytes() == before
        print(f"{manager}: stale-route, drift and symlink refusal PASS", flush=True)


if __name__ == "__main__":
    # Tests exactly both supported format boundaries on native OS Python.
    smoke(sys.argv[1])
