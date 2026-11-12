#!/usr/bin/env python3
"""Exercise actual inode journal rollback after SIGKILL in disposable distro CI.

REPOCACHE's installed CLI and host APT/DNF source paths are not affected.
Test files live under an isolated 0700 /tmp tree and require real UID 0.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import signal
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
import recoverable_fallback_pair_lab as pair
import root_source_boundary as boundary

IDENT = "a" * 32
CACHE = "https://cache.example.org/__repocache/repos/approved/"
APT = (b"deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] "
       b"https://deb.example.org/debian/ trixie main\n")
DNF = (b"[baseos]\nname=AlmaLinux\n"
       b"baseurl=https://rpm.example.org/alma/\n"
       b"enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"
       b"gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10\n")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build(root: Path, manager: str):
    root.chmod(0o700)
    for name, payload in (
        (boundary.MARKER, boundary.MAGIC),
        (".repocache-source-preflight-test",
         b"REPOCACHE_SOURCE_PREFLIGHT_TEST_V1\n"),
        (pair.MARKER, pair.MAGIC),
    ):
        path = root / name
        path.write_bytes(payload)
        path.chmod(0o600)
    relative = ("etc/apt/sources.list.d/base.list" if manager == "apt"
                else "etc/yum.repos.d/base.repo")
    raw = APT if manager == "apt" else DNF
    source = root / relative
    source.parent.mkdir(parents=True)
    source.write_bytes(raw)
    source.chmod(0o644)
    if manager == "apt":
        (root / "etc/apt/mirrors").mkdir(mode=0o755)
    state = root / "var/lib/repocache-client/approved-entries"
    state.mkdir(parents=True)
    for parent in (root / "var", root / "var/lib"):
        parent.chmod(0o755)
    for parent in (root / "var/lib/repocache-client", state):
        parent.chmod(0o700)
    lock = state / ".transaction.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    approval = {
        "schema": 1, "id": IDENT, "source": relative,
        "source_sha256": sha(raw), "entry_sha256": sha(raw),
        "upstream": ("https://deb.example.org/debian/" if manager == "apt"
                     else "https://rpm.example.org/alma/"),
        "cache": CACHE, "route_sha256": sha(CACHE.encode("ascii")),
    }
    item = state / ("candidate-" + IDENT + ".json")
    item.write_text(json.dumps(approval, sort_keys=True))
    item.chmod(0o600)
    mirror = root / ("etc/apt/mirrors/repocache-" + IDENT + ".list")
    return source, mirror, lock, state


def refuses(action, message):
    try:
        action()
    except (pair.PairRefused, boundary.BoundaryRefused):
        return
    raise AssertionError(message)


def exercise(manager: str, root: Path):
    source, mirror, lock, state = build(root, manager)
    before = source.read_bytes()
    assert not mirror.exists()

    def clean(phase):
        assert source.read_bytes() == before, phase
        assert not mirror.exists(), phase

    # Normal exact-identity apply, repeated no-op, recover is non-destructive
    # for fully committed transactions, explicit restore is reversible.
    assert pair.apply_sandbox(root, IDENT)["status"] == "installed-sandbox"
    assert source.read_bytes() != before
    if manager == "apt":
        assert mirror.read_bytes().startswith(CACHE.encode())
    assert pair.apply_sandbox(root, IDENT)["status"] == "unchanged"
    assert pair.recover_sandbox(root, IDENT)["status"] == "installed-sandbox"
    assert pair.restore_sandbox(root, IDENT)["status"] == "restored"
    clean("normal restore")
    print(f"{manager}: installed and repeated exact-no-op, journalled restore PASS",
          flush=True)


def recovery_matrix(manager):
    stages = ("armed", "companion", "source") if manager == "apt" else (
        "armed", "source")
    for index, name in enumerate(stages):
        with tempfile.TemporaryDirectory(prefix="repocache-pair-ci-") as place:
            root = Path(place)
            src, mirror, lock, state = build(root, manager)
            before = src.read_bytes()
            try:
                pair.apply_sandbox(root, IDENT, crash=name)
            except pair.InjectedCrash:
                pass
            else:
                raise AssertionError("Fault injection did not trigger")
            assert pair.recover_sandbox(root, IDENT)["status"] == "restored"
            assert src.read_bytes() == before
            assert not mirror.exists()
            assert pair.recover_sandbox(root, IDENT)["status"] == "restored"
            print(f"{manager}: interrupted {name} recovered PASS", flush=True)

    for name in ("restore-armed", "source-restored", "companion-removed"):
        with tempfile.TemporaryDirectory(prefix="repocache-pair-restore-ci-") as place:
            root = Path(place)
            src, mirror, lock, state = build(root, manager)
            prior = src.read_bytes()
            pair.apply_sandbox(root, IDENT)
            try:
                pair.restore_sandbox(root, IDENT, crash=name)
            except pair.InjectedCrash:
                pass
            else:
                raise AssertionError("Rollback fault injection did not trigger")
            assert pair.recover_sandbox(root, IDENT)["status"] == "restored"
            assert src.read_bytes() == prior
            assert not mirror.exists()
            print(f"{manager}: interrupted rollback {name} recovered PASS",
                  flush=True)


def sigkill_recovery(manager):
    for point in (("armed", "source") if manager == "dnf"
                  else ("armed", "companion", "source")):
        with tempfile.TemporaryDirectory(prefix="repocache-pair-kill-ci-") as place:
            root = Path(place)
            src, mirror, lock, state = build(root, manager)
            before = src.read_bytes()
            pid = os.fork()
            if pid == 0:
                def kill_at(active, current):
                    if active == current:
                        os.kill(os.getpid(), signal.SIGKILL)
                pair._crash = kill_at
                pair.apply_sandbox(root, IDENT, crash=point)
                os._exit(77)
            _, status = os.waitpid(pid, 0)
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            assert pair.recover_sandbox(root, IDENT)["status"] == "restored"
            assert src.read_bytes() == before
            assert not mirror.exists()
            print(f"{manager}: real SIGKILL at {point} recovered PASS", flush=True)


def hostile(manager):
    with tempfile.TemporaryDirectory(prefix="repocache-pair-foreign-ci-") as place:
        root = Path(place)
        src, mirror, lock, state = build(root, manager)
        original = src.read_bytes()
        pair.apply_sandbox(root, IDENT)
        # Foreign replacement with the exact same content has a different
        # inode. No digest-based forced restore may erase its ownership.
        copied = src.read_bytes()
        foreign = src.with_name(src.name + ".foreign")
        foreign.write_bytes(copied)
        foreign.chmod(0o644)
        assert foreign.stat().st_ino != src.stat().st_ino
        os.replace(foreign, src)
        refuses(lambda: pair.restore_sandbox(root, IDENT),
                "Foreign equal-content source must be rejected")
        assert src.read_bytes() == copied
        if manager == "apt":
            assert mirror.exists()
        print(f"{manager}: equal-content foreign inode refusal PASS", flush=True)

    with tempfile.TemporaryDirectory(prefix="repocache-pair-approval-ci-") as place:
        root = Path(place)
        src, mirror, lock, state = build(root, manager)
        pair.apply_sandbox(root, IDENT)
        manifest = state / ("candidate-" + IDENT + ".json")
        approval = json.loads(manifest.read_text())
        approval["route_sha256"] = sha(b"changed route without consent")
        manifest.write_text(json.dumps(approval))
        refuses(lambda: pair.apply_sandbox(root, IDENT),
                "Stale route must not be idempotently accepted")
        print(f"{manager}: no-op replay requires authentic route binding PASS",
              flush=True)

    if manager == "apt":
        with tempfile.TemporaryDirectory(prefix="repocache-pair-missing-ci-") as place:
            root = Path(place)
            src, mirror, lock, state = build(root, manager)
            pair.apply_sandbox(root, IDENT)
            proposed = src.read_bytes()
            mirror.unlink()
            refuses(lambda: pair.restore_sandbox(root, IDENT),
                    "Missing committed mirror must not authorize source restore")
            assert src.read_bytes() == proposed
            print("apt: missing committed mirror refuses destructive rollback PASS",
                  flush=True)

        with tempfile.TemporaryDirectory(prefix="repocache-pair-mirror-ci-") as place:
            root = Path(place)
            src, mirror, lock, state = build(root, manager)
            pair.apply_sandbox(root, IDENT)
            foreign = mirror.with_name(mirror.name + ".foreign")
            foreign.write_bytes(mirror.read_bytes())
            foreign.chmod(0o644)
            assert foreign.stat().st_ino != mirror.stat().st_ino
            os.replace(foreign, mirror)
            proposed = src.read_bytes()
            refuses(lambda: pair.restore_sandbox(root, IDENT),
                    "Foreign mirror with equal bytes must not be removed")
            assert src.read_bytes() == proposed and mirror.exists()
            print("apt: foreign equal-content mirror inode refused PASS", flush=True)

    with tempfile.TemporaryDirectory(prefix="repocache-pair-lock-ci-") as place:
        root = Path(place)
        src, mirror, lock, state = build(root, manager)
        with lock.open("r+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            refuses(lambda: pair.apply_sandbox(root, IDENT),
                    "Competing root transaction lock must refuse")
            fcntl.flock(stream, fcntl.LOCK_UN)
        assert src.read_bytes() == (APT if manager == "apt" else DNF)
        refuses(lambda: pair.apply_sandbox(Path("/"), IDENT),
                "Never write the actual host root")
        print(f"{manager}: root-lock and production-root refusal PASS", flush=True)


if __name__ == "__main__":
    if (len(sys.argv) != 2 or sys.argv[1] not in ("apt", "dnf")
            or os.geteuid() != 0 or
            not Path("/.dockerenv").exists()):
        raise SystemExit("Use only disposable Docker UID 0 with apt/dnf")
    manager = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="repocache-pair-normal-ci-") as p:
        exercise(manager, Path(p))
    recovery_matrix(manager)
    sigkill_recovery(manager)
    hostile(manager)
    print(f"{manager}: paired transaction full disposable-native matrix PASS",
          flush=True)
