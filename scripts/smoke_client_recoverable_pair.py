#!/usr/bin/env python3
"""Exercise actual inode journal rollback after SIGKILL in disposable distro CI.

REPOCACHE's installed CLI and host APT/DNF source paths are not affected.
Test files live under an isolated 0700 /tmp tree and require real UID 0.
"""
from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import signal
import struct
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
    # Fixed private native lock paths; never create host lock files.
    native_locks = pair.locks.APT if manager == "apt" else pair.locks.DNF5
    for name in native_locks:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
        path.chmod(0o600)
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


def sigkill_restore(manager):
    for point in ("restore-armed", "source-restored", "companion-removed"):
        with tempfile.TemporaryDirectory(prefix="repocache-restore-kill-ci-") as place:
            root = Path(place)
            src, mirror, lock, state = build(root, manager)
            before = src.read_bytes()
            metadata = src.stat()
            pair.apply_sandbox(root, IDENT)
            pid = os.fork()
            if pid == 0:
                def kill_at(active, current):
                    if active == current:
                        os.kill(os.getpid(), signal.SIGKILL)
                pair._crash = kill_at
                pair.restore_sandbox(root, IDENT, crash=point)
                os._exit(77)
            _, status = os.waitpid(pid, 0)
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            assert pair.recover_sandbox(root, IDENT)["status"] == "restored"
            assert src.read_bytes() == before and not mirror.exists()
            after = src.stat()
            assert (after.st_uid, after.st_gid, after.st_mode) == (
                metadata.st_uid, metadata.st_gid, metadata.st_mode)
            print(f"{manager}: real SIGKILL during rollback {point} recovered PASS",
                  flush=True)


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
        # A completely self-consistent changed cache and digest must also
        # fail; the original protected journal binds exact consent.
        approval["cache"] = "https://cache.example.org/__repocache/repos/changed/"
        approval["route_sha256"] = sha(approval["cache"].encode("ascii"))
        manifest.write_text(json.dumps(approval))
        refuses(lambda: pair.apply_sandbox(root, IDENT),
                "A different self-consistent approval cannot authorize replay")
        # Recovery is local and may restore exact original resources even
        # when current approval is gone or no longer published.
        manifest.unlink()
        assert pair.restore_sandbox(root, IDENT)["status"] == "restored"
        assert src.read_bytes() == (APT if manager == "apt" else DNF)
        assert not mirror.exists()
        print(f"{manager}: exact approval replay refusal and independent restore PASS",
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

    with tempfile.TemporaryDirectory(prefix="repocache-pair-v2-ci-") as place:
        root = Path(place)
        src, mirror, lock, state = build(root, manager)
        original = src.read_bytes()
        manifest = state / ("candidate-" + IDENT + ".json")
        approval = json.loads(manifest.read_text())
        snapshot = boundary.pre.inspect_source(approval["source"], root=root)
        approval["schema"] = 2
        approval["source_identity"] = {
            key: snapshot[key] for key in boundary.SOURCE_IDENTITY_FIELDS
        }
        manifest.write_text(json.dumps(approval))
        assert pair.apply_sandbox(root, IDENT)["status"] == "installed-sandbox"
        assert pair.apply_sandbox(root, IDENT)["status"] == "unchanged"
        assert pair.restore_sandbox(root, IDENT)["status"] == "restored"
        assert src.read_bytes() == original and not mirror.exists()
        print(f"{manager}: schema-2 approved plan bound to journal/restore PASS", flush=True)

    with tempfile.TemporaryDirectory(prefix="repocache-pair-attrs-ci-") as place:
        root = Path(place)
        src, mirror, lock, state = build(root, manager)
        os.setxattr(src, "user.repocache-ci", b"exact-private-metadata")
        # Linux POSIX ACL xattr format v2: explicit read-only named user,
        # owner rw, group/mask/other r. No widened write authority.
        acl = struct.pack("<I", 2) + b"".join(
            struct.pack("<HHI", tag, perms, uid)
            for tag, perms, uid in ((1, 6, 0xffffffff), (2, 4, 65534),
                                    (4, 4, 0xffffffff), (16, 4, 0xffffffff),
                                    (32, 4, 0xffffffff)))
        os.setxattr(src, "system.posix_acl_access", acl)
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            identity, attrs = boundary.metadata._metadata(fd)
        finally:
            os.close(fd)
        assert {name for name, _ in attrs} == {"user.repocache-ci", "system.posix_acl_access"}
        manifest = state / ("candidate-" + IDENT + ".json")
        approval = json.loads(manifest.read_text())
        approval["schema"] = 3
        approval["source_identity"] = identity
        approval["source_attributes_sha256"] = boundary.metadata.attribute_digest(attrs)
        manifest.write_text(json.dumps(approval))
        before = src.read_bytes()
        assert pair.apply_sandbox(root, IDENT)["status"] == "installed-sandbox"
        assert pair.apply_sandbox(root, IDENT)["status"] == "unchanged"
        assert tuple(sorted((name, os.getxattr(src, name)) for name in os.listxattr(src))) == attrs
        os.setxattr(src, "user.repocache-ci", b"foreign")
        refuses(lambda: pair.restore_sandbox(root, IDENT),
                "Changed approved metadata cannot authorize rollback")
        os.setxattr(src, "user.repocache-ci", b"exact-private-metadata")
        assert pair.restore_sandbox(root, IDENT)["status"] == "restored"
        assert src.read_bytes() == before
        assert tuple(sorted((name, os.getxattr(src, name)) for name in os.listxattr(src))) == attrs
        print(f"{manager}: schema-3 ACL/xattr apply, drift refusal and restore PASS", flush=True)

    with tempfile.TemporaryDirectory(prefix="repocache-pair-native-lock-ci-") as place:
        root = Path(place)
        src, mirror, lock, state = build(root, manager)
        name = (pair.locks.APT if manager == "apt" else pair.locks.DNF5)[0]
        before = src.stat()
        # flock and POSIX locks are independent: another process holds the
        # former; the transaction cannot stage or publish anything.
        with (root / name).open("r+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            refuses(lambda: pair.apply_sandbox(root, IDENT),
                    "Competing native lock must refuse source transaction")
            fcntl.flock(held, fcntl.LOCK_UN)
        assert src.stat().st_ino == before.st_ino
        assert not list(state.glob("pair-*.json")) and not mirror.exists()
        pair.apply_sandbox(root, IDENT)
        installed = src.read_bytes()
        with (root / name).open("r+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            refuses(lambda: pair.restore_sandbox(root, IDENT),
                    "Competing native lock must refuse rollback")
            fcntl.flock(held, fcntl.LOCK_UN)
        assert src.read_bytes() == installed
        assert pair.restore_sandbox(root, IDENT)["status"] == "restored"
        print(f"{manager}: native lock interlock across apply/restore PASS", flush=True)

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


def retained_apt_matrix(with_metadata=False):
    """Exercise both retained schemas at every durable boundary."""
    upstream = b"https://deb.example.org/debian/\tpriority:1\n"
    for point in ("armed", "companion", "source", "retention-armed",
                  "companion-neutralized", "restore-armed", "source-restored", None):
        with tempfile.TemporaryDirectory(prefix="repocache-retained-apt-") as place:
            root = Path(place)
            source, mirror, _, state = build(root, "apt")
            before = source.read_bytes()
            if with_metadata:
                os.setxattr(source, "user.repocache-ci", b"retained-exact")
                acl = struct.pack("<I", 2) + b"".join(
                    struct.pack("<HHI", tag, perms, uid)
                    for tag, perms, uid in ((1, 6, 0xffffffff), (2, 4, 65534),
                                            (4, 4, 0xffffffff), (16, 4, 0xffffffff),
                                            (32, 4, 0xffffffff)))
                os.setxattr(source, "system.posix_acl_access", acl)
                fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    identity, attrs = boundary.metadata._metadata(fd)
                finally:
                    os.close(fd)
                assert {name for name, _ in attrs} == {
                    "user.repocache-ci", "system.posix_acl_access"}
                manifest = state / ("candidate-" + IDENT + ".json")
                approval = json.loads(manifest.read_text())
                approval.update(schema=3, source_identity=identity,
                                source_attributes_sha256=boundary.metadata.attribute_digest(attrs))
                manifest.write_text(json.dumps(approval))
            else:
                attrs = ()
            schema = 5 if with_metadata else 4
            apply = lambda **kw: pair.apply_retaining_apt_companion_sandbox(
                root, IDENT, current_catalog=False, **kw)
            applying = point in ("armed", "companion", "source")
            if not applying:
                assert apply()["status"] == "installed-sandbox"
                assert apply()["status"] == "unchanged"
                refuses(lambda: pair.apply_sandbox(root, IDENT),
                        "Legacy entry must not change new recovery contract")
            if point is None:
                assert pair.restore_sandbox(root, IDENT)["status"] == "restored"
            else:
                pid = os.fork()
                if pid == 0:
                    def kill_at(active, phase):
                        if active == phase:
                            os.kill(os.getpid(), signal.SIGKILL)
                    pair._crash = kill_at
                    if applying:
                        apply(crash=point)
                    else:
                        pair.restore_sandbox(root, IDENT, crash=point)
                    os._exit(77)
                _, status = os.waitpid(pid, 0)
                assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            journal = state / ("pair-" + IDENT + ".json")
            assert json.loads(journal.read_text())["schema"] == schema
            assert pair.recover_sandbox(root, IDENT)["status"] == "restored"
            assert source.read_bytes() == before
            assert tuple(sorted((name, os.getxattr(source, name))
                                for name in os.listxattr(source))) == attrs
            if point == "armed":
                assert not mirror.exists()
            else:
                assert mirror.read_bytes() == upstream
                assert mirror.stat().st_uid == mirror.stat().st_gid == 0
                assert mirror.stat().st_mode & 0o777 == 0o644
                assert not os.listxattr(mirror)
                saved = mirror.stat().st_ino
                assert pair.recover_sandbox(root, IDENT)["status"] == "restored"
                assert mirror.stat().st_ino == saved
                # A matching digest in a foreign inode is not ownership.
                replacement = mirror.with_suffix(".foreign")
                replacement.write_bytes(upstream)
                os.replace(replacement, mirror)
                refuses(lambda: pair.recover_sandbox(root, IDENT),
                        "Foreign retained inode must be refused")
                assert mirror.read_bytes() == upstream
            refuses(apply, "Restored approval ID cannot be reused")
            assert not list(source.parent.glob(".repocache-atomic-*"))
            print(f"apt: retained companion schema-{schema} recovery {point} PASS", flush=True)


def incomplete_journal_matrix(manager):
    """Inject ENOSPC at the pending journal fsync, not on the runner disk.

    Every public sandbox entry must preserve the last committed journal,
    incomplete pending file, and source/companion/staging inodes. A prior
    installed/restored-looking snapshot is not sufficient recovery proof.
    """
    cases = (("apply", 1, None), ("apply", 2, "armed"),
             ("restore", 1, "installed"), ("restore", 2, "restore-armed"))
    if manager == "apt":
        cases += (("restore", 3, "restore-armed"),)
    for action, fail_at, prior_phase in cases:
        with tempfile.TemporaryDirectory(prefix="repocache-pair-io-fault-") as place:
            root = Path(place)
            source, mirror, _, state = build(root, manager)
            original = source.read_bytes()
            pending = state / pair._pending_journal_name(IDENT)
            journal = state / pair._journal_name(IDENT)
            def apply():
                if manager == "apt":
                    return pair.apply_retaining_apt_companion_sandbox(
                        root, IDENT, current_catalog=False)
                return pair.apply_sandbox(root, IDENT)
            def restore():
                return pair.restore_sandbox(root, IDENT)
            if action == "restore":
                assert apply()["status"] == "installed-sandbox"
            actual_fsync = os.fsync
            calls = 0
            injected = OSError(errno.ENOSPC, "injected pending journal fsync")
            def fail_pending(fd):
                nonlocal calls
                # Only the exact new regular journal file in this private
                # fixture is subject to the simulated kernel error.
                if os.readlink("/proc/self/fd/" + str(fd)) == str(pending):
                    calls += 1
                    if calls == fail_at:
                        raise injected
                actual_fsync(fd)
            try:
                os.fsync = fail_pending
                try:
                    (apply if action == "apply" else restore)()
                except Exception as exc:
                    # Different protected directory/state contexts wrap I/O
                    # errors differently. Require the exact original injected
                    # exception in the explicit cause chain; any unrelated
                    # exception fails this test, regardless of its type.
                    cause = exc
                    for _ in range(4):
                        if cause is injected:
                            break
                        cause = cause.__cause__
                        if cause is None:
                            break
                    assert cause is injected and cause.errno == errno.ENOSPC
                else:
                    raise AssertionError("Pending journal fsync error was accepted")
            finally:
                os.fsync = actual_fsync
            assert calls == fail_at and pending.is_file()
            assert pending.stat().st_uid == 0 and pending.stat().st_mode & 0o777 == 0o600
            if prior_phase is None:
                assert not journal.exists() and source.read_bytes() == original
                assert not mirror.exists()
            else:
                assert json.loads(journal.read_text())["phase"] == prior_phase
            def snapshot():
                # All regular fixture files, including exact staged and
                # pending inodes. Never follow links or examine host data.
                return {str(path.relative_to(root)): (
                    path.stat().st_dev, path.stat().st_ino, path.stat().st_uid,
                    path.stat().st_gid, path.stat().st_mode,
                    path.read_bytes(), tuple(sorted(
                        (key, os.getxattr(path, key)) for key in os.listxattr(path))))
                        for path in root.rglob("*") if path.is_file()}
            before = snapshot()
            for operation in (lambda: pair.recover_sandbox(root, IDENT), apply, restore):
                try:
                    operation()
                except pair.PairRefused as exc:
                    assert str(exc) == "Pending journal requires manual recovery"
                else:
                    raise AssertionError("Incomplete journal was treated as clean")
                assert snapshot() == before
            print(f"{manager}: pending journal {action} fsync {fail_at} ENOSPC refusal and inode preservation PASS",
                  flush=True)


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
    sigkill_restore(manager)
    hostile(manager)
    incomplete_journal_matrix(manager)
    if manager == "apt":
        retained_apt_matrix()
        retained_apt_matrix(with_metadata=True)
    print(f"{manager}: paired transaction full disposable-native matrix PASS",
          flush=True)
