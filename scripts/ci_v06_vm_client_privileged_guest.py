#!/usr/bin/env python3
"""Booted native privileged client fixture; never writes host sources."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import ssl
import subprocess
import sys
import tempfile
import time

from ci_v06_vm_signed_client_guest import (
    guarded_native_guest, installed_packages, installed_sources,
)
from ci_client_native_fallback import HTTPBackend, temporary_tls_identity
from smoke_client_recoverable_pair import build, IDENT, sha
import root_source_boundary as boundary
import recoverable_fallback_pair_lab as pair


def _snapshot(path: Path):
    info = path.lstat()
    attrs = tuple(sorted((name, os.getxattr(path, name, follow_symlinks=False))
                         for name in os.listxattr(path, follow_symlinks=False)))
    return (path.read_bytes(), info.st_dev, info.st_ino, info.st_uid,
            info.st_gid, info.st_mode, info.st_mtime_ns, info.st_ctime_ns, attrs)


def _apt_source_read_order(root: Path) -> None:
    """Exercise real APT parsing before the full existing native lock set.

    The guarded booted guest supplies its marked disposable root. Isolate
    apt.conf loading *before* APT reads its normal configuration, as well
    as lists, archives, status, logs and sources. No network repositories.
    """
    assert root.is_absolute() and root.resolve(strict=True) == root
    assert root.parent == Path("/tmp") and root.name.startswith("repocache-booted-approval-")
    assert re.fullmatch(r"[A-Za-z0-9_/-]+", str(root))
    assert root.stat().st_uid == 0 and root.stat().st_mode & 0o777 == 0o700
    etc = root / "etc/apt"
    lists = root / "var/lib/apt/lists"
    for directory in (lists / "partial", root / "var/cache/apt/archives/partial",
                      root / "var/log/apt", etc / "empty-parts", etc / "apt.conf.d"):
        directory.mkdir(mode=0o700, parents=True)
    status = root / "var/lib/dpkg/status"
    empty = etc / "empty.list"
    for path in (status, empty, etc / "apt.conf"):
        with path.open("x"):
            pass
    config = etc / "fixture.conf"
    with config.open("x") as handle:
        handle.write(
            f'Dir "{root}/";\n'
            'Dir::Etc "etc/apt";\n'
            'Dir::Etc::main "apt.conf";\n'
            'Dir::Etc::parts "apt.conf.d";\n'
            'Dir::Etc::sourcelist "empty.list";\n'
            'Dir::Etc::sourceparts "empty-parts";\n'
            'Dir::State "var/lib/apt";\n'
            f'Dir::State::status "{status}";\n'
            'Dir::Cache "var/cache/apt";\n'
            'Dir::Log "var/log/apt";\n'
            'APT::Update::Error-Mode "any";\n'
            'Acquire::Retries "0";\n'
        )
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "APT_CONFIG": str(config)}

    def update():
        return subprocess.run(["/usr/bin/apt-get", "update"], check=False,
                              capture_output=True, text=True, timeout=30, env=env)

    def require_lock_refusal():
        refused = update()
        assert refused.returncode == 100 and "Could not get lock" in refused.stderr
        assert str(lists / "lock") in refused.stderr

    with pair.locks.hold_existing_native_package_locks(
            "apt", root=root, revalidation=True) as recheck:
        require_lock_refusal()
        recheck()
        try:
            empty.write_text("repocache-invalid-source\n")
            malformed = update()
            assert malformed.returncode == 100
            assert f"Malformed line 1 in source list {empty}" in malformed.stderr
            assert "The list of sources could not be read" in malformed.stderr
            assert "Could not get lock" not in malformed.stderr
            recheck()
        finally:
            empty.write_text("")
        require_lock_refusal()
        recheck()
    assert update().returncode == 0
    assert status.read_bytes() == b"" and empty.read_bytes() == b""
    print("PASS: native apt-get reads sources before the held lists lock, "
          "even with all four transaction locks held; release succeeds")


def _signed_recovery_readback(root, ident, *, platform, phase, source_state, companion_state,
                              source_stage="absent", companion_stage=None):
    """Inspect existing exact lab evidence using only the authenticated zip."""
    guarded_native_guest(platform)
    target = "/usr/libexec/repocache-client/client-source-helper"
    code = """
import json,sys,zipimport
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import recovery_journal_v1 as recovery
assert isinstance(recovery.__loader__, zipimport.zipimporter)
assert recovery.__loader__.archive == sys.argv[1]
assert "recoverable_fallback_pair_lab" not in sys.modules
root=Path(sys.argv[2])
with recovery.security_metadata.native_metadata_scope(root):
    print(json.dumps(recovery.inspect_local_recovery_record(sys.argv[3], _test_root=root)))
assert "recoverable_fallback_pair_lab" not in sys.modules
"""
    report = json.loads(subprocess.run(
        ["/usr/bin/python3", "-IS", "-B", "-c", code, target, str(root), ident],
        check=True, capture_output=True, timeout=20,
    ).stdout)
    assert report["status"] == "record-verified-read-only"
    assert report["journal_record_verified"]
    if source_state == "restored":
        # Independently inspect the private fixture's exact journal and
        # actual source inode. DNF may reuse the freed original inode.
        journal = json.loads((root / "var/lib/repocache-client/approved-entries" /
                              ("pair-" + ident + ".json")).read_text("ascii"))
        actual = (root / journal["source"]).stat()
        assert [actual.st_dev, actual.st_ino] == journal["restore_id"]
        if journal["original_id"] == journal["restore_id"]:
            source_state = "original-or-restored"
    assert (report["phase"], report["source_state"], report["companion_state"]) == (
        phase, source_state, companion_state), report
    if companion_stage is None:
        companion_stage = ("not-applicable" if companion_state == "not-applicable" else "absent")
    assert (report["source_stage_state"], report["companion_stage_state"]) == (
        source_stage, companion_stage), report
    assert all(report[name] is False for name in (
        "local_rollback_verified", "route_revocation_verified",
        "native_exclusion_verified", "write_eligible"))
    print("PASS: authenticated read-only recovery record, exact local evidence, "
          "no revocation or write claim: " + phase + " " + source_state, flush=True)
    if phase == "restored":
        # Negative readback from the same authenticated archive, not a
        # second writer. Only the exact marked fixture journal is touched.
        journal_path = root / "var/lib/repocache-client/approved-entries" / ("pair-" + ident + ".json")
        pending = journal_path.with_name(".pair-" + ident + ".pending")
        before = _snapshot(journal_path)
        with pending.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(b"partial fixture evidence")
        try:
            pending_before = _snapshot(pending)
            denied = subprocess.run(
                ["/usr/bin/python3", "-IS", "-B", "-c", code, target, str(root), ident],
                capture_output=True, timeout=20)
            assert denied.returncode != 0 and b"Pending journal requires manual recovery" in denied.stderr
            assert _snapshot(pending) == pending_before and _snapshot(journal_path) == before
        finally:
            # This test owns the deliberately injected pending leaf.
            pending.unlink()
        print("PASS: authenticated readback refuses pending journal without changes", flush=True)
        # Preserve the exact owned file as a separate fixture leaf; publish
        # a different inode with the same content and attributes. The
        # authenticated read-only helper must refuse for identity, not a
        # missing label or changed source bytes. Never touch host sources.
        entry = root / (journal["companion"] or journal["source"])
        saved = entry.with_name(".repocache-ci-readback-owned")
        foreign = entry.with_name(".repocache-ci-readback-foreign")
        assert not os.path.lexists(saved) and not os.path.lexists(foreign)
        owned = _snapshot(entry)
        import shutil
        with foreign.open("xb") as stream:
            stream.write(owned[0])
            os.fchown(stream.fileno(), owned[3], owned[4])
            os.fchmod(stream.fileno(), owned[5] & 0o777)
        shutil.copystat(entry, foreign, follow_symlinks=False)
        for name, value in owned[-1]:
            os.setxattr(foreign, name, value, follow_symlinks=False)
        replacement = _snapshot(foreign)
        assert replacement[0] == owned[0] and replacement[3:7] == owned[3:7]
        assert replacement[-1] == owned[-1] and replacement[1:3] != owned[1:3]
        os.rename(entry, saved)
        os.rename(foreign, entry)
        try:
            foreign_before = _snapshot(entry)
            saved_before = _snapshot(saved)
            denied = subprocess.run(
                ["/usr/bin/python3", "-IS", "-B", "-c", code, target, str(root), ident],
                capture_output=True, timeout=20)
            assert denied.returncode != 0 and b"is not a recorded inode" in denied.stderr, denied.stderr
            assert _snapshot(entry) == foreign_before and _snapshot(saved) == saved_before
            assert _snapshot(journal_path) == before
        finally:
            os.rename(entry, foreign)
            os.rename(saved, entry)
            foreign.unlink()
        again = json.loads(subprocess.run(
            ["/usr/bin/python3", "-IS", "-B", "-c", code, target, str(root), ident],
            check=True, capture_output=True, timeout=20).stdout)
        assert again == report
        print("PASS: authenticated readback refuses same-byte foreign inode; owned evidence preserved", flush=True)
        # A terminal journal must not authorize a stray staging leaf. The
        # negative is an actual guarded private fixture, never a host path.
        paths = [root / journal["source"]]
        if journal["companion"] is not None:
            paths.append(root / journal["companion"])
        for path in paths:
            staged = path.with_name(".repocache-atomic-" + ident)
            assert not os.path.lexists(staged)
            with staged.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(b"foreign fixture stage")
            try:
                foreign_stage = _snapshot(staged)
                denied = subprocess.run(
                    ["/usr/bin/python3", "-IS", "-B", "-c", code, target, str(root), ident],
                    capture_output=True, timeout=20)
                assert denied.returncode != 0 and b"Unexpected recovery stage" in denied.stderr
                assert _snapshot(staged) == foreign_stage and _snapshot(journal_path) == before
            finally:
                staged.unlink()
        print("PASS: authenticated readback refuses stray stage in terminal journal", flush=True)


def _debian_fixture(root: Path) -> None:
    source, _, lock, state = build(root, "apt")
    original = _snapshot(source)
    old = state / ("candidate-" + IDENT + ".json")
    record = json.loads(old.read_text())
    old.unlink()
    (root / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    config = root / "etc/repocache-client"
    config.mkdir(mode=0o755)
    www = root / "www"
    catalog = www / ".well-known/repocache/catalog.json"
    catalog.parent.mkdir(parents=True)
    certificate, private_key = temporary_tls_identity(root, "approved-catalog")
    foreign, _ = temporary_tls_identity(root, "foreign-catalog")
    backend = HTTPBackend(www, certificate=certificate, key=private_key)
    original_context = boundary._native_tls_context
    try:
        origin = backend.origin.removesuffix("/repo/")
        route = origin + "/__repocache/repos/approved/"
        (config / "config.json").write_text(json.dumps({"server": origin}))
        (config / "config.json").chmod(0o644)
        catalog.write_text(json.dumps({"schema": 1, "repositories": [
            {"upstream": record["upstream"], "cache": route}]}))
        # Guest-local fixture CA; the actual transport and verifier execute.
        wrong = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        wrong.load_verify_locations(cafile=str(foreign))
        boundary._native_tls_context = lambda: wrong
        try:
            boundary.prepare_current_candidate(
                record["source_sha256"], record["entry_sha256"], _test_root=root)
        except boundary.BoundaryRefused:
            pass
        else:
            raise AssertionError("Foreign fixture CA was accepted")
        assert not list(state.glob("pending-*.json")) and not backend.hits
        trusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trusted.load_verify_locations(cafile=str(certificate))
        boundary._native_tls_context = lambda: trusted
        prepared = boundary.prepare_current_candidate(
            record["source_sha256"], record["entry_sha256"], _test_root=root)
        ident = prepared["managed_id"]
        assert prepared["route_sha256"] == sha(route.encode("ascii"))
        assert not prepared["approval_granted"] and not prepared["write_eligible"]
        manifest = state / ("candidate-" + ident + ".json")
        assert not manifest.exists()
        review = boundary.review_current_candidate(ident, _test_root=root)
        assert review["source"] == record["source"]
        assert review["upstream"] == record["upstream"] and review["cache"] == route
        assert review["route_sha256"] == prepared["route_sha256"]
        assert review["current_active_catalog_route_matched"]
        assert not review["approval_issued"] and not review["write_eligible"]
        assert not manifest.exists() and _snapshot(source) == original
        approved = boundary.approve_current_candidate(
            ident, review["route_sha256"], _test_root=root)
        assert approved["status"] == "approved" and not approved["write_eligible"]
        assert manifest.is_file() and _snapshot(source) == original
        assert len(backend.hits) >= 2
        # A withdrawn or changed route must refuse before any stage or source
        # modification, even when the root-owned consent remains on disk.
        for mappings in ([], [{"upstream": record["upstream"],
                                "cache": origin + "/__repocache/repos/changed/"}]):
            catalog.write_text(json.dumps({"schema": 1, "repositories": mappings}))
            try:
                boundary.review_current_candidate(ident, _test_root=root)
            except boundary.BoundaryRefused:
                pass
            else:
                raise AssertionError("Withdrawn or changed route permitted review")
            try:
                pair.apply_catalog_bound_sandbox(root, ident)
            except pair.PairRefused:
                pass
            else:
                raise AssertionError("Withdrawn or changed route permitted commit")
            assert _snapshot(source) == original
            assert not list(state.glob("pair-*.json"))
            assert not list(source.parent.glob(".repocache-atomic-*"))
        catalog.write_text(json.dumps({"schema": 1, "repositories": [
            {"upstream": record["upstream"], "cache": route}]}))
        # Kill after actual private source publication while both authenticated
        # route checks succeeded. The parent will recover with server offline.
        pid = os.fork()
        if pid == 0:
            def kill_at(active, phase):
                if active == phase:
                    os.kill(os.getpid(), signal.SIGKILL)
            pair._crash = kill_at
            pair.apply_retaining_apt_companion_sandbox(root, ident, crash="source")
            os._exit(77)
        _, status = os.waitpid(pid, 0)
        assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        assert _snapshot(source)[0] != original[0]
        print("PASS: current authenticated catalog under locks; withdrawn/changed route refused")
    finally:
        boundary._native_tls_context = original_context
        backend.close()
    _apt_source_read_order(root)

    # The catalog is offline. All changes are in the marked private lab root.
    mirror = root / ("etc/apt/mirrors/repocache-" + ident + ".list")
    _signed_recovery_readback(root, ident, platform="debian13", phase="armed",
                              source_state="proposed", companion_state="cache-bearing")
    # A foreign source stage must stop the modern writer before it can
    # neutralize the already-published companion or modify its journal.
    stage = source.with_name(".repocache-atomic-" + ident)
    journal = state / ("pair-" + ident + ".json")
    with stage.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(b"foreign fixture stage")
    try:
        resources = (source, mirror, journal, stage)
        before = tuple(_snapshot(path) for path in resources)
        try:
            pair.recover_sandbox(root, ident)
        except pair.PairRefused as exc:
            assert "Unexpected recovery stage" in str(exc)
        else:
            raise AssertionError("Unknown stage admitted to recovery")
        assert tuple(_snapshot(path) for path in resources) == before
    finally:
        stage.unlink()
    print("PASS: shared pre-mutation readback refuses foreign stage before companion neutralization", flush=True)
    # Interrupt recovery after the real restore inode and journal are durable.
    # The authenticated installed read-only helper must observe that exact
    # stage before the separate lab resumes the rollback, with catalog offline.
    pid = os.fork()
    if pid == 0:
        def kill_restore(active, phase):
            if active == "recover" and phase == "restore-armed":
                os.kill(os.getpid(), signal.SIGKILL)
        pair._crash = kill_restore
        pair.recover_sandbox(root, ident)
        os._exit(77)
    _, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    _signed_recovery_readback(root, ident, platform="debian13", phase="restore-armed",
                              source_state="proposed", companion_state="upstream-only",
                              source_stage="recorded")
    assert pair.recover_sandbox(root, ident)["status"] == "restored"
    restored = _snapshot(source)
    assert restored[0] == original[0]
    assert restored[3:6] == original[3:6] and restored[-1] == original[-1]
    assert mirror.read_bytes() == (record["upstream"] + "\tpriority:1\n").encode("ascii")
    retained = _snapshot(mirror)
    assert pair.recover_sandbox(root, ident)["status"] == "restored"
    assert _snapshot(mirror) == retained
    _signed_recovery_readback(root, ident, platform="debian13", phase="restored",
                              source_state="restored", companion_state="upstream-only")
    print("PASS: Debian booted root exact HTTPS preparation/approval and sandbox SIGKILL restore with retained upstream-only companion")


def _alma_label_refusal(root: Path) -> None:
    source, _, lock, state = build(root, "dnf")
    before = _snapshot(source)
    lock_before = _snapshot(lock)
    assert os.getxattr(source, "security.selinux")
    assert os.getxattr(lock, "security.selinux")
    record = json.loads((state / ("candidate-" + IDENT + ".json")).read_text())
    assert boundary.pre.inspect_source(record["source"], root=root)[
        "extended_attributes_present"]
    (root / "etc/os-release").write_text('ID=almalinux\nVERSION_ID="10"\n')
    try:
        boundary.prepare_current_candidate(
            record["source_sha256"], record["entry_sha256"], _test_root=root)
    except boundary.BoundaryRefused:
        pass
    else:
        raise AssertionError("Unreviewed labelled fixture preparation was accepted")
    try:
        pair.apply_sandbox(root, IDENT)
    except pair.PairRefused:
        pass
    else:
        raise AssertionError("Unreviewed labelled transaction was accepted")
    assert _snapshot(source) == before and _snapshot(lock) == lock_before
    assert not list(state.glob("pending-*.json")) and not list(state.glob("pair-*.json"))
    print("PASS: AlmaLinux enforcing unreviewed labels refused; source and lock labels intact")


@contextlib.contextmanager
def _alma_fixture_file_context(root: Path):
    """Local pathname mapping for this disposable VM fixture only.

    Stock policy need not map arbitrary /tmp or /var/tmp descendants.
    Never change domain permissions, enforcement, host source mappings or
    production lookup behavior. Keep the exact random path rule ephemeral.
    """
    guarded_native_guest("almalinux10")
    assert os.getresuid() == (0, 0, 0)
    assert root.parent == Path("/var/tmp")
    assert re.fullmatch(r"repocache-booted-(?:label|dnf4)-[a-z0-9_]+", root.name)
    assert root.resolve(strict=True) == root
    assert root.stat().st_uid == 0 and root.stat().st_mode & 0o777 == 0o700
    rule = re.escape(str(root)) + "(/.*)?"
    def semanage(*args):
        return subprocess.run(
            ["/usr/sbin/semanage", "fcontext", *args], check=True,
            capture_output=True, text=True, timeout=60,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        ).stdout
    before = semanage("-l", "-C")
    assert str(root) not in before and rule not in before
    semanage("-a", "-t", "tmp_t", rule)
    try:
        assert rule in semanage("-l", "-C")
        yield
    finally:
        semanage("-d", rule)
        assert semanage("-l", "-C") == before
        guarded_native_guest("almalinux10")


def _private_dnf4_setup(root: Path) -> None:
    """Move only a native-created private RPM lock inode, never a host lock."""
    from ci_dnf_signed_rpm_fallback import _label_isolated_rpmdb, _run
    assert pair._is_dnf4_pair_root(root) and root.resolve(strict=True) == root
    marker = root / pair.DNF4_MARKER
    with marker.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(pair.DNF4_MAGIC)
    # build() created these known synthetic locks in this fresh fixture.
    # Remove them before creating DNF4 evidence; no DNF5 fallback.
    for relative in pair.locks.DNF5:
        leaf = root / relative
        assert leaf.is_file() and not leaf.is_symlink() and leaf.read_bytes() == b""
        leaf.unlink()
    (root / "var/lib/dnf").mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="repocache-ci-rpmdb-", dir="/var/lib") as place:
        db = Path(place)
        _label_isolated_rpmdb(db)
        _run(["/usr/bin/rpm", "--dbpath", place, "--initdb"])
        _run(["/usr/bin/rpm", "--dbpath", place, "--import",
              "/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10"])
        lock = db / ".rpm.lock"
        info = lock.lstat()
        assert info.st_uid == 0 and info.st_nlink == 1
        target = root / "usr/lib/sysimage/rpm/.rpm.lock"
        assert not os.path.lexists(target)
        os.rename(lock, target)
        moved = target.lstat()
        assert (info.st_dev, info.st_ino) == (moved.st_dev, moved.st_ino)


@contextlib.contextmanager
def _native_dnf4_library_owner(root):
    """Actual installed DNF4 ProcessLock on this fixed private persistdir."""
    assert pair._is_dnf4_pair_root(root)
    code = """
import dnf.lock, sys
with dnf.lock.build_rpmdb_lock(sys.argv[1], True):
    print("DNF4_READY", flush=True)
    sys.stdin.read()
"""
    child = subprocess.Popen(["/usr/bin/python3", "-I", "-B", "-c", code,
                              str(root / "var/lib/dnf")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True,
                             env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    try:
        ready, _, _ = select.select([child.stdout], [], [], 20)
        assert ready and child.stdout.readline().strip() == "DNF4_READY"
        lock = root / "var/lib/dnf/rpmdb_lock.pid"
        assert lock.read_bytes() == str(child.pid).encode("ascii")
        yield lock
    finally:
        child.stdin.close()
        try:
            rc = child.wait(timeout=20)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)
            raise
        assert rc == 0, child.stderr.read()[-1500:]
    assert not os.path.lexists(root / "var/lib/dnf/rpmdb_lock.pid")


def _alma_label_roundtrip(root: Path, *, dnf4=False) -> None:
    source, _, lock, state = build(root, "dnf")
    old = state / ("candidate-" + IDENT + ".json")
    record = json.loads(old.read_text())
    old.unlink()
    (root / "etc/os-release").write_text('ID=almalinux\nVERSION_ID="10"\n')
    # Only this freshly created private VM fixture may be normalized to
    # native default labels, never any real host source or trust directory.
    assert root.parent == Path("/var/tmp") and (root.name.startswith("repocache-booted-label-") or (dnf4 and pair._is_dnf4_pair_root(root)))
    subprocess.run(["/usr/sbin/restorecon", "-RF", str(root)], check=True,
                   timeout=30, capture_output=True)
    # Verify the actual raw policy lookup for every initial private control
    # file before attempting approval. Diagnostic names are fixture-only.
    with boundary.metadata.native_metadata_scope(root):
        for path in (root / boundary.MARKER, lock, source):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                boundary.metadata._policy_label(fd)
            except boundary.pre.PreflightError as exc:
                cause = exc.__cause__
                detail = (" errno=" + str(cause.errno)
                          if isinstance(cause, OSError) else "")
                raise AssertionError("Fixture policy lookup refused " + path.name + detail) from exc
            finally:
                os.close(fd)
    if dnf4:
        _private_dnf4_setup(root)
    os.setxattr(source, "user.repocache-ci", b"preserve")
    baseline = _snapshot(source)
    origin = "https://cache.example.org"
    original_catalog = boundary.client._catalog
    original_config = boundary.client._installed_server_config
    original_context = boundary._native_tls_context
    boundary.client._catalog = lambda *_a, **_kw: {
        "schema": 1, "repositories": [{"upstream": record["upstream"],
                                       "cache": record["cache"]}]}
    boundary.client._installed_server_config = lambda *_: origin
    boundary._native_tls_context = lambda: object()
    try:
        with boundary.metadata.native_metadata_scope(root):
            proposal = boundary.prepare_current_candidate(
                record["source_sha256"], record["entry_sha256"], _test_root=root)
            ident = proposal["managed_id"]
            boundary.approve_current_candidate(
                ident, proposal["route_sha256"], _test_root=root)
            approved = json.loads((state / ("candidate-" + ident + ".json")).read_text())
            assert approved["schema"] == 3 and approved["source_attributes_sha256"]
            assert boundary.validate(ident, _test_root=root)["source_attributes_matched"]
            if dnf4:
                journal = state / ("pair-" + ident + ".json")
                with _native_dnf4_library_owner(root) as native_lock:
                    before = native_lock.lstat()
                    try:
                        pair.apply_sandbox(root, ident)
                    except pair.PairRefused:
                        pass
                    else:
                        raise AssertionError("Journal apply bypassed native DNF4 PID lock")
                    assert _snapshot(source) == baseline and not journal.exists()
                    assert native_lock.lstat().st_ino == before.st_ino
                print("PASS: actual DNF4 ProcessLock blocks marked journal apply before intent", flush=True)
            pid = os.fork()
            if pid == 0:
                def kill_at(active, phase):
                    if active == phase:
                        os.kill(os.getpid(), signal.SIGKILL)
                pair._crash = kill_at
                pair.apply_sandbox(root, ident, crash="source")
                os._exit(77)
            _, status = os.waitpid(pid, 0)
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            changed = _snapshot(source)
            assert changed[0] != baseline[0] and changed[-1] == baseline[-1]
            _signed_recovery_readback(root, ident, platform="almalinux10", phase="armed",
                                      source_state="proposed", companion_state="not-applicable")
            if dnf4:
                stale = root / "var/lib/dnf/rpmdb_lock.pid"
                info = stale.lstat()
                assert stale.read_bytes() == str(pid).encode("ascii")
                before_journal = journal.read_bytes()
                try:
                    pair.recover_sandbox(root, ident)
                except pair.PairRefused:
                    pass
                else:
                    raise AssertionError("Journal recovery silently took over stale DNF4 owner")
                assert _snapshot(source) == changed and journal.read_bytes() == before_journal
                assert stale.lstat().st_ino == info.st_ino
                assert stale.read_bytes() == str(pid).encode("ascii")
                # The fixture owner reaped that exact SIGKILL child.
                # No general stale PID cleanup or production policy.
                stale.unlink()
                parentfd = os.open(stale.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parentfd)
                finally:
                    os.close(parentfd)
            assert pair.recover_sandbox(root, ident)["status"] == "restored"
            restored = _snapshot(source)
            assert restored[0] == baseline[0]
            assert restored[3:6] == baseline[3:6] and restored[-1] == baseline[-1]
            assert pair.recover_sandbox(root, ident)["status"] == "restored"
            _signed_recovery_readback(root, ident, platform="almalinux10", phase="restored",
                                      source_state="restored", companion_state="not-applicable")
            if dnf4:
                # The private foreign-inode test moved the owned inode
                # out and back, changing ctime as expected. Verify all
                # other fields, then retain the new exact snapshot for
                # the native-lock noninterference observation.
                after_readback = _snapshot(source)
                assert after_readback[:7] == restored[:7]
                assert after_readback[-1] == restored[-1]
                with _native_dnf4_library_owner(root):
                    assert _snapshot(source) == after_readback
                print("PASS: real DNF4 PID scope and native-created RPM lock across labelled SIGKILL journal; stale refusal, explicit fixture-owner cleanup and recovery", flush=True)
    finally:
        boundary.client._catalog = original_catalog
        boundary.client._installed_server_config = original_config
        boundary._native_tls_context = original_context
    print("PASS: AlmaLinux Enforcing schema-3 source label/user-xattr SIGKILL recovery; private fixture")


def _signed_helper_placement(platform: str) -> None:
    """Actual fixed root-owned helper placement with synthetic Ed25519 trust."""
    checkout = Path("/home/pr237ci/source")
    sys.path[:0] = [str(checkout / "src"), str(checkout), str(checkout / "tests")]
    from repocache import signatures
    from scripts import build_release, stage_native_client_helper as stage
    from test_v06_release_source_inventory import _candidate_source

    target = Path("/usr/libexec/repocache-client") / stage.HELPER
    registry = Path("/var/lib/repocache-client/approved-entries")
    lock = registry / ".transaction.lock"
    assert not os.path.lexists(registry.parent)
    assert not os.path.lexists(target) and not os.path.lexists(target.parent)
    with tempfile.TemporaryDirectory(prefix="repocache-client-signed-", dir="/root") as work:
        root = Path(work)
        source = _candidate_source(root)
        prior_root = build_release.ROOT
        try:
            build_release.ROOT = source
            archive, _ = build_release.build_release(root / "assets", "v0.6.0")
        finally:
            build_release.ROOT = prior_root
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        # Synthetic fixture identity, NOT a claim of a publisher Git commit.
        # The outer QEMU artifact independently records the exact source HEAD.
        pin = digest[:40]
        now = int(time.time())
        manifest = archive.with_name(archive.name + ".manifest.json")
        manifest.write_text(json.dumps({
            "schema": 1, "repository": "repocache-project/repocache",
            "key_id": "client-vm-fixture", "channel": "stable", "version": "0.6.0",
            "commit": pin, "archive": archive.name, "archive_sha256": digest,
            "policy_sha256": hashlib.sha256((source / "release-policy.json").read_bytes()).hexdigest(),
            "wheelhouse_sha256": "b" * 64, "issued_at": now - 30, "expires_at": now + 3600,
        }, sort_keys=True, separators=(",", ":")) + "\n")
        trust = root / "etc/repocache/trust.d"
        trust.mkdir(parents=True, mode=0o700)
        key = root / "fixture-key.pem"
        public = trust / "client-vm-fixture.pem"
        detached = manifest.with_name(manifest.name + ".sig")
        for args in (
            ["genpkey", "-algorithm", "Ed25519", "-out", str(key)],
            ["pkey", "-in", str(key), "-pubout", "-out", str(public)],
            ["pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(manifest), "-out", str(detached)],
        ):
            subprocess.run(["/usr/bin/openssl", *args], check=True,
                           capture_output=True, timeout=20)
        key.unlink()
        original_trust = signatures.TRUST_DIR
        signatures.TRUST_DIR = trust
        options = {"platform": platform, "commit": pin, "archive_sha256": digest}
        signed = detached.read_bytes()
        try:
            detached.write_bytes(b"\0" * 64)
            try:
                stage.install_authenticated_fixture(archive.parent, **options)
            except signatures.SignatureError:
                pass
            else:
                raise AssertionError("Invalid signature placed a client helper")
            assert not os.path.lexists(target.parent)
            assert not os.path.lexists(registry.parent)
            detached.write_bytes(signed)
            placed = stage.install_authenticated_fixture(archive.parent, **options)
            assert placed["placement"] == "placed" and not placed["source_writer_installed"]
            assert placed["registry"] == "created" and placed["protected_state_ready"]
            assert set(p.name for p in registry.iterdir()) == {".transaction.lock"}
            for directory in (registry.parent, registry):
                assert directory.stat().st_uid == directory.stat().st_gid == 0
                assert directory.stat().st_mode & 0o777 == 0o700
            lock_before = _snapshot(lock)
            before = _snapshot(target)
            repeat = stage.install_authenticated_fixture(archive.parent, **options)
            assert repeat["placement"] == "unchanged" and _snapshot(target) == before
            assert repeat["registry"] == "unchanged" and _snapshot(lock) == lock_before
            assert lock.stat().st_mode & 0o777 == 0o600
            assert lock_before[0] == b""
            if platform == "almalinux10":
                assert os.getxattr(lock, "security.selinux")
            print("PASS: root-private native registry and lock provisioned after signature verification")
            assert hashlib.sha256(before[0]).hexdigest() == placed["helper_sha256"]
            assert target.stat().st_uid == target.stat().st_gid == 0
            assert target.stat().st_mode & 0o777 == 0o700
            status = subprocess.run([str(target), "--json", "status"],
                                    check=True, capture_output=True, timeout=15)
            report = json.loads(status.stdout)
            assert not report["write_eligible"] and not report["commit_available"]
            try:
                subprocess.run([str(target), "--json", "status"],
                               user=65534, group=65534, extra_groups=[],
                               cwd="/", capture_output=True, timeout=15)
            except PermissionError:
                pass
            else:
                raise AssertionError("Unprivileged execution reached the root-only helper")
        finally:
            signatures.TRUST_DIR = original_trust
    print("PASS: synthetic Ed25519 authenticated fixed root-only client helper placement and idempotence")


def main(platform: str) -> None:
    guarded_native_guest(platform)
    before_sources = installed_sources(platform)
    before_packages = installed_packages(platform)
    _signed_helper_placement(platform)
    with tempfile.TemporaryDirectory(prefix="repocache-booted-approval-", dir="/tmp") as work:
        root = Path(work)
        if platform == "debian13":
            _debian_fixture(root)
            from ci_apt_stale_reader import probe as probe_stale_reader
            probe_stale_reader()
        else:
            _alma_label_refusal(root)
    if platform == "almalinux10":
        # Native raw lookup returned ENOENT on both private temp locations.
        # Use a test-only local file-context rule, not a production bypass.
        with tempfile.TemporaryDirectory(prefix="repocache-booted-label-", dir="/var/tmp") as work:
            root = Path(work)
            with _alma_fixture_file_context(root):
                _alma_label_roundtrip(root)
        from ci_dnf_signed_rpm_fallback import _native_dnf_transaction_variant
        if _native_dnf_transaction_variant() == ("/usr/bin/dnf", "dnf4"):
            with tempfile.TemporaryDirectory(prefix="repocache-booted-dnf4-", dir="/var/tmp") as work:
                root = Path(work)
                with _alma_fixture_file_context(root):
                    _alma_label_roundtrip(root, dnf4=True)
    assert installed_sources(platform) == before_sources
    assert installed_packages(platform) == before_packages
    guarded_native_guest(platform)
    print("PASS: booted-native-client-privileged-fixture " + platform)
    print("NOT VERIFIED: installed root source writer, complete native locks, "
          "installed SELinux-labelled transactions, publisher identity")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Only the two fixed VM targets are supported")
    main(sys.argv[1])
