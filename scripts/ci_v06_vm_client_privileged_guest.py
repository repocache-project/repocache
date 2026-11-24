#!/usr/bin/env python3
"""Booted native privileged client fixture; never writes host sources."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import ssl
import sys
import tempfile

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
        approved = boundary.approve_current_candidate(
            ident, prepared["route_sha256"], _test_root=root)
        assert approved["status"] == "approved" and not approved["write_eligible"]
        assert manifest.is_file() and _snapshot(source) == original
        assert len(backend.hits) >= 2
    finally:
        boundary._native_tls_context = original_context
        backend.close()
    # The catalog is offline. All changes are in the marked private lab root.
    mirror = root / ("etc/apt/mirrors/repocache-" + ident + ".list")
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
    assert pair.recover_sandbox(root, ident)["status"] == "restored"
    restored = _snapshot(source)
    assert restored[0] == original[0]
    assert restored[3:6] == original[3:6] and restored[-1] == original[-1]
    assert not mirror.exists()
    print("PASS: Debian booted root exact HTTPS preparation/approval and sandbox SIGKILL restore")


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


def main(platform: str) -> None:
    guarded_native_guest(platform)
    before_sources = installed_sources(platform)
    before_packages = installed_packages(platform)
    with tempfile.TemporaryDirectory(prefix="repocache-booted-approval-") as work:
        root = Path(work)
        if platform == "debian13":
            _debian_fixture(root)
        else:
            _alma_label_refusal(root)
    assert installed_sources(platform) == before_sources
    assert installed_packages(platform) == before_packages
    guarded_native_guest(platform)
    print("PASS: booted-native-client-privileged-fixture " + platform)
    print("NOT VERIFIED: installed root helper, real host source writer, native locks, "
          "AlmaLinux positive SELinux-labelled transactions, publisher identity")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Only the two fixed VM targets are supported")
    main(sys.argv[1])
