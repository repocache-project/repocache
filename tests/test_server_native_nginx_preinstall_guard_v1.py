"""Retained-lock late native APT/DNF NGINX recheck regressions (#27)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

from repocache import server_native_nginx_ownership_v1 as ownership
from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, _prepare_native_journal_under_root,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME, _locked

_ROOT = Path(__file__).resolve().parents[1]
_DOC = json.loads((_ROOT / "docs/examples/server-install-v1.json").read_text("utf-8"))
_NATIVE = {
    "debian": ("ID=debian\nVERSION_ID=13\n", (3, 13)),
    "almalinux": ("ID=almalinux\nVERSION_ID=10\n", (3, 12)),
}


@pytest.fixture
def journal_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    directory = root
    for part in ("var", "lib", "repocache", "server"):
        directory = directory / part
        directory.mkdir(mode=0o700)
    (directory / LOCK_NAME).write_bytes(b"")
    (directory / LOCK_NAME).chmod(0o600)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield root_fd, directory, os.geteuid()
    finally:
        os.close(root_fd)


def recheck(directory, owner, distribution, **kwargs):
    release, py = _NATIVE[distribution]
    def absent(path):
        assert path != "/var/lib/repocache/server"
        raise FileNotFoundError(path)
    return ownership.recheck_fresh_native_nginx_before_manager(
        directory, owner_uid=owner, distribution=distribution,
        os_release=release, python_version=py, document=_DOC,
        lstat=absent,
        process_probe=lambda: "PROCESS_NGINX_NOT_OBSERVED",
        **kwargs,
    )


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_late_recheck_requires_real_held_state_lock_and_pending_marker(
    journal_root, distribution,
):
    fd, state, uid = journal_root
    # A free lock is never proof of an active package-effects transaction.
    free_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ownership.NativeNginxPreinstallGuardError,
                           match="^NATIVE_PREINSTALL_LOCK_NOT_HELD$"):
            recheck(free_fd, uid, distribution)
    finally:
        os.close(free_fd)
    # Even a genuinely held lock cannot replace the durable pending marker.
    with _locked(fd, uid) as directory:
        with pytest.raises(ownership.NativeNginxPreinstallGuardError,
                           match="^NATIVE_PREINSTALL_PROTECTED_STATE_OR_PROCESS_UNVERIFIED$"):
            recheck(directory, uid, distribution)
    _prepare_native_journal_under_root(
        fd, owner_uid=uid, distribution=distribution,
    )
    marker = state / NATIVE_PENDING_NAME
    original = marker.read_bytes()
    inode = marker.stat().st_ino
    with _locked(fd, uid) as directory:
        report = recheck(directory, uid, distribution)
        assert report["status"] == "FRESH_NATIVE_PREINSTALL_RECHECK_OBSERVED_ONLY"
        assert report["distribution"] == distribution
        assert report["external_lock_contention_observed"] is True
        assert report["protected_pending_journal_unchanged"] is True
        assert report["late_foreign_nginx_process_not_observed"] is True
        assert report["transaction_cannot_be_raced"] is False
        assert all(
            value is False for key, value in report.items()
            if key.startswith("authorizes_") or key.endswith("_authenticated")
        )
    assert marker.read_bytes() == original
    assert marker.stat().st_ino == inode


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_late_running_process_refused_before_native_execution(
    journal_root, distribution,
):
    fd, state, uid = journal_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution=distribution)
    release, py = _NATIVE[distribution]
    with _locked(fd, uid) as directory:
        with pytest.raises(ownership.NativeNginxPreinstallGuardError,
                           match="^NATIVE_PREINSTALL_FRESH_NGINX_RUNNING_PROCESS_REFUSED$"):
            ownership.recheck_fresh_native_nginx_before_manager(
                directory, owner_uid=uid, distribution=distribution,
                os_release=release, python_version=py, document=_DOC,
                lstat=lambda path: (_ for _ in ()).throw(FileNotFoundError(path)),
                process_probe=lambda: "PROCESS_NGINX_FOUND",
            )
    assert (state / NATIVE_PENDING_NAME).is_file()


@pytest.mark.parametrize("code", [
    "PROCESS_SCAN_UNVERIFIED", None, True, "UNKNOWN",
])
def test_unknown_proc_result_does_not_authorize_late_native_manager(
    journal_root, code,
):
    fd, state, uid = journal_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    with _locked(fd, uid) as directory:
        with pytest.raises(ownership.NativeNginxPreinstallGuardError,
                           match="^NATIVE_PREINSTALL_FRESH_NGINX_PROCESS_SCAN_UNVERIFIED$"):
            ownership.recheck_fresh_native_nginx_before_manager(
                directory, owner_uid=uid, distribution="debian",
                os_release=_NATIVE["debian"][0],
                python_version=_NATIVE["debian"][1], document=_DOC,
                lstat=lambda path: (_ for _ in ()).throw(FileNotFoundError(path)),
                process_probe=lambda: code,
            )
    assert (state / NATIVE_PENDING_NAME).is_file()


def test_late_disk_conflict_dominates_even_clean_process_snapshot(journal_root):
    fd, state, uid = journal_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    seen = []
    def foreign(path):
        seen.append(path)
        if path == "/usr/sbin/nginx":
            return os.stat_result((stat.S_IFREG | 0o755, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        raise FileNotFoundError(path)
    with _locked(fd, uid) as directory:
        with pytest.raises(ownership.NativeNginxPreinstallGuardError,
                           match="^NATIVE_PREINSTALL_FRESH_EXISTING_NGINX_OWNERSHIP_UNPROVEN$"):
            ownership.recheck_fresh_native_nginx_before_manager(
                directory, owner_uid=uid, distribution="debian",
                os_release=_NATIVE["debian"][0],
                python_version=_NATIVE["debian"][1], document=_DOC,
                lstat=foreign,
                process_probe=lambda: pytest.fail("no process scan after known file conflict"),
            )
    assert "/var/lib/repocache/server" not in seen
    assert (state / NATIVE_PENDING_NAME).is_file()


@pytest.mark.parametrize("variant", ["changed", "missing", "unsafe-mode", "symlink"])
def test_marker_drift_or_foreign_journal_never_accepted(journal_root, variant):
    fd, state, uid = journal_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    marker = state / NATIVE_PENDING_NAME
    if variant == "changed":
        marker.write_bytes(b"{\"forged\":true}\n")
    elif variant == "missing":
        marker.unlink()
    elif variant == "unsafe-mode":
        marker.chmod(0o666)
    elif variant == "symlink":
        marker.unlink()
        marker.symlink_to("/etc/passwd")
    with _locked(fd, uid) as directory:
        with pytest.raises(ownership.NativeNginxPreinstallGuardError,
                           match="^NATIVE_PREINSTALL_PROTECTED_STATE_OR_PROCESS_UNVERIFIED$"):
            recheck(directory, uid, "debian")
    if variant == "symlink":
        assert marker.is_symlink()


def test_journal_change_during_process_scan_is_denied(journal_root):
    fd, state, uid = journal_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    marker = state / NATIVE_PENDING_NAME
    before = marker.read_bytes()
    def drift():
        marker.write_bytes(b"untrusted native journal")
        return "PROCESS_NGINX_NOT_OBSERVED"
    with _locked(fd, uid) as directory:
        with pytest.raises(ownership.NativeNginxPreinstallGuardError,
                           match="^NATIVE_PREINSTALL_PROTECTED_STATE_OR_PROCESS_UNVERIFIED$"):
            ownership.recheck_fresh_native_nginx_before_manager(
                directory, owner_uid=uid, distribution="debian",
                os_release=_NATIVE["debian"][0],
                python_version=_NATIVE["debian"][1], document=_DOC,
                lstat=lambda path: (_ for _ in ()).throw(FileNotFoundError(path)),
                process_probe=drift,
            )
    assert marker.read_bytes() != before


def test_distro_mismatch_cannot_use_other_pending_journal(journal_root):
    fd, state, uid = journal_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    with _locked(fd, uid) as directory:
        with pytest.raises(ownership.NativeNginxPreinstallGuardError):
            recheck(directory, uid, "almalinux")
    assert (state / NATIVE_PENDING_NAME).is_file()


def test_late_recheck_invalid_type_does_not_touch_journal(journal_root):
    fd, state, uid = journal_root
    def must_not_read(path):
        pytest.fail("invalid inputs reached filesystem")
    for invalid in (None, True, "0", 0.0):
        with pytest.raises(ownership.NativeNginxPreinstallGuardError,
                           match="^NATIVE_PREINSTALL_ARGUMENT_INVALID$"):
            ownership.recheck_fresh_native_nginx_before_manager(
                invalid, owner_uid=uid, distribution="debian",
                os_release=_NATIVE["debian"][0],
                python_version=_NATIVE["debian"][1], document=_DOC,
                lstat=must_not_read,
            )
    assert list(state.iterdir()) == [state / LOCK_NAME]
