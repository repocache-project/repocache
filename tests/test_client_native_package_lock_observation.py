"""Fixed native APT/DNF5 lock observation is read-only and never write authority."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
import native_package_lock_observation as locks


def setup_locks(root, names):
    for item in names:
        path = root / item
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
    return {item: root / item for item in names}


def line_for(path, *, holder=12345, mode="WRITE"):
    s = path.stat()
    return (f"1: POSIX ADVISORY {mode} {holder} "
            f"{os.major(s.st_dev):02x}:{os.minor(s.st_dev):02x}:{s.st_ino} 0 EOF\n")


@pytest.mark.parametrize("manager,names", [
    ("apt", locks.APT),
    ("dnf5", locks.DNF5),
])
def test_uncontended_snapshot_has_no_write_permission(tmp_path, manager, names):
    setup_locks(tmp_path, names)
    result = locks.inspect_native_locks(manager, root=tmp_path, proc_locks="")
    assert result["status"] == "OBSERVED_UNCONTENDED"
    assert result["observed_files"] == len(names)
    assert result["missing"] == ()
    assert result["exclusive_lock_held"] is False
    assert result["write_eligible"] is False
    assert result["native_host"] is False


@pytest.mark.parametrize("manager,names", [
    ("apt", locks.APT),
    ("dnf5", locks.DNF5),
])
def test_active_posix_and_flock_snapshots_detect_busy(tmp_path, manager, names):
    files = setup_locks(tmp_path, names)
    snapshot = line_for(files[names[0]])
    hit = locks.inspect_native_locks(manager, root=tmp_path, proc_locks=snapshot)
    assert hit["status"] == "BUSY"
    assert hit["busy"] == (names[0],)
    assert not hit["write_eligible"]
    a, b, c = (os.major(files[names[-1]].stat().st_dev),
               os.minor(files[names[-1]].stat().st_dev),
               files[names[-1]].stat().st_ino)
    flocks = f"2: FLOCK ADVISORY WRITE 222 {a:x}:{b:x}:{c} 0 EOF\n"
    result = locks.inspect_native_locks(
        manager, root=tmp_path, proc_locks=snapshot + flocks)
    assert result["status"] == "BUSY"
    assert set(result["busy"]) == {names[0], names[-1]}


def test_missing_lock_files_are_unknown_not_clear(tmp_path):
    result = locks.inspect_native_locks("apt", root=tmp_path, proc_locks="")
    assert result["status"] == "NOT_VERIFIED"
    assert result["observed_files"] == 0
    assert result["missing"] == locks.APT
    assert not result["write_eligible"]


@pytest.mark.parametrize("untrusted", [
    "1: POSIX ADVISORY WRITE bad not-an-inode 0 EOF",
    "MALICIOUS NOT A LOCK RECORD",
    "1: POSIX ADVISORY WRITE 2 00:0F:invalid 0 EOF",
    "1: POSIX ADVISORY WRITE 2 00:0F:33 -1 EOF",
])
def test_malformed_proc_lock_snapshot_refused(tmp_path, untrusted):
    with pytest.raises(locks.LockInspectionRefused):
        locks.inspect_native_locks(
            "apt", root=tmp_path, proc_locks=untrusted)


def test_native_host_cannot_accept_caller_supplied_proc_locks():
    with pytest.raises(locks.LockInspectionRefused):
        locks.inspect_native_locks("apt", root=Path("/"), proc_locks="")


@pytest.mark.parametrize("manager", ["dnf", "rpm", "APT", "", None])
def test_invalid_package_manager_refused(tmp_path, manager):
    with pytest.raises(locks.LockInspectionRefused):
        locks.inspect_native_locks(manager, root=tmp_path, proc_locks="")


def test_symlink_and_hardlinked_lock_files_are_refused(tmp_path):
    names = locks.APT
    paths = setup_locks(tmp_path, names)
    needle = paths[names[0]]
    needle.unlink()
    needle.symlink_to(paths[names[1]])
    with pytest.raises(locks.LockInspectionRefused):
        locks.inspect_native_locks("apt", root=tmp_path, proc_locks="")
    needle.unlink()
    os.link(paths[names[1]], needle)
    with pytest.raises(locks.LockInspectionRefused):
        locks.inspect_native_locks("apt", root=tmp_path, proc_locks="")


def test_symlinked_parent_directory_is_refused(tmp_path):
    setup_locks(tmp_path, locks.APT)
    parent = tmp_path / "var/lib/dpkg"
    parent.rename(tmp_path / "var/lib/dpkg-original")
    parent.symlink_to("dpkg-original", target_is_directory=True)
    with pytest.raises(locks.LockInspectionRefused):
        locks.inspect_native_locks("apt", root=tmp_path, proc_locks="")


def test_group_writable_parent_is_refused(tmp_path):
    setup_locks(tmp_path, locks.APT)
    parent = tmp_path / "var/lib/dpkg"
    parent.chmod(0o775)
    with pytest.raises(locks.LockInspectionRefused):
        locks.inspect_native_locks("apt", root=tmp_path, proc_locks="")



def _competing_process(path: Path, family: str) -> int:
    """Another actual Linux process attempts one nonblocking lock."""
    import subprocess
    script = (
        "import fcntl, os, sys\n"
        "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC)\n"
        "try:\n"
        "    if sys.argv[2] == 'flock':\n"
        "        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        "    else:\n"
        "        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        "except (BlockingIOError, OSError):\n"
        "    sys.exit(17)\n"
        "sys.exit(0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(path), family],
        capture_output=True, timeout=4, check=False,
        stdin=subprocess.DEVNULL,
    )
    assert result.stdout == result.stderr == b""
    return result.returncode


@pytest.mark.parametrize("manager,names", [
    ("apt", locks.APT), ("dnf5", locks.DNF5),
])
def test_held_real_flock_and_posix_lock_excludes_other_process(
        tmp_path, manager, names):
    paths = setup_locks(tmp_path, names)
    selected = paths[names[-1]]
    assert _competing_process(selected, "flock") == 0
    assert _competing_process(selected, "posix") == 0
    with locks.hold_existing_native_package_locks(manager, root=tmp_path) as grant:
        # No authorization token/capability escapes this context manager.
        assert grant is None
        for kind in ("flock", "posix"):
            assert _competing_process(selected, kind) == 17
    for kind in ("flock", "posix"):
        assert _competing_process(selected, kind) == 0


def test_busy_later_lock_drops_all_previously_held_locks(tmp_path):
    import fcntl
    paths = setup_locks(tmp_path, locks.APT)
    final = os.open(paths[locks.APT[-1]], os.O_RDWR | os.O_CLOEXEC)
    try:
        fcntl.flock(final, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(locks.LockInspectionRefused,
                           match="lock scope unavailable"):
            with locks.hold_existing_native_package_locks("apt", root=tmp_path):
                pytest.fail("busy lock was accepted")
        assert _competing_process(paths[locks.APT[0]], "flock") == 0
        assert _competing_process(paths[locks.APT[0]], "posix") == 0
    finally:
        os.close(final)


@pytest.mark.parametrize("manager,names", [
    ("apt", locks.APT), ("dnf5", locks.DNF5),
])
def test_missing_lock_inodes_refuse_without_creating_them(tmp_path, manager, names):
    paths = setup_locks(tmp_path, names)
    paths[names[-1]].unlink()
    with pytest.raises(locks.LockInspectionRefused):
        with locks.hold_existing_native_package_locks(manager, root=tmp_path):
            pytest.fail("missing lock passed")
    assert not paths[names[-1]].exists()
    assert _competing_process(paths[names[0]], "flock") == 0


@pytest.mark.parametrize("tamper", [
    "leaf-symlink", "hardlink", "parent-symlink", "parent-writable",
    "leaf-writable", "oversized-lock",
])
def test_unsafe_native_lock_inodes_refused(tmp_path, tamper):
    paths = setup_locks(tmp_path, locks.APT)
    selected = paths[locks.APT[0]]
    if tamper == "leaf-symlink":
        selected.unlink()
        selected.symlink_to(paths[locks.APT[1]])
    elif tamper == "hardlink":
        selected.unlink()
        os.link(paths[locks.APT[1]], selected)
    elif tamper == "parent-symlink":
        parent = selected.parent
        parent.rename(parent.with_name(parent.name + "-real"))
        parent.symlink_to(parent.name + "-real", target_is_directory=True)
    elif tamper == "parent-writable":
        selected.parent.chmod(0o775)
    elif tamper == "leaf-writable":
        selected.chmod(0o666)
    else:
        selected.write_bytes(b"X" * 5000)
    with pytest.raises(locks.LockInspectionRefused):
        with locks.hold_existing_native_package_locks("apt", root=tmp_path):
            pytest.fail("foreign lock inode accepted")


@pytest.mark.parametrize("manager", ["dnf", "", None, True, "apt2"])
def test_invalid_manager_rejected_before_any_lock_access(tmp_path, manager):
    with pytest.raises(locks.LockInspectionRefused):
        with locks.hold_existing_native_package_locks(manager, root=tmp_path):
            pytest.fail("unsupported manager passed")


def test_native_lock_scope_requires_root_not_just_snapshot(monkeypatch):
    monkeypatch.setattr(locks.os, "geteuid", lambda: 1001)
    with pytest.raises(locks.LockInspectionRefused,
                       match="requires root"):
        with locks.hold_existing_native_package_locks("apt", root=Path("/")):
            pytest.fail("nonroot opened native locks")


def test_caller_exception_propagates_after_all_kernel_locks_release(tmp_path):
    paths = setup_locks(tmp_path, locks.DNF5)
    with pytest.raises(ZeroDivisionError):
        with locks.hold_existing_native_package_locks("dnf5", root=tmp_path):
            raise ZeroDivisionError("caller error is never masked")
    assert _competing_process(paths[locks.DNF5[0]], "flock") == 0
    assert _competing_process(paths[locks.DNF5[0]], "posix") == 0


@pytest.mark.parametrize("manager,names", [
    ("apt", locks.APT), ("dnf5", locks.DNF5),
])
def test_replaced_earlier_lock_before_scope_entry_refuses_and_releases(
        tmp_path, monkeypatch, manager, names):
    import fcntl
    paths = setup_locks(tmp_path, names)
    first = paths[names[0]]
    original = first.with_name(first.name + ".original")
    actual_lockf = fcntl.lockf
    calls = 0

    def replace_during_later_acquisition(fd, operation):
        nonlocal calls
        actual_lockf(fd, operation)
        calls += 1
        if calls == 2:
            first.rename(original)
            first.write_bytes(b"")

    monkeypatch.setattr(locks.fcntl, "lockf", replace_during_later_acquisition)
    with pytest.raises(locks.LockInspectionRefused, match="scope drift"):
        with locks.hold_existing_native_package_locks(manager, root=tmp_path):
            pytest.fail("stale lock set reached caller")
    for path in (original, first, paths[names[-1]]):
        for family in ("flock", "posix"):
            assert _competing_process(path, family) == 0


@pytest.mark.parametrize("manager,names", [
    ("apt", locks.APT), ("dnf5", locks.DNF5),
])
def test_drift_during_scope_cannot_report_clean_completion(
        tmp_path, manager, names):
    paths = setup_locks(tmp_path, names)
    first = paths[names[0]]
    original = first.with_name(first.name + ".original")
    with pytest.raises(locks.LockInspectionRefused, match="scope drift"):
        with locks.hold_existing_native_package_locks(manager, root=tmp_path):
            first.rename(original)
            first.write_bytes(b"")
            assert _competing_process(original, "posix") == 17
    for path in (original, first, paths[names[-1]]):
        for family in ("flock", "posix"):
            assert _competing_process(path, family) == 0


def test_lock_parent_mode_drift_during_scope_refuses(tmp_path):
    paths = setup_locks(tmp_path, locks.APT)
    first = paths[locks.APT[0]]
    with pytest.raises(locks.LockInspectionRefused):
        with locks.hold_existing_native_package_locks("apt", root=tmp_path):
            first.parent.chmod(0o775)
    first.parent.chmod(0o755)
    assert _competing_process(first, "flock") == 0
    assert _competing_process(first, "posix") == 0


@pytest.mark.parametrize("manager,names", [("apt", locks.APT), ("dnf5", locks.DNF5)])
def test_revalidation_is_opt_in_and_expires_with_scope(tmp_path, manager, names):
    paths = setup_locks(tmp_path, names)
    with locks.hold_existing_native_package_locks(
            manager, root=tmp_path, revalidation=True) as recheck:
        assert callable(recheck)
        assert recheck() is None
        for family in ("flock", "posix"):
            assert _competing_process(paths[names[-1]], family) == 17
    with pytest.raises(locks.LockInspectionRefused, match="scope expired"):
        recheck()


def test_revalidation_detects_drift_before_returning_from_scope(tmp_path):
    paths = setup_locks(tmp_path, locks.APT)
    with pytest.raises(locks.LockInspectionRefused, match="scope drift"):
        with locks.hold_existing_native_package_locks(
                "apt", root=tmp_path, revalidation=True) as recheck:
            first = paths[locks.APT[0]]
            first.rename(first.with_name("previous-lock"))
            first.write_bytes(b"")
            recheck()

@pytest.mark.parametrize("manager,names", [("apt", locks.APT), ("dnf5", locks.DNF5)])
def test_nested_scope_refusal_preserves_outer_posix_and_flock(
        tmp_path, manager, names):
    paths = setup_locks(tmp_path, names)
    with locks.hold_existing_native_package_locks(
            manager, root=tmp_path, revalidation=True) as recheck:
        with pytest.raises(locks.LockInspectionRefused, match="already active"):
            with locks.hold_existing_native_package_locks(manager, root=tmp_path):
                pytest.fail("nested native lock scope entered")
        # A second open/close in this process would silently release the
        # outer POSIX lock even if the nested flock acquisition failed.
        recheck()
        for path in paths.values():
            for family in ("flock", "posix"):
                assert _competing_process(path, family) == 17
    # The guard and both kernel lock families must be released on exit.
    with locks.hold_existing_native_package_locks(manager, root=tmp_path):
        for family in ("flock", "posix"):
            assert _competing_process(paths[names[0]], family) == 17
    for path in paths.values():
        for family in ("flock", "posix"):
            assert _competing_process(path, family) == 0


def test_revalidation_cannot_be_reused_by_a_different_process(tmp_path, monkeypatch):
    setup_locks(tmp_path, locks.APT)
    original_pid = os.getpid()
    with locks.hold_existing_native_package_locks(
            "apt", root=tmp_path, revalidation=True) as recheck:
        with monkeypatch.context() as child:
            child.setattr(locks.os, "getpid", lambda: original_pid + 1)
            with pytest.raises(locks.LockInspectionRefused, match="scope expired"):
                recheck()
        recheck()


@pytest.mark.parametrize("manager,names", [("apt", locks.APT), ("dnf5", locks.DNF5)])
def test_same_process_close_releases_posix_without_inode_drift(tmp_path, manager, names):
    paths = setup_locks(tmp_path, names)
    selected = paths[names[0]]
    before = selected.stat()
    with pytest.raises(locks.LockInspectionRefused, match="kernel lock scope drift"):
        with locks.hold_existing_native_package_locks(
                manager, root=tmp_path, revalidation=True) as recheck:
            recheck()
            extra = os.open(selected, os.O_RDONLY | os.O_CLOEXEC)
            os.close(extra)
            assert selected.stat() == before
            assert _competing_process(selected, "flock") == 17
            assert _competing_process(selected, "posix") == 0
            recheck()
    for family in ("flock", "posix"):
        assert _competing_process(selected, family) == 0
    # No lock or process-local guard leaks on refusal.
    with locks.hold_existing_native_package_locks(manager, root=tmp_path):
        assert _competing_process(selected, "posix") == 17


def test_lost_posix_lock_detected_on_successful_scope_exit(tmp_path):
    paths = setup_locks(tmp_path, locks.APT)
    with pytest.raises(locks.LockInspectionRefused, match="kernel lock scope drift"):
        with locks.hold_existing_native_package_locks("apt", root=tmp_path):
            os.close(os.open(paths[locks.APT[-1]], os.O_RDONLY | os.O_CLOEXEC))
    assert _competing_process(paths[locks.APT[-1]], "flock") == 0


@pytest.mark.parametrize("fault", ["none", "missing", "owner", "device", "inode",
                                  "partial", "read", "duplicate", "unknown", "oversize"])
def test_kernel_fdinfo_requires_exact_full_range_write_locks(tmp_path, fault):
    path = tmp_path / "lock"
    path.touch()
    info = path.stat()
    pid = os.getpid()
    address = f"{os.major(info.st_dev):x}:{os.minor(info.st_dev):x}:{info.st_ino}"
    first = f"lock:\t1: FLOCK ADVISORY WRITE {pid} {address} 0 EOF\n"
    second = f"lock:\t2: POSIX ADVISORY WRITE {pid} {address} 0 EOF\n"
    if fault == "missing":
        second = ""
    elif fault == "owner":
        second = second.replace(f"WRITE {pid} ", f"WRITE {pid + 1} ")
    elif fault == "device":
        second = second.replace(address, f"{os.major(info.st_dev) + 1:x}:{os.minor(info.st_dev):x}:{info.st_ino}")
    elif fault == "inode":
        second = second.replace(address, f"{os.major(info.st_dev):x}:{os.minor(info.st_dev):x}:{info.st_ino + 1}")
    elif fault == "partial":
        second = second.replace("0 EOF", "0 15")
    elif fault == "read":
        second = second.replace("WRITE", "READ")
    elif fault == "duplicate":
        second += first
    elif fault == "unknown":
        second = second.replace("POSIX", "OFDLCK")
    elif fault == "oversize":
        second += "x" * locks._FDINFO_MAX
    raw = "pos:\t0\nflags:\t02000002\n" + first + second
    if fault == "none":
        locks._require_kernel_lock_records(raw, info, pid)
    else:
        with pytest.raises(locks.LockInspectionRefused):
            locks._require_kernel_lock_records(raw, info, pid)
