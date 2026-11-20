"""Fixture-only safe NGINX metrics file creation/retention adversarial tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import pytest

from repocache.server_native_metrics_file_bootstrap_v1 import (
    NativeMetricsBootstrapError, bootstrap_private_metrics_file_under_root,
    reconcile_private_metrics_rotation_under_root,
)
from repocache.server_native_storage_bootstrap_v1 import (
    bootstrap_native_nginx_storage_under_root,
)
from repocache.server_protected_namespace_bootstrap_v1 import bootstrap_protected_namespace_under_root
from repocache.server_native_metrics_logrotate_candidate_v1 import render_native_metrics_rotation_candidate


@pytest.fixture
def owned(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir(mode=0o700)
    for part in ("var", "var/cache", "var/cache/nginx",
                 "var/log", "var/log/nginx"):
        (root / part).mkdir(mode=0o700)
    uid, gid = os.geteuid(), os.getegid()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        bootstrap_native_nginx_storage_under_root(
            fd, root_uid=uid, cache_uid=uid, cache_gid=gid,
        )
        yield root, fd, uid, gid
    finally:
        os.close(fd)


def run(owned, **kwargs):
    _, fd, uid, gid = owned
    return bootstrap_private_metrics_file_under_root(
        fd, owner_uid=uid, owner_gid=gid, **kwargs,
    )


def paths(owned):
    root = owned[0] / "var/log/nginx"
    return root / "repocache-managed/metrics.jsonl", root / ".repocache-metrics-log.owner-v1"


def test_initial_private_file_has_durable_marker_and_no_host_capability(owned):
    result = run(owned)
    log, marker = paths(owned)
    assert result["file_created"] is True
    assert log.is_file() and log.stat().st_mode & 0o777 == 0o600
    assert marker.is_file() and marker.stat().st_mode & 0o777 == 0o600
    assert result["owned_file_inode"] == log.stat().st_ino
    assert json.loads(marker.read_text())["ino"] == log.stat().st_ino
    for key, value in result.items():
        if key.startswith("authorizes_") or key.endswith("_authenticated") or key == "selinux_enforcing_verified":
            assert value is False, key


def test_repeated_prepare_preserves_live_metrics_bytes_and_inode(owned):
    run(owned)
    log, marker = paths(owned)
    log.write_bytes(b'{"privacy_limited":true}\n')
    before = log.stat()
    old_marker = marker.read_bytes()
    result = run(owned)
    assert result["file_created"] is False
    assert result["existing_log_bytes_preserved"] is True
    assert log.stat().st_ino == before.st_ino
    assert log.read_bytes() == b'{"privacy_limited":true}\n'
    assert marker.read_bytes() == old_marker


@pytest.mark.parametrize("attack", ["orphan-log", "orphan-marker", "symlink-log",
                                    "weak-file-mode", "hardlink-log", "forged-marker"])
def test_foreign_or_partial_file_refuses_without_removing_bytes(owned, tmp_path, attack):
    log, marker = paths(owned)
    sentinel = tmp_path / "foreign-secret"
    sentinel.write_bytes(b"do-not-touch")
    if attack in ("orphan-log", "symlink-log"):
        if attack == "symlink-log":
            log.symlink_to(sentinel)
        else:
            log.write_bytes(b"foreign-log")
    elif attack == "orphan-marker":
        marker.write_bytes(b"foreign")
    else:
        run(owned)
        if attack == "weak-file-mode":
            log.chmod(0o644)
        elif attack == "hardlink-log":
            os.link(log, tmp_path / "second-link")
        else:
            original = json.loads(marker.read_bytes())
            original["ino"] += 1
            marker.write_text(json.dumps(original, sort_keys=True,
                                          separators=(",", ":")), encoding="ascii")
    with pytest.raises(NativeMetricsBootstrapError):
        run(owned)
    assert sentinel.read_bytes() == b"do-not-touch"
    if attack == "orphan-log":
        assert log.read_bytes() == b"foreign-log"


@pytest.mark.parametrize("point", ["log_file_durable", "log_marker_durable"])
def test_crash_does_not_silently_repair_or_adopt_partial_file(owned, point):
    def interrupt(stage):
        if stage == point:
            raise RuntimeError("deliberate crash")
    with pytest.raises(RuntimeError, match="deliberate crash"):
        run(owned, inject_fault=interrupt)
    log, marker = paths(owned)
    assert log.exists()
    if point == "log_file_durable":
        assert not marker.exists()
        with pytest.raises(NativeMetricsBootstrapError,
                           match="NATIVE_METRICS_PARTIAL_OR_FOREIGN_FILE"):
            run(owned)
    else:
        assert marker.exists()
        assert run(owned)["file_created"] is False


def test_foreign_owned_log_root_marker_refused_before_write(owned):
    root = owned[0] / "var/log/nginx"
    marker = root / ".repocache-managed.owner-v1"
    data = marker.read_bytes()
    marker.unlink()
    marker.write_bytes(data.replace(b'"kind":"log"', b'"kind":"foreign"'))
    marker.chmod(0o600)
    with pytest.raises(NativeMetricsBootstrapError):
        run(owned)
    assert not paths(owned)[0].exists()


@pytest.mark.parametrize("relative", [".", "var", "var/log", "var/log/nginx"])
def test_unreviewed_ancestor_attribute_refused_before_metrics_creation(owned, relative):
    directory = owned[0] / relative
    log, marker = paths(owned)
    try:
        os.setxattr(directory, "user.repocache-unreviewed", b"fixture attribute")
    except OSError as exc:
        pytest.skip("fixture filesystem lacks user xattrs: " + type(exc).__name__)
    try:
        with pytest.raises(NativeMetricsBootstrapError):
            run(owned)
        assert not log.exists() and not marker.exists()
        assert os.getxattr(directory, "user.repocache-unreviewed") == b"fixture attribute"
    finally:
        os.removexattr(directory, "user.repocache-unreviewed")


def test_unreviewed_ancestor_refuses_reentry_preserving_log_history(owned):
    run(owned)
    log, marker = paths(owned)
    log.write_bytes(b'{"retained":true}\n')
    original = (log.stat().st_ino, log.read_bytes(), marker.read_bytes())
    directory = owned[0] / "var/log"
    try:
        os.setxattr(directory, "user.repocache-unreviewed", b"fixture attribute")
    except OSError as exc:
        pytest.skip("fixture filesystem lacks user xattrs: " + type(exc).__name__)
    try:
        with pytest.raises(NativeMetricsBootstrapError):
            run(owned)
        assert (log.stat().st_ino, log.read_bytes(), marker.read_bytes()) == original
    finally:
        os.removexattr(directory, "user.repocache-unreviewed")


@pytest.mark.parametrize("wrong", [{"owner_uid": True}, {"owner_gid": -1},
                                    {"inject_fault": "bad"}])
def test_bad_inputs_do_not_mutate(owned, wrong):
    _, fd, uid, gid = owned
    args = dict(owner_uid=uid, owner_gid=gid)
    args.update(wrong)
    with pytest.raises(NativeMetricsBootstrapError, match="ARGUMENT_INVALID"):
        bootstrap_private_metrics_file_under_root(fd, **args)
    assert not paths(owned)[0].exists()


def test_live_root_descriptor_refused():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(NativeMetricsBootstrapError,
                           match="NATIVE_METRICS_LIVE_ROOT_FORBIDDEN"):
            bootstrap_private_metrics_file_under_root(
                fd, owner_uid=0, owner_gid=0,
            )
    finally:
        os.close(fd)


def test_no_cleanup_or_installed_service_actions():
    text = (Path(__file__).resolve().parents[1]
            / "src/repocache/server_native_metrics_file_bootstrap_v1.py"
            ).read_text()
    for forbidden in ("os.unlink(", "os.remove(", "os.rmdir(", "os.rename(",
                      "subprocess", "systemctl", "nginx -s", "shell=True"):
        assert forbidden not in text


def _prepare_rotation(owned):
    root, fd, uid, _ = owned
    (root / "var/lib").mkdir(mode=0o755)
    bootstrap_protected_namespace_under_root(fd, owner_uid=uid)
    run(owned)
    return paths(owned)


def _reconcile(owned, **kwargs):
    _, fd, uid, gid = owned
    return reconcile_private_metrics_rotation_under_root(fd, owner_uid=uid, owner_gid=gid, **kwargs)


def _one_rotation(log):
    archive = log.with_name(log.name + ".1")
    log.rename(archive)
    log.touch(mode=0o600, exist_ok=False)
    return archive


@pytest.mark.parametrize("fault", [None, "rotation_stage_durable", "rotation_marker_durable"])
def test_rotation_marker_rebind_replay_preserves_archive_and_new_inode(owned, fault):
    log, marker = _prepare_rotation(owned)
    log.write_bytes(b"historical metrics\n")
    prior = marker.read_bytes()
    archive = _one_rotation(log)
    successor = log.stat().st_ino
    def interrupt(point):
        if point == fault:
            raise RuntimeError("controlled interruption")
    if fault is not None:
        with pytest.raises(RuntimeError, match="controlled interruption"):
            _reconcile(owned, inject_fault=interrupt)
        if fault == "rotation_stage_durable":
            assert marker.read_bytes() == prior
    report = _reconcile(owned)
    assert report["owner_marker_rebound"] is (fault != "rotation_marker_durable")
    assert report["logs_modified"] is False
    assert report["authorizes_host_installation"] is False
    assert json.loads(marker.read_bytes())["ino"] == successor
    assert archive.read_bytes() == b"historical metrics\n" and log.read_bytes() == b""
    assert run(owned)["file_created"] is False
    assert _reconcile(owned)["owner_marker_rebound"] is False


@pytest.mark.parametrize("problem", ["unmatched-archive", "nonempty-successor", "missing-archive", "weak-successor-mode"])
def test_rotation_refuses_unverified_predecessor_or_successor(owned, problem):
    log, marker = _prepare_rotation(owned)
    log.write_bytes(b"history")
    archive = _one_rotation(log)
    before = marker.read_bytes()
    if problem == "unmatched-archive":
        archive.rename(archive.with_name("retained-original"))
        archive.write_bytes(b"unrelated archive")
        archive.chmod(0o600)
    elif problem == "nonempty-successor":
        log.write_bytes(b"unexpected data")
    elif problem == "missing-archive":
        archive.rename(archive.with_name("retained-original"))
    else:
        log.chmod(0o644)
    current = log.read_bytes()
    with pytest.raises(NativeMetricsBootstrapError):
        _reconcile(owned)
    assert marker.read_bytes() == before and log.read_bytes() == current
    assert not marker.with_name(marker.name + ".rotation-stage").exists()


def test_rotation_refuses_unrelated_staged_marker_and_retains_evidence(owned):
    log, marker = _prepare_rotation(owned)
    log.write_bytes(b"old log")
    archive = _one_rotation(log)
    prior = marker.read_bytes()
    stage = marker.with_name(marker.name + ".rotation-stage")
    stage.write_bytes(b"incomplete foreign stage")
    stage.chmod(0o600)
    with pytest.raises(NativeMetricsBootstrapError):
        _reconcile(owned)
    assert marker.read_bytes() == prior
    assert stage.read_bytes() == b"incomplete foreign stage"
    assert archive.read_bytes() == b"old log" and log.stat().st_size == 0


def test_rotation_refuses_busy_protected_lock_and_preserves_log(owned):
    from repocache.server_protected_state_store_v1 import _locked
    log, marker = _prepare_rotation(owned)
    log.write_bytes(b"old log")
    archive = _one_rotation(log)
    before = marker.read_bytes()
    _, fd, uid, _ = owned
    with _locked(fd, uid):
        with pytest.raises(NativeMetricsBootstrapError):
            _reconcile(owned)
    assert marker.read_bytes() == before and archive.read_bytes() == b"old log"
    assert _reconcile(owned)["owner_marker_rebound"] is True


def test_rotation_refuses_live_namespace_fd():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(NativeMetricsBootstrapError, match="LIVE_ROOT_FORBIDDEN"):
            reconcile_private_metrics_rotation_under_root(fd, owner_uid=0, owner_gid=0)
    finally:
        os.close(fd)


def test_stock_logrotate_rebinds_twice_without_losing_history(owned):
    if shutil.which("logrotate") is None:
        pytest.skip("native logrotate not installed")
    root, _, uid, gid = owned
    log, marker = _prepare_rotation(owned)
    document = json.loads((Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json").read_text())
    document["deployment"]["logging"].update(metrics_opt_in=True, retention_days=3)
    candidate = render_native_metrics_rotation_candidate(document)["rotation_candidate"]
    profile = root / "rotation.conf"
    profile.write_text(candidate.replace("/var/log/nginx/repocache-managed/metrics.jsonl", str(log))
                       .replace("/usr/bin/systemctl kill --kill-who=main --signal=USR1 nginx.service", "/bin/true")
                       .replace("create 0600 root root", f"create 0600 {uid} {gid}"))
    previous = log.stat().st_ino
    for line in (b"first history\n", b"second history\n"):
        log.write_bytes(line)
        result = subprocess.run(["logrotate", "--force", "--state", str(root / "rotation.state"), str(profile)],
                                capture_output=True, timeout=20, check=False)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        archive = log.with_name(log.name + ".1")
        assert archive.stat().st_ino == previous and archive.read_bytes() == line
        assert _reconcile(owned)["owner_marker_rebound"] is True
        previous = log.stat().st_ino
        assert json.loads(marker.read_bytes())["ino"] == previous and run(owned)["file_created"] is False
    import gzip
    with gzip.open(log.with_name(log.name + ".2.gz"), "rb") as stream:
        assert stream.read() == b"first history\n"
