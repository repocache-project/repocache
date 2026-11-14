"""Fixture-only safe NGINX metrics file creation/retention adversarial tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from repocache.server_native_metrics_file_bootstrap_v1 import (
    NativeMetricsBootstrapError, bootstrap_private_metrics_file_under_root,
)
from repocache.server_native_storage_bootstrap_v1 import (
    bootstrap_native_nginx_storage_under_root,
)


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
