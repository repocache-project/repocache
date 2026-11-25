import os
from pathlib import Path
import stat
import pytest
from repocache import server_native_installed_storage_v1 as m

@pytest.fixture
def root(tmp_path):
    for name in ('var/cache/nginx', 'var/log/nginx'):
        (tmp_path / name).mkdir(parents=True)
    return tmp_path


def prepare(root, *, create=True):
    fd = os.open(root, m._DIR)
    try:
        return m._prepare_under_root(fd, owner=os.getuid(), owner_gid=os.getgid(),
                                     uid=os.getuid(), gid=os.getgid(),
                                     labels=m._Labels('debian'), allow_create=create)
    finally:
        os.close(fd)


def test_repeat_preserves_bytes_and_metadata(root):
    report = prepare(root)
    assert report['cache_root_verified'] and report['log_root_verified']
    cache = root / 'var/cache/nginx/repocache-managed'
    log = root / 'var/log/nginx/repocache-managed'
    assert stat.S_IMODE(cache.stat().st_mode) == 0o700
    assert stat.S_IMODE(log.stat().st_mode) == 0o750
    (cache / 'payload').write_bytes(b'cache')
    (log / 'metrics.jsonl').write_bytes(b'history')
    snapshot = [(p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in (cache/'payload', log/'metrics.jsonl')]
    assert prepare(root, create=False) == report
    assert prepare(root) == report
    assert snapshot == [(p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in (cache/'payload', log/'metrics.jsonl')]


def test_foreign_log_refused_before_cache_mutation(root):
    (root / 'var/log/nginx/repocache-managed').mkdir()
    with pytest.raises(m.InstalledStorageError, match='PARTIAL_OR_FOREIGN_ROOT'):
        prepare(root)
    assert not list((root/'var/cache/nginx').iterdir())


def test_missing_refused_on_active_recheck(root):
    with pytest.raises(m.InstalledStorageError, match='OWNED_ROOT_MISSING'):
        prepare(root, create=False)
    assert not list((root/'var/cache/nginx').iterdir())


def test_marker_tamper_refused_without_touching_contents(root):
    prepare(root)
    marker = root/'var/cache/nginx/.repocache-managed.owner-v1'
    marker.write_bytes(b'wrong')
    before = marker.stat().st_mtime_ns
    with pytest.raises(m.InstalledStorageError, match='MARKER_MISMATCH'):
        prepare(root)
    assert marker.read_bytes() == b'wrong' and marker.stat().st_mtime_ns == before


def test_xattr_refusal(root):
    os.setxattr(root/'var/log/nginx', 'user.untrusted', b'1')
    with pytest.raises(m.InstalledStorageError, match='XATTR_UNVERIFIED'):
        prepare(root)
    assert not list((root/'var/cache/nginx').iterdir())


def test_symlink_refused(root):
    (root/'var/log/nginx').rmdir()
    (root/'var/log/nginx').symlink_to(root/'var/cache/nginx', target_is_directory=True)
    with pytest.raises(m.InstalledStorageError):
        prepare(root)
    assert not list((root/'var/cache/nginx').iterdir())


def test_hardlinked_marker_refused(root):
    prepare(root)
    marker = root/'var/cache/nginx/.repocache-managed.owner-v1'
    os.link(marker, root/'extra')
    with pytest.raises(m.InstalledStorageError, match='MARKER_UNSAFE'):
        prepare(root)


def test_selinux_existing_label_never_relabelled(monkeypatch):
    calls = []
    monkeypatch.setattr(m._Labels, '_command', staticmethod(lambda *args: b'Enforcing' if len(args)==1 else b'system_u:object_r:httpd_cache_t:s0'))
    monkeypatch.setattr(m.os, 'listxattr', lambda fd: ['security.selinux'])
    monkeypatch.setattr(m.os, 'getxattr', lambda *args: b'unconfined_u:object_r:var_t:s0\0')
    monkeypatch.setattr(m.os, 'setxattr', lambda *args: calls.append(args))
    with pytest.raises(m.InstalledStorageError, match='SELINUX_LABEL_UNVERIFIED'):
        m._Labels('almalinux').check(11, '/var/cache/nginx/repocache-managed', b'httpd_cache_t')
    assert not calls


def test_service_self_namespace_refused():
    if os.geteuid() != 0:
        pytest.skip('root-only observation')
    with pytest.raises(m.InstalledStorageError, match='SERVICE_MOUNT_NAMESPACE_UNVERIFIED'):
        m.verify_service_storage_mounts(os.getpid())


def test_control_storage_refuses_nonroot_before_host_lookup(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(m, "os", SimpleNamespace(getresuid=lambda: (0, 1000, 0)))
    with pytest.raises(m.InstalledStorageError, match="HOST_UNVERIFIED"):
        m.verify_control_storage("debian")


def test_control_storage_uses_only_fixed_read_only_host_root(monkeypatch):
    from types import SimpleNamespace
    calls = []
    root_stat = SimpleNamespace(st_dev=1, st_ino=2, st_mode=0o40755,
                                st_uid=0, st_gid=0)
    ns_stat = SimpleNamespace(st_dev=3, st_ino=4, st_mode=0o100444,
                              st_uid=0, st_gid=0)
    def opened(path, flags):
        assert path == "/proc/1/root"
        assert flags == os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        calls.append("open")
        return 71
    monkeypatch.setattr(m, "os", SimpleNamespace(
        getresuid=lambda: (0, 0, 0), getresgid=lambda: (0, 0, 0),
        stat=lambda path: ns_stat if path == "/proc/1/ns/mnt" else root_stat,
        fstat=lambda fd: root_stat, open=opened,
        close=lambda fd: calls.append(("close", fd)),
        O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY, O_CLOEXEC=os.O_CLOEXEC,
    ))
    monkeypatch.setattr(m.pwd, "getpwnam", lambda name:
                        SimpleNamespace(pw_uid=33, pw_gid=33))
    def verify(fd, **kw):
        assert fd == 71
        assert kw["allow_create"] is False
        assert (kw["owner"], kw["owner_gid"], kw["uid"], kw["gid"]) == (0, 0, 33, 33)
        calls.append("verify")
        return {"verified": True}
    monkeypatch.setattr(m, "_prepare_under_root", verify)
    assert m.verify_control_storage("debian") == {"verified": True}
    assert calls == ["open", "verify", ("close", 71)]
