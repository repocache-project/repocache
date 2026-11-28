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

def _data_document(*, metrics=True, active=True):
    import json
    source = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
    doc = json.loads(source.read_text())
    doc["deployment"]["logging"]["metrics_opt_in"] = metrics
    doc["repositories"][0]["desired_state"] = "active" if active else "disabled"
    doc["repositories"][1]["id"] = "almalinux-baseos"
    doc["repositories"][1]["desired_state"] = "active" if active else "disabled"
    return doc


def _prepare_data(root, *, doc=None, create=True):
    fd = os.open(root, m._DIR)
    try:
        return m._prepare_repository_storage_under_root(
            fd, owner=os.getuid(), owner_gid=os.getgid(),
            uid=os.getuid(), gid=os.getgid(), labels=m._Labels("debian"),
            document=_data_document() if doc is None else doc, allow_create=create,
        )
    finally:
        os.close(fd)


def test_active_storage_creates_separate_owned_roots_and_private_metrics(root):
    prepare(root)
    report = _prepare_data(root)
    cache = root / m.CACHE_ROOT.lstrip("/")
    log = root / m.LOG_ROOT.lstrip("/") / "metrics.jsonl"
    assert report["repository_cache_roots_verified"] == ["almalinux-baseos", "debian-trixie-main"]
    assert report["metrics_file_verified"] and not report["actual_service_write_verified"]
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    log.write_bytes(b"history")
    for name in report["repository_cache_roots_verified"]:
        assert stat.S_IMODE((cache / name).stat().st_mode) == 0o700
        (cache / name / "package").write_bytes(name.encode("ascii"))
    paths = [log, *(cache / name / "package" for name in report["repository_cache_roots_verified"])]
    before = [(p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in paths]
    assert _prepare_data(root, create=False) == report
    assert _prepare_data(root) == report
    assert before == [(p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in paths]
    # Disabling/opt-out never deletes or truncates previously owned data.
    assert _prepare_data(root, doc=_data_document(active=False))["repository_cache_roots_verified"] == []
    assert before == [(p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in paths]


def test_active_storage_preflights_all_leaves_before_creation(root):
    prepare(root)
    log = root / m.LOG_ROOT.lstrip("/") / "metrics.jsonl"
    log.write_bytes(b"foreign")
    with pytest.raises(m.InstalledStorageError, match="PARTIAL_OR_FOREIGN_DATA"):
        _prepare_data(root)
    assert list((root / m.CACHE_ROOT.lstrip("/")).iterdir()) == []
    assert log.read_bytes() == b"foreign"


def test_active_storage_opt_out_does_not_create_metrics(root):
    prepare(root)
    report = _prepare_data(root, doc=_data_document(metrics=False))
    assert not report["metrics_file_verified"]
    assert list((root / m.LOG_ROOT.lstrip("/")).iterdir()) == []


@pytest.mark.parametrize("key", ["cache_root", "log_root"])
def test_active_storage_rejects_nonfixed_paths_before_io(root, key):
    doc = _data_document()
    doc["deployment"]["paths"][key] = "/tmp/foreign"
    with pytest.raises(m.InstalledStorageError, match="REPOSITORY_LAYOUT_UNSUPPORTED"):
        _prepare_data(root, doc=doc)
    assert not list((root / "var/cache/nginx").iterdir())


def test_active_storage_read_only_refuses_missing_leaves(root):
    prepare(root)
    with pytest.raises(m.InstalledStorageError, match="OWNED_DATA_MISSING"):
        _prepare_data(root, create=False)
    assert list((root / m.CACHE_ROOT.lstrip("/")).iterdir()) == []


def test_active_storage_foreign_marker_and_symlink_refused(root):
    prepare(root)
    _prepare_data(root)
    cache = root / m.CACHE_ROOT.lstrip("/")
    leaf = cache / "almalinux-baseos"
    leaf.rename(cache / "retained")
    leaf.symlink_to(cache / "retained", target_is_directory=True)
    with pytest.raises(m.InstalledStorageError):
        _prepare_data(root)
    assert leaf.is_symlink() and (cache / "retained").is_dir()


def test_active_storage_atomic_publication_never_overwrites_racing_directory(root, monkeypatch):
    prepare(root)
    cache = root / m.CACHE_ROOT.lstrip("/")
    original = m._rename_directory_noreplace
    def race(parent, stage, directory, name):
        os.mkdir(name, 0o700, dir_fd=directory)
        original(parent, stage, directory, name)
    monkeypatch.setattr(m, "_rename_directory_noreplace", race)
    with pytest.raises(m.InstalledStorageError, match="DATA_PUBLICATION_REFUSED"):
        _prepare_data(root)
    foreign = cache / "almalinux-baseos"
    before = foreign.stat().st_ino
    monkeypatch.setattr(m, "_rename_directory_noreplace", original)
    with pytest.raises(m.InstalledStorageError, match="DATA_STAGE_PENDING"):
        _prepare_data(root)
    assert foreign.stat().st_ino == before
    assert not (cache / "debian-trixie-main").exists()


def test_active_storage_metrics_hardlink_refused_without_truncation(root):
    prepare(root)
    _prepare_data(root)
    log = root / m.LOG_ROOT.lstrip("/") / "metrics.jsonl"
    log.write_bytes(b"history")
    os.link(log, root / "other")
    with pytest.raises(m.InstalledStorageError, match="DATA_METADATA_UNSAFE"):
        _prepare_data(root)
    assert log.read_bytes() == (root / "other").read_bytes() == b"history"

def test_service_view_cannot_be_used_with_creation(root):
    prepare(root)
    fd = os.open(root, m._DIR)
    try:
        with pytest.raises(m.InstalledStorageError, match="ARGUMENT_INVALID"):
            m._prepare_repository_storage_under_root(
                fd, owner=os.getuid(), owner_gid=os.getgid(), uid=os.getuid(),
                gid=os.getgid(), labels=m._Labels("debian"),
                document=_data_document(), allow_create=True, service_root=fd)
        assert not list((root / m.CACHE_ROOT.lstrip("/")).iterdir())
    finally:
        os.close(fd)


def test_read_only_service_view_is_bound_to_each_marked_leaf(root, monkeypatch):
    prepare(root)
    _prepare_data(root)
    observed = []
    def inspect(service_root, *, host_directory, segments, name, kind, expected):
        path = root.joinpath(*segments, m._LEAF, name)
        assert m._identity(path.lstat()) == expected
        assert m._identity(path.parent.stat()) == m._identity(os.fstat(host_directory))
        observed.append((kind, name))
    monkeypatch.setattr(m, "_verify_service_data_view", inspect)
    fd = os.open(root, m._DIR)
    try:
        report = m._prepare_repository_storage_under_root(
            fd, owner=os.getuid(), owner_gid=os.getgid(), uid=os.getuid(),
            gid=os.getgid(), labels=m._Labels("debian"),
            document=_data_document(), allow_create=False, service_root=fd)
        assert report["service_data_mounts_verified"] is True
        assert report["actual_service_write_verified"] is False
        assert observed == [
            ("repository-cache", "almalinux-baseos"),
            ("repository-cache", "debian-trixie-main"),
            ("metrics-log", "metrics.jsonl"),
        ]
    finally:
        os.close(fd)


def test_actual_service_view_rejects_foreign_inode_and_writable_parent(root, monkeypatch):
    from types import SimpleNamespace

    prepare(root)
    _prepare_data(root)
    parent = root / "var/cache/nginx"
    leaf = parent / m._LEAF / "almalinux-baseos"
    directory = os.open(leaf.parent, m._DIR)
    fd = os.open(root, m._DIR)
    try:
        # Only mount flags are synthetic here; the descriptor and inode
        # comparisons use real filesystem objects.
        monkeypatch.setattr(m.os, "fstatvfs", lambda _: SimpleNamespace(f_flag=0))
        kw = dict(host_directory=directory, segments=m._CACHE, name=leaf.name,
                  kind="repository-cache", expected=m._identity(leaf.stat()))
        with pytest.raises(m.InstalledStorageError, match="SERVICE_PARENT_WRITABLE"):
            m._verify_service_data_view(fd, **kw)
        parent_inode = parent.stat().st_ino
        monkeypatch.setattr(m.os, "fstatvfs", lambda n: SimpleNamespace(
            f_flag=os.ST_RDONLY if os.fstat(n).st_ino == parent_inode else 0))
        m._verify_service_data_view(fd, **kw)
        old = leaf.with_name("retained")
        leaf.rename(old)
        leaf.mkdir(mode=0o700)
        with pytest.raises(m.InstalledStorageError, match="SERVICE_DATA_IDENTITY_CHANGED"):
            m._verify_service_data_view(fd, **kw)
        assert old.is_dir() and leaf.is_dir()
    finally:
        os.close(fd)
        os.close(directory)



def _dedicated_data(root, *, create=True):
    fd = os.open(root, m._DIR)
    try:
        opts = dict(owner=os.getuid(), owner_gid=os.getgid(), uid=os.getuid(),
                    gid=os.getgid(), labels=m._Labels("debian", dedicated=True),
                    allow_create=create, dedicated=True)
        m._prepare_under_root(fd, **opts)
        return m._prepare_repository_storage_under_root(
            fd, document=_data_document(), **opts)
    finally:
        os.close(fd)


def test_fresh_dedicated_storage_profile_preserves_private_repository_leaves(root):
    report = _dedicated_data(root)
    cache = root / m.CACHE_ROOT.lstrip("/")
    log = root / m.LOG_ROOT.lstrip("/") / "metrics.jsonl"
    assert stat.S_IMODE(cache.stat().st_mode) == 0o711
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    for name in report["repository_cache_roots_verified"]:
        leaf = cache / name
        assert stat.S_IMODE(leaf.stat().st_mode) == 0o700
        (leaf / "payload").write_bytes(b"preserve")
    log.write_bytes(b"history")
    paths = [cache, log, *(cache / n / "payload" for n in report["repository_cache_roots_verified"])]
    before = [(p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_mode) for p in paths]
    assert _dedicated_data(root, create=False) == _dedicated_data(root) == report
    assert before == [(p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_mode) for p in paths]
    assert log.read_bytes() == b"history"
    with pytest.raises(m.InstalledStorageError, match="ROOT_METADATA_UNSAFE"):
        prepare(root)


def test_dedicated_profile_never_reinterprets_legacy_ownership(root):
    prepare(root)
    _prepare_data(root)
    cache = root / m.CACHE_ROOT.lstrip("/")
    log = root / m.LOG_ROOT.lstrip("/") / "metrics.jsonl"
    log.write_bytes(b"legacy")
    before = [(p.stat().st_ino, p.stat().st_mode, p.stat().st_mtime_ns) for p in (cache, log)]
    with pytest.raises(m.InstalledStorageError, match="ROOT_METADATA_UNSAFE"):
        _dedicated_data(root)
    assert before == [(p.stat().st_ino, p.stat().st_mode, p.stat().st_mtime_ns) for p in (cache, log)]
    assert log.read_bytes() == b"legacy"


def test_dedicated_labels_only_assign_fresh_pinned_leaf(monkeypatch):
    context = b"system_u:object_r:repocache_nginx_rw_t:s0"
    seen = [b"system_u:object_r:httpd_cache_t:s0\0"]
    calls = []
    monkeypatch.setattr(m._Labels, "_command", staticmethod(
        lambda *args: b"Enforcing" if len(args) == 1 else
        pytest.fail("dedicated leaf must not inherit vendor context")))
    monkeypatch.setattr(m.os, "listxattr", lambda fd: ["security.selinux"])
    monkeypatch.setattr(m.os, "getxattr", lambda *args: seen[0])
    def set_label(fd, name, value):
        calls.append((fd, name, value))
        seen[0] = value
    monkeypatch.setattr(m.os, "setxattr", set_label)
    labels = m._Labels("almalinux", dedicated=True)
    with pytest.raises(m.InstalledStorageError, match="SELINUX_LABEL_UNVERIFIED"):
        labels.check(11, m.CACHE_ROOT, b"repocache_nginx_rw_t")
    assert not calls
    labels.check(11, m.CACHE_ROOT, b"repocache_nginx_rw_t", fresh=True)
    labels.check(11, m.CACHE_ROOT, b"repocache_nginx_rw_t")
    assert calls == [(11, "security.selinux", context + b"\0")]


def test_dedicated_profile_keeps_worker_private_leaf_ownership():
    assert m._storage_profile(owner=0, owner_gid=0, uid=987, gid=988, dedicated=True) == (
        ("cache", m._CACHE, 0, 0, 0o711, b"httpd_cache_t", b"repocache_nginx_rw_t"),
        ("log", m._LOG, 0, 0, 0o750, b"httpd_log_t", b"repocache_nginx_rw_t"),
    )
