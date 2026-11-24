"""Source-only root client boundary: strict pinned approvals, no production writes."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
import root_source_boundary as helper

IDENT = "a" * 32
APT = ("deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] "
       "https://deb.example.org/debian/ trixie main\n")
DNF = ("[baseos]\nname=AlmaLinux\n"
       "baseurl=https://rpm.example.org/alma/\n"
       "enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"
       "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10\n")
CACHE = "https://cache.example.org/__repocache/repos/baseos/"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def private_fixture(root: Path, *, manager: str = "apt"):
    """Populate only an ephemeral private test tree with fixed roots."""
    root.chmod(0o700)
    marker = root / helper.MARKER
    marker.write_bytes(helper.MAGIC)
    marker.chmod(0o600)
    pre = root / ".repocache-source-preflight-test"
    pre.write_bytes(b"REPOCACHE_SOURCE_PREFLIGHT_TEST_V1\n")
    pre.chmod(0o600)

    relative = ("etc/apt/sources.list.d/base.list" if manager == "apt"
                else "etc/yum.repos.d/base.repo")
    payload = APT.encode() if manager == "apt" else DNF.encode()
    source = root / relative
    source.parent.mkdir(parents=True)
    source.write_bytes(payload)
    source.chmod(0o644)

    approvals = root / "var/lib/repocache-client/approved-entries"
    approvals.mkdir(parents=True)
    for ancestor in (root/"var", root/"var/lib"):
        ancestor.chmod(0o755)
    for ancestor in (root/"var/lib/repocache-client", approvals):
        ancestor.chmod(0o700)
    lock = approvals / ".transaction.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    record = {
        "schema": 1, "id": IDENT, "source": relative,
        "source_sha256": sha(payload),
        "entry_sha256": sha(payload),
        "upstream": ("https://deb.example.org/debian/" if manager == "apt"
                     else "https://rpm.example.org/alma/"),
        "cache": CACHE,
        "route_sha256": sha(CACHE.encode()),
    }
    path = approvals / ("candidate-" + IDENT + ".json")
    path.write_text(json.dumps(record), encoding="utf-8")
    path.chmod(0o600)
    return record, source, path, lock


def test_prototype_always_denies_source_mutations(capsys):
    for args in (["commit"], ["recover"], ["restore"],
                 ["validate", "--candidate", "../etc/passwd"],
                 ["validate", "--candidate", "x" * 32]):
        rc = helper.main(["--json", *args])
        assert rc != 0
        output = json.loads(capsys.readouterr().out)
        assert output["write_eligible"] is False
        assert output["error"]["code"] in ("ROOT_REQUIRED", "VALIDATION_REFUSED")


def test_duplicate_json_field_refused():
    with pytest.raises(helper.BoundaryRefused, match="Duplicate"):
        helper._no_duplicate_fields([("schema", 1), ("schema", 1)])


def test_read_protected_file_by_fd_checks_mode_link_and_inode(tmp_path):
    path = tmp_path / "approved.json"
    path.write_bytes(b"managed-secret")
    path.chmod(0o600)
    dir_fd = os.open(tmp_path, helper.DIR)
    try:
        assert helper._read_pinned(dir_fd, path.name, 64,
                                   owner=os.geteuid()) == b"managed-secret"
        path.chmod(0o644)
        with pytest.raises(helper.BoundaryRefused):
            helper._read_pinned(dir_fd, path.name, 64,
                                owner=os.geteuid())
        path.chmod(0o600)
        alias = tmp_path / "alias"
        os.link(path, alias)
        with pytest.raises(helper.BoundaryRefused):
            helper._read_pinned(dir_fd, path.name, 64,
                                owner=os.geteuid())
        alias.unlink()
        path.unlink()
        path.symlink_to("/etc/passwd")
        with pytest.raises(helper.BoundaryRefused):
            helper._read_pinned(dir_fd, path.name, 64,
                                owner=os.geteuid())
    finally:
        os.close(dir_fd)


@pytest.mark.parametrize("manager", ["apt", "dnf"])
@pytest.mark.skipif(os.geteuid() != 0, reason="Positive trusted source inspection requires real root")
def test_root_fixture_accepts_only_source_level_validation(tmp_path, manager):
    record, source, manifest, lock = private_fixture(tmp_path, manager=manager)
    before = sorted((str(p.relative_to(tmp_path)), p.read_bytes())
                    for p in tmp_path.rglob("*") if p.is_file())
    state = helper.validate(IDENT, _test_root=tmp_path)
    assert state["status"] == "validated-read-only"
    assert state["managed_id"] == IDENT
    assert state["source_digest_matched"]
    assert state["entry_digest_matched"]
    assert state["route_digest_matched"]
    assert state["current_active_catalog_route_matched"] is False
    assert state["fallback_plan_generated"]
    assert not state["installed"]
    assert not state["write_eligible"]
    assert not state["native_fallback_verified"]
    assert not state["package_signatures_verified"]
    assert state["multi_file_changes_required"] is (manager == "apt")
    assert sorted((str(p.relative_to(tmp_path)), p.read_bytes())
                  for p in tmp_path.rglob("*") if p.is_file()) == before
    # The source is unchanged, even under UID 0, and still direct upstream.
    assert source.read_bytes() == (APT if manager == "apt" else DNF).encode()


@pytest.mark.skipif(os.geteuid() != 0, reason="Positive native refusal needs root")
def test_root_denies_tamper_symlink_modified_source_and_lock_races(tmp_path):
    rec, source, manifest, lock = private_fixture(tmp_path)
    helper.validate(IDENT, _test_root=tmp_path)

    # In-flight package-source changes invalidate immutable approval.
    source.write_bytes(source.read_bytes() + b"# concurrent change\n")
    with pytest.raises(helper.BoundaryRefused):
        helper.validate(IDENT, _test_root=tmp_path)
    source.write_bytes(APT.encode())
    helper.validate(IDENT, _test_root=tmp_path)

    # New exact route or an altered hash cannot reuse the old consent.
    modified = dict(rec, cache="https://cache.example.org/changed/")
    manifest.write_text(json.dumps(modified))
    with pytest.raises(helper.BoundaryRefused):
        helper.validate(IDENT, _test_root=tmp_path)
    manifest.write_text(json.dumps(rec))
    helper.validate(IDENT, _test_root=tmp_path)

    # Existing exclusive flock blocks concurrent operations promptly.
    with lock.open("r+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with pytest.raises(helper.BoundaryBusy):
                helper.validate(IDENT, _test_root=tmp_path)
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)

    # Third-party redirect of the approved manifest is never followed.
    manifest.unlink()
    manifest.symlink_to("/etc/passwd")
    with pytest.raises(helper.BoundaryRefused):
        helper.validate(IDENT, _test_root=tmp_path)


@pytest.mark.skipif(os.geteuid() != 0, reason="Positive native refusal needs root")
def test_root_denies_untrusted_directories_and_malformed_manifest(tmp_path):
    rec, source, manifest, lock = private_fixture(tmp_path)
    lib = tmp_path / "var/lib/repocache-client"
    lib.chmod(0o755)
    with pytest.raises(helper.BoundaryRefused):
        helper.validate(IDENT, _test_root=tmp_path)
    lib.chmod(0o700)
    manifest.write_text(json.dumps(rec)[:-1] + ', "schema":1}')
    with pytest.raises(helper.BoundaryRefused):
        helper.validate(IDENT, _test_root=tmp_path)
    manifest.write_text(json.dumps(rec))
    manifest.chmod(0o644)
    with pytest.raises(helper.BoundaryRefused):
        helper.validate(IDENT, _test_root=tmp_path)


def test_plain_status_refuses_nonroot(monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 1000)
    with pytest.raises(helper.BoundaryRefused):
        helper.status()
    with pytest.raises(helper.BoundaryRefused):
        helper.validate(IDENT)


@pytest.mark.skipif(os.geteuid() != 0, reason="Positive native refusal requires root")
def test_labelled_source_and_lock_xattrs_fail_closed(tmp_path):
    rec, source, manifest, lock = private_fixture(tmp_path)
    for path in (source, lock):
        try:
            os.setxattr(path, "user.repocache-ci-boundary", b"label")
        except (OSError, AttributeError) as exc:
            pytest.skip(f"Container filesystem does not expose user xattrs: {exc}")
        try:
            with pytest.raises(helper.BoundaryRefused):
                helper.validate(IDENT, _test_root=tmp_path)
        finally:
            os.removexattr(path, "user.repocache-ci-boundary")
        assert helper.validate(IDENT, _test_root=tmp_path)["write_eligible"] is False


@pytest.mark.parametrize("mode", [
    "exact", "withdrawn", "changed-path", "different-upstream",
    "prefix-only", "foreign-origin", "legacy", "origin-drift", "offline",
])
def test_current_route_requires_exact_fresh_authenticated_mapping(monkeypatch, mode):
    monkeypatch.setattr(helper.os, "getresuid", lambda: (0, 0, 0))
    upstream = "https://deb.example.org/debian/"
    cache = CACHE
    if mode == "foreign-origin":
        cache = "https://foreign.example.org/__repocache/repos/baseos/"
    elif mode == "legacy":
        cache = "https://cache.example.org/debian/"
    record = {"upstream": upstream, "cache": cache}
    reads = []
    origin = "https://cache.example.org"

    def config(root):
        reads.append(root)
        if mode == "origin-drift" and len(reads) > 1:
            return "https://other.example.org"
        return origin

    context = object()
    calls = []

    def catalog(server, *, context):
        calls.append((server, context))
        if mode == "offline":
            raise helper.client.ClientError("unavailable")
        item = {"upstream": upstream, "cache": cache}
        if mode == "changed-path":
            item["cache"] = origin + "/__repocache/repos/new/"
        if mode == "different-upstream":
            item["upstream"] = "https://other.example.org/debian/"
        if mode == "prefix-only":
            item["upstream"] = "https://deb.example.org/"
        return {"schema": 1, "repositories": [] if mode == "withdrawn" else [item]}

    monkeypatch.setattr(helper.client, "_installed_server_config", config)
    monkeypatch.setattr(helper.client, "_catalog", catalog)
    monkeypatch.setattr(helper, "_native_tls_context", lambda: context)
    if mode == "exact":
        assert helper._current_route(record, Path("/")) == origin
        assert calls == [(origin, context)]
        assert reads == [Path("/"), Path("/")]
    else:
        with pytest.raises(helper.BoundaryRefused):
            helper._current_route(record, Path("/"))
        if mode in ("foreign-origin", "legacy"):
            assert not calls


def test_current_route_rejects_nonroot_before_origin_read(monkeypatch):
    monkeypatch.setattr(helper.os, "getresuid", lambda: (1000, 0, 0))
    monkeypatch.setattr(helper.client, "_installed_server_config", lambda *_:
                        pytest.fail("untrusted process reached origin read"))
    with pytest.raises(helper.BoundaryRefused, match="root authorization"):
        helper._current_route({}, Path("/"))


def test_native_tls_context_refuses_unsupported_target(monkeypatch):
    monkeypatch.setattr(helper.os, "getresuid", lambda: (0, 0, 0))
    monkeypatch.setattr(helper.client, "_distro", lambda _: {
        "ID": "unsupported", "VERSION_ID": "13",
    })
    with pytest.raises(helper.BoundaryRefused):
        helper._native_tls_context()


def _pending_v2(root):
    record, source, approval, lock = private_fixture(root)
    snapshot = helper.pre.inspect_source(record["source"], root=root)
    record["schema"] = 2
    record["source_identity"] = {
        key: snapshot[key] for key in helper.SOURCE_IDENTITY_FIELDS
    }
    pending = approval.with_name("pending-" + IDENT + ".json")
    approval.rename(pending)
    pending.write_text(json.dumps(record))
    pending.chmod(0o600)
    return record, source, pending, approval, lock


def _mock_current_route(monkeypatch):
    monkeypatch.setattr(helper, "_current_route", lambda *_: "https://cache.example.org")
    monkeypatch.setattr(helper.client, "_installed_server_config",
                        lambda *_: "https://cache.example.org")


@pytest.mark.skipif(os.geteuid() != 0, reason="Real root-only approval fixture")
def test_exact_consent_issues_durable_immutable_approval_without_source_change(
        tmp_path, monkeypatch):
    record, source, pending, approval, lock = _pending_v2(tmp_path)
    _mock_current_route(monkeypatch)
    before = source.stat()
    with pytest.raises(helper.BoundaryRefused, match="consent"):
        helper.approve_current_candidate(IDENT, "0" * 64, _test_root=tmp_path)
    assert not approval.exists()
    assert helper.approve_current_candidate(
        IDENT, record["route_sha256"], _test_root=tmp_path)["status"] == "approved"
    assert json.loads(approval.read_text()) == record
    assert approval.stat().st_uid == 0
    assert stat.S_IMODE(approval.stat().st_mode) == 0o600
    assert approval.stat().st_nlink == 1
    inode = approval.stat().st_ino
    assert helper.approve_current_candidate(
        IDENT, record["route_sha256"], _test_root=tmp_path)["status"] == "unchanged"
    assert approval.stat().st_ino == inode
    assert helper.validate(IDENT, _test_root=tmp_path)["source_inode_identity_matched"]
    after = source.stat()
    assert source.read_bytes() == APT.encode()
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino, after.st_mtime_ns, after.st_ctime_ns)


@pytest.mark.skipif(os.geteuid() != 0, reason="Real root-only approval fixture")
def test_same_bytes_foreign_inode_cannot_reuse_pending_or_issued_approval(
        tmp_path, monkeypatch):
    record, source, pending, approval, lock = _pending_v2(tmp_path)
    _mock_current_route(monkeypatch)
    helper.approve_current_candidate(IDENT, record["route_sha256"], _test_root=tmp_path)
    replacement = source.with_name("foreign.list")
    replacement.write_bytes(source.read_bytes())
    replacement.chmod(0o644)
    os.replace(replacement, source)
    with pytest.raises(helper.BoundaryRefused, match="inode identity"):
        helper.approve_current_candidate(
            IDENT, record["route_sha256"], _test_root=tmp_path)
    with pytest.raises(helper.BoundaryRefused, match="inode identity"):
        helper.validate(IDENT, _test_root=tmp_path)
    assert json.loads(approval.read_text()) == record


@pytest.mark.skipif(os.geteuid() != 0, reason="Real root-only approval fixture")
def test_route_failure_and_concurrent_publication_preserve_existing_state(
        tmp_path, monkeypatch):
    record, source, pending, approval, lock = _pending_v2(tmp_path)
    def denied(*_):
        raise helper.BoundaryRefused("Route unavailable")
    monkeypatch.setattr(helper, "_current_route", denied)
    with pytest.raises(helper.BoundaryRefused, match="Route unavailable"):
        helper.approve_current_candidate(IDENT, record["route_sha256"], _test_root=tmp_path)
    assert not approval.exists()
    _mock_current_route(monkeypatch)
    real_rename = helper._rename_noreplace
    def race(fd, temporary, target):
        approval.write_bytes(b"foreign")
        approval.chmod(0o600)
        real_rename(fd, temporary, target)
    monkeypatch.setattr(helper, "_rename_noreplace", race)
    with pytest.raises(helper.BoundaryRefused, match="cannot be replaced"):
        helper.approve_current_candidate(IDENT, record["route_sha256"], _test_root=tmp_path)
    assert approval.read_bytes() == b"foreign"
    assert not list(approval.parent.glob(".approval-*"))
    assert source.read_bytes() == APT.encode()


def test_approval_issuance_refuses_nonroot_before_state_access(monkeypatch):
    monkeypatch.setattr(helper.os, "getresuid", lambda: (1000, 0, 0))
    monkeypatch.setattr(helper, "_state", lambda *_:
                        pytest.fail("unprivileged approval reached state"))
    with pytest.raises(helper.BoundaryRefused, match="Root OS authorization"):
        helper.approve_current_candidate(IDENT, "a" * 64)


@pytest.mark.parametrize("manager", ["apt", "dnf"])
@pytest.mark.skipif(os.geteuid() != 0, reason="Real root-only preparation fixture")
def test_prepare_uses_exact_source_and_current_catalog_without_granting_consent(
        tmp_path, monkeypatch, manager):
    record, source, approval, lock = private_fixture(tmp_path, manager=manager)
    approval.unlink()
    (tmp_path / "etc/os-release").write_text(
        'ID=debian\nVERSION_ID="13"\n' if manager == "apt"
        else 'ID=almalinux\nVERSION_ID="10"\n')
    origin = "https://cache.example.org"
    monkeypatch.setattr(helper.client, "_installed_server_config", lambda _: origin)
    monkeypatch.setattr(helper, "_native_tls_context", lambda: object())
    active = [{"upstream": record["upstream"], "cache": record["cache"]}]
    monkeypatch.setattr(helper.client, "_catalog", lambda *_, **kw: {
        "schema": 1, "repositories": active})
    before = source.stat()
    result = helper.prepare_current_candidate(
        record["source_sha256"], record["entry_sha256"], _test_root=tmp_path)
    assert result["status"] == "prepared"
    assert not result["approval_granted"] and not result["write_eligible"]
    ident = result["managed_id"]
    pending = approval.with_name("pending-" + ident + ".json")
    approved = approval.with_name("candidate-" + ident + ".json")
    assert pending.exists() and not approved.exists()
    snapshot = json.loads(pending.read_text())
    assert snapshot["source_identity"]["inode"] == before.st_ino
    assert snapshot["cache"] == record["cache"]
    repeated = helper.prepare_current_candidate(
        record["source_sha256"], record["entry_sha256"], _test_root=tmp_path)
    assert repeated["status"] == "unchanged"
    assert repeated["managed_id"] == ident
    helper.approve_current_candidate(
        ident, result["route_sha256"], _test_root=tmp_path)
    assert approved.exists()
    active[0]["cache"] = origin + "/__repocache/repos/changed/"
    changed = helper.prepare_current_candidate(
        record["source_sha256"], record["entry_sha256"], _test_root=tmp_path)
    assert changed["managed_id"] != ident
    assert changed["route_sha256"] != result["route_sha256"]
    assert not changed["approval_granted"]
    with pytest.raises(helper.BoundaryRefused, match="absent"):
        helper.approve_current_candidate(
            ident, result["route_sha256"], _test_root=tmp_path)
    assert source.read_bytes() == (APT if manager == "apt" else DNF).encode()
    assert source.stat().st_ino == before.st_ino


@pytest.mark.skipif(os.geteuid() != 0, reason="Real root-only preparation fixture")
def test_prepare_rejects_ambiguous_source_before_network(tmp_path, monkeypatch):
    record, source, approval, lock = private_fixture(tmp_path)
    approval.unlink()
    (tmp_path / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    duplicate = source.with_name("duplicate.list")
    duplicate.write_bytes(source.read_bytes())
    duplicate.chmod(0o644)
    monkeypatch.setattr(helper.client, "_installed_server_config", lambda *_:
                        pytest.fail("Ambiguous selection reached origin read"))
    with pytest.raises(helper.BoundaryRefused, match="Ambiguous source"):
        helper.prepare_current_candidate(
            record["source_sha256"], record["entry_sha256"], _test_root=tmp_path)
    assert not list(approval.parent.glob("pending-*"))


def test_prepare_refuses_nonroot_before_state_access(monkeypatch):
    monkeypatch.setattr(helper.os, "getresuid", lambda: (1000, 0, 0))
    monkeypatch.setattr(helper, "_state", lambda *_:
                        pytest.fail("unprivileged preparation reached state"))
    with pytest.raises(helper.BoundaryRefused, match="root authorization"):
        helper.prepare_current_candidate("a" * 64, "b" * 64)


@pytest.mark.skipif(os.geteuid() != 0, reason="Root-only bootstrap fixture")
def test_protected_state_bootstrap_is_idempotent_and_does_not_adopt_missing_lock(tmp_path):
    root = tmp_path
    root.chmod(0o700)
    marker = root / helper.MARKER
    marker.write_bytes(helper.MAGIC)
    marker.chmod(0o600)
    (root / "var/lib").mkdir(parents=True, mode=0o755)
    first = helper.bootstrap_protected_state(_test_root=root)
    assert first == {"status": "created", "protected_state_ready": True, "write_eligible": False}
    state = root / "var/lib/repocache-client/approved-entries"
    lock = state / ".transaction.lock"
    before = lock.stat()
    assert before.st_mode & 0o777 == 0o600
    assert lock.read_bytes() == b""
    assert helper.bootstrap_protected_state(_test_root=root)["status"] == "unchanged"
    after = lock.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
    lock.unlink()
    evidence = state / "pair-evidence"
    evidence.write_bytes(b"retain")
    with pytest.raises(helper.BoundaryRefused, match="Missing registry lock"):
        helper.bootstrap_protected_state(_test_root=root)
    assert not lock.exists() and evidence.read_bytes() == b"retain"


@pytest.mark.skipif(os.geteuid() != 0, reason="Root-only bootstrap fixture")
def test_protected_state_bootstrap_refuses_symlink_and_nonempty_lock(tmp_path):
    root = tmp_path
    root.chmod(0o700)
    marker = root / helper.MARKER
    marker.write_bytes(helper.MAGIC)
    marker.chmod(0o600)
    parent = root / "var/lib"
    parent.mkdir(parents=True, mode=0o755)
    unrelated = root / "unrelated"
    unrelated.mkdir(mode=0o700)
    target = parent / "repocache-client"
    target.symlink_to(unrelated)
    with pytest.raises(helper.BoundaryRefused):
        helper.bootstrap_protected_state(_test_root=root)
    assert not list(unrelated.iterdir())
    target.unlink()
    helper.bootstrap_protected_state(_test_root=root)
    lock = target / "approved-entries/.transaction.lock"
    lock.write_bytes(b"foreign")
    with pytest.raises(helper.BoundaryRefused):
        helper.bootstrap_protected_state(_test_root=root)
    assert lock.read_bytes() == b"foreign"
