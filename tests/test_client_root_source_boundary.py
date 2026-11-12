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
