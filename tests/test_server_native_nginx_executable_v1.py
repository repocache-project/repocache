"""Private-root tests; never read or replace a host package executable."""
import hashlib
import os

import pytest

from repocache.server_native_nginx_executable_v1 import (
    NativeExecutableCandidateError, stage_verified_nginx_candidate,
)


def test_rejects_nonroot_or_invalid_identity(monkeypatch):
    monkeypatch.setattr(os, "getresuid", lambda: (0, 0, 1))
    with pytest.raises(NativeExecutableCandidateError, match="INPUT_REFUSED"):
        stage_verified_nginx_candidate(5, 6, authenticated_sha256="a" * 64)


@pytest.mark.skipif(os.geteuid() != 0 or os.getegid() != 0, reason="private root fixture")
def test_stage_idempotence_foreign_and_pending_refusal(tmp_path):
    source = tmp_path / "vendor"
    source.write_bytes(b"private synthetic executable")
    source.chmod(0o755)
    owned = tmp_path / "owned"
    owned.mkdir(mode=0o700)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    parent = os.open(owned, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with pytest.raises(NativeExecutableCandidateError):
            stage_verified_nginx_candidate(parent, fd, authenticated_sha256="a" * 64)
        assert not list(owned.iterdir())
        first = stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest)
        target = owned / "nginx"
        info = target.stat()
        assert first["status"].endswith("STAGED")
        assert not first["authorizes_nginx_activation"]
        assert not first["native_payload_authenticity_verified_by_primitive"]
        assert target.read_bytes() == source.read_bytes()
        assert target.stat().st_ino != source.stat().st_ino
        with pytest.raises(NativeExecutableCandidateError, match="FOREIGN_DESTINATION"):
            stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest)
        again = stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest,
                                              previous_inode=(info.st_dev, info.st_ino))
        assert again["status"].endswith("UNCHANGED")
        assert target.stat().st_ino == info.st_ino
        assert target.stat().st_mtime_ns == info.st_mtime_ns
        pending = owned / ".repocache-nginx-executable.pending"
        pending.symlink_to("absent")
        with pytest.raises(NativeExecutableCandidateError, match="PENDING_REFUSED"):
            stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest)
        assert pending.is_symlink()
        pending.unlink()
        target.write_bytes(b"foreign")
        with pytest.raises(NativeExecutableCandidateError):
            stage_verified_nginx_candidate(parent, fd, authenticated_sha256=digest,
                                           previous_inode=(info.st_dev, info.st_ino))
        assert target.read_bytes() == b"foreign"
        assert source.read_bytes() == b"private synthetic executable"
    finally:
        os.close(fd)
        os.close(parent)


def test_debian_metadata_digest_exact_version_and_conflicting_hash():
    from repocache.server_native_nginx_executable_v1 import debian_nginx_metadata_digest
    stanza = "Package: nginx\nVersion: 1.2-3+deb13u1\nArchitecture: amd64\nSHA256: " + "a" * 64
    assert debian_nginx_metadata_digest(stanza, "1.2-3+deb13u1") == "a" * 64
    for bad in (stanza.replace("amd64", "arm64"), stanza + "\nSHA256: " + "a" * 64,
                stanza + "\n\n" + stanza.replace("a" * 64, "b" * 64)):
        with pytest.raises(NativeExecutableCandidateError):
            debian_nginx_metadata_digest(bad, "1.2-3+deb13u1")


@pytest.mark.parametrize("fault", [None, "duplicate", "symlink", "owner", "mode", "traversal", "missing"])
def test_debian_data_tar_exact_regular_executable(fault):
    import io
    import tarfile
    from repocache.server_native_nginx_executable_v1 import debian_nginx_tar_digest
    raw = io.BytesIO()
    payload = b"synthetic fixture bytes"
    with tarfile.open(fileobj=raw, mode="w") as archive:
        entry = tarfile.TarInfo("./usr/sbin/nginx" if fault != "missing" else "other")
        entry.mode = 0o755 if fault != "mode" else 0o4755
        entry.uid = 1 if fault == "owner" else 0
        entry.size = len(payload)
        if fault == "symlink":
            entry.type, entry.linkname, entry.size = tarfile.SYMTYPE, "other", 0
        if fault == "traversal":
            entry.name = "./usr/../usr/sbin/nginx"
        archive.addfile(entry, io.BytesIO(payload))
        if fault == "duplicate":
            archive.addfile(entry, io.BytesIO(payload))
    if fault is None:
        assert debian_nginx_tar_digest(raw.getvalue()) == hashlib.sha256(payload).hexdigest()
    else:
        with pytest.raises(NativeExecutableCandidateError):
            debian_nginx_tar_digest(raw.getvalue())


@pytest.mark.skipif(os.geteuid() != 0 or os.getegid() != 0, reason="private root fixture")
def test_receipt_requires_exact_owned_inode_and_native_release_identity(tmp_path):
    from repocache.server_native_nginx_executable_v1 import stage_nginx_candidate_with_receipt
    source = tmp_path / "vendor"
    source.write_bytes(b"synthetic native executable")
    source.chmod(0o755)
    owned = tmp_path / "owned"
    owned.mkdir(mode=0o700)
    opts = dict(distribution="debian", package_identity="nginx:amd64=1.2-3",
                native_payload_sha256="a" * 64, release_source_sha="b" * 40,
                release_archive_sha256="c" * 64,
                authenticated_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    parent = os.open(owned, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = stage_nginx_candidate_with_receipt(parent, fd, **opts)
        receipt = owned / ".native-nginx-executable-v1.json"
        before = receipt.read_bytes()
        assert first["receipt_sha256"] == hashlib.sha256(before).hexdigest()
        second = stage_nginx_candidate_with_receipt(parent, fd, **opts)
        assert second["status"].endswith("UNCHANGED") and second["inode"] == first["inode"]
        for key, value in (("native_payload_sha256", "d" * 64), ("release_archive_sha256", "e" * 64)):
            with pytest.raises(NativeExecutableCandidateError):
                stage_nginx_candidate_with_receipt(parent, fd, **{**opts, key: value})
            assert receipt.read_bytes() == before
        # An independently created equal-byte inode cannot be adopted.
        replacement = owned / "foreign"
        replacement.write_bytes(source.read_bytes())
        replacement.chmod(0o755)
        os.replace(replacement, owned / "nginx")
        with pytest.raises(NativeExecutableCandidateError):
            stage_nginx_candidate_with_receipt(parent, fd, **opts)
        assert receipt.read_bytes() == before
    finally:
        os.close(fd)
        os.close(parent)


@pytest.mark.skipif(os.geteuid() != 0 or os.getegid() != 0, reason="private root fixture")
def test_receipt_refuses_same_inode_metadata_change_and_partial_publication(tmp_path):
    from repocache.server_native_nginx_executable_v1 import stage_nginx_candidate_with_receipt
    source = tmp_path / "vendor"
    source.write_bytes(b"private synthetic executable")
    source.chmod(0o755)
    owned = tmp_path / "owned"
    owned.mkdir(mode=0o700)
    opts = dict(distribution="debian", package_identity="nginx:amd64=1.2-3",
                native_payload_sha256="a" * 64, release_source_sha="b" * 40,
                release_archive_sha256="c" * 64,
                authenticated_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    parent = os.open(owned, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        receipt = owned / ".native-nginx-executable-v1.json"
        receipt.write_bytes(b"partial")
        receipt.chmod(0o600)
        with pytest.raises(NativeExecutableCandidateError):
            stage_nginx_candidate_with_receipt(parent, fd, **opts)
        assert receipt.read_bytes() == b"partial"
        assert not (owned / "nginx").exists()
        receipt.unlink()  # This deliberately injected fixture leaf is ours.
        stage_nginx_candidate_with_receipt(parent, fd, **opts)
        raw = receipt.read_bytes()
        candidate = owned / "nginx"
        info = candidate.stat()
        os.utime(candidate, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
        with pytest.raises(NativeExecutableCandidateError, match="RECEIPT_CHANGED"):
            stage_nginx_candidate_with_receipt(parent, fd, **opts)
        assert receipt.read_bytes() == raw and candidate.stat().st_ino == info.st_ino
        assert candidate.read_bytes() == source.read_bytes()
    finally:
        os.close(fd)
        os.close(parent)


def test_signed_policy_candidate_is_exact_reviewed_fixture_permissions():
    from pathlib import Path
    from repocache import server_native_nginx_executable_v1 as candidate
    root = Path(__file__).resolve().parents[1]
    raw = (root / "docs/examples/selinux/repocache-nginx.te").read_bytes()
    fixture = (root / "scripts/ci_selinux_nginx_egress_fixture.te").read_bytes()

    def rules(data):
        return [line for line in data.splitlines() if line and not line.startswith(b"#")]

    # The shipped candidate is not the disposable policy copied wholesale.
    # Only this explicit reviewed delta is permitted for the fixed native
    # paths and low-port listener, with no additional vendor-domain grants.
    expected = fixture.replace(b"repocache_ci_nginx", b"repocache_nginx")
    expected = expected.replace(b"    type init_t;\n", b"""    type init_t;
    type httpd_config_t;
    type httpd_cache_t;
    type httpd_log_t;
    type var_t;
    type var_log_t;
    type var_run_t;
    type cert_t;
""")
    expected = expected.replace(
        b"allow repocache_nginx_t self:capability { chown kill setgid setuid };",
        b"""allow repocache_nginx_t self:capability { chown kill setgid setuid net_bind_service };
allow repocache_nginx_t { httpd_config_t httpd_cache_t httpd_log_t var_t var_log_t var_run_t }:dir search_dir_perms;
allow repocache_nginx_t cert_t:dir search_dir_perms;
allow repocache_nginx_t cert_t:file read_file_perms;
allow repocache_nginx_t cert_t:lnk_file { getattr read };""")
    assert rules(raw) == rules(expected)
    report = candidate._policy_candidate(raw)
    assert report["policy_bytes"] == raw
    assert report["policy_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["module"] == "repocache_nginx"
    assert report["executable_context"] == "system_u:object_r:repocache_nginx_exec_t:s0"
    assert not report["authorizes_policy_installation"]
    assert not report["runtime_selinux_policy_verified"]
    assert not report["authorizes_nginx_activation"]
    with pytest.raises(NativeExecutableCandidateError, match="SIGNED_POLICY_SOURCE_REQUIRED"):
        candidate.signed_owned_nginx_policy_candidate()


@pytest.mark.parametrize("raw", [b"", b"policy_module(httpd, 1.0.0)\n",
                                  b"policy_module(repocache_nginx, 1.0.0)\n\0",
                                  b" " * 16385, "not bytes"])
def test_policy_asset_consistency_refuses_invalid_source(raw):
    from repocache.server_native_nginx_executable_v1 import _policy_candidate
    with pytest.raises(NativeExecutableCandidateError, match="POLICY_SOURCE_REFUSED"):
        _policy_candidate(raw)


@pytest.mark.skipif(os.geteuid() != 0 or os.getegid() != 0, reason="private root fixture")
@pytest.mark.parametrize("fault", ["none", "label-denied", "foreign-label", "foreign-attr"])
def test_dedicated_label_before_publish_and_receipt_binding(tmp_path, monkeypatch, fault):
    from repocache import server_native_nginx_executable_v1 as candidate

    source = tmp_path / "vendor"
    source.write_bytes(b"private synthetic native executable")
    source.chmod(0o755)
    owned = tmp_path / "owned"
    owned.mkdir(mode=0o700)
    parent = os.open(owned, os.O_RDONLY | os.O_DIRECTORY)
    vendor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    target = owned / "nginx"
    pending = owned / candidate._PENDING
    original = b"system_u:object_r:bin_t:s0\0"
    label = [original]
    changes = []
    real_list, real_get, real_set = os.listxattr, os.getxattr, os.setxattr

    def is_candidate(fd):
        return (type(fd) is int and fd not in (parent, vendor)
                and os.readlink("/proc/self/fd/" + str(fd)) in (str(target), str(pending)))

    def listxattr(fd, *args, **kwargs):
        if is_candidate(fd):
            return ["security.selinux"] + (["user.foreign"] if fault == "foreign-attr" else [])
        return real_list(fd, *args, **kwargs)

    def getxattr(fd, name, *args, **kwargs):
        if is_candidate(fd) and name == "security.selinux":
            return label[0]
        return real_get(fd, name, *args, **kwargs)

    def setxattr(fd, name, value, *args, **kwargs):
        if is_candidate(fd):
            assert os.readlink("/proc/self/fd/" + str(fd)) == str(pending)
            assert not target.exists() and name == "security.selinux"
            changes.append(value)
            if fault == "label-denied":
                raise PermissionError("simulated native label refusal")
            label[0] = original if fault == "foreign-label" else value
            return
        return real_set(fd, name, value, *args, **kwargs)

    opts = dict(distribution="almalinux", package_identity="nginx-core-0:1.2-3.x86_64",
                native_payload_sha256="a" * 64, release_source_sha="b" * 40,
                release_archive_sha256="c" * 64, dedicated_policy_sha256="d" * 64,
                authenticated_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(os, "listxattr", listxattr)
            scoped.setattr(os, "getxattr", getxattr)
            scoped.setattr(os, "setxattr", setxattr)
            if fault != "none":
                with pytest.raises(NativeExecutableCandidateError):
                    candidate.stage_nginx_candidate_with_receipt(parent, vendor, **opts)
                assert pending.exists() and not target.exists()
                assert not (owned / candidate._RECEIPT).exists()
                with pytest.raises(NativeExecutableCandidateError):
                    candidate.stage_nginx_candidate_with_receipt(parent, vendor, **opts)
                return
            first = candidate.stage_nginx_candidate_with_receipt(parent, vendor, **opts)
            assert changes == [candidate._EXEC_CONTEXT + b"\0"]
            assert first["dedicated_executable_label_observed"]
            assert not first["runtime_selinux_policy_verified"]
            assert first["dedicated_policy_sha256"] == "d" * 64
            receipt = (owned / candidate._RECEIPT).read_bytes()
            again = candidate.stage_nginx_candidate_with_receipt(parent, vendor, **opts)
            assert again["status"].endswith("UNCHANGED")
            assert changes == [candidate._EXEC_CONTEXT + b"\0"]
            for wrong in (None, "e" * 64):
                with pytest.raises(NativeExecutableCandidateError):
                    candidate.stage_nginx_candidate_with_receipt(
                        parent, vendor, **dict(opts, dedicated_policy_sha256=wrong))
            label[0] = original
            with pytest.raises(NativeExecutableCandidateError, match="DEDICATED_LABEL_REFUSED"):
                candidate.stage_nginx_candidate_with_receipt(parent, vendor, **opts)
            assert (owned / candidate._RECEIPT).read_bytes() == receipt
            assert target.read_bytes() == source.read_bytes()
    finally:
        os.close(vendor)
        os.close(parent)
