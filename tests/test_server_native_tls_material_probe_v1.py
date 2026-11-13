"""Native OpenSSL TLS material and real filesystem security refusals."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from repocache.server_native_tls_material_probe_v1 import (
    NativeTLSMaterialProbeError, inspect_native_tls_pair_under_root,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
OPENSSL = shutil.which("openssl")


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "root"
    tls = root / "etc/repocache/tls"
    tls.mkdir(parents=True)
    tls.chmod(0o700)
    doc = json.loads(EXAMPLE.read_text())
    doc["deployment"]["tls"]["certificate_file"] = "/etc/repocache/tls/test.crt"
    doc["deployment"]["tls"]["private_key_file"] = "/etc/repocache/tls/test.key"
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield fd, root, tls, doc
    finally:
        os.close(fd)


def generate(tls, name):
    if OPENSSL is None:
        pytest.skip("OpenSSL not present")
    cert = tls / (name + ".crt")
    key = tls / (name + ".key")
    result = subprocess.run([
        OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-keyout", str(key), "-out", str(cert),
        "-subj", "/CN=cache.example.invalid",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
       timeout=40, check=False)
    assert result.returncode == 0
    cert.chmod(0o644)
    key.chmod(0o600)
    return cert, key


def inspect(fixture):
    fd, _, _, doc = fixture
    return inspect_native_tls_pair_under_root(
        fd, owner_uid=os.geteuid(), document=doc,
    )


def test_actual_matching_certificate_key_via_pinned_openssl_descriptors(fixture):
    _, _, tls, _ = fixture
    generate(tls, "test")
    result = inspect(fixture)
    assert result["openssl_matching_pair_verified"]
    assert result["host_root_authenticated"] is False
    assert result["operator_identity_verified"] is False
    assert result["certificate_hostname_verified"] is False
    assert result["selinux_context_verified"] is False
    assert result["authorizes_nginx_reload"] is False


def test_mismatched_private_key_refused(fixture):
    _, _, tls, _ = fixture
    generate(tls, "test")
    _, foreign = generate(tls, "other")
    (tls / "test.key").write_bytes(foreign.read_bytes())
    (tls / "test.key").chmod(0o600)
    with pytest.raises(NativeTLSMaterialProbeError,
                       match="TLS_MATERIAL_TLS_PAIR_OR_INODE_UNVERIFIED"):
        inspect(fixture)


def test_symlink_or_hardlink_refused(fixture):
    _, _, tls, _ = fixture
    generate(tls, "test")
    (tls / "test.key").rename(tls / "original.key")
    (tls / "test.key").symlink_to(tls / "original.key")
    with pytest.raises(NativeTLSMaterialProbeError):
        inspect(fixture)
    (tls / "test.key").unlink()
    os.link(tls / "original.key", tls / "test.key")
    with pytest.raises(NativeTLSMaterialProbeError):
        inspect(fixture)


def test_world_readable_private_key_refused(fixture):
    _, _, tls, _ = fixture
    generate(tls, "test")
    (tls / "test.key").chmod(0o644)
    with pytest.raises(NativeTLSMaterialProbeError, match="FILE_UNTRUSTED"):
        inspect(fixture)


def test_tls_parent_symlink_refused(fixture):
    _, root, tls, _ = fixture
    generate(tls, "test")
    tls.rename(root / "etc/repocache/tls-old")
    (root / "etc/repocache/tls").symlink_to(root / "etc/repocache/tls-old")
    with pytest.raises(NativeTLSMaterialProbeError):
        inspect(fixture)


def test_unsupported_external_key_path_rejected(fixture):
    _, _, tls, doc = fixture
    generate(tls, "test")
    doc["deployment"]["tls"]["private_key_file"] = "/home/outside.key"
    with pytest.raises(NativeTLSMaterialProbeError, match="PATH_UNSUPPORTED"):
        inspect(fixture)


def test_weak_parent_permissions_refused(fixture):
    _, root, tls, _ = fixture
    generate(tls, "test")
    (root / "etc").chmod(0o777)
    with pytest.raises(NativeTLSMaterialProbeError, match="DIRECTORY_UNTRUSTED"):
        inspect(fixture)


@pytest.mark.parametrize("invalid", [None, True, "0", -1])
def test_invalid_owner_uid_refused(fixture, invalid):
    fd, _, _, doc = fixture
    with pytest.raises(NativeTLSMaterialProbeError, match="ARGUMENT_INVALID"):
        inspect_native_tls_pair_under_root(
            fd, owner_uid=invalid, document=doc,
        )
