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


def generate(tls, name, *, dns_san=False, san_name=None):
    if OPENSSL is None:
        pytest.skip("OpenSSL not present")
    cert = tls / (name + ".crt")
    key = tls / (name + ".key")
    result = subprocess.run([
        OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-keyout", str(key), "-out", str(cert),
        "-subj", "/CN=cache.example.invalid",
    ] + (["-addext", "subjectAltName=DNS:" +
          (san_name if san_name is not None else "cache.example.invalid")]
         if dns_san or san_name is not None else []),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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



def inspect_fixture_identity(fixture, ca_pem):
    fd, _, _, doc = fixture
    return inspect_native_tls_pair_under_root(
        fd, owner_uid=os.geteuid(), document=doc,
        fixture_ca_pem=ca_pem,
    )


def test_real_in_memory_tls_ca_san_and_validity_match_without_network(fixture):
    _, _, tls, _ = fixture
    cert, _ = generate(tls, "test", dns_san=True)
    result = inspect_fixture_identity(fixture, cert.read_bytes())
    assert result["fixture_ca_san_expiry_handshake_verified"] is True
    assert result["fixture_ca_is_installed_trust_anchor"] is False
    assert result["certificate_chain_verified"] is False
    assert result["certificate_hostname_verified"] is False
    assert result["certificate_expiry_verified"] is False
    assert result["authorizes_nginx_reload"] is False
    assert result["authorizes_firewall_change"] is False
    assert inspect(fixture)["fixture_ca_san_expiry_handshake_verified"] is False


def test_real_tls_handshake_refuses_wrong_hostname(fixture):
    _, _, tls, doc = fixture
    cert, _ = generate(tls, "test", dns_san=True)
    doc["deployment"]["listen"]["hostname"] = "wrong.example.invalid"
    with pytest.raises(
        NativeTLSMaterialProbeError,
        match="^TLS_MATERIAL_FIXTURE_IDENTITY_REJECTED$",
    ):
        inspect_fixture_identity(fixture, cert.read_bytes())


def test_real_tls_handshake_refuses_untrusted_fixture_issuer(fixture):
    _, _, tls, _ = fixture
    generate(tls, "test", dns_san=True)
    unrelated_cert, _ = generate(tls, "unrelated", dns_san=True)
    with pytest.raises(
        NativeTLSMaterialProbeError,
        match="^TLS_MATERIAL_FIXTURE_IDENTITY_REJECTED$",
    ):
        inspect_fixture_identity(fixture, unrelated_cert.read_bytes())


def test_common_name_alone_is_not_a_valid_tls_identity(fixture):
    _, _, tls, _ = fixture
    cert, _ = generate(tls, "test")
    with pytest.raises(
        NativeTLSMaterialProbeError,
        match="^TLS_MATERIAL_FIXTURE_IDENTITY_REJECTED$",
    ):
        inspect_fixture_identity(fixture, cert.read_bytes())


@pytest.mark.parametrize("bad_ca", [
    "", "-----BEGIN CERTIFICATE-----", b"", b"invalid-pem", b"x" * 65537,
    True, 1, [],
])
def test_fixture_ca_input_is_bounded_and_strictly_typed_before_host_access(
    fixture, bad_ca, monkeypatch,
):
    from repocache import server_native_tls_material_probe_v1 as tls_probe
    monkeypatch.setattr(
        tls_probe, "_directory",
        lambda *_: pytest.fail("bad CA reached a privileged FD"),
    )
    with pytest.raises(
        NativeTLSMaterialProbeError, match="^TLS_MATERIAL_FIXTURE_CA_INVALID$"
    ):
        inspect_fixture_identity(fixture, bad_ca)


@pytest.mark.parametrize("start_date,end_date", [
    ("20000101000000Z", "20000102000000Z"),
    ("20990101000000Z", "20990102000000Z"),
])
def test_expired_and_future_signed_leafs_refused_by_openssl(
    fixture, tmp_path, start_date, end_date,
):
    if OPENSSL is None:
        pytest.skip("OpenSSL not present")
    _, _, tls, _ = fixture
    ca = tmp_path / "fixture-ca"
    ca.mkdir()
    (ca / "newcerts").mkdir()
    (ca / "index.txt").write_text("", encoding="ascii")
    (ca / "serial").write_text("1000\n", encoding="ascii")
    config = ca / "ca.cnf"
    config.write_text(
        "[ ca ]\n"
        "default_ca = CA_default\n"
        "[ CA_default ]\n"
        "database = index.txt\n"
        "serial = serial\n"
        "new_certs_dir = newcerts\n"
        "private_key = ca.key\n"
        "certificate = ca.crt\n"
        "default_md = sha256\n"
        "policy = policy_any\n"
        "x509_extensions = usr_cert\n"
        "default_days = 1\n"
        "[ policy_any ]\n"
        "commonName = supplied\n"
        "[ usr_cert ]\n"
        "basicConstraints = critical,CA:FALSE\n"
        "subjectAltName = DNS:cache.example.invalid\n",
        encoding="ascii",
    )

    def run(*args):
        subprocess.run(
            [OPENSSL, *map(str, args)], cwd=ca, check=True, timeout=40,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    run(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=Disposable CI Fixture CA",
        "-keyout", "ca.key", "-out", "ca.crt",
    )
    run(
        "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-subj", "/CN=cache.example.invalid",
        "-keyout", tls / "test.key", "-out", "leaf.csr",
    )
    run(
        "ca", "-batch", "-config", "ca.cnf",
        "-startdate", start_date, "-enddate", end_date,
        "-in", "leaf.csr", "-out", tls / "test.crt",
    )
    (tls / "test.key").chmod(0o600)
    (tls / "test.crt").chmod(0o644)
    # Structurally matching cert/key may be expired or not yet valid.
    assert inspect(fixture)["openssl_matching_pair_verified"] is True
    with pytest.raises(
        NativeTLSMaterialProbeError,
        match="^TLS_MATERIAL_FIXTURE_IDENTITY_REJECTED$",
    ):
        inspect_fixture_identity(fixture, (ca / "ca.crt").read_bytes())



@pytest.mark.parametrize("san_name", [
    "cache.example.invalid",
    "CACHE.EXAMPLE.INVALID",
])
def test_exact_dns_san_accepts_case_insensitive_distro_openssl_identity(
    fixture, san_name,
):
    _, _, tls, _ = fixture
    cert, _ = generate(tls, "test", san_name=san_name)
    result = inspect_fixture_identity(fixture, cert.read_bytes())
    assert result["fixture_ca_san_expiry_handshake_verified"] is True
    assert result["fixture_ca_is_installed_trust_anchor"] is False
    assert result["authorizes_nginx_reload"] is False


@pytest.mark.parametrize("san_name", [
    "*.example.invalid",
    "*.EXAMPLE.INVALID",
])
def test_wildcard_dns_san_is_not_an_exact_listener_identity(fixture, san_name):
    """OpenSSL hostname matching permits wildcards, fixture policy does not."""
    _, _, tls, _ = fixture
    cert, _ = generate(tls, "test", san_name=san_name)
    assert inspect(fixture)["openssl_matching_pair_verified"] is True
    with pytest.raises(
        NativeTLSMaterialProbeError,
        match="^TLS_MATERIAL_FIXTURE_IDENTITY_REJECTED$",
    ):
        inspect_fixture_identity(fixture, cert.read_bytes())
