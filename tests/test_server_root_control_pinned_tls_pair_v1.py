"""Pinned TLS pair preflight: no arbitrary paths, keys, privileges or reload."""
from __future__ import annotations

import os
import ssl
import subprocess
import stat

import pytest

import repocache.server_root_control_pinned_tls_pair_v1 as gate


def _open_readonly(path):
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)


@pytest.fixture
def synthetic_pair(tmp_path):
    openssl = "/usr/bin/openssl"
    if not os.path.isfile(openssl):
        pytest.skip("native openssl unavailable; distro smoke must still pass")
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    done = subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "1", "-keyout", str(key), "-out", str(cert),
         "-subj", "/CN=synthetic.invalid"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, check=False, timeout=15,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    assert done.returncode == 0
    os.chmod(cert, 0o600)
    os.chmod(key, 0o600)
    return cert, key


def _verify(cert, key):
    c, k = _open_readonly(cert), _open_readonly(key)
    try:
        return gate._inspect_pinned_tls_pair_for_future_transaction(
            c, k, expected_owner_uid=os.geteuid(),
        )
    finally:
        os.close(c)
        os.close(k)


def test_native_pair_load_and_no_authority(synthetic_pair):
    report = _verify(*synthetic_pair)
    assert report["private_key_pair_load_observed"] is True
    assert report["pinned_opened_file_descriptions_observed"] is True
    assert all(report[k] is False for k in report
               if k.startswith("authorizes_") or k.endswith("_verified")
               or k == "native_nginx_reloaded")


@pytest.mark.parametrize("case,code", [
    ("same-fd", "ARGUMENTS_REFUSED"),
    ("bool-fd", "ARGUMENTS_REFUSED"),
    ("bad-uid", "FD_UNTRUSTED"),
    ("cert-world-writable", "FD_UNTRUSTED"),
    ("key-group-readable", "FD_UNTRUSTED"),
    ("cert-hardlink", "FD_UNTRUSTED"),
    ("key-hardlink", "FD_UNTRUSTED"),
    ("writable-key-fd", "FD_UNTRUSTED"),
])
def test_untrusted_pinned_fd_refused(synthetic_pair, tmp_path, case, code):
    cert, key = synthetic_pair
    if case == "cert-world-writable":
        os.chmod(cert, 0o666)
    if case == "key-group-readable":
        os.chmod(key, 0o640)
    if case == "cert-hardlink":
        os.link(cert, tmp_path / "extra-cert")
    if case == "key-hardlink":
        os.link(key, tmp_path / "extra-key")
    c = _open_readonly(cert)
    k = _open_readonly(key)
    if case == "writable-key-fd":
        os.close(k)
        k = os.open(key, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        selected_c = True if case == "bool-fd" else c
        selected_k = c if case == "same-fd" else k
        uid = os.geteuid() + 1 if case == "bad-uid" else os.geteuid()
        with pytest.raises(gate.PinnedTLSPairError, match=code):
            gate._inspect_pinned_tls_pair_for_future_transaction(
                selected_c, selected_k, expected_owner_uid=uid,
            )
    finally:
        os.close(c)
        os.close(k)


@pytest.mark.parametrize("case", ["missing", "mismatched", "invalid"])
def test_real_bad_pair_is_refused_without_secrets(synthetic_pair, tmp_path, case):
    cert, key = synthetic_pair
    if case == "missing":
        key = tmp_path / "absent-key.pem"
        with pytest.raises(OSError):
            _verify(cert, key)
        return
    if case == "invalid":
        key.write_bytes(b"NOT A PEM PRIVATE KEY\n")
    else:
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        openssl = "/usr/bin/openssl"
        result = subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-keyout", str(foreign / "key.pem"),
             "-out", str(foreign / "cert.pem"),
             "-subj", "/CN=foreign.invalid"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15,
        )
        assert result.returncode == 0
        key = foreign / "key.pem"
    os.chmod(key, 0o600)
    with pytest.raises(gate.PinnedTLSPairError,
                       match="CERT_KEY_LOAD_FAILED") as caught:
        _verify(cert, key)
    assert "PRIVATE KEY" not in str(caught.value)


def test_inode_replacement_does_not_change_pinned_pair(synthetic_pair, tmp_path,
                                                      monkeypatch):
    cert, key = synthetic_pair
    old = cert.read_bytes()
    c, k = _open_readonly(cert), _open_readonly(key)
    try:
        real = gate.ssl.SSLContext
        def replace_after_open(protocol):
            staged = tmp_path / "replacement"
            staged.write_bytes(b"BAD-CERT")
            os.replace(staged, cert)
            return real(protocol)
        monkeypatch.setattr(gate.ssl, "SSLContext", replace_after_open)
        # The originally opened FD remains pinned despite path substitution:
        # it is unsafe to assert pathname stability or host provenance here.
        result = gate._inspect_pinned_tls_pair_for_future_transaction(
            c, k, expected_owner_uid=os.geteuid(),
        )
        assert result["private_key_pair_load_observed"] is True
        assert cert.read_bytes() != old
    finally:
        os.close(c)
        os.close(k)


def test_mutation_of_opened_key_during_openssl_refused(synthetic_pair,
                                                      monkeypatch):
    cert, key = synthetic_pair
    c, k = _open_readonly(cert), _open_readonly(key)
    try:
        real = gate.ssl.SSLContext
        def changed_in_place(protocol):
            with open(key, "ab") as f:
                f.write(b"tampered")
            return real(protocol)
        monkeypatch.setattr(gate.ssl, "SSLContext", changed_in_place)
        with pytest.raises(gate.PinnedTLSPairError, match="FILES_CHANGED"):
            gate._inspect_pinned_tls_pair_for_future_transaction(
                c, k, expected_owner_uid=os.geteuid(),
            )
    finally:
        os.close(c)
        os.close(k)


def test_worker_never_dispatches_tls_validator():
    import inspect
    from repocache.server_root_control_worker_v1 import serve_one_fixed_request
    code = inspect.getsource(serve_one_fixed_request)
    assert "_inspect_pinned_tls_pair_for_future_transaction" not in code
    assert "ROOT_TRANSACTION_NOT_IMPLEMENTED" in code
