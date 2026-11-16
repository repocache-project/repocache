"""Encrypted TLS private keys must not trigger an interactive prompt."""
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

_OPENSSL = shutil.which("openssl")
_EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


@pytest.mark.skipif(_OPENSSL is None, reason="OpenSSL binary required")
def test_real_encrypted_key_is_refused_without_terminal_interaction(tmp_path):
    root = tmp_path / "root"
    tls = root / "etc" / "repocache" / "tls"
    tls.mkdir(parents=True)
    tls.chmod(0o700)
    cert = tls / "fixture.crt"
    key = tls / "fixture.key"
    subprocess.run(
        [_OPENSSL, "req", "-x509", "-newkey", "rsa:2048",
         "-passout", "pass:disposable-fixture-only",
         "-days", "1", "-subj", "/CN=cache.example.invalid",
         "-keyout", str(key), "-out", str(cert)],
        check=True, timeout=30, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    cert.chmod(0o644)
    original = cert.read_bytes(), key.read_bytes()
    doc = json.loads(_EXAMPLE.read_text())
    doc["deployment"]["tls"]["certificate_file"] = "/etc/repocache/tls/fixture.crt"
    doc["deployment"]["tls"]["private_key_file"] = "/etc/repocache/tls/fixture.key"
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(
            NativeTLSMaterialProbeError,
            match="^TLS_MATERIAL_TLS_PAIR_OR_INODE_UNVERIFIED$",
        ):
            inspect_native_tls_pair_under_root(
                fd, owner_uid=os.geteuid(), document=doc,
            )
    finally:
        os.close(fd)
    assert (cert.read_bytes(), key.read_bytes()) == original


def test_pinned_context_load_explicitly_disables_prompt():
    source = (Path(__file__).resolve().parents[1] /
              "src/repocache/server_native_tls_material_probe_v1.py").read_text()
    assert "password=b\"\"" in source
    assert "getpass" not in source
    assert "input(" not in source
