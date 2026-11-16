"""Live / cannot be used as a fixture root for TLS material inspection."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from repocache.server_native_tls_material_probe_v1 import (
    NativeTLSMaterialProbeError, inspect_native_tls_pair_under_root,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def test_live_root_fd_is_refused_even_with_no_tls_certificate_files():
    doc = json.loads(EXAMPLE.read_text())
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(
            NativeTLSMaterialProbeError,
            match="^TLS_MATERIAL_LIVE_ROOT_FORBIDDEN$",
        ):
            inspect_native_tls_pair_under_root(
                fd, owner_uid=os.geteuid(), document=doc,
            )
    finally:
        os.close(fd)


def test_live_root_refusal_precedes_private_key_directory_walk(monkeypatch):
    import repocache.server_native_tls_material_probe_v1 as mod
    doc = json.loads(EXAMPLE.read_text())
    monkeypatch.setattr(
        mod, "_directory",
        lambda *_a: pytest.fail("should not inspect live TLS tree"),
    )
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(
            NativeTLSMaterialProbeError,
            match="^TLS_MATERIAL_LIVE_ROOT_FORBIDDEN$",
        ):
            inspect_native_tls_pair_under_root(
                fd, owner_uid=os.geteuid(), document=doc,
            )
    finally:
        os.close(fd)
