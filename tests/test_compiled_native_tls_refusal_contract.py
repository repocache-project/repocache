"""Adversarial contract for generated native APT/DNF wrong-CA refusal."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/ci_compiled_native_fallback.py"


def _module():
    import sys
    base = str(SCRIPT.parent)
    if base not in sys.path:
        sys.path.insert(0, base)
    spec = importlib.util.spec_from_file_location("ci_compiled_native_fallback", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_nonzero_tls_handshake_refusal_requires_no_accepted_http_requests():
    _module()._assert_compiled_tls_refusal(1, [], [])


@pytest.mark.parametrize("status,cache,upstream", [
    (0, [], []),
    (0, ["GET /metadata"], []),
    (0, [], ["GET /metadata"]),
    (1, ["GET /metadata"], []),
    (1, [], ["GET /metadata"]),
    (1, ["GET /metadata"], ["GET /metadata"]),
    (True, [], []),
    ("1", [], []),
    (None, [], []),
    (1, "GET", []),
    (1, [], "GET"),
])
def test_ambiguous_or_successful_foreign_ca_fetch_is_not_accepted(
    status, cache, upstream,
):
    with pytest.raises(RuntimeError, match="COMPILED_NATIVE_TLS_FOREIGN_CA_NOT_REFUSED"):
        _module()._assert_compiled_tls_refusal(status, cache, upstream)


def test_existing_generated_source_smoke_still_explicitly_avoids_host_install():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "foreign-ca" in source
    assert "ca_certificate=foreign_ca" in source
    assert "sslverify=1" in source
    assert "signed" in source
    assert "native.proposed" in source
    assert "_assert_compiled_tls_refusal" in source
