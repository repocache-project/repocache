"""HTTPS listener intent must not accept non-unicast IP aliases."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_install_v1 import InstallInputError, validate_install_document
from repocache.server_native_firewall_intent_v1 import (
    NativeFirewallIntentError, preview_native_firewall_intent,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


@pytest.mark.parametrize("bad", [
    "224.0.0.1", "239.255.255.250", "ff02::1", "ff0e::1",
    "::ffff:c000:201", "::ffff:7f00:1",
])
def test_nonunicast_tls_address_refused_at_install_input_before_intent(bad):
    doc = json.loads(EXAMPLE.read_text())
    doc["deployment"]["listen"]["bind_address"] = bad
    original = copy.deepcopy(doc)
    with pytest.raises(InstallInputError, match="unsafe bind IP"):
        validate_install_document(doc, for_apply=True)
    with pytest.raises(NativeFirewallIntentError,
                       match="^FIREWALL_DOCUMENT_INVALID$"):
        preview_native_firewall_intent(doc, distribution="debian13")
    assert doc == original


@pytest.mark.parametrize("good", [
    "127.0.0.1", "::1", "0.0.0.0", "::", "192.0.2.15",
    "2001:db8::15",
])
def test_unicast_and_explicit_wildcard_review_compatibility(good):
    doc = json.loads(EXAMPLE.read_text())
    doc["deployment"]["listen"]["bind_address"] = good
    assert validate_install_document(doc, for_apply=True) == doc
    result = preview_native_firewall_intent(
        doc, distribution="almalinux10",
    )
    assert result["listen_address"] == good
    assert not result["authorizes_firewall_change"]
