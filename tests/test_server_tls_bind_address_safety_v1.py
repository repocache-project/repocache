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


@pytest.mark.parametrize("distribution", ["debian13", "almalinux10"])
@pytest.mark.parametrize("bad", [
    "240.0.0.1", "250.1.2.3", "255.255.255.255",
])
@pytest.mark.parametrize("requested", [False, True])
def test_reserved_ipv4_rejected_at_install_schema_even_without_firewall_intent(
    distribution, bad, requested,
):
    # A document that cannot produce meaningful TCP exposure must fail
    # at the common installation contract, not only in a firewall preview.
    from repocache.server_nginx_tls_listener_candidate_v1 import (
        NativeTLSListenerCandidateError, render_native_tls_listener_candidate,
    )

    document = json.loads(EXAMPLE.read_text())
    document["deployment"]["listen"]["bind_address"] = bad
    document["deployment"]["firewall"]["modify"] = requested
    snapshot = copy.deepcopy(document)

    for for_apply in (False, True):
        with pytest.raises(InstallInputError, match="unsafe bind IP"):
            validate_install_document(document, for_apply=for_apply)
    with pytest.raises(NativeFirewallIntentError,
                       match="^FIREWALL_DOCUMENT_INVALID$"):
        preview_native_firewall_intent(document, distribution=distribution)
    with pytest.raises(NativeTLSListenerCandidateError,
                       match="^NATIVE_TLS_CANDIDATE_INVALID$"):
        render_native_tls_listener_candidate(document)
    assert document == snapshot
