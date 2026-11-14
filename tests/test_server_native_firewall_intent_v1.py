"""Native HTTPS firewall intent is opt-in, inert, strict and fail-closed."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from repocache.server_native_firewall_intent_v1 import (
    NativeFirewallIntentError, preview_native_firewall_intent,
)

EXAMPLE = (Path(__file__).resolve().parents[1] /
           "docs/examples/server-install-v1.json")


def document(*, modify=None, address="127.0.0.1", port=443):
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    doc["deployment"]["listen"]["bind_address"] = address
    doc["deployment"]["listen"]["https_port"] = port
    if modify is None:
        doc["deployment"].pop("firewall", None)
    else:
        doc["deployment"]["firewall"] = {"modify": modify}
    return doc


@pytest.mark.parametrize("distro", ["debian13", "almalinux10"])
def test_omitted_and_false_firewall_never_open_ports(distro):
    for value in (None, False):
        data = document(modify=value, address="0.0.0.0", port=8443)
        before = deepcopy(data)
        report = preview_native_firewall_intent(data, distribution=distro)
        assert data == before
        assert report["status"] == "NO_FIREWALL_CHANGE_PROPOSED"
        assert report["https_port"] == 8443
        assert report["exposure_scope"] == "unspecified"
        assert report["firewall_change_review_required"] is False
        assert report["explicit_modify_requested"] is False
        assert not report["authorizes_firewall_change"]


@pytest.mark.parametrize("distro", ["debian13", "almalinux10"])
@pytest.mark.parametrize("address,scope,family,change", [
    ("127.0.0.1", "loopback", "ipv4", False),
    ("::1", "loopback", "ipv6", False),
    ("0.0.0.0", "unspecified", "ipv4", True),
    ("::", "unspecified", "ipv6", True),
    ("192.0.2.15", "specific", "ipv4", True),
    ("2001:db8::15", "specific", "ipv6", True),
    ("fe80::1", "link_local", "ipv6", True),
])
def test_explicit_request_is_only_review_not_permission(
    distro, address, scope, family, change,
):
    report = preview_native_firewall_intent(
        document(modify=True, address=address), distribution=distro,
    )
    assert report["exposure_scope"] == scope
    assert report["address_family"] == family
    assert report["protocol"] == "tcp"
    assert report["firewall_change_review_required"] is change
    assert report["status"] == (
        "FIREWALL_REVIEW_ONLY" if change else "NO_FIREWALL_CHANGE_PROPOSED"
    )
    for name in (
        "native_distribution_observed", "native_firewall_backend_verified",
        "current_firewall_rules_verified", "existing_firewall_ownership_verified",
        "effective_listener_verified", "admin_identity_verified",
        "rollback_verified", "authorizes_firewall_change",
        "authorizes_nginx_activation", "authorizes_package_installation",
    ):
        assert report[name] is False


@pytest.mark.parametrize("bad", ["debian", "debian12", "almalinux9", "",
                                  "ubuntu", None, True, 2])
def test_unknown_or_forged_platform_refused(bad):
    with pytest.raises(NativeFirewallIntentError,
                       match="FIREWALL_DISTRO_UNVERIFIED"):
        preview_native_firewall_intent(document(), distribution=bad)


@pytest.mark.parametrize("bad", [0, 1, "true", [], {}])
def test_untyped_firewall_input_refused(bad):
    with pytest.raises(NativeFirewallIntentError,
                       match="FIREWALL_DOCUMENT_INVALID"):
        preview_native_firewall_intent(
            document(modify=bad), distribution="debian13",
        )


@pytest.mark.parametrize("address", ["192.168.001.1", "localhost", "bad;rule",
                                    "[::1]", "", "::ffff:192.0.2.1"])
def test_noncanonical_or_injected_listen_refused(address):
    with pytest.raises(NativeFirewallIntentError,
                       match="FIREWALL_DOCUMENT_INVALID"):
        preview_native_firewall_intent(
            document(modify=True, address=address), distribution="almalinux10",
        )


@pytest.mark.parametrize("port", [-1, 0, 65536, True, "443", 1.0])
def test_invalid_port_refused(port):
    with pytest.raises(NativeFirewallIntentError,
                       match="FIREWALL_DOCUMENT_INVALID"):
        preview_native_firewall_intent(
            document(modify=True, port=port), distribution="debian13",
        )


def test_only_semantic_data_no_shell_or_firewall_effect():
    source = (Path(__file__).resolve().parents[1] /
              "src/repocache/server_native_firewall_intent_v1.py"
              ).read_text(encoding="utf-8")
    for forbidden in ("subprocess", "os.system(", "socket.socket(",
                      "os.open(", "os.unlink(", "os.chmod(", "shell=True",
                      "firewall-cmd --", "nft add rule", "iptables -A"):
        assert forbidden not in source
    assert "authorizes_firewall_change" in source
