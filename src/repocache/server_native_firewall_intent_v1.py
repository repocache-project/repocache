"""Inert explicit native firewall intent for an operator-provided HTTPS listener.

#30: preview only; this is NOT a firewall management command, permission
grant or evidence of an installed nftables/firewalld policy.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from repocache.server_install_v1 import validate_install_document


class NativeFirewallIntentError(ValueError):
    """Static redacted refusal code."""


def preview_native_firewall_intent(
    document: dict[str, Any], *, distribution: str,
) -> dict[str, Any]:
    """Represent a validated administrator-selected TCP exposure as intent.

    Never synthesize an nft/iptables/firewall-cmd invocation from input. An
    installed worker must separately verify real distro, active backend,
    firewall ownership, current rules, effective listener, explicit operator
    approval and rollback before changing a single rule.
    """
    if type(distribution) is not str or distribution not in (
        "debian13", "almalinux10"
    ):
        raise NativeFirewallIntentError("FIREWALL_DISTRO_UNVERIFIED")
    try:
        validated = validate_install_document(document, for_apply=True)
        deploy = validated["deployment"]
        firewall = deploy.get("firewall", {"modify": False})
        requested = firewall["modify"]
        if type(requested) is not bool:
            raise ValueError("invalid request")
        listen = deploy["listen"]
        address = ipaddress.ip_address(listen["bind_address"])
        port = listen["https_port"]
        if (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError("invalid port")
        # The server install schema already validates a canonical textual
        # literal; repeat the closed semantic checks for this output.
        if (isinstance(address, ipaddress.IPv6Address)
                and address.ipv4_mapped is not None):
            raise ValueError("IPv4-mapped IPv6 listener ambiguous")
        # Class-E and limited-broadcast IPv4 addresses are not a
        # meaningful TCP exposure target for an installed HTTPS listener.
        # A firewall review must not present them as a specific unicast.
        if (isinstance(address, ipaddress.IPv4Address)
                and address.is_reserved):
            raise ValueError("reserved IPv4 listener refused")
        if str(address) != listen["bind_address"]:
            raise ValueError("noncanonical IP")
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise NativeFirewallIntentError("FIREWALL_DOCUMENT_INVALID") from None

    scope = ("loopback" if address.is_loopback else
             "unspecified" if address.is_unspecified else
             "multicast" if address.is_multicast else
             "link_local" if address.is_link_local else
             "specific")
    # There are two independent decisions: requesting a firewall rule and
    # approving NGINX listener exposure. Opting out of firewall changes must
    # NEVER be interpreted as an authenticated deny-by-default policy: an
    # already-open host firewall can expose a wildcard/specific listener.
    # This report cannot authorize either operation or inspect host policy.
    external_listener = scope != "loopback"
    change = requested and external_listener
    return {
        "schema_version": 1,
        "status": ("FIREWALL_REVIEW_ONLY" if change else
                   "NO_FIREWALL_CHANGE_PROPOSED"),
        "explicit_modify_requested": requested,
        "protocol": "tcp",
        "https_port": port,
        "listen_address": str(address),
        "address_family": "ipv4" if address.version == 4 else "ipv6",
        "exposure_scope": scope,
        "firewall_change_review_required": change,
        # Independent of firewall.modify: a public/non-loopback bind needs an
        # explicit host/listener authorization, even when no rule is proposed.
        "network_exposure_review_required": external_listener,
        "network_exposure_verified": False,
        "native_distribution_observed": False,
        "native_firewall_backend_verified": False,
        "current_firewall_rules_verified": False,
        "existing_firewall_ownership_verified": False,
        "effective_listener_verified": False,
        "admin_identity_verified": False,
        "rollback_verified": False,
        "authorizes_firewall_change": False,
        "authorizes_nginx_activation": False,
        "authorizes_package_installation": False,
    }
