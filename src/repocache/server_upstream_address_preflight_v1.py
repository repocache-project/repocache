"""No-network preflight for reported upstream addresses (#28).

This validates a caller-supplied DNS answer snapshot ONLY. The caller may be
untrusted and addresses may change before NGINX resolves a name. A passing
result is NEVER a license to render/activate a proxy or publish a catalog.
Real serving additionally requires controlled native DNS resolution,
destination enforcement across reconnects, redirect refusal, TLS/metadata
verification and transactional host activation.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from repocache.server_install_v1 import (
    ID, _host, validate_install_document,
)


class UpstreamAddressError(ValueError):
    """Unsafe or incomplete reported DNS records; no input values in errors."""


def inspect_upstream_address_snapshot(
    document: dict[str, Any],
    *,
    repository_id: str,
    answers_by_host: dict[str, list[str]],
) -> dict[str, Any]:
    """Fail closed on unsafe addresses in one complete, static DNS snapshot.

    The snapshot cannot bind NGINX's eventual DNS answers. No resolver, socket,
    filesystem or process side effect happens here.
    """
    validated = validate_install_document(document, for_apply=True)
    if (type(repository_id) is not str or len(repository_id) > 48\n            or ID.fullmatch(repository_id) is None):
        raise UpstreamAddressError("repository_id: invalid")
    matching = [item for item in validated["repositories"]
                if item.get("id") == repository_id]
    if len(matching) != 1:
        raise UpstreamAddressError("repository_id: unknown or unallocated")

    hosts = {
        _host(name, "upstream.allowed_hosts")
        for name in matching[0]["upstream"]["allowed_hosts"]
    }
    if type(answers_by_host) is not dict or not 1 <= len(answers_by_host) <= 32:
        raise UpstreamAddressError("DNS snapshot: invalid host mapping")
    if len(answers_by_host) != len(hosts):
        raise UpstreamAddressError("DNS snapshot: missing or additional host")
    normalized: dict[str, tuple[str, ...]] = {}
    for name, addresses in answers_by_host.items():
        if type(name) is not str or len(name) > 253:
            raise UpstreamAddressError("DNS snapshot: invalid host")
        try:
            canonical = _host(name, "DNS host")
        except ValueError:
            raise UpstreamAddressError("DNS snapshot: invalid host") from None
        if canonical not in hosts or canonical in normalized:
            raise UpstreamAddressError("DNS snapshot: unexpected or duplicate host")
        if type(addresses) is not list or not 1 <= len(addresses) <= 32:
            raise UpstreamAddressError("DNS snapshot: missing or unbounded addresses")
        checked: set[str] = set()
        for value in addresses:
            if (type(value) is not str or not value.isascii()
                    or not 1 <= len(value) <= 45 or "%" in value):
                raise UpstreamAddressError("DNS snapshot: invalid IP address")
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                raise UpstreamAddressError("DNS snapshot: invalid IP address") from None
            # Deny all special-purpose destinations; also deny IPv4-mapped
            # IPv6 regardless of the mapped IPv4's apparent global status.
            if (not address.is_global or address.is_multicast or address.is_reserved
                    or (isinstance(address, ipaddress.IPv6Address)
                        and (address.ipv4_mapped is not None
                             or address.scope_id is not None))):
                raise UpstreamAddressError("DNS snapshot: non-global IP address")
            normalized_ip = str(address)
            if normalized_ip in checked:
                raise UpstreamAddressError("DNS snapshot: duplicate IP address")
            checked.add(normalized_ip)
        normalized[canonical] = tuple(sorted(checked))
    if set(normalized) != hosts:
        raise UpstreamAddressError("DNS snapshot: host mismatch")

    return {
        "schema_version": 1,
        "status": "STATIC_PREFLIGHT_ONLY",
        "repository_id": repository_id,
        "checked_hosts": len(hosts),
        "checked_addresses": sum(map(len, normalized.values())),
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "runtime_dns_binding_verified": False,
    }
