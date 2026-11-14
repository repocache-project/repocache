"""Explicit DNS refresh planning for automatically rotating approved upstream IPs.

A trusted future scheduler may call this primitive at a bounded interval.
It performs DNS lookups (no HTTP connection) and creates a deterministic
candidate pin set, never a live NGINX configuration or an authorization.

The engine integrating this module must independently enforce:
  * trusted repository approval, protected state, locking, generation and IDs;
  * an actually installed stock NGINX data plane with ONLY pinned literal
    destinations, TLS verification, original Host/SNI, and safe redirects;
  * nginx -t, staged activation, observed exposure, atomic catalog and rollback.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit
from typing import Any, Callable

from repocache.server_bounded_dns_v1 import bounded_getaddrinfo
from repocache.server_install_v1 import ID, MAX_INT, validate_install_document
from repocache.server_upstream_address_preflight_v1 import (
    UpstreamAddressError,
    inspect_upstream_address_snapshot,
)

# A *recommended lower bound* for a future trusted systemd scheduler, not
# a timer or proof of an actual automated activation service.
MIN_REFRESH_INTERVAL_SECONDS = 300
MAX_DNS_RECORDS_PER_HOST = 32


class UpstreamRotationError(ValueError):
    """Refused DNS refresh; errors never include hostnames, IPs or secrets."""


def _checked_pins(
    document: dict[str, Any], repository_id: str,
    answers: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Canonicalize a complete snapshot only after strict safety preflight."""
    try:
        inspect_upstream_address_snapshot(
            document, repository_id=repository_id, answers_by_host=answers,
        )
    except (ValueError, TypeError) as exc:
        raise UpstreamRotationError("DNS pin set: incomplete or unsafe") from None
    return {
        host.lower(): sorted(str(ipaddress.ip_address(ip)) for ip in ips)
        for host, ips in sorted(answers.items())
    }


def propose_automatic_upstream_refresh(
    document: dict[str, Any],
    *,
    repository_id: str,
    current_generation: int,
    previous_pins_by_host: dict[str, list[str]] | None,
    resolver: Callable[..., list[tuple[Any, ...]]] | None = None,
) -> dict[str, Any]:
    """Resolve approved hosts and propose a full, immutable-generation IP set.

    With no injected resolver the DNS lookup uses the existing isolated,
    timeout-bounded child. A blocked libc resolver cannot stall this path.
    Every address returned by getaddrinfo must be globally routable; one
    private/special answer refuses the *whole* refresh. No partial candidate
    or fallback to hostname-based NGINX resolution is emitted on failure.

    previous_pins_by_host is caller-provided, not proof of a trusted ledger.
    Its provenance and current_generation must be checked under the future
    exclusive transaction lock before any real activation.
    """
    if (type(current_generation) is not int
            or not 0 <= current_generation <= MAX_INT):
        raise UpstreamRotationError("generation: invalid")
    if (type(repository_id) is not str or len(repository_id) > 48
            or ID.fullmatch(repository_id) is None):
        raise UpstreamRotationError("repository_id: invalid")

    try:
        validated = validate_install_document(document, for_apply=True)
    except ValueError:
        raise UpstreamRotationError("document: invalid") from None
    if validated["expected_state_generation"] != current_generation:
        raise UpstreamRotationError("generation: stale configuration")

    matches = [
        r for r in validated["repositories"] if r.get("id") == repository_id
    ]
    if len(matches) != 1:
        raise UpstreamRotationError("repository_id: not allocated")
    repo = matches[0]
    if repo["desired_state"] != "active":
        raise UpstreamRotationError("repository: not enabled for refresh")

    allowed_hosts = sorted({host.lower() for host in repo["upstream"]["allowed_hosts"]})
    # Keep the destination port bound to the approved URL; never silently
    # pin port 443 when an explicit non-default HTTPS port was approved.
    port = urlsplit(repo["upstream"]["base_url"]).port or 443
    if previous_pins_by_host is not None:
        previous = _checked_pins(validated, repository_id, previous_pins_by_host)
    else:
        previous = None

    lookup = bounded_getaddrinfo if resolver is None else resolver
    if not callable(lookup):
        raise UpstreamRotationError("resolver: invalid")
    candidate: dict[str, list[str]] = {}
    for host in allowed_hosts:
        try:
            # Use the approved hostname exclusively. Never fetch HTTP or
            # follow a redirect while discovering candidate destinations.
            records = lookup(
                host, port, family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
            )
        except OSError:
            raise UpstreamRotationError("DNS lookup: failed") from None
        if (type(records) is not list
                or not 1 <= len(records) <= MAX_DNS_RECORDS_PER_HOST):
            raise UpstreamRotationError("DNS lookup: incomplete or unbounded")

        addresses: set[str] = set()
        for item in records:
            if (type(item) is not tuple or len(item) != 5
                    or item[0] not in (socket.AF_INET, socket.AF_INET6)
                    or type(item[4]) is not tuple or not item[4]
                    or type(item[4][0]) is not str):
                raise UpstreamRotationError("DNS lookup: unsupported answer")
            sockaddr = item[4]
            family = item[0]
            if (item[1] != socket.SOCK_STREAM
                    or item[2] != socket.IPPROTO_TCP
                    or len(sockaddr) != (2 if family == socket.AF_INET else 4)
                    or type(sockaddr[1]) is not int or sockaddr[1] != port
                    or (family == socket.AF_INET6
                        and (type(sockaddr[2]) is not int or sockaddr[2] != 0
                             or type(sockaddr[3]) is not int or sockaddr[3] != 0))):
                raise UpstreamRotationError("DNS lookup: mismatched socket answer")
            address = sockaddr[0]
            if len(address) > 45:
                raise UpstreamRotationError("DNS lookup: invalid address")
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError:
                raise UpstreamRotationError("DNS lookup: invalid IP address") from None
            if parsed_address.version != (4 if family == socket.AF_INET else 6):
                raise UpstreamRotationError("DNS lookup: address-family mismatch")
            addresses.add(address)
        # Deduplicate getaddrinfo alias/address repetitions before applying
        # the existing strict public-address and full-allowlist checks.
        candidate[host] = sorted(addresses)

    checked = _checked_pins(validated, repository_id, candidate)
    changed = previous is None or checked != previous
    return {
        "schema_version": 1,
        "status": "PIN_REFRESH_CANDIDATE" if changed else "PINS_UNCHANGED",
        "repository_id": repository_id,
        "expected_state_generation": current_generation,
        "candidate_pins_by_host": checked,
        "changed": changed,
        "recommended_min_refresh_seconds": MIN_REFRESH_INTERVAL_SECONDS,
        "requires_staged_nginx_activation": changed,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "trusted_state_provenance_verified": False,
        "runtime_destination_enforcement_verified": False,
        "automatic_scheduler_installed": False,
    }
