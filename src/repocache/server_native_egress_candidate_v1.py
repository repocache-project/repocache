"""Candidate-only, generation-bound egress for the dedicated NGINX service.

The existing WAL authenticates exact configuration/include bytes, not kernel
rules. Reconstruct the exact origin tuples from the canonical upstream
fragment rather than persist another operator-editable allowlist. Never
resolve DNS during recovery. This module performs no I/O, activates no
service, grants no authority and does not prove a namespace or policy loaded.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from repocache.server_install_v1 import MAX_INT, validate_install_document
from repocache.server_nginx_pin_render_v1 import render_pinned_upstream_fragments


class NativeEgressCandidateError(ValueError):
    """Redacted invalid candidate; never echo caller-controlled data."""


_TABLE = "repocache_egress"
_MAX_FRAGMENT = 1024 * 1024
_ROW = re.compile(r"    server (?:([0-9.]+)|\[([0-9a-f:]+)\]):([0-9]{1,5});\n", re.ASCII)


def derive_pinned_egress_candidate(
    document: dict[str, Any], *, generation: int, http_fragment: bytes,
) -> dict[str, Any]:
    """Recover only canonical numeric origin tuples, including shared pins.

    Additional allowed DNS hosts do not become connect permissions: the
    stock renderer only emits the base URL's pins. Re-render the exact
    upstream/cache fragment with the selected origin's validated addresses.
    This verifies structure and destination safety, not original DNS
    provenance. The caller must authenticate the containing WAL resources.
    """
    try:
        if (type(generation) is not int or not 1 <= generation <= MAX_INT
                or type(http_fragment) is not bytes
                or len(http_fragment) > _MAX_FRAGMENT):
            raise ValueError("invalid input")
        doc = validate_install_document(document, for_apply=True)
        if doc["expected_state_generation"] != generation:
            raise ValueError("stale generation")
        active = sorted(
            (repo for repo in doc["repositories"] if repo["desired_state"] == "active"),
            key=lambda repo: repo["id"],
        )
        lines = http_fragment.decode("ascii").splitlines(keepends=True)
        index = 0
        all_destinations = set()
        by_repository = {}
        for repo in active:
            start = index
            rid = repo["id"]
            # The exact proxy_cache_path line is checked by re-rendering.
            if (index + 2 >= len(lines)
                    or not lines[index].startswith("proxy_cache_path ")
                    or lines[index + 1] !=
                        f"upstream repocache_pin_{rid.replace('-', '_')} {{\n"):
                raise ValueError("upstream group missing")
            index += 2
            origin = urlsplit(repo["upstream"]["base_url"])
            hostname, port = origin.hostname, origin.port or 443
            addresses = []
            while index < len(lines) and lines[index] != "}\n":
                match = _ROW.fullmatch(lines[index])
                if match is None or int(match[3]) != port or len(addresses) >= 32:
                    raise ValueError("invalid origin tuple")
                address = ipaddress.ip_address(match[1] or match[2])
                addresses.append(str(address))
                index += 1
            if index >= len(lines) or not addresses:
                raise ValueError("unterminated or empty upstream")
            index += 1
            # Retain all validated repository/cache properties. The base URL
            # is the only host rendered into the numeric upstream group.
            scoped = {**doc, "repositories": [
                {**repo, "upstream": {**repo["upstream"], "allowed_hosts": [hostname]}}
            ]}
            rendered = render_pinned_upstream_fragments(
                scoped, repository_id=rid,
                candidate_pins_by_host={hostname: addresses},
                # This argument affects only the unused location fragment.
                ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
            )
            if rendered["http_upstream_fragment"] != "".join(lines[start:index]):
                raise ValueError("noncanonical upstream fragment")
            endpoints = tuple((address, port) for address in addresses)
            by_repository[rid] = endpoints
            all_destinations.update(endpoints)
        if index != len(lines):
            raise ValueError("extra upstream fragment")
        return {
            "generation": generation,
            "http_sha256": hashlib.sha256(http_fragment).hexdigest(),
            "repository_destinations": by_repository,
            "destinations": tuple(sorted(
                all_destinations,
                key=lambda endpoint: (ipaddress.ip_address(endpoint[0]).version,
                                      int(ipaddress.ip_address(endpoint[0])), endpoint[1]),
            )),
            "authorizes_nginx_activation": False,
            "authorizes_firewall_change": False,
            "runtime_egress_verified": False,
        }
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise NativeEgressCandidateError("NATIVE_EGRESS_CANDIDATE_INVALID") from None


def render_namespace_egress_candidate(
    document: dict[str, Any], *, generation: int, http_fragment: bytes, worker_uid: int,
) -> dict[str, Any]:
    """Render one fixed-table candidate for a separately verified private netns.

    Only established TCP replies, exact fresh worker tuples and root's
    local-only health probe are accepted. No related traffic, DNS egress,
    arbitrary root connects, sets of independent addresses/ports, shell
    commands, host firewall operations or namespace creation. The caller
    must verify namespace exclusivity, local listener, worker UID, existing
    table ownership and kernel rule readback before applying any candidate.
    This is not an ingress/routing policy and cannot authorize publication.
    """
    if type(worker_uid) is not int or not 0 < worker_uid < 2**31:
        raise NativeEgressCandidateError("NATIVE_EGRESS_WORKER_UID_INVALID")
    plan = derive_pinned_egress_candidate(
        document, generation=generation, http_fragment=http_fragment,
    )
    listen = validate_install_document(document, for_apply=True)["deployment"]["listen"]
    address = ipaddress.ip_address(listen["bind_address"])
    family = "ip" if address.version == 4 else "ip6"
    port = listen["https_port"]
    lines = [
        f"table inet {_TABLE} {{",
        "    counter denied { }",
        "    chain output {",
        "        type filter hook output priority 0; policy drop;",
        "        meta l4proto tcp ct state established accept",
        f'        meta skuid 0 oifname "lo" {family} daddr {address} tcp dport {port} ct state new accept',
    ]
    for raw, port in plan["destinations"]:
        family = "ip" if ipaddress.ip_address(raw).version == 4 else "ip6"
        lines.append(
            f"        meta skuid {worker_uid} {family} daddr {raw} tcp dport {port} ct state new accept"
        )
    lines.extend(("        counter name denied reject", "    }", "}"))
    return {**plan, "nft_candidate": "\n".join(lines) + "\n"}
