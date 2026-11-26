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


# Read back the complete dedicated namespace, not just a named chain. Use
# nft --stateless --numeric-priority list ruleset with no name resolution.
# This closed grammar ignores formatting only, never rule ordering or
# arbitrary statements. The caller independently binds the namespace.
_HEADER = re.compile(
    r'table inet repocache_egress \{ counter "?denied"? \{ \} '
    r'chain output \{ type filter hook output priority (?:0|filter); policy drop; '
    r'meta l4proto (?:tcp|6) ct state established accept '
    r'meta skuid 0 oifname "lo" (ip6?) daddr ([0-9a-f:.]+) '
    r'tcp dport ([0-9]{1,5}) ct state new accept (.*) \} \}',
    re.ASCII,
)
_ALLOW = re.compile(
    r'meta skuid ([0-9]{1,10}) (ip6?) daddr ([0-9a-f:.]+) '
    r'tcp dport ([0-9]{1,5}) ct state new accept ',
    re.ASCII,
)


def _readback_tuple(family: str, address: str, port: str) -> tuple[str, int]:
    value = ipaddress.ip_address(address)
    number = int(port)
    if ((family == "ip") != (value.version == 4)
            or str(value) != address or not 1 <= number <= 65535
            or str(number) != port):
        raise ValueError("noncanonical tuple")
    return address, number


def _closed_ruleset(raw: str) -> tuple:
    if type(raw) is not str or len(raw) > _MAX_FRAGMENT or not raw.isascii():
        raise ValueError("invalid ruleset")
    # No comment stripping, case folding, expression rewriting, omitted
    # chain policy, sets, foreign tables, or reordered rules are accepted.
    flat = " ".join(raw.split())
    parsed = _HEADER.fullmatch(flat)
    if parsed is None:
        raise ValueError("unexpected ruleset shape")
    health = _readback_tuple(*parsed.groups()[:3])
    rest = parsed[4]
    rules = []
    while (match := _ALLOW.match(rest)) is not None:
        uid, family, address, port = match.groups()
        number = int(uid)
        if not 0 < number < 2**31 or str(number) != uid:
            raise ValueError("invalid worker identity")
        rules.append((number, *_readback_tuple(family, address, port)))
        rest = rest[match.end():]
    if (rest not in ('counter name denied reject', 'counter name "denied" reject')
            or len(rules) != len(set(rules))
            or len({uid for uid, _, _ in rules}) > 1):
        raise ValueError("unexpected rule or verdict")
    return health, tuple(rules)


def verify_namespace_egress_readback(expected: str, observed: str) -> dict[str, Any]:
    """Compare a trusted rendered candidate with complete nft readback.

    The expected string must come from the authenticated generation renderer,
    not an operator request. No command is executed here. The observed text
    must be supplied by a separately verified namespace controller using
    the fixed listing command. This proves shape equality only, not kernel
    provenance, namespace exclusivity, packet delivery or durable ownership.
    """
    try:
        if _closed_ruleset(expected) != _closed_ruleset(observed):
            raise ValueError("ruleset differs")
        return {
            "status": "NAMESPACE_EGRESS_RULESET_MATCH",
            "ruleset_shape_matches": True,
            "runtime_egress_verified": False,
            "authorizes_firewall_change": False,
            "authorizes_nginx_activation": False,
        }
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise NativeEgressCandidateError("NATIVE_EGRESS_READBACK_REFUSED") from None
