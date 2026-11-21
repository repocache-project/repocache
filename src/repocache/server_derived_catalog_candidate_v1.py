"""Pure active-only client catalog *candidate* for approved repository routes.

The authoritative catalog must be derived from the protected repository
configuration after NGINX activation and independent exposure verification.
This module checks a CLOSED, test-supplied full nginx -T dump against the
exact deterministic pinned repository fragments, but cannot authenticate
the dump, operator, host, TLS runtime, NGINX master or cache. It NEVER writes
a file, grants root privileges, or returns a publication authorization.
"""
from __future__ import annotations

import json
import re
from typing import Any

from repocache.server_install_v1 import validate_install_document
from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError, render_repository_nginx_bundle_candidate,
    render_repository_https_server_candidate,
)

_MAX_NGINX_DUMP = 4 * 1024 * 1024
_MAX_CATALOG = 512000
_PREFIX = "/__repocache/repos/"
_REPO_LOC = re.compile(
    r"\s*location\s+\^~\s+/__repocache/repos/([a-z0-9-]+)/\s*\{\s*"
)
_UPSTREAM = re.compile(r"\s*upstream\s+(repocache_pin_[a-z0-9_]+)\s*\{\s*")


class DerivedCatalogCandidateError(ValueError):
    """Fixed, value-redacted refusal only."""


def _deny(code: str) -> None:
    raise DerivedCatalogCandidateError("CATALOG_CANDIDATE_" + code)


def preview_derived_catalog_from_nginx_dump(
    untrusted_document: dict[str, Any], *,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
    nginx_dump_text: str,
    nginx_t_exit_code: int,
) -> dict[str, Any]:
    """Build a client-schema-compatible CANDIDATE after bounded syntax hints.

    `nginx_t_exit_code` and `nginx_dump_text` are UNTRUSTED caller claims;
    this is never evidence of a real running service or its route exposure.
    The future privileged engine must re-read state, run installed nginx -T
    itself under the root lock, prove true routing and only then publish.
    """
    if type(nginx_t_exit_code) is not int or nginx_t_exit_code != 0:
        _deny("NGINX_SYNTAX_NOT_OBSERVED")
    # Do not allocate a proportional encoded copy of an unbounded
    # caller-supplied Python string. A genuine nginx -T text dump must also
    # be valid strict UTF-8, never a surrogate-containing Python surrogatepass
    # fixture that would be impossible to serialize safely as native text.
    if (type(nginx_dump_text) is not str
            or not 1 <= len(nginx_dump_text) <= _MAX_NGINX_DUMP
            or "\x00" in nginx_dump_text or "\r" in nginx_dump_text):
        _deny("NGINX_DUMP_INVALID")
    try:
        dump_bytes = nginx_dump_text.encode("utf-8", "strict")
    except UnicodeError:
        _deny("NGINX_DUMP_INVALID")
    if len(dump_bytes) > _MAX_NGINX_DUMP:
        _deny("NGINX_DUMP_INVALID")
    try:
        document = validate_install_document(untrusted_document, for_apply=True)
        candidate = render_repository_nginx_bundle_candidate(
            document,
            expected_state_generation=document["expected_state_generation"],
            candidate_pins_by_repository=candidate_pins_by_repository,
            ca_bundle_path=ca_bundle_path,
        )
    except (ValueError, TypeError, RecursionError, NginxRepositoryBundleError):
        _deny("RENDER_INVALID")
    if (candidate.get("status") != "MULTI_REPOSITORY_RENDER_CANDIDATE_ONLY"
            or candidate.get("authorizes_catalog_publication") is not False
            or candidate.get("authorizes_nginx_activation") is not False):
        _deny("RENDER_INVALID")
    active_ids = candidate["proposed_repository_ids"]
    http, server = (candidate["http_upstream_fragment"],
                    candidate["server_location_fragment"])
    if (http and nginx_dump_text.count(http) != 1
            or server and nginx_dump_text.count(server) != 1):
        _deny("MANAGED_FRAGMENT_MISSING_OR_AMBIGUOUS")

    routes: list[str] = []
    upstream_names: list[str] = []
    for line in nginx_dump_text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        # nginx -T accepts whitespace (including newlines) between tokens
        # in a location/upstream header. A foreign multi-line definition
        # could previously evade this line-oriented exact-route inventory,
        # making an inactive route appear absent. Fail closed on any split
        # header rather than trying to infer multi-line grammar or claim a
        # trusted host configuration from a caller-supplied dump.
        if re.match(r"\s*(?:location|upstream)\b", line) and "{" not in line:
            _deny("SPLIT_DIRECTIVE_UNVERIFIED")
        if re.match(r"\s*location\b", line) and _PREFIX in line:
            match = _REPO_LOC.fullmatch(line)
            if match is None:
                _deny("FOREIGN_REPOSITORY_LOCATION")
            routes.append(match.group(1))
        if re.match(r"\s*upstream\b", line) and "repocache_pin_" in line:
            match = _UPSTREAM.fullmatch(line)
            if match is None:
                _deny("FOREIGN_REPOSITORY_UPSTREAM")
            upstream_names.append(match.group(1))
    if (sorted(routes) != active_ids or len(routes) != len(set(routes))
            or sorted(upstream_names)
               != sorted("repocache_pin_" + n.replace("-", "_")
                         for n in active_ids)):
        _deny("OBSERVED_ROUTE_SET_MISMATCH")

    deployment = document["deployment"]["listen"]
    port = deployment["https_port"]
    origin = ("https://" + deployment["hostname"]
              + ("" if port == 443 else f":{port}"))
    mapped = []
    for repo in document["repositories"]:
        if repo["desired_state"] != "active":
            continue
        identifier = repo["id"]
        mapped.append({
            "upstream": repo["upstream"]["base_url"],
            "cache": origin + _PREFIX + identifier + "/",
        })
    # The shipped client schema rejects duplicate upstream/cache mappings.
    # A valid managed repository identity does not automatically imply a
    # client-unambiguous source URL (APT/DNF may share one origin URL).
    if (len({row["upstream"] for row in mapped}) != len(mapped)
            or len({row["cache"] for row in mapped}) != len(mapped)):
        _deny("CLIENT_MAPPING_AMBIGUOUS")
    mapped.sort(key=lambda item: (item["upstream"], item["cache"]))
    catalog = {"schema": 1, "repositories": mapped}
    if len(json.dumps(catalog, sort_keys=True).encode("utf-8")) > _MAX_CATALOG:
        _deny("CLIENT_CATALOG_TOO_LARGE")
    return {
        "schema_version": 1,
        "status": "INERT_DERIVED_CATALOG_CANDIDATE_ONLY",
        "candidate_catalog": catalog,
        "desired_active_repository_ids": active_ids,
        "inert_nginx_dump_routes_match_candidate": True,
        "root_owned_installed_nginx_verified": False,
        "kernel_operator_authorization_verified": False,
        "actual_active_exposure_verified": False,
        "installed_catalog_publication_verified": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
    }



def preview_derived_https_catalog_from_nginx_dump(
    untrusted_document: dict[str, Any], *,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
    nginx_dump_text: str,
    nginx_t_exit_code: int,
) -> dict[str, Any]:
    """Require exact fully composed HTTPS server context for a catalog hint.

    A route-only nginx -T preview can match active repository locations
    while omitting their HTTPS listener, SNI, key references or whole
    server context. This stronger preview checks the single composed
    server block AND exact named upstreams from the same validated v1
    document. All inputs, including the dump and test exit code, remain
    UNTRUSTED. The result is never permission to publish or activate.
    """
    # Reuse the closed schema, bounds, route set, upstream and client-schema
    # checks, and refuse incomplete byte/text or unsuccessful syntax claims.
    ordinary = preview_derived_catalog_from_nginx_dump(
        untrusted_document,
        candidate_pins_by_repository=candidate_pins_by_repository,
        ca_bundle_path=ca_bundle_path,
        nginx_dump_text=nginx_dump_text,
        nginx_t_exit_code=nginx_t_exit_code,
    )
    try:
        document = validate_install_document(untrusted_document, for_apply=True)
        complete = render_repository_https_server_candidate(
            document,
            expected_state_generation=document["expected_state_generation"],
            candidate_pins_by_repository=candidate_pins_by_repository,
            ca_bundle_path=ca_bundle_path,
        )
    except (ValueError, TypeError, RecursionError, NginxRepositoryBundleError):
        _deny("HTTPS_RENDER_INVALID")
    if (complete.get("status") != "HTTPS_REPOSITORY_SERVER_CANDIDATE_ONLY"
            or complete.get("proposed_repository_ids")
               != ordinary["desired_active_repository_ids"]
            or complete.get("authorizes_nginx_activation") is not False
            or complete.get("authorizes_catalog_publication") is not False
            or complete.get("authorizes_firewall_change") is not False):
        _deny("HTTPS_RENDER_INVALID")

    https_block = complete["server_block_fragment"]
    upstream_blocks = complete["http_context_fragment"]
    # Match the entire block as one contiguous candidate, not isolated
    # TLS/SNI directive strings scattered among foreign server contexts.
    # This still does NOT authenticate an installed nginx -T or running
    # listener and cannot replace a protected, locked root-side recheck.
    if (not https_block
            or nginx_dump_text.count(https_block) != 1
            or (upstream_blocks and nginx_dump_text.count(upstream_blocks) != 1)):
        _deny("HTTPS_SERVER_CONTEXT_MISSING_OR_AMBIGUOUS")
    return {
        **ordinary,
        "status": "INERT_DERIVED_HTTPS_CATALOG_CANDIDATE_ONLY",
        "exact_https_server_context_candidate_matched": True,
        "installed_tls_certificate_verified": False,
        "real_tls_handshake_verified": False,
        "nginx_dump_provenance_authenticated": False,
        "kernel_listener_exposure_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
    }
