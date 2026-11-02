"""Deterministic, non-activating NGINX pin *fragments* for issue #28.

The upstream block belongs in the managed http{} context and the two
location blocks belong in its dedicated server{} context. These fragments
are NOT a complete server configuration and MUST NOT be installed or
advertised until the protected transaction, native capability and
ownership gates have passed. No hostname-based runtime resolution.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from repocache.server_install_v1 import ID, _path, validate_install_document
from repocache.server_upstream_address_preflight_v1 import (
    inspect_upstream_address_snapshot,
)


class PinnedNginxError(ValueError):
    """Unsafe render intent; error text never includes untrusted values."""


def render_pinned_upstream_fragments(
    document: dict[str, Any],
    *,
    repository_id: str,
    candidate_pins_by_host: dict[str, list[str]],
    ca_bundle_path: str,
) -> dict[str, Any]:
    """Build minimal stock-NGINX HTTP/server fragments without I/O.

    Caller supplied IPs and repository state are NOT authenticated. Rendering
    is not proof of trustworthy DNS answers, safe activation or real traffic.
    """
    if (type(repository_id) is not str or len(repository_id) > 48
            or ID.fullmatch(repository_id) is None):
        raise PinnedNginxError("repository_id: invalid")
    try:
        doc = validate_install_document(document, for_apply=True)
        if type(ca_bundle_path) is not str or len(ca_bundle_path) > 2048:
            raise PinnedNginxError("CA reference: invalid")
        _path(ca_bundle_path, "CA reference")
        # NGINX directives are not shell commands: semicolons, quotes and
        # whitespace still permit configuration injection if not rejected.
        if re.fullmatch(r"/[A-Za-z0-9_./+-]+", ca_bundle_path, re.ASCII) is None:
            raise PinnedNginxError("CA reference: unsafe syntax")
        inspect_upstream_address_snapshot(
            doc, repository_id=repository_id,
            answers_by_host=candidate_pins_by_host,
        )
    except (ValueError, TypeError):
        raise PinnedNginxError("render: invalid repository, CA or pin set") from None

    matches = [r for r in doc["repositories"] if r.get("id") == repository_id]
    if len(matches) != 1 or matches[0]["desired_state"] != "active":
        raise PinnedNginxError("repository: not active or unallocated")

    repo = matches[0]
    try:
        upstream_url = urlsplit(repo["upstream"]["base_url"])
        hostname = upstream_url.hostname
        # The closed input validator rejects URL userinfo, non-HTTPS,
        # encoded syntax, omitted canonical slash, and unauthorized hosts.
        if (not hostname or upstream_url.scheme != "https"
                or hostname not in repo["upstream"]["allowed_hosts"]):
            raise ValueError("invalid origin")
        if re.fullmatch(r"/[A-Za-z0-9_./+-]*", upstream_url.path, re.ASCII) is None:
            raise ValueError("NGINX-unsafe origin path")
        ip_set = candidate_pins_by_host[hostname]
        addresses = sorted(
            {ipaddress.ip_address(raw) for raw in ip_set},
            key=lambda ip: (ip.version, int(ip)),
        )
    except (KeyError, TypeError, ValueError):
        raise PinnedNginxError("render: upstream address mismatch") from None

    group = f"repocache_pin_{repository_id.replace('-', '_')}"
    route = f"/__repocache/repos/{repository_id}/"
    reject_name = f"@repocache_redirect_denied_{repository_id.replace('-', '_')}"
    # No variables, interpolation or URL-supplied NGINX syntax are accepted.
    upstream = [f"upstream {group} {{"]
    for ip in addresses:
        numeric = f"[{ip}]" if ip.version == 6 else str(ip)
        upstream.append(f"    server {numeric}:443;")
    upstream.append("}")

    location = [
        f"location ^~ {route} {{",
        "    limit_except GET HEAD { deny all; }",
        f"    proxy_pass https://{group}{upstream_url.path};",
        f"    proxy_set_header Host {hostname};",
        f"    proxy_ssl_name {hostname};",
        "    proxy_ssl_server_name on;",
        "    proxy_ssl_verify on;",
        "    proxy_ssl_verify_depth 3;",
        f"    proxy_ssl_trusted_certificate {ca_bundle_path};",
        "    proxy_redirect off;",
        # Do not forward a redirect response to a package manager which
        # could follow it to an unapproved host, bypassing this proxy.
        "    proxy_intercept_errors on;",
        f"    error_page 301 302 303 307 308 =502 {reject_name};",
        "    proxy_connect_timeout 10s;",
        "    proxy_read_timeout 60s;",
        "}",
        f"location {reject_name} {{",
        "    internal;",
        "    return 502;",
        "}",
    ]
    return {
        "schema_version": 1,
        "status": "RENDER_CANDIDATE_ONLY",
        "repository_id": repository_id,
        "http_upstream_fragment": "\n".join(upstream) + "\n",
        "server_location_fragment": "\n".join(location) + "\n",
        "pin_count": len(addresses),
        "requires_nginx_t_and_activation": True,
        "trusted_state_provenance_verified": False,
        "runtime_destination_enforcement_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
    }
