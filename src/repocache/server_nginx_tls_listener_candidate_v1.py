"""Non-activating TLS listener candidate from validated install-v1 config (#30).

No certificate/key bytes are read. TLS credentials and host firewall remain
exclusively operator-owned; merely rendering does not prove certificate
provenance, installed NGINX access or permission to expose a network port.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from repocache.server_install_v1 import validate_install_document

_SAFE_FILE = re.compile(r"/[A-Za-z0-9_./+-]+\Z", re.ASCII)
_MAX_BYTES = 4096


class NativeTLSListenerCandidateError(ValueError):
    """Static code refusal with no leaked file names or host details."""


def render_native_tls_listener_candidate(document: dict[str, Any]
                                        ) -> dict[str, Any]:
    """Render only fixed server-context HTTPS directives, with no I/O."""
    try:
        validated = validate_install_document(document, for_apply=True)
        listen = validated["deployment"]["listen"]
        tls = validated["deployment"]["tls"]
        if tls["mode"] != "operator-provided":
            raise ValueError("unsupported TLS mode")
        addr = ipaddress.ip_address(listen["bind_address"])
        hostname = listen["hostname"]
        port = listen["https_port"]
        cert, key = tls["certificate_file"], tls["private_key_file"]
        if (type(cert) is not str or type(key) is not str
                or cert == key or _SAFE_FILE.fullmatch(cert) is None
                or _SAFE_FILE.fullmatch(key) is None
                or not hostname.isascii()):
            raise ValueError("unsafe NGINX SSL directive token")
        address = f"[{addr}]" if addr.version == 6 else str(addr)
        fragment = (
            f"listen {address}:{port} ssl;\n"
            f"server_name {hostname};\n"
            # HTTP Host (or :authority) must match the authenticated
            # candidate DNS name, even on a shared IP/default server.
            # This rejects cross-vhost requests before any repo location.
            f"if ($host != {hostname}) {{ return 421; }}\n"
            f"ssl_certificate {cert};\n"
            f"ssl_certificate_key {key};\n"
            "ssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_session_tickets off;\n"
            "server_tokens off;\n"
        )
        if len(fragment.encode("ascii")) > _MAX_BYTES:
            raise ValueError("candidate too large")
    except (ValueError, TypeError, RecursionError, OverflowError, KeyError):
        raise NativeTLSListenerCandidateError("NATIVE_TLS_CANDIDATE_INVALID") from None

    return {
        "schema_version": 1,
        "status": "NATIVE_TLS_LISTENER_CANDIDATE_ONLY",
        "server_context_fragment": fragment,
        "operator_key_bytes_read": False,
        "certificate_chain_verified": False,
        "key_pair_verified": False,
        "hostname_authority_verified": False,
        "installed_nginx_access_verified": False,
        "firewall_mutation_requested": validated["deployment"].get(
            "firewall", {"modify": False})["modify"],
        "authorizes_firewall_change": False,
        "authorizes_nginx_activation": False,
    }
