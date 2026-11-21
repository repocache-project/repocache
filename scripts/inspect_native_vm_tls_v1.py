#!/usr/bin/env python3
"""Read-only, loopback-only HTTPS identity observation for issue #30.

This probe cannot authorize native NGINX, firewall or certificate changes.
Only allowlisted status fields reach the one-line operator paste receipt.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys

_HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z", re.ASCII)
_PREFIX = "REPOCACHE_TLS_VM_V1="


def _receipt(code: str, *, tls_version: str | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "issue": 30,
        "status": "PARTIAL_EVIDENCE" if code == "TLS_IDENTITY_OBSERVED" else "NOT_VERIFIED",
        "check_code": code,
        "read_only": True,
        "loopback_only": True,
        "trusted_tls_handshake_observed": code == "TLS_IDENTITY_OBSERVED",
        "exact_dns_san_observed": code == "TLS_IDENTITY_OBSERVED",
        "tls_version": tls_version if code == "TLS_IDENTITY_OBSERVED" else None,
        "operator_ca_provenance_verified": False,
        "installed_nginx_identity_verified": False,
        "private_key_ownership_verified": False,
        "selinux_and_firewall_verified": False,
        "authorizes_nginx_activation": False,
        "authorizes_firewall_change": False,
        "issue_30_accepted": False,
    }


def inspect_tls(*, hostname: str, connect_ip: str, port: int, ca_file: str | None) -> dict[str, object]:
    # All user errors remain fixed codes; neither input nor TLS exception is printed.
    if (type(hostname) is not str or _HOST.fullmatch(hostname) is None
            or type(connect_ip) is not str or type(port) is not int
            or not 1 <= port <= 65535
            or (ca_file is not None and
                (type(ca_file) is not str or not ca_file.startswith("/") or len(ca_file) > 4096))):
        return _receipt("INPUT_REFUSED")
    try:
        # A numeric literal is never a DNS authority for this fixed probe.
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return _receipt("INPUT_REFUSED")
    try:
        address = ipaddress.ip_address(connect_ip)
    except ValueError:
        return _receipt("INPUT_REFUSED")
    if (str(address) != connect_ip or not address.is_loopback
            or isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None):
        return _receipt("NON_LOOPBACK_REFUSED")
    try:
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.hostname_checks_common_name = False
    except (OSError, ValueError, ssl.SSLError):
        return _receipt("TRUST_STORE_UNAVAILABLE")
    try:
        with socket.create_connection((connect_ip, port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as conn:
                version = conn.version()
                if version not in ("TLSv1.2", "TLSv1.3"):
                    return _receipt("TLS_IDENTITY_REFUSED")
                peer = conn.getpeercert()
                sans = peer.get("subjectAltName") if type(peer) is dict else None
                if (type(sans) is not tuple or not any(
                    type(pair) is tuple and len(pair) == 2
                    and pair[0] == "DNS" and type(pair[1]) is str
                    and pair[1].lower() == hostname
                    for pair in sans
                )):
                    return _receipt("TLS_IDENTITY_REFUSED")
                return _receipt("TLS_IDENTITY_OBSERVED", tls_version=version)
    except (OSError, ValueError, ssl.SSLError, TimeoutError):
        return _receipt("TLS_IDENTITY_REFUSED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observe loopback TLS identity; never authorize deployment")
    parser.add_argument("--hostname", required=True, help="Expected DNS SAN and SNI (not included in output)")
    parser.add_argument("--connect-ip", required=True, help="Loopback IP only (not included in output)")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ca-file", help="Optional independently supplied CA PEM path (not included in output)")
    args = parser.parse_args(argv)
    result = inspect_tls(hostname=args.hostname, connect_ip=args.connect_ip,
                         port=args.port, ca_file=args.ca_file)
    print(_PREFIX + json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["check_code"] == "TLS_IDENTITY_OBSERVED" else 2


if __name__ == "__main__":
    sys.exit(main())
