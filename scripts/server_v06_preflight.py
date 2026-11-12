#!/usr/bin/env python3
"""Read-only v0.6.0 server preflight; no installation authority (#26).

No filesystem writes, package transactions, subprocesses, network I/O or
service activation. Source must be independently authenticated before use.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from repocache.server_host_checks_v1 import inspect_deployment_host
from repocache.server_install_v1 import MAX_DOCUMENT_BYTES, parse_install_bytes
from repocache.server_preflight_guidance_v1 import explain_native_preflight


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError("INVALID_ARGUMENT")


def read_document(path: str) -> dict:
    """Read only a stable, single-link, absolute regular JSON document."""
    if (type(path) is not str or not path.startswith("/") or "\x00" in path
            or any(part == ".." for part in path.split("/"))):
        raise ValueError("INVALID_DOCUMENT")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_DOCUMENT_BYTES):
            raise ValueError("INVALID_DOCUMENT")
        raw = os.read(fd, MAX_DOCUMENT_BYTES + 1)
        after = os.fstat(fd)
        if (len(raw) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns) !=
                   (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("INVALID_DOCUMENT")
    finally:
        os.close(fd)
    return parse_install_bytes(raw, for_apply=False)


def run(argv: list[str] | None = None) -> int:
    parser = SafeParser(description="Partial read-only server preflight; never install")
    parser.add_argument("--document", required=True, help="Absolute install-v1 JSON file")
    parser.add_argument("--intent", choices=("inspect", "install"),
                        default="inspect", help="Diagnostic intent only")
    try:
        args = parser.parse_args(argv)
        document = read_document(args.document)
        report = inspect_deployment_host(document, intent=args.intent)
        result = {
            "schema_version": 1,
            "kind": "repocache.server.vm-preflight.partial",
            "status": "FAIL" if report.has_failures else "NOT VERIFIED",
            "read_only": True,
            "authorizes_installation": False,
            "checks": list(explain_native_preflight(report)),
        }
        code = 1 if report.has_failures else 3
    except (OSError, ValueError, TypeError, UnicodeError):
        result = {
            "schema_version": 1,
            "kind": "repocache.server.vm-preflight.partial",
            "status": "FAIL",
            "read_only": True,
            "authorizes_installation": False,
            "error": {"code": "INVALID_INPUT_OR_HOST_OBSERVATION"},
        }
        code = 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(run())
