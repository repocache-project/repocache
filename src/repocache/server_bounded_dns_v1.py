"""Bounded, single-purpose DNS A/AAAA lookup for candidate pin refresh (#28).

This module is a resolver, NOT an authorization or service. DNS is performed
in a short-lived isolated Python interpreter; a blocked libc getaddrinfo
cannot stall an operator/control loop indefinitely. Never invoke as root
network authority or treat the answers as approval provenance.
"""
from __future__ import annotations

import builtins
import json
import math
import os
import socket
import subprocess
import sys
from typing import Any

# An immutable child program avoids hostnames as code, shell parsing, and
# importing application modules in the resolver process.
_WORKER = """
import json, socket, sys
try:
    records = socket.getaddrinfo(
        sys.argv[1], int(sys.argv[2]),
        family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    if not 1 <= len(records) <= 32:
        sys.exit(2)
    print(json.dumps([[int(f), int(t), int(p), c, list(a)]
                      for f, t, p, c, a in records],
                     separators=(",", ":")))
except (OSError, ValueError, TypeError):
    sys.exit(3)
"""
MAX_DNS_SECONDS = 15.0
DEFAULT_DNS_SECONDS = 8.0
_MAX_REPLY_BYTES = 16384
_MAX_RECORDS = 32


def bounded_getaddrinfo(
    host: str, port: int, *,
    family: int, type: int, proto: int,
    timeout_seconds: float = DEFAULT_DNS_SECONDS,
    run_as_uid: int | None = None,
    run_as_gid: int | None = None,
) -> list[tuple[Any, ...]]:
    """Resolve in a killable process; report only redacted socket errors.

    The *existing* candidate planner must still validate the complete set:
    this function is NOT an address policy, port grant, or protected-state
    capability. It intentionally does not make HTTP requests or write files.
    """
    if (builtins.type(host) is not str or not 1 <= len(host) <= 253
            or not host.isascii() or any(ord(x) < 33 or ord(x) > 126 for x in host)
            or builtins.type(port) is not int or not 1 <= port <= 65535
            or family != socket.AF_UNSPEC or type != socket.SOCK_STREAM
            or proto != socket.IPPROTO_TCP
            or builtins.type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= MAX_DNS_SECONDS
            or not os.path.isabs(sys.executable)):
        raise socket.gaierror("DNS worker: invalid request")
    # The native root worker must never run name resolution with its own
    # credentials. Explicit client-requested numeric identities are not
    # authority: this API only supports a *downward* privilege transition
    # from an already-root process, never a root-target child.
    if (run_as_uid is None) != (run_as_gid is None):
        raise socket.gaierror("DNS worker: invalid identity")
    child_identity: dict[str, Any] = {}
    if run_as_uid is not None:
        if (builtins.type(run_as_uid) is not int
                or builtins.type(run_as_gid) is not int
                or not 1 <= run_as_uid <= 2**32 - 2
                or not 1 <= run_as_gid <= 2**32 - 2
                or os.geteuid() != 0):
            raise socket.gaierror("DNS worker: invalid identity")
        child_identity = {
            "user": run_as_uid,
            "group": run_as_gid,
            "extra_groups": [],
        }
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", _WORKER, host, str(port)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            close_fds=True,
            start_new_session=True,
            **child_identity,
        )
        if (completed.returncode != 0 or builtins.type(completed.stdout) is not bytes
                or not 2 <= len(completed.stdout) <= _MAX_REPLY_BYTES):
            raise ValueError("invalid resolver exit or response")
        raw = json.loads(completed.stdout)
        if builtins.type(raw) is not list or not 1 <= len(raw) <= _MAX_RECORDS:
            raise ValueError("invalid record count")
        answer: list[tuple[Any, ...]] = []
        for record in raw:
            if (builtins.type(record) is not list or len(record) != 5
                    or builtins.type(record[0]) is not int
                    or builtins.type(record[1]) is not int
                    or builtins.type(record[2]) is not int
                    or builtins.type(record[3]) is not str
                    or builtins.type(record[4]) is not list
                    or not 2 <= len(record[4]) <= 4):
                raise ValueError("invalid record shape")
            answer.append((
                record[0], record[1], record[2], record[3],
                tuple(record[4]),
            ))
        return answer
    except (OSError, subprocess.TimeoutExpired, ValueError,
            TypeError, UnicodeError, OverflowError):
        # Never expose the approved hostname, resolver diagnostics, or
        # subprocess environment in logs or a public error string.
        raise socket.gaierror("DNS worker: lookup failed") from None
