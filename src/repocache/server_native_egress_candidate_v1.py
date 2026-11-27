"""Candidate-only, generation-bound egress for the dedicated NGINX service.

The existing WAL authenticates exact configuration/include bytes, not kernel
rules. Reconstruct the exact origin tuples from the canonical upstream
fragment rather than persist another operator-editable allowlist. Never
resolve DNS during recovery. The renderer performs no I/O. The separate fixed readback opens a retained
kernel network namespace and lists rules. Internal replacement is only for
an independently owned, locked candidate namespace; no host dispatch.
"""
from __future__ import annotations

from contextlib import contextmanager
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
    return {**plan, "nft_candidate": _render_closed_output_rules(
        listen["bind_address"], listen["https_port"], plan["destinations"], worker_uid)}


def render_bootstrap_egress_candidate(*, worker_uid: int) -> dict[str, Any]:
    """Fixed loopback bootstrap; never permit a fresh upstream connection."""
    if type(worker_uid) is not int or not 0 < worker_uid < 2**31:
        raise NativeEgressCandidateError("NATIVE_EGRESS_WORKER_UID_INVALID")
    return {
        "generation": 0,
        "http_sha256": hashlib.sha256(b"").hexdigest(),
        "repository_destinations": {},
        "destinations": (),
        "authorizes_nginx_activation": False,
        "authorizes_firewall_change": False,
        "runtime_egress_verified": False,
        "nft_candidate": _render_closed_output_rules("127.0.0.1", 8008, (), worker_uid),
    }


def _render_closed_output_rules(address_text, port, destinations, worker_uid):
    address = ipaddress.ip_address(address_text)
    family = "ip" if address.version == 4 else "ip6"
    lines = [
        f"table inet {_TABLE} {{",
        "    counter denied { }",
        "    chain output {",
        "        type filter hook output priority 0; policy drop;",
        "        meta l4proto tcp ct state established accept",
        f'        meta skuid 0 oifname "lo" {family} daddr {address} tcp dport {port} ct state new accept',
    ]
    for raw, port in destinations:
        family = "ip" if ipaddress.ip_address(raw).version == 4 else "ip6"
        lines.append(
            f"        meta skuid {worker_uid} {family} daddr {raw} tcp dport {port} ct state new accept"
        )
    lines.extend(("        counter name denied reject", "    }", "}"))
    return "\n".join(lines) + "\n"


# Read back the complete dedicated namespace, not just a named chain. Use
# nft --stateless --numeric-priority list ruleset with no name resolution.
# This closed grammar ignores formatting only, never rule ordering or
# arbitrary statements. The caller independently binds the namespace.
_HEADER = re.compile(
    r'table inet repocache_egress \{ counter (?:denied|"denied") \{ \} '
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


# Linux nsfs ioctls from <linux/nsfs.h>. The fixed reader is not a
# provisioner, an arbitrary namespace executor or an ingress controller.
_NS_GET_USERNS = 0xB701
_NS_GET_NSTYPE = 0xB703
_CLONE_NEWNET = 0x40000000
_FIXED_NAMESPACE = "repocache-nginx"
_NSENTER = "/usr/bin/nsenter"
_NFT = "/usr/sbin/nft"


def _namespace_identity(info):
    import stat
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o444
            or info.st_ino <= 0):
        raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_METADATA_REFUSED")
    return info.st_dev, info.st_ino


def _verify_network_namespace_fd(fd):
    """Kernel type and owning userns; reject PID1 and caller network views."""
    import fcntl
    import os
    identity = _namespace_identity(os.fstat(fd))
    if fcntl.ioctl(fd, _NS_GET_NSTYPE) != _CLONE_NEWNET:
        raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_TYPE_REFUSED")
    owner = fcntl.ioctl(fd, _NS_GET_USERNS)
    try:
        if _namespace_identity(os.fstat(owner)) != _namespace_identity(
                os.stat("/proc/1/ns/user")):
            raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_OWNER_REFUSED")
    finally:
        os.close(owner)
    if identity in tuple(_namespace_identity(os.stat(path)) for path in (
            "/proc/1/ns/net", "/proc/self/ns/net")):
        raise NativeEgressCandidateError("NATIVE_EGRESS_HOST_NAMESPACE_REFUSED")
    return identity


def _safe_readback_programs():
    """Check fixed native executables and ancestors, not a caller's PATH."""
    import os
    import stat
    identities = []
    for path, directory in (("/", True), ("/usr", True), ("/usr/bin", True),
                            ("/usr/sbin", True), (_NSENTER, False), (_NFT, False)):
        info = os.lstat(path)
        if ((not stat.S_ISDIR(info.st_mode) if directory
             else not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
             or not info.st_mode & 0o100)
                or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022):
            raise NativeEgressCandidateError("NATIVE_EGRESS_PROGRAM_REFUSED")
        identities.append((info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                           info.st_gid, info.st_size, info.st_ctime_ns))
    return tuple(identities)


def _read_namespace_rules(fd):
    """Bounded read-only nft listing in a child, using the inherited nsfs fd."""
    import os
    import selectors
    import subprocess
    import time
    argv = (_NSENTER, "--net=/proc/self/fd/" + str(fd), "--", _NFT,
            "--stateless", "--numeric-priority", "list", "ruleset")
    deadline = time.monotonic() + 10
    with subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, shell=False, cwd="/",
        env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
        close_fds=True, pass_fds=(fd,), start_new_session=True,
    ) as child:
        try:
            raw = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise NativeEgressCandidateError("NATIVE_EGRESS_LIST_TIMEOUT")
                    block = os.read(child.stdout.fileno(),
                                    min(65536, _MAX_FRAGMENT + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
                    if len(raw) > _MAX_FRAGMENT:
                        raise NativeEgressCandidateError("NATIVE_EGRESS_LIST_TOO_LARGE")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or child.wait(timeout=remaining) != 0:
                raise NativeEgressCandidateError("NATIVE_EGRESS_LIST_REFUSED")
            return raw.decode("ascii")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


def _namespace_parent_identity(fd):
    import os
    import stat
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_mode & 0o022 or info.st_ino <= 0
            or any(name != "security.selinux" for name in os.listxattr(fd))):
        raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_PARENT_REFUSED")
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


@contextmanager
def _fixed_namespace_scope():
    """Retain the one fixed nsfs descriptor and native command identities."""
    import os
    import subprocess
    from contextlib import ExitStack
    from repocache.server_root_control_host_preflight_v1 import (
        require_native_host_preconditions,
    )

    try:
        require_native_host_preconditions()
        programs = _safe_readback_programs()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        with ExitStack() as stack:
            root = os.open("/", flags)
            stack.callback(os.close, root)
            _namespace_parent_identity(root)
            parent = root
            chain = []
            for name in ("run", "netns"):
                fd = os.open(name, flags, dir_fd=parent)
                stack.callback(os.close, fd)
                chain.append((parent, name, fd, _namespace_parent_identity(fd)))
                parent = fd
            # Reject special files and symlinks before opening the leaf.
            named_identity = _namespace_identity(os.stat(
                _FIXED_NAMESPACE, dir_fd=parent, follow_symlinks=False))
            net = os.open(_FIXED_NAMESPACE, os.O_RDONLY | os.O_NONBLOCK |
                          os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            stack.callback(os.close, net)
            identity = _verify_network_namespace_fd(net)
            if identity != named_identity:
                raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_CHANGED")

            def recheck():
                for directory, name, fd, original in chain:
                    named = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (_namespace_parent_identity(fd) != original or
                            (named.st_dev, named.st_ino, named.st_mode,
                             named.st_uid, named.st_gid) != original):
                        raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_PARENT_CHANGED")
                if (_verify_network_namespace_fd(net) != identity or
                        _namespace_identity(os.stat(
                            _FIXED_NAMESPACE, dir_fd=parent,
                            follow_symlinks=False)) != identity):
                    raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_CHANGED")
                if _safe_readback_programs() != programs:
                    raise NativeEgressCandidateError("NATIVE_EGRESS_PROGRAM_CHANGED")

            recheck()
            yield net, identity, recheck
            recheck()
    except NativeEgressCandidateError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, subprocess.SubprocessError):
        raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_READBACK_REFUSED") from None


def inspect_fixed_namespace_egress(expected: str) -> dict[str, Any]:
    """Observe only the fixed service netns and complete closed kernel rules.

    Caller must authenticate expected generation and retain its ownership/WAL
    lock. This observation grants no namespace exclusivity or write authority.
    """
    try:
        _closed_ruleset(expected)
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_READBACK_REFUSED") from None
    with _fixed_namespace_scope() as (net, identity, recheck):
        result = verify_namespace_egress_readback(expected, _read_namespace_rules(net))
        recheck()
        if verify_namespace_egress_readback(expected, _read_namespace_rules(net)) != result:
            raise NativeEgressCandidateError("NATIVE_EGRESS_RULES_CHANGED")
        recheck()
        return {**result, "fixed_namespace_identity_observed": True,
                "namespace_device": identity[0], "namespace_inode": identity[1],
                "namespace_exclusivity_verified": False}


def _canonical_ruleset(raw: str) -> str:
    """Reconstruct command bytes from the closed grammar, not input text."""
    health, rules = _closed_ruleset(raw)
    return _render_closed_output_rules(
        health[0], health[1], tuple((address, port) for _, address, port in rules),
        rules[0][0] if rules else 1,
    )


def _run_namespace_batch(fd, batch, *, validate_only):
    """One fixed nft transaction via the retained nsfs fd, never a shell."""
    import subprocess
    argv = (_NSENTER, "--net=/proc/self/fd/" + str(fd), "--", _NFT,
            *(("-c",) if validate_only else ()), "-f", "-")
    result = subprocess.run(
        argv, input=batch.encode("ascii"), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, shell=False, cwd="/",
        env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
        close_fds=True, pass_fds=(fd,), timeout=10, check=False,
    )
    if result.returncode != 0:
        raise NativeEgressCandidateError("NATIVE_EGRESS_BATCH_REFUSED")


def _initialize_fixed_namespace_egress(proposed: str, *,
                                       namespace_identity: tuple[int, int],
                                       recheck_owned) -> dict[str, Any]:
    """Install one closed table only in a freshly owned empty service netns.

    The trusted caller must retain the namespace creation witness and
    state lock, prove the service cannot start yet, and independently
    authenticate the generation. An existing table, even byte-identical,
    is not adopted. No host, link, routing, flush or delete operation is
    available. A later exact repeat is a separate read-only observation.
    This is not yet a boot-time provisioner or a concurrent root lease.
    """
    try:
        canonical = _canonical_ruleset(proposed)
        if (type(namespace_identity) is not tuple or len(namespace_identity) != 2
                or any(type(x) is not int or x <= 0 for x in namespace_identity)
                or not callable(recheck_owned)):
            raise ValueError("invalid ownership witness")
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise NativeEgressCandidateError("NATIVE_EGRESS_INITIALIZATION_INPUT_REFUSED") from None
    with _fixed_namespace_scope() as (net, identity, recheck):
        if identity != namespace_identity:
            raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_OWNERSHIP_REFUSED")

        def require_empty():
            recheck_owned()
            recheck()
            observed = _read_namespace_rules(net)
            if type(observed) is not str or observed.strip():
                raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_NOT_EMPTY")
            recheck()
            recheck_owned()

        require_empty()
        _run_namespace_batch(net, canonical, validate_only=True)
        require_empty()
        _run_namespace_batch(net, canonical, validate_only=False)
        for _ in range(2):
            recheck_owned()
            recheck()
            verify_namespace_egress_readback(canonical, _read_namespace_rules(net))
            recheck()
            recheck_owned()
        return {
            "status": "NAMESPACE_EGRESS_INITIALIZATION_OBSERVED",
            "namespace_device": identity[0], "namespace_inode": identity[1],
            "proposed_sha256": hashlib.sha256(canonical.encode("ascii")).hexdigest(),
            "ruleset_shape_matches": True,
            "namespace_exclusivity_verified": False,
            "runtime_egress_verified": False,
            "authorizes_nginx_activation": False,
            "authorizes_catalog_publication": False,
        }


_BOOT_EGRESS_RECEIPT = ".native-nginx-boot-egress-v1.json"
_BOOT_EGRESS_RECEIPT_MAX = 4096
_BOOT_ID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)


def _current_boot_id() -> str:
    """Read the kernel boot UUID, never a caller-selected identifier."""
    import os
    import stat
    fd = os.open("/proc/sys/kernel/random/boot_id",
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_ID_REFUSED")
        raw = os.read(fd, 65)
        if (not raw.endswith(b"\n") or len(raw) != 37
                or _BOOT_ID.fullmatch(raw[:-1].decode("ascii")) is None
                or os.read(fd, 1)):
            raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_ID_REFUSED")
        return raw[:-1].decode("ascii")
    finally:
        os.close(fd)


def _read_boot_egress_receipt(state_fd: int, owner: int, group: int) -> bytes | None:
    import os
    from repocache.server_protected_state_inspect_v1 import _FILE_FLAGS, _identity
    from repocache.server_protected_state_store_v1 import _read_file
    limit = _BOOT_EGRESS_RECEIPT_MAX
    raw = _read_file(state_fd, _BOOT_EGRESS_RECEIPT, owner, limit)
    if raw is None:
        return None
    fd = os.open(_BOOT_EGRESS_RECEIPT, _FILE_FLAGS, dir_fd=state_fd)
    try:
        info = os.fstat(fd)
        if (info.st_gid != group
                or set(os.listxattr(fd)) - {"security.selinux"}
                or _identity(info) != _identity(os.stat(
                    _BOOT_EGRESS_RECEIPT, dir_fd=state_fd, follow_symlinks=False))
                or os.read(fd, limit + 1) != raw
                or _identity(os.fstat(fd)) != _identity(info)
                or _identity(os.stat(_BOOT_EGRESS_RECEIPT, dir_fd=state_fd,
                                     follow_symlinks=False)) != _identity(info)):
            raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_RECEIPT_REFUSED")
        return raw
    finally:
        os.close(fd)


def _prepare_boot_egress_locked(
    root_fd: int, state_fd: int, proposed: str, *,
    namespace_identity: tuple[int, int], generation: int,
    generation_manifest_sha256: str, profile_receipt_sha256: str,
    executable_receipt_sha256: str, recheck_owned, allow_prepare: bool,
) -> dict[str, Any]:
    """Bind initial namespace rules to a durable, boot-specific intent.

    The trusted caller holds the protected state lock, independently
    authenticates the generation and executable/profile receipts, and
    proves the fresh namespace's ownership, ingress/routing and service
    exclusion before allowing preparation. The receipt alone proves none
    of those prerequisites. Verify-only may observe an active service
    if its caller independently binds that service to this namespace.
    No installed dispatcher calls this internal candidate. A different
    boot, generation or namespace is refused, not automatically adopted
    or garbage-collected. No host routing or service action is performed.
    """
    import os
    import stat
    from contextlib import ExitStack
    from repocache.server_protected_state_inspect_v1 import (
        _STATE_SEGMENTS, _identity, _safe_directory, _walk,
    )
    from repocache.server_protected_state_store_v1 import (
        _canonical, _recheck_after_mutation, _write_exclusive,
    )
    try:
        canonical = _canonical_ruleset(proposed)
        if (type(namespace_identity) is not tuple or len(namespace_identity) != 2
                or any(type(x) is not int or x <= 0 for x in namespace_identity)
                or type(generation) is not int or not 0 <= generation <= MAX_INT
                or any(type(value) is not str or _SHA256.fullmatch(value) is None
                       for value in (generation_manifest_sha256, profile_receipt_sha256,
                                     executable_receipt_sha256))
                or not callable(recheck_owned) or type(allow_prepare) is not bool):
            raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_INPUT_REFUSED")
        owner, group = os.geteuid(), os.getegid()
        with ExitStack() as stack:
            pinned_state, chain = _walk(root_fd, _STATE_SEGMENTS, stack, owner)
            state_identity = _identity(_safe_directory(state_fd, owner))[:6]
            if (_identity(os.fstat(pinned_state))[:6] != state_identity
                    or stat.S_IMODE(state_identity[2]) != 0o700
                    or state_identity[4] != group
                    or set(os.listxattr(state_fd)) - {"security.selinux"}):
                raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_STATE_REFUSED")
            boot = _current_boot_id()
            net, identity, recheck = stack.enter_context(_fixed_namespace_scope())
            if identity != namespace_identity:
                raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_OWNERSHIP_REFUSED")
            policy_sha = hashlib.sha256(canonical.encode("ascii")).hexdigest()
            expected = _canonical({
                "schema_version": 1,
                "boot_id": boot,
                "namespace_device": identity[0],
                "namespace_inode": identity[1],
                "generation": generation,
                "generation_manifest_sha256": generation_manifest_sha256,
                "profile_receipt_sha256": profile_receipt_sha256,
                "executable_receipt_sha256": executable_receipt_sha256,
                "ruleset_sha256": policy_sha,
                "authorizes_nginx_activation": False,
            }, limit=_BOOT_EGRESS_RECEIPT_MAX)

            def guard():
                recheck_owned()
                _recheck_after_mutation(chain, owner)
                if (_identity(_safe_directory(state_fd, owner))[:6] != state_identity
                        or _current_boot_id() != boot):
                    raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_SCOPE_CHANGED")
                recheck()

            def receipt():
                return _read_boot_egress_receipt(state_fd, owner, group)

            def check_receipt():
                guard()
                if receipt() != expected:
                    raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_RECEIPT_CHANGED")
                guard()

            guard()
            saved = receipt()
            observed = _read_namespace_rules(net)
            if type(observed) is not str:
                raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_RULES_REFUSED")
            if saved is None:
                if not allow_prepare or observed.strip():
                    # No adoption of an existing table, even identical.
                    raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_INTENT_REQUIRED")
                guard()
                if receipt() is not None or _read_namespace_rules(net).strip():
                    raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_INTENT_COLLISION")
                _write_exclusive(state_fd, _BOOT_EGRESS_RECEIPT, expected, owner,
                                 _BOOT_EGRESS_RECEIPT_MAX)
            elif saved != expected:
                # Old boot, different generation, foreign namespace or
                # receipt drift are preserved for explicit reconciliation.
                raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_RECEIPT_MISMATCH")
            check_receipt()
            observed = _read_namespace_rules(net)
            if not observed.strip():
                if not allow_prepare:
                    raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_POLICY_PENDING")
                _initialize_fixed_namespace_egress(
                    canonical, namespace_identity=identity, recheck_owned=check_receipt)
            for _ in range(2):
                check_receipt()
                verify_namespace_egress_readback(canonical, _read_namespace_rules(net))
                check_receipt()
            return {
                "status": "NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED",
                "boot_id": boot,
                "namespace_device": identity[0],
                "namespace_inode": identity[1],
                "generation": generation,
                "ruleset_sha256": policy_sha,
                "receipt_sha256": hashlib.sha256(expected).hexdigest(),
                "ruleset_shape_matches": True,
                "namespace_exclusivity_verified": False,
                "runtime_egress_verified": False,
                "authorizes_nginx_activation": False,
                "authorizes_catalog_publication": False,
            }
    except NativeEgressCandidateError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        raise NativeEgressCandidateError("NATIVE_EGRESS_BOOT_PREPARATION_REFUSED") from None


def _replace_fixed_namespace_egress(previous: str, proposed: str, *,
                                    namespace_identity: tuple[int, int],
                                    recheck_owned) -> dict[str, Any]:
    """Internal candidate mutation, not exposed through host dispatch.

    Trusted caller retains the namespace ownership and service/WAL lock
    and supplies only independently authenticated generation rules. A
    same-shaped foreign table must never be adopted: require its previously
    recorded namespace identity and caller's ownership recheck. This cannot
    exclude a concurrent privileged netlink administrator. On uncertainty
    do not guess, retry or flush; retain durable caller recovery evidence.
    """
    try:
        old = _canonical_ruleset(previous)
        new = _canonical_ruleset(proposed)
        if (type(namespace_identity) is not tuple or len(namespace_identity) != 2
                or any(type(x) is not int or x <= 0 for x in namespace_identity)
                or not callable(recheck_owned)):
            raise ValueError("invalid ownership witness")
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise NativeEgressCandidateError("NATIVE_EGRESS_REPLACEMENT_INPUT_REFUSED") from None
    with _fixed_namespace_scope() as (net, identity, recheck):
        if identity != namespace_identity:
            raise NativeEgressCandidateError("NATIVE_EGRESS_NAMESPACE_OWNERSHIP_REFUSED")

        def require(expected):
            recheck_owned()
            recheck()
            verify_namespace_egress_readback(expected, _read_namespace_rules(net))
            recheck()
            recheck_owned()

        require(old)
        if old != new:
            batch = "delete table inet repocache_egress\n" + new
            _run_namespace_batch(net, batch, validate_only=True)
            require(old)
            _run_namespace_batch(net, batch, validate_only=False)
            require(new)
        require(new)
        return {
            "status": "NAMESPACE_EGRESS_REPLACEMENT_OBSERVED" if old != new else
                      "NAMESPACE_EGRESS_UNCHANGED",
            "namespace_device": identity[0], "namespace_inode": identity[1],
            "previous_sha256": hashlib.sha256(old.encode("ascii")).hexdigest(),
            "proposed_sha256": hashlib.sha256(new.encode("ascii")).hexdigest(),
            "ruleset_shape_matches": True,
            "namespace_exclusivity_verified": False,
            "runtime_egress_verified": False,
            "authorizes_nginx_activation": False,
            "authorizes_catalog_publication": False,
        }
