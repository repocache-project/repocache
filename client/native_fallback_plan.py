"""Pure Debian 13 / AlmaLinux 10 native fallback configuration compiler.

Stage-A building block for #24, intentionally NOT an installed root helper.
The returned bytes are *untrusted proposals*, never a grant to write /etc.
No filesystem access, imports of client CLI, network calls or privilege
acquisition occur in this module. A production transaction must independently
verify the installed issuer/catalog, administrator route approval (UC-45),
native package-manager behavior and locks, inode/metadata ownership and
durable journal before considering a commit.
"""
from __future__ import annotations

import configparser
import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import source_entry_boundaries as boundaries
import source_preflight as pre
import source_structure_subset as structure

_ID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_DNF_URL = re.compile(rb"(?im)^([ \t]*baseurl[ \t]*=[ \t]*)(\S+)([ \t]*)(?=\n|$)")
_APT_URI = re.compile(rb"(?m)^(URIs:[ \t]*)(\S+)([ \t]*)(?=\n|$)")


class FallbackRefused(ValueError):
    """One source or URL fails the approved fail-closed compiler subset."""


@dataclass(frozen=True)
class FallbackProposal:
    source: str
    kind: str
    managed_id: str
    original_sha256: str
    proposed_sha256: str
    selected_sha256: str
    route_sha256: str
    original: bytes
    proposed: bytes
    companion: tuple[str, bytes] | None
    # Source compiler never grants OS write authorization.
    production_write_eligible: bool = False
    native_fallback_verified: bool = False
    route_approval_verified: bool = False


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_https(value: str, *, allow_missing_slash: bool = False) -> str:
    if (type(value) is not str or not 12 <= len(value) <= 2048
            or not value.startswith("https://")
            or any(ord(c) < 33 or ord(c) > 126 for c in value)
            or any(c in value for c in ('"', "'", "\\", "#", "?", "%"))
            or "//" in value[8:]):
        raise FallbackRefused("Invalid canonical HTTPS repository endpoint")
    try:
        uri = urlsplit(value)
        port = uri.port
    except ValueError as exc:
        raise FallbackRefused("Invalid HTTPS endpoint port") from exc
    if (uri.scheme != "https" or not uri.hostname
            or uri.username is not None or uri.password is not None
            or uri.query or uri.fragment or port == 0
            or not uri.path.startswith("/")
            or (not allow_missing_slash and not uri.path.endswith("/"))
            or uri.hostname.lower() != uri.hostname
            or any(seg in (".", "..") for seg in uri.path.split("/"))
            or value.endswith(":")):
        raise FallbackRefused("Unsupported HTTPS endpoint")
    return value


def _strict_source(relative: str, original: bytes, expected_sha256: str,
                   selected_sha256: str) -> tuple[list[dict], dict, bytes]:
    if (type(relative) is not str or not pre.SOURCE_PATH.fullmatch(relative)
            or relative.startswith("etc/apt/mirrors/")
            or type(original) is not bytes or not original
            or len(original) > pre.MAX_SOURCE_BYTES
            or type(expected_sha256) is not str
            or not _DIGEST.fullmatch(expected_sha256)
            or type(selected_sha256) is not str
            or not _DIGEST.fullmatch(selected_sha256)
            or _sha(original) != expected_sha256):
        raise FallbackRefused("Source baseline or path refused")
    try:
        chunks = boundaries.boundaries(relative, original)
    except boundaries.EntryRefused as exc:
        raise FallbackRefused("Ambiguous source boundaries") from exc
    chosen = [chunk for chunk in chunks
              if chunk["sha256"] == selected_sha256
              and chunk["structure_subset_pass"]]
    if len(chosen) != 1:
        raise FallbackRefused("Selected entry is absent or ambiguous")
    item = chosen[0]
    if item["kind"] not in ("apt-list", "apt-deb822", "dnf-repo"):
        raise FallbackRefused("Unsupported source family")
    return chunks, item, original[item["start"]:item["end"]]


def _apt_endpoint(entry: bytes, kind: str) -> tuple[str, bytes, bytes]:
    if kind == "apt-list":
        try:
            match = structure.APT_LINE.fullmatch(entry.decode("utf-8").strip())
        except UnicodeError as exc:
            raise FallbackRefused("Invalid source encoding") from exc
        if not match:
            raise FallbackRefused("Invalid APT line")
        opts = match.group(2) or ""
        if not re.search(r"(?:^|\s)signed-by=/((?:etc/apt|usr/share)/keyrings)/", opts):
            # Require an explicit existing trust anchor; do not invent keys.
            raise FallbackRefused("APT source lacks explicit signed-by keyring")
        uri = match.group(3)
        needle = uri.encode("ascii")
        if entry.count(needle) != 1:
            raise FallbackRefused("Ambiguous APT endpoint")
        return uri, needle, b"apt-list"
    regex = _APT_URI
    matches = list(regex.finditer(entry))
    if len(matches) != 1 or not re.search(rb"(?m)^Signed-By:[ \t]*/(?:etc/apt|usr/share)/keyrings/[A-Za-z0-9._-]+\.gpg[ \t]*$", entry):
        raise FallbackRefused("deb822 source lacks verified explicit keyring or URI")
    uri = matches[0].group(2).decode("ascii")
    if entry.count(matches[0].group(2)) != 1:
        raise FallbackRefused("Ambiguous deb822 endpoint")
    return uri, matches[0].group(2), b"apt-deb822"


def _dnf_endpoint(entry: bytes) -> tuple[str, bytes]:
    try:
        text = entry.decode("utf-8")
        config = configparser.ConfigParser(interpolation=None, strict=True)
        config.read_string(text)
    except (UnicodeError, configparser.Error) as exc:
        raise FallbackRefused("Unsupported DNF source syntax") from exc
    if len(config.sections()) != 1:
        raise FallbackRefused("Ambiguous DNF repository")
    section = config[config.sections()[0]]
    if (section.get("enabled", "1") != "1"
            or section.get("gpgcheck") != "1"
            or section.get("repo_gpgcheck") != "1"
            or not re.fullmatch(
                r"file:///etc/pki/rpm-gpg/[A-Za-z0-9_.+-]+",
                section.get("gpgkey", ""))):
        raise FallbackRefused("DNF requires pre-existing local metadata and package keys")
    matches = list(_DNF_URL.finditer(entry))
    if len(matches) != 1:
        raise FallbackRefused("Ambiguous DNF baseurl")
    uri = matches[0].group(2).decode("ascii")
    if section.get("baseurl", "").strip() != uri or entry.count(matches[0].group(2)) != 1:
        raise FallbackRefused("Ambiguous DNF baseurl or multiple endpoints")
    return uri, matches[0].group(2)


def compile_fallback(*, source: str, original: bytes,
                     expected_source_sha256: str, selected_entry_sha256: str,
                     managed_id: str, upstream: str, cache: str) -> FallbackProposal:
    """Build byte-exact non-activating fallback inputs for a future root transaction.

    The cache URL must have been independently authenticated and explicitly
    approved by the future privileged helper. No approval is accepted here.
    """
    if type(managed_id) is not str or not _ID.fullmatch(managed_id):
        raise FallbackRefused("Invalid protected managed identifier")
    upstream = _canonical_https(upstream)
    cache = _canonical_https(cache)
    if upstream == cache:
        raise FallbackRefused("Cache and upstream are not independent")
    chunks, chosen, selected = _strict_source(
        source, original, expected_source_sha256, selected_entry_sha256)
    kind = chosen["kind"]
    if kind in ("apt-list", "apt-deb822"):
        existing, token, _ = _apt_endpoint(selected, kind)
    else:
        existing, token = _dnf_endpoint(selected)
    _canonical_https(existing, allow_missing_slash=True)
    if existing.rstrip("/") != upstream.rstrip("/"):
        raise FallbackRefused("Selected original upstream differs from approved mapping")

    companion = None
    if kind in ("apt-list", "apt-deb822"):
        relative = f"etc/apt/mirrors/repocache-{managed_id}.list"
        # The mirror transport chooses the lowest priority first and retries
        # a secondary mirror. Do not replace trusted APT Signed-By settings.
        mirror = (cache + "\tpriority:1\n" + upstream +
                  "\tpriority:2\n").encode("ascii")
        replacement = ("mirror+file:/" + relative).encode("ascii")
        companion = (relative, mirror)
    else:
        # DNF5's documented list-valued baseurl tries URLs in this order.
        # Preserve the original gpgcheck/repo_gpgcheck/gpgkey bytes unchanged.
        replacement = (cache + " " + upstream).encode("ascii")
    if selected.count(token) != 1:
        raise FallbackRefused("Selected upstream is not unique")
    modified = selected.replace(token, replacement, 1)
    proposed = (original[:chosen["start"]] + modified +
                original[chosen["end"]:])
    if proposed == original or len(proposed) > pre.MAX_SOURCE_BYTES:
        raise FallbackRefused("Ineffective or oversized proposal")
    try:
        next_entries = boundaries.boundaries(source, proposed)
    except boundaries.EntryRefused as exc:
        raise FallbackRefused("Proposed source boundaries are ambiguous") from exc
    if len(next_entries) != len(chunks):
        raise FallbackRefused("Proposal changes repository entry count")
    for i, (before, after) in enumerate(zip(chunks, next_entries)):
        if i == chunks.index(chosen):
            if (after["kind"] != before["kind"] or after["key"] != before["key"]
                    or after["sha256"] == before["sha256"]):
                raise FallbackRefused("Changed entry lost its identity")
        elif (after["kind"] != before["kind"] or after["key"] != before["key"]
              or after["sha256"] != before["sha256"]):
            raise FallbackRefused("Sibling entry was changed")
    if kind == "dnf-repo":
        # The source subset only parses one original URL; verify the two
        # ordered DNF URLs in the proposed entry with the real INI parser.
        edited = proposed[next_entries[chunks.index(chosen)]["start"]:
                          next_entries[chunks.index(chosen)]["end"]]
        config = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            config.read_string(edited.decode("utf-8"))
        except (UnicodeError, configparser.Error) as exc:
            raise FallbackRefused("Generated DNF format is invalid") from exc
        section = config[config.sections()[0]]
        if section.get("baseurl", "").split() != [cache, upstream]:
            raise FallbackRefused("DNF fallback URL order was lost")
    return FallbackProposal(
        source=source, kind=kind, managed_id=managed_id,
        original_sha256=_sha(original), proposed_sha256=_sha(proposed),
        selected_sha256=selected_entry_sha256, route_sha256=_sha(cache.encode("ascii")),
        original=original, proposed=proposed, companion=companion,
    )


def proposal_bytes_converged(proposal: FallbackProposal, current: bytes,
                             companion: bytes | None = None) -> bool:
    """Identify an exact byte-level no-op for a *previously staged* proposal.

    This cannot authenticate the observed file's inode, ownership, ACL,
    xattrs, approved route or journal; only a future root helper can do so.
    """
    if (type(proposal) is not FallbackProposal or type(current) is not bytes
            or current != proposal.proposed
            or _sha(current) != proposal.proposed_sha256):
        return False
    if proposal.companion is None:
        return companion is None
    return (type(companion) is bytes
            and companion == proposal.companion[1])
