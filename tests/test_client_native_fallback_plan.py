"""Stage-A byte-compiler regression tests for Debian 13 / AlmaLinux 10.

These tests validate only non-activating bytes; the installed root helper,
package-manager locks, signed native fallback and SELinux remain separate.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
import native_fallback_plan as plan

IDENT = "a" * 32
UPSTREAM = "https://deb.example.org/debian/"
CACHE = "https://cache.example.org/__repocache/repos/approved/"
RPM_UPSTREAM = "https://rpm.example.org/alma/"
APT = "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.example.org/debian/ trixie main\n"
APT_SIBLING = "# keep this comment byte-for-byte\ndeb [signed-by=/etc/apt/keyrings/other.gpg] https://unrelated.example.org/stable/ stable main\n"
DEB822 = ("Types: deb\nURIs: https://deb.example.org/debian/\n"
          "Suites: trixie\nComponents: main\n"
          "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n")
DNF = ("[baseos]\nname=AlmaLinux\nbaseurl=https://rpm.example.org/alma/\n"
       "enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"
       "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10\n")
DNF_SIBLING = ("\n[foreign]\nname=Foreign\nbaseurl=https://foreign.example.org/repo/\n"
               "enabled=0\ngpgcheck=0\n")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compile_one(source, text, entry, *, upstream=UPSTREAM, cache=CACHE):
    data, selected = text.encode(), entry.encode()
    return plan.compile_fallback(
        source=source, original=data, expected_source_sha256=sha(data),
        selected_entry_sha256=sha(selected), managed_id=IDENT,
        upstream=upstream, cache=cache)


@pytest.mark.parametrize("source,body,entry", [
    ("etc/apt/sources.list", APT, APT),
    ("etc/apt/sources.list.d/main.list", APT + APT_SIBLING, APT),
    ("etc/apt/sources.list.d/main.sources", DEB822, DEB822),
])
def test_apt_mirror_priority_signing_and_original_bytes(source, body, entry):
    result = compile_one(source, body, entry)
    assert result.kind in {"apt-list", "apt-deb822"}
    assert result.original == body.encode()
    assert result.production_write_eligible is False
    assert result.route_approval_verified is False
    assert result.native_fallback_verified is False
    assert result.companion is not None
    mirror_path, mirror = result.companion
    assert mirror_path == f"etc/apt/mirrors/repocache-{IDENT}.list"
    assert mirror == (CACHE + "\tpriority:1\n" + UPSTREAM + "\tpriority:2\n").encode()
    assert result.proposed.count(b"mirror+file:/etc/apt/mirrors/") == 1
    assert result.proposed.count(b"debian-archive-keyring.gpg") == 1
    assert result.proposed.endswith(APT_SIBLING.encode()) if source.endswith("main.list") else True
    assert result.original_sha256 == sha(result.original)
    assert result.proposed_sha256 == sha(result.proposed)
    assert result.route_sha256 == sha(CACHE.encode())


def test_dnf5_ordered_baseurl_preserves_gpg_and_siblings():
    p = compile_one("etc/yum.repos.d/alma.repo", DNF + DNF_SIBLING, DNF + "\n",
                    upstream=RPM_UPSTREAM)
    assert p.kind == "dnf-repo"
    assert p.companion is None
    assert p.proposed == (
        DNF.replace("baseurl=" + RPM_UPSTREAM,
                    "baseurl=" + CACHE + " " + RPM_UPSTREAM)
        + DNF_SIBLING).encode()
    assert b"gpgcheck=1\nrepo_gpgcheck=1" in p.proposed
    assert p.proposed.endswith(DNF_SIBLING.encode())
    assert not p.production_write_eligible


@pytest.mark.parametrize("source,text,entry", [
    ("etc/apt/sources.list", APT + APT, APT),
    ("etc/apt/sources.list", APT_SIBLING, APT),
    ("etc/apt/sources.list.d/main.list", APT, DEB822),
])
def test_duplicate_absent_or_wrong_entry_refused(source, text, entry):
    with pytest.raises(plan.FallbackRefused):
        compile_one(source, text, entry)


@pytest.mark.parametrize("source", [
    "etc/apt/../../etc/passwd",
    "/etc/apt/sources.list",
    "etc/apt/mirrors/foo",
    "etc/yum.repos.d/foreign.txt",
    "etc/apt/sources.list.d/evil.list/extra",
])
def test_unsafe_source_paths_refused(source):
    with pytest.raises(plan.FallbackRefused):
        compile_one(source, APT, APT)


@pytest.mark.parametrize("url", [
    "http://cache.example.org/repo/",
    "https://user:secret@cache.example.org/repo/",
    "https://cache.example.org/repo/%2e%2e/",
    "https://cache.example.org/repo/../",
    "https://cache.example.org//repo/",
    "https://cache.example.org/repo/?token=hidden",
    "https://cache.example.org/repo/#fragment",
    "https://cache.example.org/repo/\\evil/",
    "https://cache.example.org/repo",
    "https://cache.example.org:0/repo/",
    "https://cache.example.org:99999/repo/",
])
def test_cache_uri_injection_refused(url):
    with pytest.raises(plan.FallbackRefused):
        compile_one("etc/apt/sources.list", APT, APT, cache=url)


@pytest.mark.parametrize("body", [
    APT.replace(" [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg]", ""),
    APT.replace("signed-by=", "trusted=yes signed-by="),
    APT.replace("https://deb.example.org/debian/", "http://deb.example.org/debian/"),
])
def test_apt_missing_trust_or_insecure_original_refused(body):
    with pytest.raises(plan.FallbackRefused):
        compile_one("etc/apt/sources.list", body, body)


@pytest.mark.parametrize("body", [
    DNF.replace("repo_gpgcheck=1", "repo_gpgcheck=0"),
    DNF.replace("gpgcheck=1", "gpgcheck=0"),
    DNF.replace("gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10", "gpgkey=https://keys.example.org/key"),
    DNF.replace("enabled=1", "enabled=0"),
    DNF.replace("baseurl=https://rpm.example.org/alma/", "mirrorlist=https://rpm.example.org/mirror"),
])
def test_dnf_without_both_preapproved_signature_controls_refused(body):
    with pytest.raises(plan.FallbackRefused):
        compile_one("etc/yum.repos.d/alma.repo", body, body,
                    upstream=RPM_UPSTREAM)


def test_file_digest_and_managed_id_are_immutable():
    data = APT.encode()
    kwargs = dict(source="etc/apt/sources.list", original=data,
                  expected_source_sha256=sha(data), selected_entry_sha256=sha(data),
                  managed_id=IDENT, upstream=UPSTREAM, cache=CACHE)
    for field, bad in [
        ("expected_source_sha256", "0" * 64),
        ("selected_entry_sha256", "0" * 64),
        ("managed_id", "../unsafe"),
        ("managed_id", IDENT.upper()),
        ("upstream", "https://other.example.org/repo/"),
        ("cache", UPSTREAM),
    ]:
        with pytest.raises(plan.FallbackRefused):
            plan.compile_fallback(**dict(kwargs, **{field: bad}))


def test_planning_performs_no_file_io_or_network(monkeypatch):
    import builtins
    def refused(*args, **kwargs):
        raise AssertionError("Compiler must never access filesystem")
    monkeypatch.setattr(builtins, "open", refused)
    monkeypatch.setattr(Path, "read_bytes", refused)
    monkeypatch.setattr(Path, "write_bytes", refused)
    p = compile_one("etc/apt/sources.list", APT, APT)
    assert not p.production_write_eligible


def test_unrecognized_third_party_sibling_preserved_but_not_selected():
    foreign = ("[foreign]\nname=Foreign\nbaseurl=https://untrusted.example.org/r/\n"
               "enabled=1\ngpgcheck=0\n")
    text = DNF + "\n" + foreign
    p = compile_one("etc/yum.repos.d/alma.repo", text, DNF + "\n",
                    upstream=RPM_UPSTREAM)
    assert p.proposed.endswith(foreign.encode())
    with pytest.raises(plan.FallbackRefused):
        compile_one("etc/yum.repos.d/alma.repo", text, foreign,
                    upstream="https://untrusted.example.org/r/")


def test_exact_apt_noop_requires_both_source_and_companion_bytes():
    p = compile_one("etc/apt/sources.list", APT, APT)
    assert p.companion is not None
    assert plan.proposal_bytes_converged(p, p.proposed, p.companion[1])
    assert not plan.proposal_bytes_converged(p, p.proposed)
    assert not plan.proposal_bytes_converged(p, p.proposed, b"tampered")
    assert not plan.proposal_bytes_converged(p, p.original, p.companion[1])
    assert not plan.proposal_bytes_converged(p, p.proposed + b" ", p.companion[1])
    assert not plan.proposal_bytes_converged(p, "not bytes", p.companion[1])


def test_exact_dnf_noop_requires_source_without_companion():
    p = compile_one("etc/yum.repos.d/alma.repo", DNF, DNF,
                    upstream=RPM_UPSTREAM)
    assert p.companion is None
    assert plan.proposal_bytes_converged(p, p.proposed)
    assert not plan.proposal_bytes_converged(p, p.original)
    assert not plan.proposal_bytes_converged(p, p.proposed, b"unexpected")
    assert not plan.proposal_bytes_converged(object(), p.proposed)


@pytest.mark.parametrize("authority", [
    "CACHE.example.org", "cache.example.org.",
    "cache..example.org", "-cache.example.org", "cache-.example.org",
    "cache_example.org", "cache.example.org:0443",
    "0x7f000001", "127.1", "999.999.999.999",
    "127.000.000.001", "[2001:0db8::1]",
])
def test_noncanonical_https_fallback_authority_refused(authority):
    with pytest.raises(plan.FallbackRefused):
        compile_one("etc/apt/sources.list", APT, APT,
                    cache="https://" + authority + "/repo/")


def test_literal_loopback_test_endpoints_remain_canonical_without_write_authority():
    # Native APT/DNF disposable TLS harness uses loopback numeric endpoints.
    for source, original, upstream in (
        ("etc/apt/sources.list", APT, UPSTREAM),
        ("etc/yum.repos.d/alma.repo", DNF, RPM_UPSTREAM),
    ):
        p = compile_one(source, original, original,
                        upstream=upstream,
                        cache="https://127.0.0.1:18443/repo/")
        assert p.route_sha256 == sha(b"https://127.0.0.1:18443/repo/")
        assert p.production_write_eligible is False
        assert p.route_approval_verified is False
