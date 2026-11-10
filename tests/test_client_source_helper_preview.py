"""Non-installed client helper prototype CLI and privilege boundary tests.

No tests edit real /etc. This is neither a release CLI contract nor a root
helper; _test_root is internal test injection guarded by source_preflight.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest


CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
helper = importlib.import_module("source_helper_preview")
pre = importlib.import_module("source_preflight")
SOURCE = "etc/apt/sources.list.d/ci.sources"
CONTENTS = b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n"


@pytest.fixture
def host(tmp_path):
    tmp_path.chmod(0o700)
    marker = tmp_path / pre.MARKER
    marker.write_bytes(pre.TEST_MAGIC)
    marker.chmod(0o600)
    file = tmp_path / SOURCE
    file.parent.mkdir(parents=True)
    file.write_bytes(CONTENTS)
    return tmp_path


def invoke(capsys, argv, *, root=None):
    result = helper.main(argv, _test_root=root)
    output = capsys.readouterr()
    assert output.err == ""
    doc = json.loads(output.out)
    assert doc["schema_version"] == 1
    assert doc["read_only"] is True
    assert doc["write_eligible"] is False
    return result, doc


@pytest.mark.parametrize("args", (["--json", "status"], ["status", "--json"]))
def test_status_is_rootless_and_not_installed(capsys, monkeypatch, args):
    monkeypatch.setattr(pre, "inspect_source", lambda *a, **kw:
                        pytest.fail("status must not touch /etc or any source"))
    code, doc = invoke(capsys, args)
    assert code == 0 and doc["ok"]
    assert doc["installed"] is False
    assert doc["source_writes_supported"] is False
    assert doc["semantic_repository_validation_supported"] is False
    assert doc["capabilities"] == ["status", "inspect-source", "validate-source",
                                    "verify-route-approval"]
    assert "commit" not in doc["capabilities"]


@pytest.mark.parametrize("args", (
    ["--json", "inspect-source", "--source", SOURCE],
    ["inspect-source", "--source", SOURCE, "--json"],
))
def test_scoped_inspection_passes_without_disclosing_config(capsys, host, args):
    before = (host / SOURCE).stat()
    code, doc = invoke(capsys, args, root=host)
    assert code == 0 and doc["ok"]
    assert doc["operation"] == "inspect-source"
    assert doc["filesystem_preflight"] == "pass"
    assert doc["source_contents_returned"] is False
    assert doc["source_path_returned"] is False
    for key in ("repository_syntax_verified", "package_signatures_verified",
                "upstream_fallback_verified", "managed_ownership_verified"):
        assert doc[key] is False
    assert SOURCE not in json.dumps(doc)
    assert "deb.debian.org" not in json.dumps(doc)
    assert hashlib.sha256(CONTENTS).hexdigest() not in json.dumps(doc)
    assert (host / SOURCE).read_bytes() == CONTENTS
    after = (host / SOURCE).stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before.st_dev, before.st_ino, before.st_mtime_ns)


@pytest.mark.parametrize("source", (
    "../../etc/shadow",
    "/etc/apt/sources.list",
    "etc/apt/sources.list.d/../../shadow",
    "etc/yum.repos.d/../passwd",
    "https://user:very-secret@example.org/",
    "etc/apt/sources.list.d/\u202e-malicious.sources",
))
def test_bad_source_path_is_redacted_and_fails(capsys, host, source):
    status, doc = invoke(capsys, ["inspect-source", "--source", source, "--json"],
                         root=host)
    assert status != 0 and not doc["ok"]
    assert doc["error"]["code"] == "SOURCE_PREFLIGHT_REFUSED"
    assert source not in json.dumps(doc)
    assert "very-secret" not in json.dumps(doc)
    assert (host / SOURCE).read_bytes() == CONTENTS


@pytest.mark.parametrize("args", (
    ["--json", "commit", "--source", SOURCE],
    ["--json", "verify-route-approval", "--candidate", "bad"],
    ["--json", "validate-source"],
    ["--json", "validate-source", "--source", SOURCE, "--root", "/"],
    ["--json", "recover"],
    ["--json", "restore"],
    ["--json", "validate", "--source", SOURCE],
    ["--json", "inspect-source", "--source", SOURCE, "--root", "/"],
    ["--json", "inspect-source", "--source", "secret", "--arbitrary", "token-abc"],
    ["--json", "inspect-source"],
    ["--json"],
))
def test_unapproved_commands_and_options_fail_closed_without_echo(
        capsys, host, args):
    code, doc = invoke(capsys, args, root=host)
    assert code == 2 and not doc["ok"]
    assert doc["error"]["code"] == "INVALID_ARGUMENTS"
    assert "token-abc" not in json.dumps(doc)
    assert (host / SOURCE).read_bytes() == CONTENTS


def test_unprivileged_inspection_cannot_target_native_root(capsys, monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 65534)
    code, doc = invoke(capsys, ["--json", "inspect-source", "--source", SOURCE])
    assert code != 0
    assert doc["error"]["code"] == "ROOT_REQUIRED"
    assert doc["write_eligible"] is False


def test_missing_fixture_marker_does_not_enable_root_override(capsys, host):
    (host / pre.MARKER).unlink()
    code, doc = invoke(capsys, ["--json", "inspect-source", "--source", SOURCE],
                       root=host)
    assert code != 0 and not doc["ok"]
    assert doc["error"]["code"] == "SOURCE_PREFLIGHT_REFUSED"


@pytest.mark.parametrize("mutation", ("symlink", "world-writable", "hardlink"))
def test_unsafe_sources_fail_without_mutation(capsys, host, mutation):
    path = host / SOURCE
    if mutation == "symlink":
        path.unlink()
        path.symlink_to(host / pre.MARKER)
    elif mutation == "world-writable":
        path.chmod(0o666)
    else:
        os.link(path, path.parent / "copy.sources")
    code, doc = invoke(capsys, ["--json", "inspect-source", "--source", SOURCE],
                       root=host)
    assert code == 3 and doc["error"]["code"] == "SOURCE_PREFLIGHT_REFUSED"


def test_xattrs_are_reported_only_as_presence(capsys, host):
    path = host / SOURCE
    try:
        os.setxattr(path, "user.repocache", b"sensitive-secret-value")
    except OSError:
        pytest.skip("xattrs unavailable on the sandbox filesystem")
    code, doc = invoke(capsys, ["--json", "inspect-source", "--source", SOURCE],
                       root=host)
    assert code == 0 and doc["ok"]
    assert doc["extended_attributes_present"] is True
    assert doc["write_eligible"] is False
    assert "sensitive-secret-value" not in json.dumps(doc)
    assert "user.repocache" not in json.dumps(doc)


def test_human_status_and_failure_output_are_noninteractive(capsys, host):
    assert helper.main(["status"]) == 0
    plain = capsys.readouterr().out
    assert "read-only" in plain.lower()
    assert "privileges" in plain.lower()
    assert helper.main(["inspect-source", "--source", "../../secret"],
                       _test_root=host) == 3
    plain = capsys.readouterr().out
    assert "SOURCE_PREFLIGHT_REFUSED" in plain
    assert "../../secret" not in plain


def test_installer_and_approved_client_cli_do_not_reference_preview():
    assert "source_helper_preview" not in (CLIENT / "repocache_client.py").read_text()
    assert "source_helper_preview" not in (CLIENT / "install.sh").read_text()
    assert "Applying changes is disabled until reviewed" in (
        CLIENT / "repocache_client.py").read_text()


def test_route_verification_is_never_available_for_native_root(
        capsys, monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    code, result = invoke(capsys, [
        "--json", "verify-route-approval",
        "--candidate", "a" * 32, "--route-sha256", "b" * 64,
    ])
    assert code == 3
    assert result["error"]["code"] == "NOT_INSTALLED"


def test_route_verification_refuses_rootless_before_reading_registry(
        capsys, monkeypatch, host):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 65534)
    monkeypatch.setattr(helper.approval, "_candidate", lambda *x: pytest.fail(
        "Rootless helper must not access protected approval records"))
    code, result = invoke(capsys, [
        "--json", "verify-route-approval",
        "--candidate", "a" * 32, "--route-sha256", "b" * 64,
    ], root=host)
    assert code == 3 and result["error"]["code"] == "ROOT_REQUIRED"


def test_root_approved_exact_route_can_be_verified_without_disclosure(
        capsys, host):
    if os.geteuid() != 0:
        pytest.skip("Real root required to issue and check private approval")
    import entry_candidate_sandbox as entry
    import source_entry_boundaries as bounds
    import entry_approval_plan_sandbox as approvals

    selected = bounds.boundaries(SOURCE, CONTENTS)[0]
    ident = entry.register_entry_candidate_sandbox(
        host, SOURCE, hashlib.sha256(CONTENTS).hexdigest(),
        selected["sha256"])["id"]
    route = b"https://cache.invalid/repo/"
    approvals.approve_entry_plan_sandbox(
        host, ident, hashlib.sha256(CONTENTS).hexdigest(),
        selected["sha256"], route.decode("ascii"))
    args = ["--json", "verify-route-approval",
            "--candidate", ident,
            "--route-sha256", hashlib.sha256(route).hexdigest()]
    before = (host / SOURCE).read_bytes()
    code, result = invoke(capsys, args, root=host)
    assert code == 0 and result["ok"]
    assert result["route_approval"] == "exact-route-matched"
    assert result["approval_scope"] == "sandbox-only"
    assert not result["write_eligible"] and not result["installed"]
    assert "cache.invalid" not in json.dumps(result)
    assert SOURCE not in json.dumps(result)
    assert (host / SOURCE).read_bytes() == before

    args[-1] = hashlib.sha256(b"https://other.invalid/repo/").hexdigest()
    code, result = invoke(capsys, args, root=host)
    assert code == 3 and result["error"]["code"] == "ROUTE_APPROVAL_REFUSED"
    args[-1] = hashlib.sha256(route).hexdigest()
    (host / SOURCE).write_bytes(CONTENTS + b"# independent administrator edit\n")
    code, result = invoke(capsys, args, root=host)
    assert code == 3 and result["error"]["code"] == "ROUTE_APPROVAL_REFUSED"


@pytest.mark.parametrize("relative,contents,kind", (
    ("etc/apt/sources.list.d/native.list",
     b"# local owner comment\n"
     b"deb [signed-by=/etc/apt/keyrings/source.gpg] https://deb.debian.org/debian trixie main\n"
     b"deb https://security.debian.org/debian-security trixie-security main\n",
     "apt-list"),
    ("etc/apt/sources.list.d/native.sources",
     b"Types: deb\nURIs: https://deb.debian.org/debian\n"
     b"Suites: trixie\nComponents: main\nSigned-By: /etc/apt/keyrings/source.gpg\n",
     "apt-deb822"),
    ("etc/yum.repos.d/native.repo",
     b"[BaseOS]\nbaseurl=https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/\n"
     b"enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n",
     "dnf-repo"),
))
def test_structure_validation_preserves_source_bytes_and_never_grants_writes(
        capsys, host, relative, contents, kind):
    path = host / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    before = path.stat()
    code, doc = invoke(capsys, [
        "--json", "validate-source", "--source", relative,
    ], root=host)
    assert code == 0 and doc["ok"]
    assert doc["structural_subset_verified"] is True
    assert doc["source_format"] == kind
    assert doc["repository_entries"] == (2 if relative.endswith(".list") else 1)
    for key in ("native_syntax_verified", "package_signatures_verified",
                "upstream_fallback_verified", "managed_ownership_verified",
                "source_contents_returned", "source_path_returned", "installed"):
        assert doc[key] is False
    assert relative not in json.dumps(doc)
    assert "deb.debian.org" not in json.dumps(doc)
    assert path.read_bytes() == contents
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_mtime_ns)


@pytest.mark.parametrize("relative,contents", (
    ("etc/apt/sources.list.d/bad.list",
     b"deb [trusted=yes] https://deb.debian.org/debian trixie main\n"),
    ("etc/apt/sources.list.d/bad.sources",
     b"Types: deb\nURIs: https://example.org/debian\n"
     b"Suites: trixie\nComponents: main\nTrusted: yes\n"),
    ("etc/yum.repos.d/bad.repo",
     b"[bad]\nbaseurl=https://example.org/linux/\ngpgcheck=0\n"),
    ("etc/apt/mirrors/native", b"https://deb.debian.org/debian\n"),
    ("etc/apt/sources.list.d/empty.list", b"# no enabled repository\n"),
))
def test_structure_validation_refuses_unsupported_or_unsigned_sources(
        capsys, host, relative, contents):
    target = host / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(contents)
    code, doc = invoke(capsys, [
        "--json", "validate-source", "--source", relative,
    ], root=host)
    assert code == 3 and doc["error"]["code"] == "SOURCE_STRUCTURE_REFUSED"
    assert relative not in json.dumps(doc)
    assert target.read_bytes() == contents


def test_structure_validation_rejects_symlinks_and_non_root_native(
        capsys, host, monkeypatch):
    path = host / SOURCE
    path.unlink()
    path.symlink_to(host / pre.MARKER)
    code, doc = invoke(capsys, [
        "--json", "validate-source", "--source", SOURCE,
    ], root=host)
    assert code == 3 and doc["error"]["code"] == "SOURCE_STRUCTURE_REFUSED"
    monkeypatch.setattr(helper.os, "geteuid", lambda: 65534)
    code, doc = invoke(capsys, [
        "--json", "validate-source", "--source", SOURCE,
    ])
    assert code == 3 and doc["error"]["code"] == "ROOT_REQUIRED"
