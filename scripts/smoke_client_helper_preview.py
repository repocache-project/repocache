#!/usr/bin/env python3
"""Disposable Debian 13 / AlmaLinux 10 smoke for read-only helper prototype.

Native /etc is NEVER inspected or altered by this smoke. The only native-root
attempt deliberately runs after dropping UID/GID and must be denied.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
import source_helper_preview as helper  # noqa: E402
import source_preflight as pre  # noqa: E402
import source_entry_boundaries as bounds  # noqa: E402
import entry_candidate_sandbox as candidates  # noqa: E402
import entry_approval_plan_sandbox as approvals  # noqa: E402

RELATIVE = "etc/yum.repos.d/synthetic.repo"
DATA = b"[synthetic]\nbaseurl=https://upstream.invalid/repo\ngpgcheck=1\n"


def invoke(args, root=None):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = helper.main(args, _test_root=root)
    document = json.loads(output.getvalue())
    assert document["read_only"] is True
    assert document["write_eligible"] is False
    return code, document


def main():
    with tempfile.TemporaryDirectory(prefix="repocache-helper-preview-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        marker = root / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        source = root / RELATIVE
        source.parent.mkdir(parents=True)
        source.write_bytes(DATA)
        before = source.stat()

        code, status = invoke(["status", "--json"])
        assert code == 0 and status["ok"] and not status["installed"]
        code, verified = invoke(
            ["inspect-source", "--source", RELATIVE, "--json"], root)
        assert code == 0 and verified["filesystem_preflight"] == "pass"
        assert verified["repository_syntax_verified"] is False
        assert verified["package_signatures_verified"] is False
        assert verified["upstream_fallback_verified"] is False
        assert RELATIVE not in json.dumps(verified)
        assert source.read_bytes() == DATA
        assert source.stat().st_ino == before.st_ino


        # Fixed root-only route approval check, without source mutations.
        chosen = bounds.boundaries(RELATIVE, DATA)[0]
        ident = candidates.register_entry_candidate_sandbox(
            root, RELATIVE, hashlib.sha256(DATA).hexdigest(),
            chosen["sha256"])["id"]
        approved_url = b"https://cache.invalid/repo/"
        approvals.approve_entry_plan_sandbox(
            root, ident, hashlib.sha256(DATA).hexdigest(),
            chosen["sha256"], approved_url.decode("ascii"))
        request = ["verify-route-approval", "--candidate", ident,
                   "--route-sha256", hashlib.sha256(approved_url).hexdigest(),
                   "--json"]
        code, route_status = invoke(request, root)
        assert code == 0 and route_status["route_approval"] == "exact-route-matched"
        assert route_status["approval_scope"] == "sandbox-only"
        assert route_status["write_eligible"] is False
        assert "cache.invalid" not in json.dumps(route_status)
        request[4] = hashlib.sha256(b"https://different.invalid/repo/").hexdigest()
        code, refusal = invoke(request, root)
        assert code == 3 and refusal["error"]["code"] == "ROUTE_APPROVAL_REFUSED"
        assert source.read_bytes() == DATA

        code, structural = invoke(
            ["--json", "validate-source", "--source", RELATIVE], root)
        assert code == 0 and structural["structural_subset_verified"] is True
        assert structural["source_format"] == "dnf-repo"
        assert structural["repository_entries"] == 1
        assert structural["native_syntax_verified"] is False
        assert structural["package_signatures_verified"] is False
        assert source.read_bytes() == DATA
        bad_relative = "etc/yum.repos.d/unsigned.repo"
        bad_target = root / bad_relative
        bad_target.write_bytes(
            b"[unsafe]\nbaseurl=https://example.org/repo\ngpgcheck=0\n")
        code, blocked = invoke(
            ["--json", "validate-source", "--source", bad_relative], root)
        assert code == 3
        assert blocked["error"]["code"] == "SOURCE_STRUCTURE_REFUSED"
        assert bad_target.read_bytes().endswith(b"gpgcheck=0\n")

        code, bad = invoke(["--json", "inspect-source",
                            "--source", "https://user:secret@example.org/"], root)
        assert code != 0 and bad["error"]["code"] == "SOURCE_PREFLIGHT_REFUSED"
        assert "secret" not in json.dumps(bad)

        code, denied = invoke(["--json", "commit", "--source", RELATIVE], root)
        assert code == 2 and denied["error"]["code"] == "INVALID_ARGUMENTS"

        if os.geteuid() == 0:
            worker = r"""
import json, os, sys
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
sys.path.insert(0, sys.argv[1])
import source_helper_preview as helper
code = helper.main(["--json", "inspect-source",
                    "--source", "etc/apt/sources.list"])
raise SystemExit(code)
"""
            result = subprocess.run(
                [sys.executable, "-c", worker, str(CLIENT)],
                check=False, capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 3, result.stderr
            doc = json.loads(result.stdout)
            assert doc["error"]["code"] == "ROOT_REQUIRED"
            assert doc["write_eligible"] is False
        else:
            raise AssertionError("Native privilege smoke requires isolated container root")

        assert source.read_bytes() == DATA
        assert source.stat().st_ino == before.st_ino
        print("PASS: read-only helper conservative structure, route approval, redaction, real UID denial")


if __name__ == "__main__":
    main()
