"""Release metadata invariants for the proposed v0.4.0 -> v0.5.0 transition.

These tests exercise local metadata, source layout, and policy refusal only.
They do not attest a real public-v0.4.0 -> owner-signed-v0.5.0 upgrade (#76).
"""
from __future__ import annotations

import hashlib
import json
import tarfile
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_v05_metadata_identical_and_legacy_policy_explicit():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package = (ROOT / "src/repocache/__init__.py").read_text(encoding="utf-8")
    policy = json.loads((ROOT / "release-policy.json").read_text(encoding="utf-8"))

    assert project["project"]["version"] == "0.5.0"
    assert '__version__ = "0.5.0"' in package
    assert policy["schema"] == 1
    assert policy["version"] == "0.5.0"
    assert policy["compatible_from"] == ["0.4.0"]
    assert policy["downgrade_from"] == []
    assert policy["config_schema"] == 1
    assert policy["api_schema"] == 1
    assert policy["targets"] == [
        {"id": "debian", "major": "13"},
        {"id": "almalinux", "major": "10"},
    ]


def test_v05_release_archive_matches_frozen_v04_member_inventory(
        tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    from build_release import FILES, build_release
    from verify_release_candidate import LEGACY_V04_SOURCE_MEMBERS

    assert len(FILES) == len(LEGACY_V04_SOURCE_MEMBERS)
    assert set(FILES) == LEGACY_V04_SOURCE_MEMBERS
    archive, checksum = build_release(tmp_path, tag="v0.5.0")
    assert checksum.read_text(encoding="ascii") == (
        hashlib.sha256(archive.read_bytes()).hexdigest()
        + "  repocache-v0.5.0.tar.gz\n"
    )
    with tarfile.open(archive, "r:gz") as package:
        members = package.getmembers()
    assert len(members) == len(FILES)
    assert all(member.isfile() for member in members)
    assert {member.name for member in members} == {
        "repocache-v0.5.0/" + name for name in FILES
    }
    # New first-party modules travel in the authenticated application wheel,
    # never as extra files rejected by the immutable v0.4.0 updater.
    assert "src/repocache/submissions.py" not in FILES


@pytest.mark.parametrize("installed_version", ["0.3.0", "0.6.0"])
def test_v05_policy_rejects_unapproved_upgrade_or_downgrade(
        installed_version):
    from repocache import upgrade

    policy = json.loads((ROOT / "release-policy.json").read_text(encoding="utf-8"))
    with pytest.raises(upgrade.UpgradeError):
        upgrade._policy(
            policy, "0.5.0", {"version": installed_version},
            {"ID": "debian", "VERSION_ID": "13"},
        )


def test_v05_policy_allows_v04_metadata_path_only():
    from repocache import upgrade

    policy = json.loads((ROOT / "release-policy.json").read_text(encoding="utf-8"))
    assert upgrade._policy(
        policy, "0.5.0", {"version": "0.4.0"},
        {"ID": "debian", "VERSION_ID": "13"},
    ) == policy
