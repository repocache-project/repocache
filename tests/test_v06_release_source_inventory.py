"""Frozen v0.6.0 complete source inventory, without release authorization (#76).

The current repository can still advertise the historical 0.4.0 project
version. This tests future candidate source members without signing, tagging,
publishing or installing a candidate.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile

import pytest

from scripts import build_release
from repocache import upgrade

ROOT = Path(__file__).resolve().parents[1]


def _candidate_source(tmp_path: Path) -> Path:
    """Copy only reviewed members and change metadata in a disposable tree."""
    root = tmp_path / "candidate-src"
    for name in build_release.release_files_for_version("0.6.0"):
        source = ROOT / name
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
    pyproject = root / "pyproject.toml"
    old_version = "0.4.0"
    new_version = "0.6.0"
    before = pyproject.read_text(encoding="utf-8")
    assert 'version = "' + old_version + '"' in before
    pyproject.write_text(before.replace(
        'version = "' + old_version + '"',
        'version = "' + new_version + '"',
    ), encoding="utf-8")
    init = root / "src/repocache/__init__.py"
    before = init.read_text(encoding="utf-8")
    assert '__version__ = "' + old_version + '"' in before
    init.write_text(before.replace(
        '__version__ = "' + old_version + '"',
        '__version__ = "' + new_version + '"',
    ), encoding="utf-8")
    policy = root / "release-policy.json"
    payload = json.loads(policy.read_text(encoding="utf-8"))
    assert payload["schema"] == 1
    payload["version"] = new_version
    policy.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return root


def test_exact_versioned_builder_and_verifier_inventories_agree():
    assert set(build_release.FILES) == upgrade.RELEASE_FILES
    assert len(build_release.V06_EXTRA_FILES) == len(set(build_release.V06_EXTRA_FILES))
    assert not (set(build_release.V06_EXTRA_FILES) & set(build_release.FILES))
    assert set(build_release.V06_EXTRA_FILES) == upgrade.V06_EXTRA_FILES
    expected = set(build_release.FILES) | set(build_release.V06_EXTRA_FILES)
    assert len(expected) > len(build_release.FILES)
    assert set(build_release.release_files_for_version("0.6.0")) == expected
    assert upgrade.release_files_for_version("0.6.0") == expected
    # Never silently rewrite the immutable historical archive envelope.
    for version in ("0.4.0", "0.5.0", "0.7.0"):
        assert build_release.release_files_for_version(version) == build_release.FILES
        assert upgrade.release_files_for_version(version) == upgrade.RELEASE_FILES


def test_complete_first_party_source_and_client_modules_in_inventory():
    included = set(build_release.release_files_for_version("0.6.0"))
    for directory in ("src/repocache", "client"):
        observed = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / directory).glob("*.py")
        }
        assert observed
        assert observed.issubset(included)
    for path in (
        "scripts/server_v06_preflight.py",
        "scripts/collect_native_candidate_evidence.py",
        "scripts/inspect_native_vm_nginx_prerequisites.py",
        "scripts/format_native_vm_paste_receipt.py",
        "docs/examples/server-install-v1.json",
    ):
        assert path in included
    assert all((ROOT / path).is_file()
               and not (ROOT / path).is_symlink()
               for path in included)


def test_v06_candidate_archive_is_complete_deterministic_and_bounded(
    tmp_path, monkeypatch,
):
    source = _candidate_source(tmp_path)
    monkeypatch.setattr(build_release, "ROOT", source)
    first, checksum = build_release.build_release(tmp_path / "a", "v0.6.0")
    second, _ = build_release.build_release(tmp_path / "b", "v0.6.0")
    assert first.read_bytes() == second.read_bytes()
    assert checksum.read_text(encoding="utf-8") == (
        hashlib.sha256(first.read_bytes()).hexdigest() + "  " + first.name + "\n"
    )
    with tarfile.open(first, mode="r:gz") as archive:
        names = {member.name for member in archive}
        expected = {"repocache-v0.6.0/" + path
                    for path in build_release.release_files_for_version("0.6.0")}
        assert names == expected
        assert all(m.isfile() and m.uid == m.gid == 0
                   and m.mtime == 0 and not m.pax_headers
                   for m in archive)
    assert first.stat().st_size < upgrade.MAX_ARCHIVE
    # Round trip through the real strict extraction/parser boundary, rather
    # than trusting the builder's own inventory declaration.
    staging = tmp_path / "verified-stage"
    staging.mkdir()
    extracted, policy = upgrade._extract_verified(
        first.read_bytes(), "0.6.0", staging,
        {"version": "0.0.0"}, system={"ID": "debian", "VERSION_ID": "13"},
    )
    assert policy["version"] == "0.6.0"
    assert (extracted / "src/repocache/server_install_v1.py").read_bytes() == (
        source / "src/repocache/server_install_v1.py"
    ).read_bytes()


def test_missing_added_server_module_rejected_before_partial_candidate(
    tmp_path, monkeypatch,
):
    source = _candidate_source(tmp_path)
    missing = source / "src/repocache/server_install_v1.py"
    assert missing.is_file()
    missing.unlink()
    monkeypatch.setattr(build_release, "ROOT", source)
    with pytest.raises(ValueError, match="Incomplete release bundle"):
        build_release.build_release(tmp_path / "broken", "v0.6.0")


@pytest.mark.parametrize("name", [
    "repocache-v0.6.0/src/repocache/not-reviewed.py",
    "repocache-v0.6.0/../outside",
    "repocache-v0.6.0/src/repocache/server_install_v1.py",
])
def test_extractor_rejects_extra_or_incomplete_members(tmp_path, name):
    """No use of an unsigned/partial archive can grant installation authority."""
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        item = tarfile.TarInfo(name)
        payload = b"unsafe"
        item.size = len(payload)
        item.mode = 0o644
        archive.addfile(item, io.BytesIO(payload))
    with pytest.raises(upgrade.UpgradeError, match="Unsafe or unexpected|Incomplete"):
        upgrade._extract_verified(
            data.getvalue(), "0.6.0", tmp_path,
            {"version": "0.0.0"},
            system={"ID": "debian", "VERSION_ID": "13"},
        )
