"""CI-only cache permission failure injection and restoration (#97)."""
from __future__ import annotations

from pathlib import Path
import stat
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ci_generated_nginx_route_cache_smoke import (
    READ_ONLY_APT_PATH, READ_ONLY_APT_BYTES, deny_cache_directory_writes,
)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_write_denial_restores_nested_modes_even_after_exception(tmp_path):
    cache = tmp_path / "apt"
    nested = cache / "a" / "bc"
    nested.mkdir(parents=True)
    sibling = tmp_path / "dnf"
    sibling.mkdir()
    cache.chmod(0o700)
    nested.parent.chmod(0o750)
    nested.chmod(0o700)
    originals = {path: mode(path) for path in (cache, nested.parent, nested)}
    sibling_mode = mode(sibling)
    with pytest.raises(RuntimeError, match="injected failure"):
        with deny_cache_directory_writes(cache):
            assert all(mode(path) & 0o222 == 0 for path in originals)
            assert mode(sibling) == sibling_mode
            raise RuntimeError("injected failure")
    assert {path: mode(path) for path in originals} == originals
    assert mode(sibling) == sibling_mode


def test_write_denial_restores_after_success(tmp_path):
    cache = tmp_path / "apt"
    cache.mkdir(mode=0o700)
    before = mode(cache)
    with deny_cache_directory_writes(cache):
        assert mode(cache) == before & ~0o222
    assert mode(cache) == before


def test_fixture_is_not_genuine_signed_metadata():
    assert READ_ONLY_APT_PATH == "/apt/dists/trixie/Packages.gz"
    assert READ_ONLY_APT_BYTES.startswith(b"DISPOSABLE-")
