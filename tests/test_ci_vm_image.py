"""Host-side image cache integrity and fallback, without network or QEMU."""
import hashlib
import os
import subprocess
from pathlib import Path

import pytest

HELPER = Path(__file__).resolve().parents[1] / "scripts/ci_vm_image.sh"
PAYLOAD = b"pristine vendor image fixture"


@pytest.fixture(params=["debian13", "almalinux10"])
def image_env(request, tmp_path):
    vendor = tmp_path / "vendor"
    vendor.write_bytes(PAYLOAD)
    env = dict(os.environ, PR237_PLATFORM=request.param, PR237_IMAGE_SHA256="", PR237_IMAGE_SHA512="", VENDOR=str(vendor))
    if request.param == "debian13":
        env.update(PR237_IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/example.qcow2", PR237_IMAGE_SHA512=hashlib.sha512(PAYLOAD).hexdigest())
    else:
        env.update(PR237_IMAGE_URL="https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/example.qcow2", PR237_IMAGE_SHA256=hashlib.sha256(PAYLOAD).hexdigest())
    return env


def acquire(env, dest, cache, *, network=False):
    curl = 'curl() { cp -- "$VENDOR" "${@: -2:1}"; }' if network else 'curl() { echo UNEXPECTED_NETWORK >&2; return 91; }'
    return subprocess.run(["bash", "-Eeuo", "pipefail", "-c", 'source "$1"; shift; ' + curl + '\nci_vm_image_acquire "$1" "$2"', "test", str(HELPER), str(dest), str(cache)], env=env, capture_output=True, text=True, timeout=5)


def test_hit_is_verified_copied_and_read_only(image_env, tmp_path):
    cached = tmp_path / "cache"
    cached.write_bytes(PAYLOAD)
    dest = tmp_path / "base"
    result = acquire(image_env, dest, cached)
    assert result.returncode == 0, result.stderr
    assert dest.read_bytes() == cached.read_bytes() == PAYLOAD
    assert dest.stat().st_ino != cached.stat().st_ino
    assert dest.stat().st_mode & 0o777 == 0o444
    assert "exact-digest cache" in result.stdout


def test_miss_falls_back_to_verified_origin(image_env, tmp_path):
    dest = tmp_path / "base"
    result = acquire(image_env, dest, tmp_path / "absent", network=True)
    assert result.returncode == 0, result.stderr
    assert dest.read_bytes() == PAYLOAD
    assert "official vendor origin" in result.stdout


@pytest.mark.parametrize("kind", ["corrupt", "symlink", "dangling", "directory"])
def test_invalid_cache_refuses_boot_without_fallback(image_env, tmp_path, kind):
    cached = tmp_path / "cache"
    if kind == "corrupt":
        cached.write_bytes(b"invalid")
    elif kind == "symlink":
        cached.symlink_to(image_env["VENDOR"])
    elif kind == "dangling":
        cached.symlink_to(tmp_path / "missing")
    else:
        cached.mkdir()
    dest = tmp_path / "base"
    result = acquire(image_env, dest, cached, network=True)
    assert result.returncode != 0
    assert not dest.exists()
    assert not list(tmp_path.glob("base.part.*"))
    assert "official vendor origin" not in result.stdout


def test_corrupt_origin_is_not_published(image_env, tmp_path):
    Path(image_env["VENDOR"]).write_bytes(b"bad origin")
    dest = tmp_path / "base"
    assert acquire(image_env, dest, tmp_path / "absent", network=True).returncode != 0
    assert not dest.exists() and not list(tmp_path.glob("base.part.*"))


@pytest.mark.parametrize("field,value", [("PR237_IMAGE_URL", "https://example.com/image"), ("PR237_PLATFORM", "unsupported"), ("PR237_IMAGE_SHA256", "bad"), ("PR237_IMAGE_SHA512", "bad")])
def test_invalid_inputs_fail_before_download(image_env, tmp_path, field, value):
    image_env[field] = value
    dest = tmp_path / "base"
    result = acquire(image_env, dest, tmp_path / "absent", network=True)
    assert result.returncode != 0 and not dest.exists()
    assert "official vendor origin" not in result.stdout


def test_symlink_parent_refused(image_env, tmp_path):
    target = tmp_path / "actual"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    assert acquire(image_env, link / "base", tmp_path / "absent", network=True).returncode != 0
    assert not (target / "base").exists()
