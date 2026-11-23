#!/usr/bin/env python3
"""Exercise the real worker target guard; never perform a host operation."""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import sys
from unittest.mock import patch

checkout = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(checkout / "src"), str(checkout)]

from repocache.server_native_root_control_entrypoint_v1 import (  # noqa: E402
    NativeControlDispatchError, _native_distro,
)
from scripts import install_native_root_worker as install  # noqa: E402
from scripts import stage_native_root_worker as stage  # noqa: E402


def _must_refuse(operation, code: str) -> None:
    try:
        operation()
    except NativeControlDispatchError as error:
        if str(error) != code:
            raise AssertionError(f"Unexpected target refusal: {error}") from error
    else:
        raise AssertionError("Unsafe native target was not refused")


def main() -> None:
    if len(sys.argv) != 2:
        raise ValueError("Supply the expected target classification")
    expected = sys.argv[1]
    if expected in ("debian", "almalinux"):
        assert _native_distro() == expected
        print(f"PASS: actual supported native worker target observed ({expected})")
        return
    code = {
        "unsupported": "NATIVE_ROOT_CONTROL_DISTRO_UNAVAILABLE",
        "foreign": "NATIVE_ROOT_CONTROL_NATIVE_PYTHON_REQUIRED",
        "untrusted": "NATIVE_ROOT_CONTROL_DISTRO_UNTRUSTED",
    }[expected]
    # Use the genuine OS/interpreter reader. The EFFECT boundaries are
    # sentinels only: even a regression must not consult assets, verify host
    # authorization, open a staging path or write actual protected files.
    def forbidden(*args, **kwargs):
        raise AssertionError("Downstream host or asset operation reached")

    nowhere = Path("/nonexistent-repocache-ci-target-guard")
    pins = {"commit": "a" * 40, "archive_sha256": "b" * 64}
    with ExitStack() as stack:
        for module, name in (
            (install, "require_native_host_preconditions"),
            (stage, "_authenticated_payloads"),
            (stage, "verify_installed_worker"),
            (install, "_place_worker_files"),
            (install, "_stage_proposal_under_root"),
        ):
            stack.enter_context(patch.object(module, name, forbidden))
        _must_refuse(_native_distro, code)
        _must_refuse(lambda: install.install_authenticated_worker(nowhere, **pins), code)
        _must_refuse(lambda: install.stage_authenticated_proposal(
            nowhere, nowhere / "proposal", proposal_sha256="c" * 64, **pins,
        ), code)
    print(f"PASS: actual {expected} target refused before host/asset/placement effects")


if __name__ == "__main__":
    main()
