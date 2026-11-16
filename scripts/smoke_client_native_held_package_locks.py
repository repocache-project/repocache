#!/usr/bin/env python3
"""Real disposable kernel APT/DNF5 lock holding, not installed root authority."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))

import native_package_lock_observation as locks


def _other_process(path: Path, family: str) -> int:
    script = (
        "import fcntl, os, sys\n"
        "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC)\n"
        "try:\n"
        "    if sys.argv[2] == 'flock':\n"
        "        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        "    else:\n"
        "        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        "except OSError:\n"
        "    sys.exit(17)\n"
        "sys.exit(0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(path), family],
        stdin=subprocess.DEVNULL, capture_output=True,
        timeout=5, check=False,
    )
    if result.stdout or result.stderr:
        raise RuntimeError("Unexpected child output")
    return result.returncode


def main() -> int:
    if os.geteuid() != 0:
        raise RuntimeError("Disposable native root container required")
    with tempfile.TemporaryDirectory(
        prefix="repocache-native-lock-smoke-", dir="/tmp"
    ) as name:
        sandbox = Path(name)
        for manager, relatives in (("apt", locks.APT), ("dnf5", locks.DNF5)):
            for relative in relatives:
                path = sandbox / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"")
                path.chmod(0o600)
            witness = sandbox / relatives[-1]
            with locks.hold_existing_native_package_locks(
                manager, root=sandbox
            ) as grant:
                if grant is not None:
                    raise RuntimeError("Unexpected authorization token")
                for family in ("flock", "posix"):
                    if _other_process(witness, family) != 17:
                        raise RuntimeError("Native lock failed to exclude writer")
            for family in ("flock", "posix"):
                if _other_process(witness, family) != 0:
                    raise RuntimeError("Native lock leaked after scope")
            print(f"PASS: {manager} held native kernel flock+POSIX cross-process")
        print("NOT VERIFIED: installed client --apply or package-manager exclusion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
