#!/usr/bin/env python3
"""Produce read-only GitHub dependency snapshots from pinned, verified wheels.

Issue #81: CI-only. Never installs, imports, or executes downloaded packages.
Never submits to GitHub. The separate publisher enforces the write boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory

from ci_dependency_graph_v05 import (
    GIT_SHA, TARGETS, GraphRefused, graph_snapshot, parse_lock, require,
    write_preview,
)
from ci_dependency_graph_submit_v05 import validate_snapshot

PROJECT = "teixemf/repocache"


def collect(source: Path, target: str, sha: str, output: Path) -> dict:
    require(target in TARGETS and sys.version_info[:2] == TARGETS[target],
            "Unsupported Python/profile pair")
    require(bool(GIT_SHA.fullmatch(sha)), "Invalid source SHA")
    require(source.is_dir() and not source.is_symlink(), "Unsafe source tree")
    require(output.parent.is_dir() and not output.is_symlink(), "Unsafe output")
    rows = {
        "runtime": parse_lock((source / "deps/runtime-wheels.lock").read_text("utf-8")),
        "build": parse_lock((source / "deps/build-wheels.lock").read_text("utf-8")),
    }
    require(len(rows["runtime"]) == 12 and len(rows["build"]) == 2,
            "Unexpected reviewed wheel inventory")
    with TemporaryDirectory(prefix="repocache-graph-") as tmp:
        work = Path(tmp)
        env = {
            "HOME": tmp, "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONNOUSERSITE": "1", "LANG": "C.UTF-8",
        }
        wheels: dict[str, dict[str, Path]] = {}
        for role, pins in rows.items():
            dest = work / role
            dest.mkdir(mode=0o700)
            found: dict[str, Path] = {}
            for name, (version, expected_sha) in sorted(pins.items()):
                before = set(dest.iterdir())
                command = [
                    sys.executable, "-I", "-m", "pip", "--isolated",
                    "download", "--no-deps", "--only-binary=:all:",
                    "--no-cache-dir", "--disable-pip-version-check",
                    "--index-url", "https://pypi.org/simple",
                    "--dest", str(dest), f"{name}=={version}",
                ]
                result = subprocess.run(
                    command, cwd=work, env=env, capture_output=True,
                    text=True, check=False, timeout=150,
                )
                require(result.returncode == 0,
                        f"Reviewed {role} wheel download failed: {name}")
                added = set(dest.iterdir()) - before
                require(len(added) == 1, "Ambiguous downloaded wheel")
                wheel = added.pop()
                require(wheel.is_file() and not wheel.is_symlink()
                        and wheel.suffix == ".whl", "Not a single binary wheel")
                require(hashlib.sha256(wheel.read_bytes()).hexdigest() == expected_sha,
                        f"Reviewed wheel SHA-256 mismatch: {name}")
                found[name] = wheel
            wheels[role] = found
        # This function rechecks every wheel's SHA, identity, Requires-Dist,
        # target-marker closure, direct root, and runtime/build classification.
        result = graph_snapshot(
            source, wheels["runtime"], wheels["build"], target, sha,
        )
        validate_snapshot(result, source, target, sha)
        write_preview(result, output)
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", choices=tuple(TARGETS), required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() != 0, "Do not resolve upstream packages as root")
    graph = collect(args.source, args.target, args.sha, args.output)
    runtime = graph["manifests"][f"deps/requirements-{args.target}.txt"]["resolved"]
    print(f"PASS: read-only {args.target}: {len(runtime)} pinned packages, "
          f"{sum(len(v['dependencies']) for v in runtime.values())} real edges; "
          "no submission", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (GraphRefused, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f"FAIL: dependency graph collection: {exc}") from exc
