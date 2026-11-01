#!/usr/bin/env python3
"""Fail-closed, read-only preview of real v0.5.0 Python dependency edges.

CI only (#81). Inspect SHA-256-verified upstream wheel METADATA, never
import or install packages here. This module does NOT submit to GitHub.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import tomllib
import zipfile
from collections import deque
from datetime import datetime, timezone
from email.parser import BytesParser
from pathlib import Path

# pip already carries packaging on both supported native Python targets.
from pip._vendor.packaging.markers import default_environment
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.version import Version

TARGETS = {"debian13-py313": (3, 13), "almalinux10-py312": (3, 12)}
LOCK_ROW = re.compile(r"([a-z][a-z0-9_]*) (\d+(?:\.\d+){2}) ([a-f0-9]{64})\Z")
PIN_ROW = re.compile(
    r"([a-z][a-z0-9-]*)==(\d+(?:\.\d+){2}) --hash=sha256:([a-f0-9]{64})\Z"
)
GIT_SHA = re.compile(r"[a-f0-9]{40}\Z")
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class GraphRefused(ValueError):
    """A dependency relationship is not demonstrably safe to report."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GraphRefused(message)


def normalize(name: str) -> str:
    value = re.sub(r"[-_.]+", "-", name.lower())
    require(bool(NAME.fullmatch(value)), "Unsafe Python package name")
    return value


def parse_lock(text: str) -> dict[str, tuple[str, str]]:
    require(bool(text) and text.endswith("\n") and len(text) <= 16384,
            "Unsafe source lock bytes")
    result: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        m = LOCK_ROW.fullmatch(line)
        require(m is not None, "Malformed legacy lock")
        raw, version, digest = m.groups()
        name = normalize(raw)
        require(name not in result, "Duplicate source lock package")
        result[name] = version, digest
    return result


def check_monitor(text: str, expected: dict[str, tuple[str, str]]) -> None:
    require(bool(text) and text.endswith("\n") and len(text) <= 16384,
            "Unsafe monitoring manifest bytes")
    got: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        m = PIN_ROW.fullmatch(line)
        require(m is not None, "Unsafe monitoring requirement")
        name, version, digest = m.groups()
        name = normalize(name)
        require(name not in got, "Duplicate monitoring requirement")
        got[name] = version, digest
    require(got == expected, "Monitoring manifest does not match reviewed lock")


def metadata_from_wheel(path: Path, name: str, version: str, sha256: str) -> list[Requirement]:
    require(path.is_file() and not path.is_symlink() and path.suffix == ".whl",
            "Expected an ordinary upstream binary wheel")
    require(path.stat().st_size < 15_000_000, "Unexpectedly large upstream wheel")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == sha256,
            "Wheel archive digest differs from reviewed legacy lock")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(len(members) <= 2000 and
                sum(i.file_size for i in members) <= 40_000_000,
                "Unbounded wheel ZIP contents")
        found = [i for i in members if i.filename.endswith(".dist-info/METADATA")]
        require(len(found) == 1 and found[0].file_size <= 200_000,
                "Missing, ambiguous or oversized wheel METADATA")
        raw = archive.read(found[0])
    msg = BytesParser().parsebytes(raw)
    require(normalize(msg.get("Name", "")) == name and msg.get("Version") == version,
            "Wheel distribution identity differs from pinned identity")
    try:
        return [Requirement(s) for s in msg.get_all("Requires-Dist", [])]
    except Exception as exc:
        raise GraphRefused("Invalid upstream Requires-Dist metadata") from exc


def resolve(
    rows: dict[str, tuple[str, str]],
    requirements: dict[str, list[Requirement]],
    roots: set[str],
    environment: dict[str, str],
) -> dict[str, dict[str, object]]:
    """Compute only wheel-declared, target-marker-active package edges.

    Propagate requested extras (e.g. markdown-it-py[linkify]) through a
    monotone closure; no guessed edges and no name-only transitivity.
    """
    require(bool(rows) and bool(roots) and roots <= rows.keys(),
            "Unreviewed direct dependency root")
    require(set(requirements) == set(rows), "Missing pinned wheel metadata")
    edges: dict[str, set[str]] = {n: set() for n in rows}
    seen: set[tuple[str, str]] = set()
    pending = deque((name, "") for name in sorted(roots))
    while pending:
        name, extra = pending.popleft()
        if (name, extra) in seen:
            continue
        require(len(seen) < 1000, "Excessive dependency traversal")
        seen.add((name, extra))
        for req in requirements[name]:
            try:
                enabled = req.marker is None or req.marker.evaluate(
                    {**environment, "extra": extra})
            except Exception as exc:
                raise GraphRefused("Unresolvable wheel environment marker") from exc
            if not enabled:
                continue
            child = normalize(req.name)
            require(req.url is None and child in rows,
                    f"Active unreviewed requirement from {name}: {child}")
            try:
                compatible = Version(rows[child][0]) in req.specifier
            except Exception as exc:
                raise GraphRefused("Unsupported version constraint") from exc
            require(compatible, f"Reviewed pin violates {name} metadata: {child}")
            edges[name].add(child)
            for requested_extra in sorted(set(req.extras) | {""}):
                pending.append((child, requested_extra))
    reached = {name for name, _ in seen}
    require(reached == set(rows),
            "Unreachable or missing locked distribution: " +
            ",".join(sorted(set(rows) - reached)))
    return {
        name: {"package_url": f"pkg:pypi/{name}@{rows[name][0]}",
               "relationship": "direct" if name in roots else "indirect",
               "dependencies": [f"pkg:pypi/{child}@{rows[child][0]}"
                                for child in sorted(edges[name])]}
        for name in sorted(rows)
    }


def _direct_roots(declarations: list[str], pins: dict[str, tuple[str, str]]) -> set[str]:
    roots: set[str] = set()
    for declaration in declarations:
        req = Requirement(declaration)
        name = normalize(req.name)
        require(not req.extras and req.url is None and req.marker is None,
                "Unexpected top-level extras, URL or marker")
        require(name in pins and name not in roots and
                Version(pins[name][0]) in req.specifier,
                "Invalid reviewed direct pin")
        roots.add(name)
    return roots


def graph_snapshot(
    source: Path, runtime_wheels: dict[str, Path], build_wheels: dict[str, Path],
    target: str, sha: str, *, scanned: str | None = None,
) -> dict[str, object]:
    require(target in TARGETS and sys.version_info[:2] == TARGETS[target],
            "Wrong native Python for selected OS/Python graph")
    require(bool(GIT_SHA.fullmatch(sha)), "Invalid source revision")
    runtime = parse_lock((source / "deps/runtime-wheels.lock").read_text("utf-8"))
    build = parse_lock((source / "deps/build-wheels.lock").read_text("utf-8"))
    require(len(runtime) == 12 and len(build) == 2 and not (runtime.keys() & build.keys()),
            "Reviewed runtime/build inventories have changed")
    check_monitor((source / f"deps/requirements-{target}.txt").read_text("utf-8"), runtime)
    check_monitor((source / "deps/requirements-build-v05.txt").read_text("utf-8"), build)
    with (source / "pyproject.toml").open("rb") as f:
        project = tomllib.load(f)
    direct = _direct_roots(project["project"]["dependencies"], runtime)
    require(direct == {"typer", "rich", "textual"}, "Unexpected top-level runtime roots")
    required_build = _direct_roots(project["build-system"]["requires"], build)
    require(required_build == {"setuptools"} and
            project["build-system"]["build-backend"] == "setuptools.build_meta",
            "Unexpected build backend")
    # wheel is a separately reviewed build-only helper, never runtime.
    require(set(build) == {"setuptools", "wheel"}, "Unexpected build tools")
    environment = default_environment()
    require(environment["python_version"] == ".".join(map(str, TARGETS[target])),
            "Native marker environment does not match target")
    def read_all(pins: dict[str, tuple[str, str]], files: dict[str, Path]):
        require(set(files) == set(pins), "Downloaded wheel inventory mismatch")
        return {name: metadata_from_wheel(files[name], name, *pins[name])
                for name in sorted(pins)}
    runtime_graph = resolve(runtime, read_all(runtime, runtime_wheels), direct, environment)
    build_graph = resolve(build, read_all(build, build_wheels), set(build), environment)
    for info in runtime_graph.values():
        info["scope"] = "runtime"
    for info in build_graph.values():
        info["scope"] = "development"
    timestamp = scanned or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    require(isinstance(timestamp, str) and timestamp.endswith("Z"),
            "Invalid scan timestamp")
    manifests = {}
    for path, graph in (
        (f"deps/requirements-{target}.txt", runtime_graph),
        ("deps/requirements-build-v05.txt", build_graph),
    ):
        manifests[path] = {"name": path,
                           "file": {"source_location": path},
                           "resolved": {row["package_url"]: row for row in graph.values()}}
    return {"version": 0, "sha": sha, "ref": "refs/heads/main",
            "job": {"correlator": f"repocache-v05-wheelmeta-{target}",
                    "id": sha},
            "detector": {"name": "repocache-verified-wheel-metadata",
                         "version": "0.1.0"},
            "scanned": timestamp, "manifests": manifests}


def write_preview(snapshot: dict[str, object], out: Path) -> None:
    """Preview-only evidence: no network, token use or dependency submission."""
    require(out.parent.is_dir() and not out.is_symlink(),
            "Unsafe preview target")
    out.write_text(json.dumps(snapshot, sort_keys=True, indent=2) + "\n",
                   encoding="utf-8")
