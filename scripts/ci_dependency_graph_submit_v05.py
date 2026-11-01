#!/usr/bin/env python3
"""Validate trusted-main snapshot artifacts before optional GitHub submission.

Issue #81. The producer has NO write token. The submitting job receives a
short-lived, job-scoped contents:write GITHUB_TOKEN only for this final step.
No downloaded wheel or third-party package is executed by this module.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import ssl
import sys
import urllib.error
import urllib.request

from ci_dependency_graph_v05 import (
    GIT_SHA, GraphRefused, TARGETS, normalize, parse_lock, require,
)

REPOSITORY = "teixemf/repocache"
DETECTOR = "repocache-verified-wheel-metadata"
DETECTOR_VERSION = "0.1.0"
DETECTOR_URL = "https://github.com/teixemf/repocache"
PURL_RE = re.compile(r"pkg:pypi/([a-z0-9-]+)@([0-9]+(?:\.[0-9]+){2})\Z")
SCANNED_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


def _validate_resolved(
    actual: object, pins: dict[str, tuple[str, str]],
    roots: set[str], scope: str,
) -> dict:
    require(isinstance(actual, dict) and len(actual) == len(pins),
            "Incomplete or expanded snapshot inventory")
    expected_keys = {f"pkg:pypi/{name}@{version}"
                     for name, (version, _) in pins.items()}
    require(set(actual) == expected_keys, "Unreviewed resolved PURLs")
    reachable = set(roots)
    for key, data in actual.items():
        require(isinstance(data, dict) and set(data) == {
            "package_url", "relationship", "scope", "dependencies",
        }, "Unexpected dependency fields")
        m = PURL_RE.fullmatch(key)
        require(m is not None, "Invalid dependency PURL")
        name = m.group(1)
        require(data["package_url"] == key and
                data["relationship"] == ("direct" if name in roots else "indirect")
                and data["scope"] == scope, "Misclassified package")
        children = data["dependencies"]
        require(isinstance(children, list) and children == sorted(set(children))
                and set(children) <= expected_keys, "Unsafe child dependency edges")
    seen: set[str] = set()
    pending = [f"pkg:pypi/{name}@{pins[name][0]}" for name in sorted(roots)]
    while pending:
        parent = pending.pop()
        if parent in seen:
            continue
        seen.add(parent)
        pending.extend(actual[parent]["dependencies"])
    require(seen == expected_keys,
            "Snapshot contains orphan/unreachable or fictional transitive packages")
    return actual


def validate_snapshot(snapshot: object, source: Path, target: str, sha: str) -> dict:
    require(target in TARGETS and bool(GIT_SHA.fullmatch(sha)),
            "Invalid target or commit SHA")
    require(isinstance(snapshot, dict) and set(snapshot) == {
        "version", "sha", "ref", "job", "detector", "scanned", "manifests",
    }, "Unexpected snapshot schema")
    require(snapshot["version"] == 0 and snapshot["sha"] == sha
            and snapshot["ref"] == "refs/heads/main",
            "Snapshot is not for the exact protected main SHA")
    job = snapshot["job"]
    require(isinstance(job, dict) and set(job) == {"id", "correlator"}
            and job["id"] == sha
            and job["correlator"] == f"repocache-v05-wheelmeta-{target}",
            "Unexpected submission identity")
    detector = snapshot["detector"]
    require(detector == {
        "name": DETECTOR, "version": DETECTOR_VERSION, "url": DETECTOR_URL,
    }, "Unexpected dependency detector")
    require(isinstance(snapshot["scanned"], str) and
            SCANNED_RE.fullmatch(snapshot["scanned"]) is not None,
            "Noncanonical UTC scan timestamp")
    runtime = parse_lock((source / "deps/runtime-wheels.lock").read_text("utf-8"))
    build = parse_lock((source / "deps/build-wheels.lock").read_text("utf-8"))
    require(len(runtime) == 12 and len(build) == 2 and not (runtime.keys() & build.keys()),
            "Unreviewed source lock inventory")
    names = {
        f"deps/requirements-{target}.txt": (runtime, {"rich", "textual", "typer"}, "runtime"),
        "deps/requirements-build-v05.txt": (build, set(build), "development"),
    }
    manifests = snapshot["manifests"]
    require(isinstance(manifests, dict) and set(manifests) == set(names),
            "Unexpected snapshot manifest")
    for path, (pins, roots, scope) in names.items():
        record = manifests[path]
        require(isinstance(record, dict) and set(record) == {"name", "file", "resolved"}
                and record["name"] == path
                and record["file"] == {"source_location": path},
                "Unsafe manifest location or metadata")
        _validate_resolved(record["resolved"], pins, roots, scope)
    require(sum(len(v["dependencies"]) for v in manifests[
        f"deps/requirements-{target}.txt"]["resolved"].values()) == 14,
        "Unexpected native metadata edge count; requires renewed review")
    return snapshot


def read_snapshots(source: Path, directory: Path, sha: str) -> list[dict]:
    require(source.is_dir() and directory.is_dir() and not directory.is_symlink(),
            "Invalid snapshot source/directory")
    expected = {
        f"dependency-graph-preview-{target}.json" for target in TARGETS
    }
    actual = {p.name for p in directory.iterdir()}
    require(actual == expected, "Missing or unexpected snapshot files")
    result = []
    for target in sorted(TARGETS):
        path = directory / f"dependency-graph-preview-{target}.json"
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 50000,
                "Unsafe snapshot artifact")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise GraphRefused("Unparseable snapshot JSON") from exc
        result.append(validate_snapshot(data, source, target, sha))
    # Both targets currently share exactly the same separately locked build tools.
    # A profile disagreement must not silently update the build-manifest graph.
    build = "deps/requirements-build-v05.txt"
    require(result[0]["manifests"][build] == result[1]["manifests"][build],
            "Conflicting cross-profile build metadata")
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GraphRefused("Refused GitHub API redirect")


def github_api(token: str, path: str, payload: dict | None = None) -> dict:
    require(path.startswith(f"/repos/{REPOSITORY}/") and
            re.fullmatch(r"/[A-Za-z0-9_./-]+", path) is not None,
            "Unexpected GitHub API path")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "repocache-issue81-dependency-graph",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        require(len(data) < 50000, "Submission exceeds policy size bound")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        "https://api.github.com" + path, data=data,
        headers=headers, method="POST" if payload is not None else "GET",
    )
    # Neither a bearer-token redirect nor a proxy-specified destination is
    # acceptable for a write-token operation.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(req, timeout=30) as response:
            status = response.status
            body = response.read(20000)
    except urllib.error.HTTPError as exc:
        raise GraphRefused(f"GitHub dependency API refused with HTTP {exc.code}") from exc
    require(status == (201 if payload is not None else 200),
            "Unexpected GitHub API response code")
    try:
        return json.loads(body)
    except (UnicodeError, ValueError) as exc:
        raise GraphRefused("Invalid GitHub API response") from exc


def submit(snapshots: list[dict], sha: str) -> None:
    require(os.environ.get("GITHUB_EVENT_NAME") == "push"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_SHA") == sha,
            "Refusing graph publication outside exact main push")
    token = os.environ.get("GITHUB_TOKEN", "")
    require(bool(token) and len(token) <= 4096, "Missing job-scoped token")
    # Prevalidate *both* snapshots before doing any network mutation.
    for snapshot in snapshots:
        branch = github_api(token, f"/repos/{REPOSITORY}/branches/main")
        require(branch.get("commit", {}).get("sha") == sha,
                "Protected main advanced since graph collection; refuse stale submission")
        result = github_api(token, f"/repos/{REPOSITORY}/dependency-graph/snapshots",
                            snapshot)
        require(result.get("result") in {"SUCCESS", "ACCEPTED"},
                "GitHub did not accept submitted dependency graph")
        print("PASS: accepted reviewed dependency graph for " +
              snapshot["job"]["correlator"], flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    require(bool(GIT_SHA.fullmatch(args.sha)), "Invalid source SHA")
    snapshots = read_snapshots(args.source, args.directory, args.sha)
    if args.publish:
        submit(snapshots, args.sha)
    else:
        print("PASS: validated both exact-main snapshot artifacts; NO submission",
              flush=True)


if __name__ == "__main__":
    try:
        main()
    except GraphRefused as exc:
        raise SystemExit(f"FAIL: dependency graph submission boundary: {exc}") from exc
