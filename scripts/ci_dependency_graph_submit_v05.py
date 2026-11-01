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

# An independent standard-library validator: this write-scoped job must not
# depend on pip, install Python wheels, or execute the producer's requirements.
TARGETS = {"debian13-py313": (3, 13), "almalinux10-py312": (3, 12)}
GIT_SHA = re.compile(r"[a-f0-9]{40}\Z")
LOCK_ROW = re.compile(r"([a-z][a-z0-9_]*) (\d+(?:\.\d+){2}) ([a-f0-9]{64})\Z")
PIN_ROW = re.compile(
    r"([a-z][a-z0-9-]*)==(\d+(?:\.\d+){2}) --hash=sha256:([a-f0-9]{64})\Z"
)


class GraphRefused(ValueError):
    """Reject a non-source-verified dependency submission."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GraphRefused(message)


def parse_lock(content: str) -> dict[str, tuple[str, str]]:
    require(bool(content) and content.endswith("\n") and len(content) <= 16384,
            "Invalid source wheel lock")
    found = {}
    for line in content.splitlines():
        match = LOCK_ROW.fullmatch(line)
        require(match is not None, "Malformed source lock")
        name, version, digest = match.groups()
        key = name.replace("_", "-")
        require(key not in found, "Duplicate source lock entry")
        found[key] = (version, digest)
    return found


def verify_monitor(content: str, pins: dict[str, tuple[str, str]]) -> None:
    require(bool(content) and content.endswith("\n") and len(content) <= 16384,
            "Invalid monitor manifest")
    observed = {}
    for line in content.splitlines():
        if line.startswith("#"):
            continue
        match = PIN_ROW.fullmatch(line)
        require(match is not None, "Unsafe manifest pin")
        name, version, digest = match.groups()
        require(name not in observed, "Duplicate monitor pin")
        observed[name] = (version, digest)
    require(observed == pins, "Manifest/source-locked hashes differ")


REPOSITORY = "teixemf/repocache"
DETECTOR = "repocache-verified-wheel-metadata"
DETECTOR_VERSION = "0.1.0"
DETECTOR_URL = "https://github.com/teixemf/repocache"
PURL_RE = re.compile(r"pkg:pypi/([a-z0-9-]+)@([0-9]+(?:\.[0-9]+){2})\Z")
SCANNED_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


# Independently reviewed exact adjacency from SHA-256-verified v0.5.0
# upstream wheel METADATA, reproduced in both native target userspaces.
# Deliberately checked-in: do not infer edge correctness from a 14-edge count.
# Any dependency/metadata change must update this review contract explicitly.
REVIEWED_RUNTIME_EDGES: dict[str, tuple[str, ...]] = {
    "annotated-doc": (),
    "linkify-it-py": (),
    "markdown-it-py": ("linkify-it-py", "mdurl"),
    "mdit-py-plugins": ("markdown-it-py",),
    "mdurl": (),
    "platformdirs": (),
    "pygments": (),
    "rich": ("markdown-it-py", "pygments"),
    "shellingham": (),
    "textual": (
        "markdown-it-py", "mdit-py-plugins", "platformdirs",
        "pygments", "rich", "typing-extensions",
    ),
    "typer": ("annotated-doc", "rich", "shellingham"),
    "typing-extensions": (),
}
REVIEWED_BUILD_EDGES: dict[str, tuple[str, ...]] = {
    "setuptools": (), "wheel": (),
}


def canonical_adjacency(
    pins: dict[str, tuple[str, str]], scope: str
) -> dict[str, list[str]]:
    reviewed = (REVIEWED_RUNTIME_EDGES if scope == "runtime"
                else REVIEWED_BUILD_EDGES if scope == "development" else None)
    require(reviewed is not None and set(reviewed) == set(pins),
            "Wheel inventory changed from reviewed dependency edge contract")
    return {
        name: sorted(f"pkg:pypi/{child}@{pins[child][0]}"
                     for child in children)
        for name, children in reviewed.items()
    }




def _validate_resolved(
    actual: object, pins: dict[str, tuple[str, str]],
    roots: set[str], scope: str,
) -> dict:
    require(isinstance(actual, dict) and len(actual) == len(pins),
            "Incomplete or expanded snapshot inventory")
    expected_keys = {f"pkg:pypi/{name}@{version}"
                     for name, (version, _) in pins.items()}
    require(set(actual) == expected_keys, "Unreviewed resolved PURLs")
    expected_edges = canonical_adjacency(pins, scope)
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
        require(children == expected_edges[name],
                f"Unreviewed exact wheel METADATA edge(s) for {name}")
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
    verify_monitor((source / f"deps/requirements-{target}.txt").read_text("utf-8"),
                   runtime)
    verify_monitor((source / "deps/requirements-build-v05.txt").read_text("utf-8"),
                   build)
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


def combine_snapshots(snapshots: list[dict]) -> dict:
    """Submit all three logical manifests atomically in one API request."""
    require(len(snapshots) == 2, "Expected exactly two target profiles")
    profiles = {snapshot["job"]["correlator"]: snapshot for snapshot in snapshots}
    require(set(profiles) == {
        "repocache-v05-wheelmeta-debian13-py313",
        "repocache-v05-wheelmeta-almalinux10-py312",
    }, "Missing or duplicated target profile")
    left, right = snapshots
    require(left["sha"] == right["sha"] and left["ref"] == right["ref"]
            and left["detector"] == right["detector"],
            "Inconsistent profile commit or detector")
    build = "deps/requirements-build-v05.txt"
    require(left["manifests"][build] == right["manifests"][build],
            "Conflicting build-only dependency metadata")
    manifests = {build: left["manifests"][build]}
    for snapshot in snapshots:
        for path, manifest in snapshot["manifests"].items():
            if path != build:
                require(path not in manifests, "Duplicated runtime profile")
                manifests[path] = manifest
    require(set(manifests) == {
        "deps/requirements-debian13-py313.txt",
        "deps/requirements-almalinux10-py312.txt", build,
    }, "Missing approved per-profile manifest")
    return {
        "version": 0, "sha": left["sha"], "ref": "refs/heads/main",
        "job": {"correlator": "repocache-v05-wheelmeta-two-target",
                "id": left["sha"]},
        "detector": left["detector"],
        "scanned": max(left["scanned"], right["scanned"]),
        "manifests": manifests,
    }


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
    # Prevalidate and combine both target-specific manifests plus the build
    # manifest. One atomic POST avoids partially publishing one target.
    combined = combine_snapshots(snapshots)
    branch = github_api(token, f"/repos/{REPOSITORY}/branches/main")
    require(branch.get("commit", {}).get("sha") == sha,
            "Protected main advanced since graph collection; refuse stale submission")
    result = github_api(token, f"/repos/{REPOSITORY}/dependency-graph/snapshots",
                        combined)
    # HTTP 201 can acknowledge a stale/superseded submission. Only a
    # documented SUCCESS result permits this job to report publication PASS.
    # Live Dependency Graph/SPDX readback is a separate #81 acceptance gate.
    require(result.get("result") == "SUCCESS",
            "GitHub dependency submission did not report SUCCESS")
    print("PASS: GitHub API reported SUCCESS for both locked profiles "
          "and scoped build inventory; graph readback NOT VERIFIED",
          flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    require(bool(GIT_SHA.fullmatch(args.sha)), "Invalid source SHA")
    snapshots = read_snapshots(args.source, args.directory, args.sha)
    combined = combine_snapshots(snapshots)
    require(len(combined["manifests"]) == 3,
            "Preflight could not form a complete three-manifest snapshot")
    if args.publish:
        submit(snapshots, args.sha)
    else:
        print("PASS: validated real two-profile artifacts and the atomic "
              "three-manifest submission payload; NO API call", flush=True)


if __name__ == "__main__":
    try:
        main()
    except GraphRefused as exc:
        raise SystemExit(f"FAIL: dependency graph submission boundary: {exc}") from exc
