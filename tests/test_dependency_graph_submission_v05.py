"""Security contract for main-only dependency graph submission (#81).

Pure unit tests. The API is always mocked; no publisher token or network is
used, and no approved source/production files are modified.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re

import pytest
from scripts.ci_dependency_graph_submit_v05 import (
    GraphRefused, combine_snapshots, read_snapshots,
    submit, validate_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]
SHA = "9" * 40
TARGETS = ("almalinux10-py312", "debian13-py313")


def _pins(role):
    lock = ROOT / "deps" / (role + "-wheels.lock")
    return {
        parts[0].replace("_", "-"): parts[1]
        for line in lock.read_text().splitlines()
        if (parts := line.split())
    }


def _graph(target):
    runtime = _pins("runtime")
    build = _pins("build")
    direct = {"rich", "textual", "typer"}
    manifests = {}
    for manifest, pins, roots, scope in (
        (f"deps/requirements-{target}.txt", runtime, direct, "runtime"),
        ("deps/requirements-build-v05.txt", build, set(build), "development"),
    ):
        data = {}
        for name, ver in sorted(pins.items()):
            purl = f"pkg:pypi/{name}@{ver}"
            data[purl] = {
                "package_url": purl,
                "relationship": "direct" if name in roots else "indirect",
                "scope": scope,
                "dependencies": [],
            }
        if scope == "runtime":
            indirect = sorted(set(pins) - roots)
            # A deliberately synthetic connected fixture: nine necessary edges
            # + five extra edges; no claim these are actual upstream relations.
            purls = [f"pkg:pypi/{name}@{pins[name]}" for name in indirect]
            root_purl = f"pkg:pypi/rich@{pins['rich']}"
            data[root_purl]["dependencies"] = sorted([purls[0], *purls[1:6]])
            for previous, child in zip(purls, purls[1:]):
                data[previous]["dependencies"].append(child)
            # 6 roots-to-indirect + 8 in-chain edges = 14 total.
        manifests[manifest] = {
            "name": manifest, "file": {"source_location": manifest},
            "resolved": data,
        }
    return {
        "version": 0, "sha": SHA, "ref": "refs/heads/main",
        "job": {"id": SHA, "correlator": f"repocache-v05-wheelmeta-{target}"},
        "detector": {
            "name": "repocache-verified-wheel-metadata",
            "version": "0.1.0", "url": "https://github.com/teixemf/repocache",
        },
        "scanned": "2026-11-01T00:00:00Z",
        "manifests": manifests,
    }


def test_exact_source_manifest_and_scoped_profiles_validate():
    graphs = [validate_snapshot(_graph(t), ROOT, t, SHA) for t in TARGETS]
    single = combine_snapshots(graphs)
    assert set(single["manifests"]) == {
        "deps/requirements-almalinux10-py312.txt",
        "deps/requirements-debian13-py313.txt",
        "deps/requirements-build-v05.txt",
    }
    assert single["job"]["correlator"] == "repocache-v05-wheelmeta-two-target"
    assert single["sha"] == SHA


@pytest.mark.parametrize("mutation", [
    "wrong-sha", "wrong-ref", "wrong-detector", "wrong-url", "wrong-manifest",
    "missing-package", "unknown-package", "bad-scope", "bad-relation",
    "out-of-lock-edge", "bad-edge-count", "bad-correlator",
])
def test_tampered_snapshots_fail_closed(mutation):
    target = TARGETS[0]
    snap = _graph(target)
    man = snap["manifests"][f"deps/requirements-{target}.txt"]
    keys = sorted(man["resolved"])
    node = man["resolved"][keys[0]]
    if mutation == "wrong-sha":
        snap["sha"] = "0" * 40
    elif mutation == "wrong-ref":
        snap["ref"] = "refs/pull/206/merge"
    elif mutation == "wrong-detector":
        snap["detector"]["name"] = "unknown"
    elif mutation == "wrong-url":
        snap["detector"]["url"] = "https://attacker.invalid"
    elif mutation == "wrong-manifest":
        man["file"]["source_location"] = "../../evil"
    elif mutation == "missing-package":
        del man["resolved"][keys[0]]
    elif mutation == "unknown-package":
        man["resolved"]["pkg:pypi/evil@1.0.0"] = deepcopy(node)
    elif mutation == "bad-scope":
        node["scope"] = "development"
    elif mutation == "bad-relation":
        node["relationship"] = ("direct"
                                if node["relationship"] == "indirect" else "indirect")
    elif mutation == "out-of-lock-edge":
        node["dependencies"] = ["pkg:pypi/malicious@1.0.0"]
    elif mutation == "bad-edge-count":
        for record in man["resolved"].values():
            record["dependencies"] = []
    elif mutation == "bad-correlator":
        snap["job"]["correlator"] = "foreign-job"
    with pytest.raises(GraphRefused):
        validate_snapshot(snap, ROOT, target, SHA)


def test_build_manifest_conflict_refused():
    graphs = [_graph(t) for t in TARGETS]
    build = graphs[1]["manifests"]["deps/requirements-build-v05.txt"]["resolved"]
    key = next(iter(build))
    build[key]["scope"] = "runtime"
    with pytest.raises(GraphRefused, match="Conflicting build"):
        combine_snapshots(graphs)


def test_unprivileged_event_must_not_make_an_api_call(monkeypatch):
    graphs = [_graph(t) for t in TARGETS]
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/206/merge")
    monkeypatch.setenv("GITHUB_REPOSITORY", "teixemf/repocache")
    monkeypatch.setenv("GITHUB_SHA", SHA)
    monkeypatch.setenv("GITHUB_TOKEN", "dummy")
    import scripts.ci_dependency_graph_submit_v05 as module
    def forbid(*args):
        raise AssertionError("API should be unreachable")
    monkeypatch.setattr(module, "github_api", forbid)
    with pytest.raises(GraphRefused, match="outside exact main push"):
        submit(graphs, SHA)


def test_stale_main_refuses_submission_before_post(monkeypatch):
    graphs = [_graph(t) for t in TARGETS]
    for key, val in {
        "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "teixemf/repocache", "GITHUB_SHA": SHA,
        "GITHUB_TOKEN": "mock-token",
    }.items():
        monkeypatch.setenv(key, val)
    import scripts.ci_dependency_graph_submit_v05 as module
    recorded = []
    def mock_api(token, path, payload=None):
        recorded.append((path, payload))
        return {"commit": {"sha": "0" * 40}}
    monkeypatch.setattr(module, "github_api", mock_api)
    with pytest.raises(GraphRefused, match="advanced"):
        submit(graphs, SHA)
    assert len(recorded) == 1 and recorded[0][1] is None


def test_exact_main_single_atomic_post(monkeypatch):
    graphs = [_graph(t) for t in TARGETS]
    for key, val in {
        "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "teixemf/repocache", "GITHUB_SHA": SHA,
        "GITHUB_TOKEN": "mock-token",
    }.items():
        monkeypatch.setenv(key, val)
    import scripts.ci_dependency_graph_submit_v05 as module
    posts = []
    def mock_api(token, path, payload=None):
        if payload is None:
            return {"commit": {"sha": SHA}}
        posts.append((path, payload))
        return {"result": "SUCCESS"}
    monkeypatch.setattr(module, "github_api", mock_api)
    submit(graphs, SHA)
    assert len(posts) == 1
    assert posts[0][0].endswith("/dependency-graph/snapshots")
    assert len(posts[0][1]["manifests"]) == 3


def test_workflow_uses_strict_job_scoped_write_boundary():
    text = (ROOT / ".github/workflows/dependency-graph-submit-v05.yml").read_text()
    active = "\n".join(line for line in text.splitlines()
                       if not line.lstrip().startswith("#"))
    assert re.findall(r"^\s+contents: write$", active, flags=re.MULTILINE) == [
        "      contents: write"
    ]
    assert active.count("contents: read") == 2
    assert "pull_request_target:" not in active
    assert "workflow_run:" not in active
    assert "github.event_name == 'push'" in active
    assert "github.ref == 'refs/heads/main'" in active
    assert "persist-credentials: false" in active
    assert "github.token" in active
    assert "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" in active
    assert "merge-multiple: true" in active
