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
            # Explicit independent regression fixture from the actual
            # v0.5.0 verified wheel METADATA, not a synthetic 14-edge count.
            parents = {
                "typer": ("annotated-doc", "rich", "shellingham"),
                "rich": ("markdown-it-py", "pygments"),
                "textual": ("markdown-it-py", "mdit-py-plugins",
                            "platformdirs", "pygments", "rich",
                            "typing-extensions"),
                "markdown-it-py": ("linkify-it-py", "mdurl"),
                "mdit-py-plugins": ("markdown-it-py",),
            }
            for parent, children in parents.items():
                data[f"pkg:pypi/{parent}@{pins[parent]}"]["dependencies"] = sorted(
                    f"pkg:pypi/{child}@{pins[child]}" for child in children
                )
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
    "substituted-in-lock-edge",
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
    elif mutation == "substituted-in-lock-edge":
        # Demonstrated independent reviewer F-01: same 14 edges, PURLs,
        # reachability and package classification, but an invented edge.
        textual = man["resolved"]["pkg:pypi/textual@8.2.8"]["dependencies"]
        assert "pkg:pypi/rich@15.0.0" in textual
        textual.remove("pkg:pypi/rich@15.0.0")
        textual.append("pkg:pypi/shellingham@1.5.4")
        textual.sort()
        assert sum(len(d["dependencies"]) for d in man["resolved"].values()) == 14
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
    assert active.count("contents: read") == 3
    assert "pull_request_target:" not in active
    assert "workflow_run:" not in active
    assert "github.event_name == 'push'" in active
    assert "github.ref == 'refs/heads/main'" in active
    assert "persist-credentials: false" in active
    assert "github.token" in active
    assert "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" in active
    assert "merge-multiple: true" in active
    assert "Preflight both real snapshot artifacts (read only)" in active
    assert "needs: [preflight]" in active
    assert active.count("python3 scripts/ci_dependency_graph_submit_v05.py") == 1
    preflight = active.split("  preflight:\n", 1)[1].split("  publish:\n", 1)[0]
    publish = active.split("  publish:\n", 1)[1]
    assert "snapshot_b64: ${{ steps.validate.outputs.snapshot_b64 }}" in preflight
    assert '--github-output "$GITHUB_OUTPUT"' in preflight
    assert "actions/checkout@" in preflight and "actions/download-artifact@" in preflight
    assert "uses:" not in publish
    assert "actions/checkout@" not in publish and "actions/download-artifact@" not in publish
    assert "SNAPSHOT_B64: ${{ needs.preflight.outputs.snapshot_b64 }}" in publish
    assert "python3 - <<'PY'" in publish
    assert 'response.get("result") == "SUCCESS"' in publish
    assert 'branch["commit"].get("sha") == sha' in publish


def test_reviewed_edge_contract_rejects_fictional_in_lock_relationship():
    target = TARGETS[1]
    genuine = _graph(target)
    validate_snapshot(genuine, ROOT, target, SHA)
    forged = deepcopy(genuine)
    resolved = forged["manifests"][f"deps/requirements-{target}.txt"]["resolved"]
    children = resolved["pkg:pypi/textual@8.2.8"]["dependencies"]
    children.remove("pkg:pypi/rich@15.0.0")
    children.append("pkg:pypi/shellingham@1.5.4")
    children.sort()
    assert sum(len(data["dependencies"]) for data in resolved.values()) == 14
    with pytest.raises(GraphRefused, match="Unreviewed exact wheel METADATA edge"):
        validate_snapshot(forged, ROOT, target, SHA)


@pytest.mark.parametrize("api_result,expected_success", [
    ("SUCCESS", True),
    ("ACCEPTED", False),  # e.g. older, superseded submission
    ("INVALID", False),
    ("", False),
    (None, False),
    ([], False),
    ({}, False),
])
def test_publisher_requires_explicit_success_not_accepted(
    monkeypatch, capsys, api_result, expected_success
):
    """HTTP 201 alone is insufficient to claim actual graph replacement."""
    graphs = [_graph(t) for t in TARGETS]
    for key, value in {
        "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "teixemf/repocache", "GITHUB_SHA": SHA,
        "GITHUB_TOKEN": "test-token-never-log",
    }.items():
        monkeypatch.setenv(key, value)
    import scripts.ci_dependency_graph_submit_v05 as module
    actual_calls = []

    def mock_api(token, path, payload=None):
        assert token == "test-token-never-log"
        actual_calls.append((path, payload))
        if payload is None:
            return {"commit": {"sha": SHA}}
        return {"result": api_result}

    monkeypatch.setattr(module, "github_api", mock_api)
    if expected_success:
        submit(graphs, SHA)
        output = capsys.readouterr()
        assert "API reported SUCCESS" in output.out
        assert "graph readback NOT VERIFIED" in output.out
        assert not output.err
    else:
        with pytest.raises(GraphRefused, match="did not report SUCCESS"):
            submit(graphs, SHA)
        output = capsys.readouterr()
        assert "PASS:" not in output.out
        assert "test-token-never-log" not in (output.out + output.err)
    assert len(actual_calls) == 2
    assert actual_calls[0][1] is None
    assert actual_calls[1][0].endswith("/dependency-graph/snapshots")
    assert len(actual_calls[1][1]["manifests"]) == 3


def test_native_verification_is_triggered_by_every_graph_contract_change():
    """Both trigger families must cover the collector and publisher paths."""
    workflow = (
        ROOT / ".github/workflows/native-upstream-wheels.yml"
    ).read_text(encoding="utf-8")
    for path in (
        ".github/workflows/native-upstream-wheels.yml",
        ".github/workflows/dependency-graph-submit-v05.yml",
        "scripts/ci_native_upstream_wheels.py",
        "scripts/ci_dependency_graph_v05.py",
        "scripts/ci_dependency_graph_collect_v05.py",
        "scripts/ci_dependency_graph_submit_v05.py",
        "tests/test_dependency_graph_resolution_v05.py",
        "tests/test_dependency_graph_submission_v05.py",
        "pyproject.toml",
        "deps/build-wheels.lock",
        "deps/runtime-wheels.lock",
    ):
        assert workflow.count(f"      - '{path}'") == 2
    assert workflow.count("      - 'deps/requirements-*.txt'") == 2


def test_graph_pr_and_main_push_cover_graph_contract_tests():
    workflow = (
        ROOT / ".github/workflows/dependency-graph-submit-v05.yml"
    ).read_text(encoding="utf-8")
    events = workflow.split("\npermissions:", 1)[0]
    pr, push = events.split("  push:\n", 1)
    for path in (
        "tests/test_dependency_graph_resolution_v05.py",
        "tests/test_dependency_graph_submission_v05.py",
    ):
        assert f"      - '{path}'" in pr
        assert f"      - '{path}'" in push

@pytest.mark.parametrize("body,status,accepted", [
    (b'{"result":"SUCCESS"}', 201, True),
    (b'[]', 201, False),
    (b'null', 201, False),
    (b'"not-an-object"', 201, False),
    (b'123', 201, False),
    (b'{"result":', 201, False),
    (b'{"result":"SUCCESS"}', 202, False),
    (b'{"result":"SUCCESS"}' + b' ' * 20001, 201, False),
])
def test_github_api_transport_requires_correct_status_and_object(
    monkeypatch, body, status, accepted
):
    """Exercise the real HTTP wrapper without sending any network request."""
    import scripts.ci_dependency_graph_submit_v05 as module

    class Response:
        def __enter__(self):
            self.status = status
            return self

        def __exit__(self, *_args):
            return False

        def read(self, size):
            assert size == 20001
            return body[:size]

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == (
                "https://api.github.com/repos/teixemf/repocache/dependency-graph/snapshots"
            )
            assert request.get_method() == "POST"
            assert timeout == 30
            return Response()

    monkeypatch.setattr(module.urllib.request, "build_opener",
                        lambda *args: Opener())
    path = "/repos/teixemf/repocache/dependency-graph/snapshots"
    if accepted:
        assert module.github_api("dummy", path, {"version": 0}) == {
            "result": "SUCCESS"
        }
    else:
        with pytest.raises(GraphRefused):
            module.github_api("dummy", path, {"version": 0})


@pytest.mark.parametrize("error_kind", ["http", "transport"])
def test_github_api_transport_errors_never_echo_token(monkeypatch, error_kind):
    import scripts.ci_dependency_graph_submit_v05 as module

    class Opener:
        def open(self, request, timeout):
            if error_kind == "http":
                raise module.urllib.error.HTTPError(
                    request.full_url, 403, "test-token-never-log", {}, None
                )
            raise module.urllib.error.URLError("test-token-never-log")

    monkeypatch.setattr(module.urllib.request, "build_opener",
                        lambda *args: Opener())
    path = "/repos/teixemf/repocache/dependency-graph/snapshots"
    with pytest.raises(GraphRefused) as error:
        module.github_api("test-token-never-log", path, {"version": 0})
    assert "test-token-never-log" not in str(error.value)


@pytest.mark.parametrize("invalid", [[], None, "malformed", {"commit": []}])
def test_mocked_branch_response_must_be_object_with_commit(monkeypatch, invalid):
    graphs = [_graph(t) for t in TARGETS]
    for key, value in {
        "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "teixemf/repocache", "GITHUB_SHA": SHA,
        "GITHUB_TOKEN": "dummy",
    }.items():
        monkeypatch.setenv(key, value)
    import scripts.ci_dependency_graph_submit_v05 as module
    monkeypatch.setattr(module, "github_api",
                        lambda token, path, payload=None: invalid)
    with pytest.raises(GraphRefused, match="advanced"):
        submit(graphs, SHA)

def test_unfiltered_protected_main_dependency_gates_are_fail_closed():
    """Branch-required candidates are stable jobs in the unfiltered Tests run."""
    workflow = (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    header, jobs = workflow.split("\njobs:\n", 1)
    assert "  pull_request:" in header
    assert "    branches: [main, release/v0.4.0" in header
    assert "    paths:" not in header
    assert "contents: write" not in workflow
    assert "--publish" not in workflow
    assert jobs.count("    if: ${{ always() }}") == 2

    def job(name):
        marker = f"  {name}:\n"
        assert jobs.count(marker) == 1
        tail = jobs.split(marker, 1)[1]
        return re.split(r"\n  (?=[a-z][a-z0-9-]+:\n)", tail, maxsplit=1)[0]

    native = job("dependency-native-validation")
    assert "uses: ./.github/workflows/native-upstream-wheels.yml" in native
    assert "contents: read" in native
    graph_source = job("dependency-graph-collect")
    assert "target: debian13-py313" in graph_source
    assert "target: almalinux10-py312" in graph_source
    assert "ci_dependency_graph_collect_v05.py" in graph_source
    assert "if-no-files-found: error" in graph_source

    for gate_name, prerequisite in (
        ("dependency-native-gate", "dependency-native-validation"),
        ("dependency-graph-gate", "dependency-graph-collect"),
    ):
        gate = job(gate_name)
        assert "if: ${{ always() }}" in gate
        assert f"needs: [{prerequisite}]" in gate
        assert "UPSTREAM_STATUS" in gate
        assert 'if [ "$UPSTREAM_STATUS" != \'success\' ]; then' in gate
        assert "exit 1" in gate
        assert "MAIN_TARGET" in gate
    preflight = job("dependency-graph-gate")
    assert "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" in preflight
    assert "ci_dependency_graph_submit_v05.py" in preflight
    assert "--publish" not in preflight


def test_native_validation_is_reusable_without_write_tokens():
    native = (ROOT / ".github/workflows/native-upstream-wheels.yml").read_text(
        encoding="utf-8"
    )
    assert "\non:\n  workflow_call:\n" in native
    assert "contents: read" in native
    assert "contents: write" not in native
    assert "distro: [debian13, almalinux10]" in native
    assert "persist-credentials: false" in native


def _publisher_code() -> str:
    """Extract the exact privileged step's static Python without executing Actions."""
    import textwrap
    workflow = (ROOT / ".github/workflows/dependency-graph-submit-v05.yml").read_text()
    publisher = workflow.split("\n  publish:\n", 1)[1]
    text = publisher.split("          python3 - <<'PY'\n", 1)[1]
    text = text.split("\n          PY", 1)[0]
    return textwrap.dedent(text) + "\n"


def test_unprivileged_preflight_exports_complete_atomic_payload(monkeypatch, tmp_path, capsys):
    import base64
    import json
    import sys
    from scripts import ci_dependency_graph_submit_v05 as module

    for target in TARGETS:
        (tmp_path / f"dependency-graph-preview-{target}.json").write_text(
            json.dumps(_graph(target))
        )
    output = tmp_path / "workflow-output"
    output.touch()
    monkeypatch.setattr(sys, "argv", ["preflight", "--source", str(ROOT),
                        "--directory", str(tmp_path), "--sha", SHA,
                        "--github-output", str(output)])
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    module.main()
    key, value = output.read_text().strip().split("=", 1)
    assert key == "snapshot_b64"
    data = json.loads(base64.b64decode(value, validate=True))
    assert len(data["manifests"]) == 3
    assert data["sha"] == SHA
    assert data["job"]["correlator"] == "repocache-v05-wheelmeta-two-target"
    assert "NO API call" in capsys.readouterr().out


@pytest.mark.parametrize("situation", [
    "success", "accepted", "stale", "missing", "wrong-sha",
    "wrong-ref", "wrong-repo", "pr", "bad-json", "bad-base64",
    "bad-manifest", "bad-scope", "bad-edge", "missing-token",
])
def test_actionless_write_job_refuses_bad_states(
    monkeypatch, situation, capsys
):
    import base64
    import json
    import urllib.request

    payload = combine_snapshots([_graph(t) for t in TARGETS])
    if situation == "wrong-sha":
        payload["sha"] = "0" * 40
    if situation == "bad-manifest":
        del payload["manifests"]["deps/requirements-build-v05.txt"]
    if situation in ("bad-scope", "bad-edge"):
        name = "deps/requirements-debian13-py313.txt"
        node = next(iter(payload["manifests"][name]["resolved"].values()))
        if situation == "bad-scope":
            node["scope"] = "development"
        else:
            node["dependencies"] = []
            # The original fixture has nonzero edges, adjust a linked parent:
            for item in payload["manifests"][name]["resolved"].values():
                item["dependencies"] = []
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    if situation == "missing":
        encoded = ""
    elif situation == "bad-json":
        encoded = base64.b64encode(b"{").decode()
    elif situation == "bad-base64":
        encoded = "!not-valid!"
    monkeypatch.setenv("SNAPSHOT_B64", encoded)
    monkeypatch.setenv("GITHUB_SHA", SHA)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request" if situation == "pr" else "push")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/206/merge" if situation == "wrong-ref"
                      else "refs/heads/main")
    monkeypatch.setenv("GITHUB_REPOSITORY", "another/repo" if situation == "wrong-repo"
                      else "teixemf/repocache")
    if situation == "missing-token":
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    else:
        monkeypatch.setenv("GITHUB_TOKEN", "mock-token-never-log")

    calls = []
    class Response:
        def __init__(self, status, body):
            self.status = status
            self.body = body
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def read(self, n):
            assert n == 20001
            return self.body
    class Opener:
        def open(self, request, timeout):
            calls.append((request.full_url, request.get_method(), request.data))
            assert timeout == 30
            if request.data is None:
                branch_sha = "0" * 40 if situation == "stale" else SHA
                return Response(200, json.dumps({"commit": {"sha": branch_sha}}).encode())
            response = "ACCEPTED" if situation == "accepted" else "SUCCESS"
            return Response(201, json.dumps({"result": response}).encode())
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())

    if situation == "success":
        exec(compile(_publisher_code(), "actionless-publisher", "exec"), {})
        output = capsys.readouterr()
        assert "API reported SUCCESS" in output.out
        assert len(calls) == 2
        assert len(json.loads(calls[1][2])["manifests"]) == 3
    else:
        with pytest.raises(SystemExit, match="FAIL: dependency graph submission boundary"):
            exec(compile(_publisher_code(), "actionless-publisher", "exec"), {})
        output = capsys.readouterr()
        assert "mock-token-never-log" not in output.out + output.err
        assert "PASS:" not in output.out
        if situation in ("stale", "accepted"):
            assert len(calls) == (1 if situation == "stale" else 2)
        else:
            assert not calls


def test_actionless_publisher_inline_python_compiles():
    compile(_publisher_code(), "actionless-publisher", "exec")
