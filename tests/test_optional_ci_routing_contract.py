"""Static regression for optional CI path routing (not live ruleset evidence)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows"

CLIENT = (
    "client-atomic-sandbox.yml", "client-entry-approval-plan.yml",
    "client-entry-candidates.yml", "client-helper-preview.yml",
    "client-managed-registry.yml", "client-metadata-sandbox.yml",
    "client-native-fallback.yml", "client-shared-entry-atomic.yml",
    "client-source-preflight.yml", "client-transaction-metadata.yml",
)
REQUIRED = ("tests.yml", "offline-wheelhouse.yml", "upgrade-distros.yml")


def triggers(name):
    source = (WF / name).read_text(encoding="utf-8")
    return source.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]


def test_component_smokes_remain_manually_runnable_and_cover_shared_code():
    for name in CLIENT:
        section = triggers(name)
        assert "  pull_request:\n    # " in section, name
        assert "    paths:" in section and "  workflow_dispatch:" in section, name
        assert "paths-ignore:" not in section
        for path in (
            "'client/**'", "'src/repocache/core.py'",
            "'src/repocache/cli.py'", "'scripts/*client*'",
            "'tests/test_client*'", "'tests/test_cli*'",
            "'tests/conftest.py'", "'pyproject.toml'",
            "'deps/**'", "'.github/workflows/**'",
        ):
            assert path in section, (name, path)


def test_presign_operator_has_explicit_manual_and_component_runs():
    section = triggers("release-operator-native-presign.yml")
    assert "  pull_request:\n    # " in section
    assert "    paths:" in section
    assert "  workflow_dispatch:" in section and "  push:" in section
    for path in (
        "'workstation/**'", "'src/repocache/signatures.py'",
        "'scripts/*sign*.py'", "'tests/test_release_operator*.py'",
        "'pyproject.toml'", "'.github/workflows/**'",
    ):
        assert path in section


def test_nine_protected_checks_are_unfiltered_including_merge_group():
    for name in REQUIRED:
        section = triggers(name)
        assert "  pull_request:" in section and "  merge_group:" in section
        assert "paths:" not in section and "paths-ignore:" not in section
    tests = (WF / "tests.yml").read_text(encoding="utf-8")
    assert "Dependency Graph Security Gate" in tests
    assert "Native Dependency Security Gate" in tests


def test_fast_path_retains_release_and_host_proof():
    text = (ROOT / "docs/DEVELOPMENT_FAST_PATH.md").read_text(encoding="utf-8").lower()
    for required in (
        "nine required checks remain unfiltered", "not verified",
        "debian 13", "almalinux 10", "selinux enforcing",
        "separate explicit authorization",
    ):
        assert required in text
