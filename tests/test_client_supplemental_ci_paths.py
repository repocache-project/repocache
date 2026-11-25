"""Static guards for supplementary workflows; not scheduler evidence."""
from pathlib import Path
import pytest

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
OPTIONAL_CLIENT_WORKFLOWS = (
    "client-atomic-sandbox.yml",
    "client-entry-approval-plan.yml",
    "client-entry-candidates.yml",
    "client-helper-preview.yml",
    "client-managed-registry.yml",
    "client-metadata-sandbox.yml",
    "client-native-fallback.yml",
    "client-shared-entry-atomic.yml",
    "client-source-preflight.yml",
    "client-transaction-metadata.yml",
)
REQUIRED_WORKFLOWS = ("tests.yml", "offline-wheelhouse.yml", "upgrade-distros.yml")


@pytest.mark.parametrize("name", OPTIONAL_CLIENT_WORKFLOWS + (
    "pr237-booted-native-vm.yml", "server-native-nginx-activation-vm.yml",
))
def test_optional_workflows_use_exact_diff_selection_and_isolated_dispatch(name):
    source = (WORKFLOWS / name).read_text("utf-8")
    events = source.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
    assert "pull_request:" in events and "workflow_dispatch:" in events
    assert "paths:" not in events and "paths-ignore:" not in events
    assert "pull_request_target:" not in source
    assert "uses: ./.github/workflows/supplemental-test-impact.yml" in source
    assert "needs: impact" in source
    flag = ("vm" if name.startswith("pr237") else "activation"
            if name.startswith("server") else "client")
    assert "needs.impact.outputs." + flag + " != 'false'" in source
    assert "permissions:\n  contents: read" in source
    assert "persist-credentials: false" in source
    assert "github.run_attempt == 1" in source
    assert "cancel-in-progress:" in source
    if flag == "vm":
        assert "scenario: ${{ fromJSON(needs.impact.outputs.scenarios || " in source
        assert '["smoke","native-installer","native-lifecycle","native-package-interruption"]' in source
        assert "platform: [debian13, almalinux10]" in source


@pytest.mark.parametrize("name", REQUIRED_WORKFLOWS)
def test_protected_required_workflows_still_unfiltered(name):
    source = (WORKFLOWS / name).read_text("utf-8")
    header = source.split("\npermissions:\n", 1)[0]
    assert "  pull_request:\n" in header
    assert "    paths-ignore:" not in header and "    paths:" not in header
    assert "  merge_group:\n" in header
    assert "supplemental-test-impact.yml" not in source
