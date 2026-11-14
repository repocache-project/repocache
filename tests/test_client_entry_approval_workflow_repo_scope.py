"""Keep the disposable native client approval CI dependency trust boundary (#24)."""
from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github/workflows/client-entry-approval-plan.yml"
)


def test_native_approval_fixture_avoids_optional_alma_extras_mirror():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    # The test uses only AlmaLinux's official Python build dependency. Its
    # optional extras mirror must not participate in metadata refresh here.
    assert "dnf --disable-repo=extras install -y python3" in workflow
    assert "dnf install -y python3" not in workflow
    # The change must not turn off distribution package trust or the two
    # real native source-approval/rollback smoke entry points.
    assert "--nogpgcheck" not in workflow
    assert "--disable-repo=baseos" not in workflow
    assert "--disable-repo=appstream" not in workflow
    assert "python3 scripts/smoke_client_entry_approval_plan.py" in workflow
    assert "python3 scripts/smoke_client_entry_stage.py" in workflow
    assert "apt-get install -y --no-install-recommends python3" in workflow
    assert "docker run --rm --network bridge" in workflow
    assert "--mount \"type=bind,source=$PWD,target=/workspace,readonly\"" in workflow
