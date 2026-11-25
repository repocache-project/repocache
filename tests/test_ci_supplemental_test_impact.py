"""Test closed selection, real Git diffs and fail-safe uncertainty."""
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci_supplemental_test_impact as impact


@pytest.mark.parametrize("paths,client,scenarios,activation", [
    (["README.md"], False, (), False),
    (["docs/DEVELOPMENT_WORKFLOW.md"], False, (), False),
    (["client/root_source_boundary.py", "scripts/ci_dnf_signed_rpm_fallback.py"],
     True, ("smoke",), False),
    (["scripts/ci_pr237_native_socket_guest.py", "docs/testing/PR237_BOOTED_VM.md"],
     False, ("native-installer", "native-lifecycle"), False),
    (["scripts/ci_v06_native_repository_lifecycle_guest.py"],
     False, ("native-lifecycle",), False),
    (["scripts/ci_pr237_native_package_interrupt_guest.py"],
     False, ("native-package-interruption",), False),
    (["scripts/ci_native_nginx_activate_guest.py"], False, (), True),
    (["src/repocache/server_native_installed_storage_v1.py"],
     False, impact.SCENARIOS, True),
    (["client/root_source_boundary.py", "scripts/ci_pr237_native_socket_guest.py"],
     True, ("smoke", "native-installer", "native-lifecycle"), False),
    (["scripts/ci_v06_vm_client_privileged_guest.py"], True, ("smoke",), False),
    (["client/root_source_boundary.py", "scripts/build_release.py"],
     True, impact.SCENARIOS, True),
    (["src/repocache/upgrade.py"], True, impact.SCENARIOS, True),
    (["src/repocache/server_derived_catalog_candidate_v1.py"],
     True, impact.SCENARIOS, True),
    (["src/repocache/server_native_v2_transaction_v1.py"],
     True, impact.SCENARIOS, True),
    (["new/unclassified.py"], True, impact.SCENARIOS, True),
    ([".github/workflows/client-native-fallback.yml"], True, impact.SCENARIOS, True),
    (["scripts/ci_pr237_booted_vm.sh"], True, impact.SCENARIOS, True),
    ([], True, impact.SCENARIOS, True),
])
def test_selection(paths, client, scenarios, activation):
    actual = impact.select([("M", path) for path in paths])
    assert (actual.client, actual.scenarios, actual.activation) == (
        client, scenarios, activation)


@pytest.mark.parametrize("status", ["D", "R100", "T", "U", "?"])
def test_uncertain_change_always_full(status):
    assert impact.select([(status, "README.md")]) == impact.full("non-add-modify-change")


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()


@pytest.fixture
def repository(tmp_path):
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.name", "Test")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    (tmp_path / "README.md").write_text("base")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-m", "base")
    return tmp_path, git(tmp_path, "rev-parse", "HEAD")


def commit(root, name):
    git(root, "add", "-A")
    git(root, "commit", "-m", name)
    return git(root, "rev-parse", "HEAD")


def decide(root, base, head, event="pull_request", target="integration/v0.6.0",
           source="feature/isolated"):
    return impact.decide(event, base, head, target, source, root)


def test_complete_git_diff_and_manual_override(repository):
    root, base = repository
    path = root / "scripts/ci_pr237_native_socket_guest.py"
    path.parent.mkdir()
    path.write_text("fixture")
    head = commit(root, "test fixture")
    assert decide(root, base, head).scenarios == ("native-installer", "native-lifecycle")
    assert decide(root, base, head, event="workflow_dispatch") == impact.full("manual-or-non-pr-campaign")
    assert decide(root, base, head, target="release/v0.6.0").scenarios == impact.SCENARIOS
    assert decide(root, base, head, target="main", source="integration/v0.6.0").scenarios == impact.SCENARIOS


def test_deletion_and_rename_are_not_hidden(repository):
    root, base = repository
    (root / "README.md").rename(root / "SECURITY.md")
    head = commit(root, "rename")
    assert decide(root, base, head).scenarios == impact.SCENARIOS


def test_stale_base_wrong_head_and_invalid_ref_fall_back(repository):
    root, base = repository
    git(root, "switch", "-c", "feature")
    (root / "README.md").write_text("feature")
    head = commit(root, "feature")
    git(root, "switch", "main")
    (root / "README.md").write_text("base update")
    moved = commit(root, "base update")
    git(root, "switch", "feature")
    for old, new in [(moved, head), (base, moved), ("--help", head),
                     ("0" * 40, head)]:
        assert decide(root, old, new).scenarios == impact.SCENARIOS


def test_large_diff_not_truncated(repository):
    root, base = repository
    for i in range(310):
        (root / f"fixture-{i:03}.txt").write_text("fixture")
    head = commit(root, "many paths")
    assert len(impact.git_changes(base, head, root)) == 310
    assert decide(root, base, head).scenarios == impact.SCENARIOS

def test_new_symlink_and_executable_mode_change_are_full(repository):
    root, base = repository
    (root / "SECURITY.md").symlink_to("README.md")
    head = commit(root, "symlink")
    assert decide(root, base, head).scenarios == impact.SCENARIOS
    (root / "README.md").chmod(0o755)
    changed = commit(root, "mode")
    assert decide(root, head, changed).scenarios == impact.SCENARIOS
