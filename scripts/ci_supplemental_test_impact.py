"""Conservative optional development CI selection, never a merge gate.

Only explicitly reviewed isolated paths can narrow the campaign. Unknown,
shared, deleted, renamed, malformed or stale-base changes select everything.
The original acceptance criteria and mandatory workflows are independent.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SCENARIOS = ("smoke", "native-installer", "native-lifecycle",
             "native-package-interruption")
SHA = re.compile(r"[0-9a-f]{40}\Z")
ROOT = Path(__file__).resolve().parents[1]

# These are private fixture or client-only modules, not shared packaging,
# installer, trust, dependency, API, CI, or deployment infrastructure.
CLIENT_RUNTIME = frozenset({
    "client/" + name + ".py" for name in (
        "entry_approval_plan_sandbox", "entry_atomic_sandbox",
        "entry_candidate_sandbox", "entry_transaction_stage_sandbox",
        "managed_registry_sandbox", "native_fallback_plan",
        "native_package_lock_observation", "recoverable_fallback_pair_lab",
        "repocache_client", "root_source_boundary", "source_entry_boundaries",
        "source_helper_preview", "source_metadata_lab", "source_preflight",
        "source_structure_subset", "transaction_atomic_lab",
        "transaction_metadata_sandbox", "transaction_stage",
    )
})
CLIENT_FIXTURES = frozenset({
    "scripts/" + name + ".py" for name in (
        "ci_client_native_fallback", "ci_compiled_native_fallback",
        "ci_dnf_signed_rpm_fallback", "ci_v06_vm_client_cli_guest",
        "ci_v06_vm_client_privileged_guest", "ci_v06_vm_signed_client_guest",
        "smoke_client_atomic_sandbox", "smoke_client_entry_acl_atomic",
        "smoke_client_entry_approval_plan", "smoke_client_entry_atomic",
        "smoke_client_entry_candidates", "smoke_client_entry_stage",
        "smoke_client_helper_preview", "smoke_client_managed_registry",
        "smoke_client_native_held_package_locks", "smoke_client_recoverable_pair",
        "smoke_client_root_source_boundary", "smoke_client_source_metadata",
        "smoke_client_source_preflight", "smoke_client_transaction_metadata",
    )
})
CLIENT_TESTS = frozenset({
    "tests/" + name + ".py" for name in (
        "test_ci_dnf_signed_rpm_fallback", "test_client_active_catalog_trust",
        "test_client_native_package_lock_observation",
        "test_client_recoverable_fallback_pair", "test_client_root_source_boundary",
        "test_client_source_metadata_lab", "test_v06_vm_client_privileged_guest",
        "test_client_transaction_stage",
    )
})

# The server runtime remains a broad native campaign. Only the independent
# client container labs can be omitted for these specifically reviewed files.
# A change to public catalog semantics, shared core, TLS trust, release or
# install machinery is intentionally not in this list.
SERVER_PRIVATE = frozenset({
    "src/repocache/" + name + ".py" for name in (
        "server_native_installed_storage_v1", "server_native_nginx_effective_unit_v1",
        "server_native_nginx_package_journal_v1", "server_native_v2_transaction_v1",
        "server_root_control_full_context_v1", "server_root_control_worker_v1",
    )
}) | frozenset({
    "tests/" + name + ".py" for name in (
        "test_native_nginx_safe_activation_v1", "test_server_native_installed_storage_v1",
        "test_server_native_nginx_package_journal_v1", "test_server_native_v2_transaction_v1",
        "test_server_root_control_full_context_v1", "test_server_root_control_units_v1",
        "test_server_root_control_worker_v1",
    )
})

# Only scenario-local VM fixture edits can omit the other native scenarios.
# Do not classify the common shell harness or any signed-worker assembly here.
SERVER_FIXTURES = {
    "scripts/ci_pr237_native_socket_guest.py": ("native-installer",),
    "scripts/ci_v06_native_repository_lifecycle_guest.py": ("native-lifecycle",),
    "scripts/ci_pr237_native_package_interrupt_guest.py": ("native-package-interruption",),
    "scripts/ci_native_nginx_activate_guest.py": ("activation",),
    "scripts/ci_v06_vm_nginx_cache_guest.py": ("smoke",),
    "scripts/ci_v06_vm_cache_eviction.py": ("smoke",),
    "scripts/ci_v06_vm_cache_pressure_guest.py": ("smoke",),
    "scripts/ci_v06_vm_owned_storage_guest.py": ("smoke",),
}
# Documentation tied to a specific existing scenario is deliberately not
# treated as proof; it still requests that scenario on its exact HEAD.
SCENARIO_DOCS = {
    "docs/testing/PR237_BOOTED_VM.md": ("native-installer",),
    "docs/testing/SERVER_V06_NATIVE_LIFECYCLE_VM.md": ("native-lifecycle",),
    "docs/testing/SERVER_VM_NATIVE_CACHE_EVICTION.md": ("smoke",),
    "docs/testing/SERVER_NATIVE_INSTALLED_STORAGE_V1.md": ("activation",),
    "docs/architecture/SERVER_NATIVE_NGINX_PACKAGES_V1.md": (*SCENARIOS, "activation"),
}
CLIENT_DOCS = frozenset({
    "docs/CLIENT_PRIVILEGED_HELPER_CONTRACT.md",
    "docs/CLIENT_RECOVERABLE_FALLBACK_PAIR.md",
    "docs/CLIENT_ROOT_SOURCE_BOUNDARY.md",
    "docs/testing/CLIENT_NATIVE_HELD_PACKAGE_LOCKS.md",
})
PLAIN_DOCS = frozenset({
    "README.md", "CONTRIBUTING.md", "SECURITY.md", "AGENTS.md",
    "docs/DEVELOPMENT_WORKFLOW.md", "docs/DEVELOPMENT_FAST_PATH.md",
    "docs/PR_REVIEW_GOVERNANCE.md", "docs/TESTING.md",
})


@dataclass(frozen=True)
class Selection:
    client: bool
    scenarios: tuple[str, ...]
    activation: bool
    reason: str


def full(reason: str) -> Selection:
    return Selection(True, SCENARIOS, True, reason)


def select(changes: list[tuple[str, str]]) -> Selection:
    if not changes:
        return full("empty-or-unavailable-diff")
    client = False
    activation = False
    scenarios: set[str] = set()
    for status, path in changes:
        if status not in ("A", "M"):
            return full("non-add-modify-change")
        if path in CLIENT_RUNTIME or path in CLIENT_FIXTURES or path in CLIENT_TESTS:
            client = True
            scenarios.add("smoke")
        elif path in SERVER_PRIVATE:
            scenarios.update(SCENARIOS)
            activation = True
        elif path in SERVER_FIXTURES or path in SCENARIO_DOCS:
            impact = SERVER_FIXTURES.get(path, SCENARIO_DOCS.get(path, ()))
            scenarios.update(s for s in impact if s in SCENARIOS)
            activation |= "activation" in impact
        elif path in CLIENT_DOCS or path in PLAIN_DOCS:
            continue
        else:
            return full("shared-or-unclassified-change")
    return Selection(client, tuple(s for s in SCENARIOS if s in scenarios),
                     activation, "reviewed-path-impact")


def git_changes(base: str, head: str, root: Path = ROOT) -> list[tuple[str, str]]:
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        raise ValueError("invalid revision")
    def git(*args: str) -> bytes:
        return subprocess.run(
            ["git", *args], cwd=root, check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=60,
        ).stdout
    if git("rev-parse", "HEAD").strip().decode("ascii") != head:
        raise ValueError("checkout mismatch")
    # Strict branch protection requires an updated base. Until then use a
    # complete campaign rather than assuming the merge-side delta is safe.
    git("merge-base", "--is-ancestor", base, head)
    raw = git("diff", "--no-renames", "--name-status", "-z", base, head, "--")
    if not raw or not raw.endswith(b"\0"):
        raise ValueError("missing or malformed diff")
    fields = raw[:-1].decode("utf-8", errors="strict").split("\0")
    if len(fields) % 2 or any(not field for field in fields):
        raise ValueError("malformed diff")
    return list(zip(fields[::2], fields[1::2]))


def decide(event: str, base: str, head: str, base_ref: str,
           head_ref: str, root: Path = ROOT) -> Selection:
    if event != "pull_request":
        return full("manual-or-non-pr-campaign")
    if (base_ref.startswith("release/") or head_ref.startswith(("release/", "integration/"))
            or base_ref not in ("main",) and not re.fullmatch(r"integration/v\d+\.\d+\.\d+", base_ref)):
        return full("release-or-unknown-ref")
    try:
        return select(git_changes(base, head, root))
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        return full("diff-unverified")


def main() -> None:
    selection = decide(
        os.environ.get("IMPACT_EVENT", ""), os.environ.get("IMPACT_BASE", ""),
        os.environ.get("IMPACT_HEAD", ""), os.environ.get("IMPACT_BASE_REF", ""),
        os.environ.get("IMPACT_HEAD_REF", ""),
    )
    # Only closed constant values are written to Actions outputs/summary.
    # Use a valid dormant matrix when the VM job is not selected.
    values = {
        "client": str(selection.client).lower(),
        "vm": str(bool(selection.scenarios)).lower(),
        "scenarios": json.dumps(selection.scenarios or ("smoke",)),
        "activation": str(selection.activation).lower(),
    }
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        for name, value in values.items():
            print(f"{name}={value}", file=stream)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        print("### Supplemental CI selection", file=stream)
        print(f"Reason: {selection.reason}", file=stream)
        print(f"Client container labs: {'selected' if selection.client else 'not selected'}", file=stream)
        print("Native VM scenarios: " + (", ".join(selection.scenarios) or "not selected"), file=stream)
        print(f"Dedicated NGINX activation: {'selected' if selection.activation else 'not selected'}", file=stream)
        print("Unselected tests are not PASS evidence. Required checks and all original applicable acceptance remain mandatory.", file=stream)


if __name__ == "__main__":
    main()
