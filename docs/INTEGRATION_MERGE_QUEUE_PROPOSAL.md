# Proposed serialized integration merge queue (NOT ACTIVE)

Status: **proposal / preparatory CI only**. This document does not supersede the protected `main` governance, authorize any merge, or change a GitHub ruleset.

## Maintainer-approved scope to prepare

The maintainer authorized preparing conditional automatic merges **only for `integration/v*`** on 2026-11-03. `release/v*`, `main`, signing, tags, publication, production activation, destructive operations and ruleset changes remain subject to separate explicit authorization. Until a separately reviewed governance change becomes effective and activation is explicitly authorized, each merge still requires permission for the exact PR/HEAD.

## Required design before activation

1. Preserve all nine existing strict required checks, protected PR-only changes, no force pushes/deletions, and resolved review discussions. No check may be inferred successful from a skipped, neutral, missing or stale run.
2. Enable `merge_group` on all three unfiltered required workflows: `tests.yml`, `offline-wheelhouse.yml`, `upgrade-distros.yml`. The proposed trigger changes do **not** enable Merge Queue.
3. Evaluate a dedicated, exact-branch ruleset for `integration/v0.6.0`: the existing wildcard integration ruleset does not itself establish queue eligibility. Confirm GitHub plan/feature availability and interactions with overlapping rulesets before changing settings.
4. Configure merge queue with build concurrency **1**, minimum and maximum merge group size **1**; verify that each merge-group SHA is checked after earlier queue entries and that failures stop integration.
5. **Fail closed on acceptance:** a green CI alone is not an eligibility decision. An independently enforced, source-bound eligibility check must verify original applicable issue/PR acceptance criteria, actual PASS evidence, dependencies, security findings, unresolved discussions, correct target branch and exact HEAD. FAIL or mandatory NOT VERIFIED must prevent queue admission. Design the check against untrusted PR bodies/comments and stale attestations; use least-privilege credentials and protect the gate from PR-controlled code.
6. Never auto-enqueue a PR merely because its checks are green. Define a trusted eligibility/approval signal and revoke it on head changes, base changes, newly discovered blockers or changed acceptance scope.
7. Exclude pre-existing open PRs from automatic admission until reassessed under the adopted policy. Keep `release/*` and `main` manual.
8. Run a disposable pilot on an explicitly approved integration lane and verify event delivery, nine job contexts, ordering, queue failure handling, stale head invalidation and post-merge state. Record exact SHA and logs. Roll back the queue setting if acceptance fails.

## Preparatory acceptance

- PASS (source inspection): the three mandatory workflow sources use stable, unfiltered required job names and read-only contents permission.
- PASS (source inspection): the preparatory change adds `merge_group` without modifying publication workflows, rulesets, branch protection or existing required contexts.
- NOT VERIFIED: execution of `merge_group` checks on GitHub, until the live pilot.
- NOT VERIFIED: plan support, effective ruleset interactions, safe trusted eligibility enforcement and automatic queue admission.
- NOT VERIFIED: reduction in redundant CI runs and serial merge behavior until measured during a pilot.

## Activation boundary

A future PR must update `AGENTS.md`, `docs/DEVELOPMENT_WORKFLOW.md`, `docs/PR_REVIEW_GOVERNANCE.md` and related milestone guidance consistently, and specify when standing conditional merge authorization takes effect. It must not silently activate itself or retroactively approve PRs. Ruleset changes and initial production queue activation require a distinct maintainer decision.
