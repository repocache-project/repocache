# Proposed serialized integration merge queue (NOT ACTIVE)

Status: **proposal / preparatory CI only**. This document does not supersede the protected `main` governance, authorize any merge, or change a GitHub ruleset.

## Ownership and migration status (verified 2026-11-04)

**Organization transfer completed.** GitHub now identifies this public repository as
`repocache-project/repocache` (repository ID `1425889415`, owner type
`Organization`); `teixemf/repocache` redirects to it. The previous personal-account
availability blocker is **resolved**. GitHub documents native Merge Queue support for
public repositories owned by organizations. Do not confuse feature eligibility with an
activated or validated merge queue.

**Preserved state observed:** protected `main`, `integration/v0.6.0` and
`integration/v0.7.0`; five active repository rulesets, including the integration
wildcard ruleset with nine strict required job contexts; existing PR #239 and other
open PRs. The GitHub application installation for `repocache-project` now permits
writing preparatory code to the PR branch. This does not certify every external
integration, old hard-coded URL, secret, deploy key or Actions permission: investigate
those separately before operational activation.

**Remaining blockers:** queue protection is not configured, the existing wildcard
integration ruleset is not a native queue setup, the effective policy still requires
individual maintainer authorization, and admission and exact-SHA acceptance safeguards
are not implemented. Any existing PR must be individually assessed before enqueueing.
A green PR workflow does not alone grant permission to enter the queue.

**Prepare, do not activate:** this PR may supply the three `merge_group` workflow
triggers and static regression tests; subsequent, separately authorized work must
adopt the conditional authorization policy, select a compatible exact-branch queue
ruleset without weakening existing protections, and validate a real merge-group pilot.
Keep `main` and `release/v*` under individual authorization.

## Maintainer-approved scope to prepare

The maintainer authorized preparing conditional automatic merges **only for `integration/v*`** on 2026-11-03. `release/v*`, `main`, signing, tags, publication, production activation, destructive operations and ruleset changes remain subject to separate explicit authorization. Until a separately reviewed governance change becomes effective and activation is explicitly authorized, each merge still requires permission for the exact PR/HEAD.

## Required design before activation

1. Preserve all nine existing strict required checks, protected PR-only changes, no force pushes/deletions, and resolved review discussions. No check may be inferred successful from a skipped, neutral, missing or stale run.
2. Enable `merge_group` on all three unfiltered required workflows: `tests.yml`, `offline-wheelhouse.yml`, `upgrade-distros.yml`. The proposed trigger changes do **not** enable Merge Queue. Preparatory PR #239 was integrated into `main`; separate PRs #242 and #243 port the same changes to `integration/v0.6.0` and `integration/v0.7.0`. Every additional affected `integration/*` branch (including future versions) must contain all three triggers **on its own protected branch HEAD** before queue activation; a `main` change does not propagate them. Revalidate the actual merge-group revision and preserve all nine contexts.
3. Design queue targeting for all requested `integration/*` lanes, including nested `integration/**/*`, without activating it prematurely. The current integration wildcard ruleset matches historical working branches as well as release lanes, so check each affected branch and confirm GitHub's actual ruleset-versus-branch-protection wildcard support and interactions before changing settings. If exact-branch rulesets are necessary, explicitly cover `integration/v0.6.0`, `integration/v0.7.0` and each future version at creation. See the separately proposed `docs/MERGE_QUEUE_ADMISSION.md` source-bound admission contract; neither proposal grants auto-merge authority.
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
