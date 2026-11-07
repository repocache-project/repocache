# Native Merge Queue v0.7.0 — isolated pilot evidence

Status: **NOT VERIFIED — awaiting separate pilot merge authorization**.

This documentation-only change provides a disposable, narrowly scoped PR
for an actual `merge_group` delivery test on protected
`integration/v0.7.0`. It does not alter application behavior, security
controls, release scope, required check names or GitHub settings.

## Source and acceptance contract

- Baseline: `integration/v0.7.0` at
  `9c5dc3d5c7a8d4fba2ca713f9cc04b0601632ffb` when this PR was created; recheck the live base SHA
  before any future queue admission.
- Effective diff must be exactly this Markdown file. No production code,
  workflows, policies or metadata outside the PR are changed.
- The existing `Protect integration branches` ruleset (#25793496)
  must remain active, with all nine strict required GitHub Actions
  contexts, PR-only updates, discussion resolution and no bypass.
- The separately configured `Merge queue - version integrations`
  ruleset (#26753319) may be enabled only with maintainer authorization.
  It must target exact v0.6.0 and v0.7.0 lanes and group only one PR.
- The PR must remain **Draft** until its exact HEAD, current protected
  base, full diff, milestone and original applicable acceptance evidence
  are independently rechecked. A successful PR-head run is not proof of
  merge-group success.

## Real merge-group test procedure (not yet executed)

1. Confirm approval for **this exact PR HEAD** to enter the queue and
   produce a merge into `integration/v0.7.0`. The maintainer's
   separate initial-pilot merge authorization is mandatory.
2. Verify the real PR-head run has all nine existing protected checks
   completed/success, issued by GitHub Actions (App ID 15368).
3. Remove Draft only after the acceptance gate has PASS evidence.
   Add to the native Merge Queue; do not bypass branch protection.
4. Record the `merge_group` event and **synthetic merge-group SHA**.
   Confirm all nine contexts complete successfully on that SHA, not
   merely on the PR source SHA. Record workflow run IDs and duration.
5. Verify the queue merges one PR by squash into the protected target,
   then record the resulting branch SHA and post-merge `push` checks.
6. Independently test the failed/missing-check rejection path without
   ever integrating an unaccepted or intentionally unsafe change.
7. If source checks, queue checks, branch targeting or cumulative
   protection behavior fail, disable **only** the dedicated queue rule;
   do not weaken or modify the original integration protection.

## Evidence ledger

| Mandatory observation | Result | Exact evidence |
| --- | --- | --- |
| Original baseline and effective diff | NOT VERIFIED | Recheck at pilot admission |
| PR-head nine required checks | NOT VERIFIED | Run IDs and source SHA pending |
| Maintainer authorization for this pilot merge | NOT VERIFIED | Separate explicit decision required |
| Real merge-group event and group SHA | NOT VERIFIED | Awaiting pilot |
| Nine required checks on group SHA | NOT VERIFIED | Awaiting pilot |
| Queue single-PR merge and post-merge CI | NOT VERIFIED | Awaiting pilot |
| Negative path rejects unsafe/unverified admission | NOT VERIFIED | Awaiting controlled test |
| Existing protection preserved after pilot | NOT VERIFIED | Recheck rulesets |

This pilot is a CI/governance validation aid only; it is not evidence
that a release is signed, native Debian 13 or AlmaLinux 10 host testing
was executed, or production deployment is authorized.
