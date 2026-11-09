# Native integration Merge Queue — observed configuration and operating limits

**Observed 2026-11-09:** live ruleset [#26753319](https://github.com/repocache-project/repocache/rules/26753319) is **active** for the exact `integration/v0.6.0` and `integration/v0.7.0` branches, alongside the existing strict integration protections. Three `merge_group` workflow runs on 2026-11-07 completed successfully (runs #42365689658, #42365689650 and #42365689685 on `8c43d6b1fefd101f46ffb8a199ceff2c82f7c957`). Negative-path rejection, full queue admission provenance and any separately required pilot acceptance remain **NOT VERIFIED** without further specific evidence. This observed configuration is not permission to change a ruleset, admit an unaccepted PR or claim release readiness.

## Supported lanes and current evidence (2026-11-04)

The protected `main` contains unfiltered `merge_group` triggers from merged
PR #239 (SHA `9654f946eebce0e85ba2ae1f926c418d9a0b55ec`).
The same three required workflow triggers have been merged into:
- `integration/v0.6.0` via PR #242, SHA
  `95fbdf34e719f0efcd448d7272f413781a6af5c7`.
- `integration/v0.7.0` via PR #243, SHA
  `9c5dc3d5c7a8d4fba2ca713f9cc04b0601632ffb`.

Both protected-branch HEADs had all **nine required check contexts**
`completed/success` on actual `push` runs:
- v0.6.0: Tests #41803222174, Offline wheelchain #41803221810,
  upgrade rehearsal #41803221888.
- v0.7.0: Tests #41803238611, Offline wheelchain #41803238612,
  upgrade rehearsal #41803238541.

Successful `merge_group` execution is now observed; failing-check rejection, admission provenance and any other unexecuted pilot criteria remain **NOT VERIFIED**.
The live integration wildcard protection ruleset #25793496 remains ACTIVE,
covering `integration/*` and `integration/**/*`, with nine required GitHub
Actions contexts, strict checks, PR-only updates and no force/deletion bypass.
Do not disable, relax, remove or replace that protection.

An audit of all 13 existing protected `integration/*` branches found only
v0.6.0 and v0.7.0 ready for `merge_group`. Eleven historical/work branches,
including `integration/v0.5.0`, do **not** have the required triggers.
Never activate a queue across these unprepared branches.

## Native queue target pattern: exact names, not `integration/v*`

GitHub documents that wildcard **branch protection** patterns cannot be
used to enable merge queues. GitHub also announced the same limitation for
repository Merge Queue rulesets (2024 public-beta changelog). Rather than
claim wildcard compatibility without an executed pilot, target **exact**
branch names in a new repository-level ruleset:

- `integration/v0.6.0`
- `integration/v0.7.0`

Do not target `integration/v*`: it would also match historical v0.5.0
branches that have no merge-group CI. Do not target `integration/*` or
`integration/**/*` for the queue, although the *existing protection*
ruleset must continue to cover them. Keep `main` and `release/*` excluded.

For a future `integration/vMAJOR.MINOR.PATCH` lane: create it from the
verified protected baseline containing all three triggers; inspect its own
exact HEAD, original acceptance/target milestone, nine mandatory contexts
and successful native push CI; **then add its exact name** to the queue
ruleset through a separately authorized ruleset change. This is not
automatic inheritance of queue activation.

Sources:
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue
- https://github.blog/changelog/2024-02-27-repository-rules-configure-merge-queue-rule-public-beta/

## Active queue configuration and separately authorized changes

The current active exact-branch queue ruleset #26753319 uses **squash**, single-entry build/merge limits, `ALLGREEN` grouping, a 60-minute check timeout and no bypass actors. The separate wildcard ruleset #25793496 remains active with nine strict required contexts and PR-only protection. Do **not** create, disable, retarget, modify or weaken either live ruleset without distinct maintainer authorization.

For any future lane, obtain separate ruleset-change approval only after its own `merge_group` triggers, required checks, target identity and acceptance gates are verified. Do not treat `integration/v*` as an eligible queue wildcard. Preserve the existing strict integration protection.

## Operator-controlled admission (conditional delegation adopted in PR #245)

GitHub Merge Queue **does not inspect the original issue acceptance
ledger** and does not guarantee that an actor has been explicitly authorized
to integrate a particular PR. Therefore admission remains a deliberate
operator-controlled, evidence-gated action under the applicable authorization:

1. A session reviews the *actual current* PR HEAD, target branch and base,
   full diff, all original applicable issue/PR criteria and dependencies,
   material security findings, unresolved reviews and all nine successful
   CI contexts from the trusted GitHub Actions source.
2. Report PASS / FAIL / NOT VERIFIED with inspectable evidence. Any
   applicable FAIL or mandatory NOT VERIFIED blocks admission. Mark the PR
   ready for review only if applicable acceptance is satisfied.
3. PR #245 merged into protected `main` on 2026-11-04. A responsible operator may use **standing conditional authorization** only for an ordinary already-approved-scope PR targeting exactly `integration/vMAJOR.MINOR.PATCH` with all original applicable criteria PASS, all strict required and other applicable CI checks successful for the correct revision, confirmed head/base and no exceptional security, architecture, compatibility, dependency, review or scope risk. Record exact-SHA evidence before admission. Do not request redundant permission for qualifying work; obtain specific permission for exceptions. Recheck when head/base changes.

4. The authorized operator chooses **Add to merge queue** in GitHub.
   **Never enable auto-enqueue based solely on green CI.** A GitHub
   collaborator's technical ability to enqueue is *not* maintainer
   authorization under this project policy.
5. GitHub synthesizes a `merge_group` commit and reruns the nine
   mandatory checks. Failed, missing, skipped or stale required check
   contexts must block the merge. GitHub then merges a successful
   group of size one into the chosen protected integration branch.
6. Confirm the merge on the protected branch and post-merge `push`
   checks, record the exact resulting SHA and CI run IDs. This does not
   authorize any release operation on `main` or `release/*`.

This is **operator-enforced authorization**, not an independently enforced
policy against every repository writer. A collaborator with GitHub write
access may be able to enqueue an otherwise eligible PR; the native queue
cannot prevent this *solely on the basis of an external human instruction*.
This residual governance risk must be explicitly accepted before production
activation. If technical enforcement of maintainer-only admission becomes
mandatory, revisit a separate trusted gate then; do not claim the current
native-only setup provides it.

## Remaining verification, future pilot and rollback

The ruleset is **active** and successful `merge_group` runs have been observed, but a completed success event alone does not prove failure rejection, full provenance, unobserved security tests or a complete separately approved pilot. These remain **NOT VERIFIED** until source-bound logs and exact-SHA evidence are inspected. Do not rerun a pilot solely because historical guidance labels the queue “NOT ACTIVE”.

For any separately authorized new pilot or ruleset adjustment, first snapshot **all six observed rulesets**, verify the existing nine mandatory contexts and exact target branches, validate eligible PR acceptance, merge-group and post-merge push checks and a safe rejection/timeout path without merging an unaccepted PR. If a safety gate fails, stop the affected queue operation, preserve existing strict protections, record FAIL/NOT VERIFIED and obtain specific authority for any live ruleset change or rollback. Signing, releases, production and destructive changes remain independently protected.
