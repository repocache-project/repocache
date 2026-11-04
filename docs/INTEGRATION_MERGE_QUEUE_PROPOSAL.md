# Native integration Merge Queue (PROPOSED — NOT ACTIVE)

Status: **proposal; NOT ACTIVE; queue pilot NOT VERIFIED**. This procedure does
not approve a PR, replace the existing acceptance contract or modify GitHub
protections. The goal is to serialize integrations using GitHub's **native**
Merge Queue and existing GitHub Actions. No additional application, service,
runner, secret or privately hosted infrastructure is required.

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

The actual `merge_group` event remains **NOT VERIFIED** until a live pilot.
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

## Maintainer-only GitHub setup (NOT APPLIED)

In repository `Settings > Rules > Rulesets`, create a repository-level
branch ruleset specifically for these two *exact* targets. Keep it
**Disabled** until a separately authorized controlled pilot is ready.

Configuration for the pilot:
- Rule: **Require merge queue**.
- Build concurrency: **1**.
- Minimum / maximum PRs per merge: **1 / 1**.
- Only merge non-failing queue entries: **enabled**.
- Merge method: **squash**, consistent with the already used protected
  integration merges; recheck permitted effective methods.
- Timeout: **60 minutes initially**, then tune from observed worst-case CI.
- Do **not** enable bypass actors or automatic enqueueing; do not add a
  different, weaker set of required statuses. Preserve the original
  wildcard ruleset with all nine strict required checks.
- Do not activate a second merge-queue rule on the same branch.
  Confirm cumulative ruleset behavior in a small live pilot before
  broad deployment.

GitHub's administrative UI is required for ruleset edits when the
available GitHub connector does not have repository administration access.
No queue activation has been attempted by this proposal.

## Operator-controlled admission (conditional delegation proposed; NOT ACTIVE until adopted)

GitHub Merge Queue **does not inspect the original issue acceptance
ledger** and does not guarantee that an actor has been explicitly authorized
to integrate a particular PR. Therefore admission remains a deliberate
maintainer-controlled action:

1. A session reviews the *actual current* PR HEAD, target branch and base,
   full diff, all original applicable issue/PR criteria and dependencies,
   material security findings, unresolved reviews and all nine successful
   CI contexts from the trusted GitHub Actions source.
2. Report PASS / FAIL / NOT VERIFIED with inspectable evidence. Any
   applicable FAIL or mandatory NOT VERIFIED blocks admission. Mark the PR
   ready for review only if applicable acceptance is satisfied.
3. Until the governance amendment is merged on protected `main`, obtain
   **separate explicit maintainer permission** for the PR and evaluated
   HEAD to enter the queue. After adoption, routine accepted-scope PRs
   targeting an exact `integration/vMAJOR.MINOR.PATCH` lane may use the
   maintainer's **standing conditional authorization** *only* after a
   responsible operator actively verifies every original criterion as
   PASS, all applicable CI as success, exact head/base identities and
   absence of architecture, security, scope or unresolved review risk.
   Exceptional cases require specific permission. Any changed PR head
   or base invalidates prior evidence; re-evaluate before clicking.
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

## Controlled live pilot and rollback (NOT VERIFIED)

After separate maintainer authorization to activate the exact-branch rule
and to integrate the designated disposable PR/HEAD:

1. Snapshot the five existing rulesets and exact nine required contexts.
   Confirm the rule targets only `integration/v0.6.0` and
   `integration/v0.7.0`, and has no bypass actors.
2. Enable the dedicated queue ruleset. Verify that normal PRs still
   require the existing nine GitHub Actions checks, approvals and
   discussion resolution applicable under the effective protections.
3. Enqueue one small, independently accepted pilot PR, with explicit
   maintainer authorization for **that exact HEAD**. Check the
   `merge_group` event, all nine successful job contexts from the
   expected GitHub Actions App on the synthesized SHA, the queue result,
   final branch SHA and protected-branch post-merge CI.
4. Verify a failing-check path **without merging an unaccepted PR** and
   confirm failed/timeout groups are not integrated; test stale-base
   revalidation where feasible. Do not intentionally compromise or
   force-update protected branches.
5. If checks do not execute, required contexts are missing, unrelated
   branches are targeted, protections change or queue acceptance cannot
   be verified, **disable the new queue ruleset immediately**, leave the
   existing wildcard protection intact and record FAIL / NOT VERIFIED.
6. If the GitHub UI rejects wildcard or cumulative ruleset behavior, keep
   only exact targets or create separate exact-branch rulesets. Never
   weaken the existing nine contexts to make a pilot pass.

**Authority boundary:** this proposal grants no authority to merge itself or
activate a queue rule. The future standing integration-merge delegation is
conditional on the governance amendment being separately reviewed and
merged on protected `main` and applies only to fully accepted routine
`integration/vMAJOR.MINOR.PATCH` PRs. The initial pilot and activation,
exceptional merges, bypass, release tagging/signing/publishing, deployment
and destructive changes remain separately authorized.
