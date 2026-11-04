# Integration Merge Queue — admission contract (PROPOSED / NOT ACTIVE)

**Scope:** every explicitly accepted \`integration/*\` integration lane, including nested
\`integration/**/*\` and future \`integration/vMAJOR.MINOR.PATCH\` release lanes.
This proposal does not activate a ruleset, create a standing merge permission, or
supersede protected \`main\` governance. \`release/*\`, \`main\`, signing, tags,
publication and production activation remain excluded.

## Why the GitHub Merge Queue is not an admission policy

GitHub's native queue validates the synthesized merge result against required
status checks, but **green checks do not prove all original issue requirements
have been accepted**. Anyone with write access may be able to enqueue an otherwise
eligible PR. Until a separate trusted eligibility gate is live, use only
*individual, explicitly maintainer-authorized admission for the exact PR/HEAD*.
Do not automatically enqueue existing open PRs or infer permission from milestone,
labels, ordinary comments, review badges, mock reports or green CI.

## Proposed eligibility contract (all mandatory, fail closed)

1. Canonical repository \`repocache-project/repocache\`, open/non-Draft/mergeable
   PR and exact current \`head_sha\`, target \`integration/*\` branch and
   \`base_sha\`. Read these from trusted GitHub API, not PR-supplied text.
2. The original **complete** applicable criteria inventory, sourced from
   approved protected specifications and authenticated maintainer amendments.
   Every mandatory criterion is \`PASS\` on the exact evaluated source revision
   with inspection/run/host evidence. \`FAIL\`, \`NOT VERIFIED\`, missing or duplicate
   criteria and unverifiable amendments are blocking.
3. All nine existing required GitHub Actions contexts report
   \`completed/success\` for that source SHA, with the expected GitHub App
   source. Missing, stale, \`skipped\`, \`neutral\`, pending and failure block.
4. No unresolved review threads, blocking review, material security finding
   or unaccepted dependency. Milestone and branch ancestry must be correct.
5. A **provenance-verified maintainer decision** explicitly binds repository,
   PR number, target, head SHA, base SHA and acceptance-source SHA. Neither a
   Boolean field nor an issue comment from an unverified author is proof of
   that identity. The trusted controller must authenticate the actor and
   authority via the GitHub API against a protected allowlist before producing
   the decision record.
6. Revoke admission on any head/base/specification change, new required check,
   dependency movement or newly identified blocker. The queue must check the
   latest PR/base again immediately before admission.
7. During \`merge_group\`, independently confirm the group SHA, target, exact
   included PR membership (group size one), parent base and all nine successful
   group-SHA checks. A PR-head result is **not** a merge-group result.
8. Any missing API permission, absent attestation, timeout, ambiguous author
   role, stale source or partial failure rejects admission. Never fall back to
   a weaker set of checks.

### Source and security boundary

\`scripts/ci/merge_queue_admission.py\` implements a **pure fail-closed evidence
validator**; \`tests/test_merge_queue_admission.py\` contains synthetic PASS
and rejection tests. This code is deliberately **not wired into a required
GitHub check or merge bot**. A JSON snapshot can be fabricated, including its
\`verified_provenance\` field: the validator does not authenticate it. An
enforcing controller must use trusted GitHub API reads, validate the actual
maintainer's author identity/permissions, load protected criterion definitions,
prevent PR-controlled workflows from spoofing its result, and publish an
exact-SHA check from a **distinct, trusted GitHub App identity** (not a job name
that PR code may imitate). The controller must itself be protected from
pull-request code and operate with least privilege.

**Do not activate a standing conditional merge authorization based on these
unit tests.** Until that independent controller is deployed and acceptance
evidence is verified on live GitHub, the gate remains **NOT VERIFIED** and
individual maintainer permission is required before a PR enters the queue.

## CI rollout / future versions

- Source preparation #239 supplies \`merge_group\` triggers on protected
  \`main\`; backports #242 and #243 supply the same to
  \`integration/v0.6.0\` and \`integration/v0.7.0\` after separate reviewed merges.
- Before queue activation on **any other** \`integration/*\` target, including
  existing historical 13-target wildcard matches, inspect its actual three
  required workflow files, the nine contexts and current base/HEAD. Do not
  assume another branch's workflow file is inherited.
- Every future \`integration/vX.Y.Z\` must be created from a verified
  protected baseline containing the three unfiltered \`merge_group\` triggers.
  When based on an older ancestor, port them by a small PR with CI and
  source-based mutation tests before enabling a queue on that lane.
- Keep both existing wildcard integration protection patterns and their
  nine strict required checks; verify whether a dedicated exact-branch
  ruleset is needed for native queue configuration on the GitHub plan.
  Do not widen the queue setting to historical work branches before these
  are explicitly assessed.
- On every candidate lane, use build concurrency 1, merge-group size
  minimum 1 / maximum 1 and **require all queue entries to pass required
  checks**. Respect each lane's merge method and protections. GitHub queues
  are per target branch, so this does not serialize across releases.

## Pilot and authority boundary

A separately authorized pilot must exercise a disposable PR, a failed
required check, a stale-head requeue, new baseline changes, missing attestation
and the merge-group SHA before claiming the queue is secure. Record all
required contexts and run IDs on the actual protected target revision.
Changing/activating rulesets, adopting standing merge authorization, merging,
deleting refs, and any release operation require independent maintainer
approval; this document and its tests approve none of them.

**Current status:** source-only evaluator and synthetic tests: implementation
prepared, operational trust and live queue enforcement: **NOT VERIFIED**.
