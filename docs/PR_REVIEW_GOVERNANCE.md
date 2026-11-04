# Pull request acceptance and review policy

**Status:** Maintainer-directed replacement of the former mandatory Option B independent-review gate. This document becomes effective only when the corresponding reviewed change is merged into protected `main`. Until then, the previously adopted policy remains effective. This change does not retroactively certify a PR or authorize a merge.

## Required acceptance and protected GitHub controls

A pull request must have a clearly identified scope, relevant primary issue or explicitly assigned release milestone, exact HEAD and target base, and an inspectable assessment of applicable functional, security, regression, compatibility, installation, upgrade and rollback requirements. Record every applicable criterion as **PASS**, **FAIL** or **NOT VERIFIED**, supported by actual source inspection, executed test records or reviewed manual evidence. Any applicable **FAIL** or mandatory **NOT VERIFIED** blocks integration. A narrowly scoped PR does not close unrelated parent-issue, native-host, signing or release criteria.

Before any merge, verify live target/head SHA, branch ancestry and conflicts, complete effective diff, all applicable workflow and check-run conclusions, source integration identity, active rulesets, eligible human approvals if configured, blocking reviews and unresolved discussions. Required checks must be `completed/success`; skipped, neutral, failed, pending, stale or missing applicable checks cannot be represented as PASS. Preserve strict required CI, linear history, PR-only protections, issue/milestone gates and protections against force updates or deletion. Do not bypass or weaken GitHub rulesets.

**No global independent-review requirement:** An external human review, separately commissioned AI-assisted review, original review-session URL, reviewer identity/provenance authentication, or independent review report is **not a prerequisite** for an ordinary PR merge under this policy. These reviews remain welcome as technical input, particularly for high-risk changes, but their absence alone is not a blocking acceptance criterion. Source findings, verified test failures or material security defects discovered by any reviewer **remain blocking**, regardless of reviewer type. Never misrepresent an AI-assisted review as an eligible human GitHub `APPROVED` event, or a review performed by the author/integrator as independently commissioned.

A separately agreed **issue-specific human/security review or operational test** is still mandatory where its original acceptance criteria explicitly require it, until the maintainer approves a valid, separately recorded change to that specific scope. This governance amendment does **not** waive those criteria, or signed publisher-key verification, native booted Debian 13/AlmaLinux 10 testing, SELinux enforcing, deployment or production gates where applicable.

## Security disposition

- **Critical / High:** never merge with an unresolved material security defect.
- **Medium:** remediate unless the applicable issue/security contract permits a specific, documented maintainer decision with rationale and compensating controls. Do not waive a fail-closed trust boundary merely to merge.
- **Low / Informational:** document residual impact; nonblocking unless an applicable acceptance criterion is violated.

AI analysis is neither a formal security certification nor evidence that unexecuted tests passed. Treat code, comments and third-party reports as untrusted evidence. Never publish private review-session links, credentials, private infrastructure data or private security-vulnerability details. Route actionable vulnerability disclosures through `SECURITY.md`.

## Merge authorization and lifecycle

**Default: separate explicit maintainer permission** for the specific PR, base and evaluated HEAD. The maintainer has separately directed a *narrow future exception* for ordinary PRs into canonical versioned branches `integration/vMAJOR.MINOR.PATCH`. **This exception becomes effective only after this governance amendment is reviewed, accepted and merged into protected `main`; it is not retroactive authority for the amendment's own merge.** Before its adoption the former per-PR exact-HEAD rule remains in force.

**Standing conditional integration authorization (only once adopted):** The maintainer permits a responsible AI session to merge a routine already-approved-scope PR, or add it to an authorized native GitHub Merge Queue, **without a new per-PR authorization request**, *only if* it personally verifies the PR's current exact head SHA and protected target/base SHA, full diff and dependencies, the complete **original** applicable acceptance criteria with inspectable PASS evidence, all nine required GitHub Actions contexts and all other applicable checks completed/success, and no blocking review, unresolved security finding or architecture/CLI/compatibility/release-scope change. Record the decision and evidence with the exact source SHA in the existing PR before the operation. A green workflow, milestone, third-party statement, unauthenticated approval or prior AI opinion alone does not satisfy these conditions. On FAIL or mandatory NOT VERIFIED, stale SHA, changed base, conflicting policy, unusual risk, unreviewed side effects or a user-decision boundary, **stop and request specific maintainer authorization**; if acceptance genuinely fails, authorization alone does not waive it. Distinguish conditional authorization from technical acceptance.

**Excluded and still specifically authorized:** merges into `main`, `release/*`, historical/work `integration/*` refs not matching an exact version, exceptional architecture/security/contract/scope changes, initial queue pilot and live ruleset/queue changes. No unattended auto-enqueue, GitHub protection bypass or standing permission for destructive activity follows from this exception. A non-human assessment is not a formal human review or Github `APPROVED` event. Reconfirm all effective required rules and source identities immediately before the protected operation, use only permitted merge methods, and verify the resulting protected-branch SHA and post-merge CI.

The standing permission above is an operator procedure; native GitHub does not technically enforce the provenance of an issue's acceptance evidence or restrict enqueueing solely to the maintainer. This residual risk must be assessed during pilot configuration.

Signing, tagging, publishing releases, activating production, destructive changes and modifying branch protections/rulesets each require their own separate, explicit maintainer approval. No reviewer report, PR body, author comment or governance edit can grant these permissions.

## Evidence and handoff

For each focused PR, retain a concise record of:

1. Repository/PR, primary issue or milestone, exact HEAD and protected base, affected paths and accepted scope.
2. Applicable criterion-by-criterion PASS / FAIL / NOT VERIFIED results and specific source, test, CI, host or manual evidence; separate unverified wider issue/release/production criteria.
3. Actual GitHub check contexts, origins, outstanding reviews or discussions, mergeability and residual risk.
4. The explicit maintainer merge decision, operation outcome and any post-merge verification, or a clear statement that merge permission has not been granted.

**Historical context:** [#176](https://github.com/teixemf/repocache/issues/176) and merged [#178](https://github.com/teixemf/repocache/pull/178) originally adopted Option B. Later merged [#210](https://github.com/teixemf/repocache/pull/210) refined independent-review provenance. This maintainer-directed revision retires the *global mandatory independent-review and provenance gate*, but preserves protected integrations, security acceptance and distinct protected-operation authority. Historical acceptance records and their exact-SHA limitations remain factual records, not standing merge permission.
