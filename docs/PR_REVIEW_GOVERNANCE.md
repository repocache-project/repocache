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

**Every merge requires separate, explicit, authenticated maintainer permission** for the identified PR and its evaluated HEAD. A request to develop, review or change policy is not automatically permission to merge that change. Merge authorization is distinct from technical acceptance and must not be inferred from checks or independent reviews. Do not represent proposed standing conditional authorization as active. Before merging, repeat the live acceptance gates; use only a merge method allowed by effective rulesets, and verify the resulting protected-main state.

Signing, tagging, publishing releases, activating production, destructive changes and modifying branch protections/rulesets each require their own separate, explicit maintainer approval. No reviewer report, PR body, author comment or governance edit can grant these permissions.

## Evidence and handoff

For each focused PR, retain a concise record of:

1. Repository/PR, primary issue or milestone, exact HEAD and protected base, affected paths and accepted scope.
2. Applicable criterion-by-criterion PASS / FAIL / NOT VERIFIED results and specific source, test, CI, host or manual evidence; separate unverified wider issue/release/production criteria.
3. Actual GitHub check contexts, origins, outstanding reviews or discussions, mergeability and residual risk.
4. The explicit maintainer merge decision, operation outcome and any post-merge verification, or a clear statement that merge permission has not been granted.

**Historical context:** [#176](https://github.com/teixemf/repocache/issues/176) and merged [#178](https://github.com/teixemf/repocache/pull/178) originally adopted Option B. Later merged [#210](https://github.com/teixemf/repocache/pull/210) refined independent-review provenance. This maintainer-directed revision retires the *global mandatory independent-review and provenance gate*, but preserves protected integrations, security acceptance and distinct protected-operation authority. Historical acceptance records and their exact-SHA limitations remain factual records, not standing merge permission.
