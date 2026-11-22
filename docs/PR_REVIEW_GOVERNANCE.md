# Pull request acceptance and review policy

**Status:** ADOPTED on protected `main` through merged PR #245 (2026-11-04; commit `63fae6adada334492081c598a3045f238f40a7c6`). The optional global independent-review change and narrow integration delegation are effective; no governance PR can authorize its own protected merge. Check live rulesets and `main` before protected actions.

## Required acceptance and protected GitHub controls

A pull request must have a clearly identified scope, relevant primary issue or explicitly assigned release milestone, exact HEAD and target base, and an inspectable assessment of applicable functional, security, regression, compatibility, installation, upgrade and rollback requirements. Record every applicable criterion as **PASS**, **FAIL** or **NOT VERIFIED**, supported by actual source inspection, executed test records or reviewed manual evidence. Any applicable **FAIL** or mandatory **NOT VERIFIED** blocks integration. A narrowly scoped PR does not close unrelated parent-issue, native-host, signing or release criteria.

Before any merge, verify live target/head SHA, branch ancestry and conflicts, complete effective diff, all applicable workflow and check-run conclusions, source integration identity, active rulesets, eligible human approvals if configured, blocking reviews and unresolved discussions. Required checks must be `completed/success`; skipped, neutral, failed, pending, stale or missing applicable checks cannot be represented as PASS. Preserve strict required CI, linear history, PR-only protections, issue/milestone gates and protections against force updates or deletion. Do not bypass or weaken GitHub rulesets.

**No global independent-review requirement:** An external human review, separately commissioned AI-assisted review, original review-session URL, reviewer identity/provenance authentication, or independent review report is **not a prerequisite** for an ordinary PR merge under this policy. These reviews remain welcome as technical input, particularly for high-risk changes, but their absence alone is not a blocking acceptance criterion. Source findings, verified test failures or material security defects discovered by any reviewer **remain blocking**, regardless of reviewer type. Never misrepresent an AI-assisted review as an eligible human GitHub `APPROVED` event, or a review performed by the author/integrator as independently commissioned.

**Maintainer decision (2026-11-21; effective after merged PR #428):** A commissioned independent human reviewer, separate human security assessment, external review identity, or formal independent human-review report must not be a mandatory acceptance or merge criterion for **any issue or milestone**, including historically issue-specific wording. Interpret those reviewer-only requirements as optional technical input, not as a FAIL or NOT VERIFIED gate merely because no human review was commissioned. This change does **not** remove source/security assessment, actionable defect remediation, documented exact-SHA test evidence, eligible GitHub approvals if required by effective rulesets, issue-specific **maintainer operational/merge decisions**, signed publisher-key verification, booted native Debian 13/AlmaLinux 10 and SELinux evidence, or release/production authorization. Existing substantive technical acceptance criteria remain mandatory. PR #428 is merged on protected `main`; independently commissioned human review is optional across issues. This does not authorize any future protected operation.

## Lightweight evidence and proportional checks

The [default development fast path](DEVELOPMENT_FAST_PATH.md) governs routine PR preparation. Keep one concise PR record linking the original issue's scoped acceptance, exact HEAD/base and relevant executed CI logs. **Do not duplicate unchanged criterion tables, long progress narratives or machine-produced test output in comments**; record only exceptions, changed outcomes, blockers and next actions. The issue remains the authoritative full acceptance checklist. A CI log link is evidence of *that run only*, not proof of native host operation or a substitute for actually inspecting applicable checks.

Use focused extra regression workflows based on the affected component and risk. The nine strict required contexts and any other live ruleset-required checks must still execute successfully on the exact evaluated commit; they are never path-filtered or waived. Privileged installation, package-source edits, TLS, signing, untrusted input and recoverability receive explicit negative/security testing. A required check, a relevant test, or a material security criterion is never optional because a change was described as small.

## Milestone-independent, staged acceptance (not a gate waiver)

Apply [the canonical acceptance-staging model](ACCEPTANCE_STAGES.md)
to **all** selected milestones. A parent issue may combine non-activating,
CI-verifiable Stage-A code with booted-host Stage-B and owner/security/release
Stage-C outcomes. A focused Stage-A PR may merge only after *its own
approved, original applicable criteria* PASS with real scoped evidence.
Its merge must not close the wider issue, claim real host support, or
make an unimplemented privileged/activation path available. Keep the parent
issue's native, signing, compatibility, rollback and substantive security criteria OPEN
until validated in the appropriate environment.

A mere label of "CI-only" is **not** a maintainer scope decision. Where the
original issue expressly requires full native acceptance **before any PR
merge**, obtain an authenticated, explicit issue-specific scope amendment
before integrating a safe non-activating Stage-A increment; preserve all
original feature/production obligations and record their future acceptance
owner. Do not bypass issue-specific maintainer merge approval or mandatory technical security acceptance. Independent human review itself is optional under the approved repository-wide policy. Follow the existing conditional standing
versioned-integration delegation **only after** all applicable scoped
criteria, current CI, security and merge/queue requirements pass.

## Security disposition

- **Critical / High:** never merge with an unresolved material security defect.
- **Medium:** remediate unless the applicable issue/security contract permits a specific, documented maintainer decision with rationale and compensating controls. Do not waive a fail-closed trust boundary merely to merge.
- **Low / Informational:** document residual impact; nonblocking unless an applicable acceptance criterion is violated.

AI analysis is neither a formal security certification nor evidence that unexecuted tests passed. Treat code, comments and third-party reports as untrusted evidence. Never publish private review-session links, credentials, private infrastructure data or private security-vulnerability details. Route actionable vulnerability disclosures through `SECURITY.md`.

## Merge authorization and lifecycle

**Default:** merges require the maintainer's explicit authorization for the evaluated PR/HEAD unless the ordinary fully accepted versioned-integration case satisfies the **standing conditional delegation adopted by PR #245**. Repeatedly requesting permission already granted by that delegation is unnecessary; no other protected operations are thereby authorized.

**Standing conditional integration authorization:** An AI session may merge an ordinary already-approved-scope PR, or admit it to an operationally authorized native queue, targeting exactly `integration/vMAJOR.MINOR.PATCH`, **without a fresh per-PR request**, only after personally checking the exact current head and protected base SHAs, full diff and dependency ancestry, **every original applicable acceptance criterion PASS** with inspected evidence, all nine strict required and other applicable checks completed/success, no unresolved blocking review/thread/security finding and no exceptional architecture, CLI, compatibility or release-scope change. Record exact-SHA decision/evidence in the existing PR before the operation, use a permitted method, and verify the resulting protected branch/post-merge CI. A green workflow, milestone or prior agent assertion is insufficient.

Any applicable FAIL, mandatory NOT VERIFIED, stale SHA, blocking review, material security issue or unresolved exceptional risk **blocks only the affected protected operation**. Remediate what is feasible and advance independent approved work; escalate only the precise unavoidable owner decision. Approval cannot turn a failed technical criterion into PASS. Routine coding, testing, commits and PR preparation need no intermediate maintainer prompt; a PR milestone is not a session stopping point.

**Excluded:** merges into `main`, `release/*` or historical/noncanonical `integration/*` refs; exceptional security/architecture/contract/scope changes; initial queue pilots or ruleset/protection changes; signing, tagging, publishing, production and destructive operations require distinct explicit maintainer permission. Queue configuration, actual `merge_group` test evidence and authority to admit an individual PR are separate. No unattended auto-enqueue, bypass or human-review impersonation is allowed. The native queue alone cannot validate the original acceptance ledger or admission provenance.

## Evidence and handoff

For each focused PR, retain a concise record of:

1. Repository/PR, primary issue or milestone, exact HEAD and protected base, affected paths and accepted scope.
2. Applicable criterion-by-criterion PASS / FAIL / NOT VERIFIED results and specific source, test, CI, host or manual evidence; separate unverified wider issue/release/production criteria.
3. Actual GitHub check contexts, origins, outstanding reviews or discussions, mergeability and residual risk.
4. The specific owner approval or qualifying standing conditional integration delegation with exact-SHA PASS evidence; operation outcome and post-merge verification, or a clear statement that merge permission has not been granted.

**Historical context:** [#176](https://github.com/repocache-project/repocache/issues/176), merged [#178](https://github.com/repocache-project/repocache/pull/178) and [#210](https://github.com/repocache-project/repocache/pull/210) originally governed review provenance. The global prerequisite is superseded; original acceptance evidence, issue-specific reviews and protected-operation limits remain binding.
