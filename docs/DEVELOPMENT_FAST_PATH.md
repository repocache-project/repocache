# REPOCACHE development fast path

**Default for normal development.** The protected `main` version is authoritative only after merge. This is the short operational checklist; `AGENTS.md`, `DEVELOPMENT_WORKFLOW.md`, `PR_REVIEW_GOVERNANCE.md`, the original issue and live GitHub rulesets remain binding where additional detail is needed.

## 1. Deliver a usable increment

1. Read current `AGENTS.md`, the active issue's accepted criteria and the live base/overlapping PRs **once per session**; refresh only changes that matter.
2. Implement the smallest *useful* complete change in an existing issue. Prefer one independently acceptable PR, not speculative child issues or deep stacked PRs. Prioritize an installable v0.6.0 and close real issue criteria before starting v0.7.0 work.
3. Run meaningful local/component tests; resolve failures; update affected English documentation with the behaviour change. Move directly to the PR and next approved task rather than stopping at checkpoints.
4. Let required CI run; inspect failed or missing jobs and the actual source/acceptance. For fully accepted ordinary `integration/vMAJOR.MINOR.PATCH` changes, apply the harmonized PR #245 conditional authority after exact-SHA verification, without fresh routine issue-level approval. Use direct protected squash merge if no live queue rule applies; serialize merges and revalidate when the base moves. Main/release/tag/sign/publish/ruleset/queue changes still need separate explicit authorization.
5. Use the existing issue checklist for the complete criteria and link one concise source/CI evidence record in the PR. Update only on a material change. Keep unrun booted VM and genuine signed-release requirements **NOT VERIFIED**, not PASS.

**Owner-signing boundary (option C, 2026-11-22):** Complete Stage-A development and Stage-B functional/native VM evidence without requesting the maintainer's official release signature. Use only disposable, isolated test keys to exercise the real signature-verification and install/repair/recovery protocols in development; never disable verification, install test anchors in production, or treat test-signed bytes as publisher-approved. For #31, evaluate the five installation/idempotency/rollback/foreign-state/recovery criteria with real booted Debian 13 and AlmaLinux 10 evidence, independent of #76/#88 owner-key publication evidence. The owner signs the frozen, reviewed final release candidate under Stage C, **before** its real signed-candidate acceptance and publication; #76/#88 and public release gates still require genuine owner-key evidence and separate authorizations.

## 2. Extra tests follow the impact

| Change | Additional evidence beyond protected required CI |
| --- | --- |
| Documentation, comments, formatting | Relevant static/document contract checks. No unrelated optional client/NGINX smoke by default |
| Normal feature, bug or interface | Focused changed-component tests, negative/regression tests and compatible CLI/API contract checks |
| Privileged installer/writer, NGINX/systemd/SELinux, TLS, APT/DNF, recovery or signed trust | Relevant fault-injection, fail-closed, rollback and boundary tests on both target distros; real booted host and/or publisher proof when required |

**All nine required checks remain unfiltered**, including `merge_group` triggers. Main-only dependency security and milestone checks remain live. Optional component-specific `pull_request` smoke workflows may use conservative path filters but keep manual dispatch, and any change with cross-component risk must trigger or manually run the relevant optional smoke before approval. Never rely solely on changed filenames to infer safety. For a release candidate run the complete appropriate acceptance suite regardless of normal PR optimisations.

## 3. Handoffs and backlog

Record just **branch/base/HEAD, what passed (link), what failed or remains unverified, and next action**. Disclose substantive AI assistance in the PR (see `CONTRIBUTING.md`), without inventing human reviews or independent test provenance. No duplicate full test transcripts, speculative progress reports, or per-stage comments. Evidence at a different SHA/environment is a starting point, not automatically a PASS.

**Delivery focus (maintainer decision, 2026-11-25):** at most two active engineering streams (server and client for v0.6.0), plus one exceptional auxiliary stream for testing, integration or a demonstrable critical-path blocker. A stream owns a useful deliverable through implementation, acceptance and integration; waiting for CI does not free its slot. Inspect existing PRs for overlapping work, finish before starting, and record the next action in the current PR only. Park existing v0.7.0 feature work without closing, retargeting or discarding it; start no new v0.7.0 features until v0.6.0 is delivered. A blocked integration does not authorize a new feature or a security waiver. Routine dependency maintenance remains separate and is prioritized only when relevant to approved delivery or security.

Prefer stock Linux/NGINX capabilities and remove proven duplication incrementally where tests establish unchanged accepted behavior. Do not rewrite the system or change CLI, privilege/trust, compatibility, architecture or release contracts implicitly. Use the existing issue checklist and exact-head evidence. Respect the live queue configuration and preserve all protected checks and queue-compatible workflow triggers. Keep GitHub as the sole backlog and handoff record; no parallel administrative tracking system.

For v0.6.0, finish CI-verifiable implementation first. Run one coordinated Debian 13 / AlmaLinux 10 (SELinux enforcing) booted-host campaign for the assembled, exact installable candidate; use reusable QEMU/KVM CI where faithful, and do not ask the maintainer for redundant manual tests. Genuine owner-held signing, tag and publication remain separate protected stages.

**Success metric:** issues fully accepted and a working server tested end to end, not PR count, comment volume or synthetic milestone progress. Monitor time to merge, optional-workflow execution volume, stale PR count and regressions after integration.
