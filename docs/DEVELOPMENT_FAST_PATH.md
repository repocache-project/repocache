# REPOCACHE development fast path

**Default for normal development.** The protected `main` version is authoritative only after merge. This is the short operational checklist; `AGENTS.md`, `DEVELOPMENT_WORKFLOW.md`, `PR_REVIEW_GOVERNANCE.md`, the original issue and live GitHub rulesets remain binding where additional detail is needed.

## 1. Deliver a usable increment

1. Read current `AGENTS.md`, the active issue's accepted criteria and the live base/overlapping PRs **once per session**; refresh only changes that matter.
2. Implement the smallest *useful* complete change in an existing issue. Prefer one independently acceptable PR, not speculative child issues or deep stacked PRs. Prioritize an installable v0.6.0 and close real issue criteria before starting v0.7.0 work.
3. Run meaningful local/component tests; resolve failures; update affected English documentation with the behaviour change. Move directly to the PR and next approved task rather than stopping at checkpoints.
4. Let required CI run; inspect failed or missing jobs and the actual source/acceptance. For fully accepted ordinary `integration/vMAJOR.MINOR.PATCH` changes, apply PR #245 conditional authority after exact-SHA verification. Main/release/tag/sign/publish/ruleset/queue changes still need separate explicit authorization.
5. Use the existing issue checklist for the complete criteria and link one concise source/CI evidence record in the PR. Update only on a material change. Keep unrun booted VM and genuine signed-release requirements **NOT VERIFIED**, not PASS.

## 2. Extra tests follow the impact

| Change | Additional evidence beyond protected required CI |
| --- | --- |
| Documentation, comments, formatting | Relevant static/document contract checks. No unrelated optional client/NGINX smoke by default |
| Normal feature, bug or interface | Focused changed-component tests, negative/regression tests and compatible CLI/API contract checks |
| Privileged installer/writer, NGINX/systemd/SELinux, TLS, APT/DNF, recovery or signed trust | Relevant fault-injection, fail-closed, rollback and boundary tests on both target distros; real booted host and/or publisher proof when required |

**All nine required checks remain unfiltered**, including `merge_group` triggers. Main-only dependency security and milestone checks remain live. Optional component-specific `pull_request` smoke workflows may use conservative path filters but keep manual dispatch, and any change with cross-component risk must trigger or manually run the relevant optional smoke before approval. Never rely solely on changed filenames to infer safety. For a release candidate run the complete appropriate acceptance suite regardless of normal PR optimisations.

## 3. Handoffs and backlog

Record just **branch/base/HEAD, what passed (link), what failed or remains unverified, and next action**. Disclose substantive AI assistance in the PR (see `CONTRIBUTING.md`), without inventing human reviews or independent test provenance. No duplicate full test transcripts, speculative progress reports, or per-stage comments. Evidence at a different SHA/environment is a starting point, not automatically a PASS.

Limit concurrent overlapping feature work to approximately two or three active PRs. First reconcile stale/stacked PRs against integration and the accepted release requirements; close or retarget only with appropriate authority, never discard unmerged unique changes. Keep Dependabot updates separate from feature delivery and review pinned signed dependency profiles before accepting updates.

For v0.6.0, finish CI-verifiable implementation first. Run one coordinated Debian 13 / AlmaLinux 10 (SELinux enforcing) booted-host campaign for the assembled, exact installable candidate; use reusable QEMU/KVM CI where faithful, and do not ask the maintainer for redundant manual tests. Genuine owner-held signing, tag and publication remain separate protected stages.

**Success metric:** issues fully accepted and a working server tested end to end, not PR count, comment volume or synthetic milestone progress. Monitor time to merge, optional-workflow execution volume, stale PR count and regressions after integration.
