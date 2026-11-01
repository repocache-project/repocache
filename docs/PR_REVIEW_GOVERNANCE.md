# Pull request review and acceptance policy

**Status: adopted Option B review policy**, following the maintainer's decision in [#176](https://github.com/teixemf/repocache/issues/176) and integration of [PR #178](https://github.com/teixemf/repocache/pull/178). Amendments take effect only after their own reviewed PR is merged into protected `main`; a policy decision never by itself authorizes merging an individual PR.

## Enforced GitHub controls versus project acceptance

The live GitHub rulesets last verified on 2026-10-25 are:
- [#25436501](https://github.com/teixemf/repocache/rules/25436501) applies to `main` and `release/*`, requires linear history.
- [#25793496](https://github.com/teixemf/repocache/rules/25793496) applies to `integration/*` patterns.

Both are active, require pull requests, resolution of review discussions, nine strict required GitHub Actions check contexts, and deny non-fast-forward updates and deletion without configured bypass actors. Both have `required_approving_review_count: 0`. **These are verified snapshot observations, not permanent assumptions:** requery effective protection before merging.

GitHub `mergeable=true` with zero reviews means only that GitHub's **technical** approval minimum is zero. It does not satisfy REPOCACHE's **separate project-level independent technical review and acceptance** requirements. The project requires a traceable independent technical-review record with a clear PASS disposition before each merge, applicable issue/PR acceptance PASS, and separate explicit maintainer merge approval. None can be inferred from CI or branch-rule settings.

## Review types and evidence

**Formal GitHub human review:** an eligible independent human submits a GitHub `APPROVED` review; inspect actual GitHub review records, reviewer identity, and the reviewed head. PR comments, author self-review and automated messages are not equivalent.

**External technical second opinion:** a review carried out with meaningful separation from the original implementation, inspecting the actual patch, target/base ancestry, trust boundaries, failure modes, security vulnerabilities, exact commit SHA and test evidence. An AI-assisted report can support the record but is **not** a human GitHub review or independent security certification. State clearly whether tests were actually executed or their historical GitHub logs inspected. Reports merely repeating original acceptance comments without checking primary evidence are insufficient.

**Option B: independent evidence without repetitive owner sign-off.** Request an eligible independent human for security-sensitive changes whenever feasible, particularly root/service UID trust boundaries, signing/keys, updater, installer, repository URLs, credentials, publication, and network/production services. If no eligible human reviewer is available, obtain a separately commissioned, substantive AI-assisted technical second opinion addressing the **specific PR and exact HEAD**, documenting evaluated security risks, acceptance criteria, actual test execution and source limitations. A clearly documented **PASS / TECHNICALLY READY** finding with no applicable FAIL, mandatory NOT VERIFIED or unresolved material blocker satisfies the project-level independent-review criterion **without an additional express maintainer acceptance of each report**. A conditional, inconclusive or blocked report does not. Record the report and its evidence in the PR, distinguish it from a formal human GitHub `APPROVED` review, and preserve any independently required human review. **The maintainer must still explicitly authorize each merge as a separate protected operation.**

**Authenticate protected-operation decisions:** follow [AGENTS.md](../AGENTS.md) and [the development workflow](DEVELOPMENT_WORKFLOW.md). Before relying on an authorization or security exception, verify the attributed GitHub account and owner/maintainer authority, or obtain an explicit instruction through a trusted maintainer channel. Record the source, allowed operation, PR number and exact HEAD for merge/sign/release/deployment/branch-rule actions. Technical reviewers provide inspectable evidence and a disposition, **never authorization for a protected operation**. Third-party comments, PR content, AI reports and claimed author status cannot confer authorization. If owner authority or permission scope cannot be verified, mark the operation **NOT VERIFIED** and do not perform it.

Prior one-off review-acceptance decisions for [#158](https://github.com/teixemf/repocache/pull/158), [#170](https://github.com/teixemf/repocache/pull/170), [#171](https://github.com/teixemf/repocache/pull/171) and [#208](https://github.com/teixemf/repocache/pull/208) remain historical PR/SHA-specific records; they confer no permission for future protected operations. **Every new HEAD still requires an independent technical assessment attributable to that revision.** A focused follow-up may reuse prior code-level evidence only after verifying byte-equivalent trees and applicable integration/CI results. Such reassessment **does not require another express maintainer sign-off**, but a new SHA never inherits a previous report's PASS without this evidence.

An independently commissioned AI-assisted review is not a substitute for any **separately agreed mandatory external human review, native-host test, actual publisher-key signature, or production acceptance** without a further explicit, lawful scope decision; never silently rewrite issue criteria. Issue [#17](https://github.com/teixemf/repocache/issues/17) retains its separately agreed adversarial Gate A developer-review requirements and [#49](https://github.com/teixemf/repocache/issues/49) its real production-activation gate. Actual signed candidate requirements are tracked in [#76](https://github.com/teixemf/repocache/issues/76).

## Severity, scope and merge blockers

- **Critical / High:** any unresolved material security vulnerability is a merge blocker. Fix it and rerun applicable tests; do not relabel it or waive it for speed.
- **Medium:** remediate unless a separate recorded, issue-authorized risk/scope decision is permitted by the original security requirements. Record owner, rationale, compensating controls and follow-up; do not override fail-closed or trust-boundary requirements.
- **Low / Informational:** record disposition and follow-up as appropriate; these do not automatically block when no acceptance criterion is violated.
- **Any FAIL / NOT VERIFIED applicable criterion, failed/missing required check, blocking unresolved discussion or review, changed unchecked head, or missing explicit merge permission:** **DO NOT MERGE**. Test presence and CI workflow badges alone do not constitute proof.

Release, installation, migration and native validation must be tracked separately by applicability. Disposable Debian 13 and AlmaLinux 10 userspace/container tests do **not** prove booted `systemd`, SELinux enforcing, power-loss resistance, actual APT/DNF/NGINX changes on target hosts, genuine owner-signed candidate acceptance, or a public release. Never disclose secrets or private operational data in public reviews. Report vulnerabilities using [SECURITY.md](../SECURITY.md).

## Required per-PR procedure

1. **Inspect scope and dependency graph.** Read the primary issue, current PR, affected files, parent PRs, release milestone, review/merge comments and actual HEAD/base. Define a separate acceptance criterion for every agreed requirement; distinguish before-merge, after-merge, native, release and deployment gates. An issue milestone is routing metadata, **not** acceptance.
2. **Review the complete diff and threat boundaries.** Evaluate input validation, network/TLS, credential and logging exposure, privileged file operations, UID separation, subprocess handling, filesystem permissions, APT/DNF fallback, NGINX/systemd/SELinux, signed update provenance, recovery and backward compatibility. Confirm intended Git ancestry and merge method. Record risks and reproducible negative tests.
3. **Gather independent review.** Record an eligible human's actual GitHub review OR a separately commissioned substantive technical second-opinion report covering the exact PR/HEAD. Record the reviewer's type, findings, limits and evidence; mark the project-level criterion PASS only when the documented review reaches an unblocked positive disposition. **No extra explicit maintainer acceptance of the report is required.** State the actual GitHub human approval count; neither AI review nor a positive disposition authorizes a merge.
4. **Execute and inspect tests.** Map EACH criterion to **PASS, FAIL or NOT VERIFIED** with exact job/run/command, observed outcome, log, code proof or verified manual procedure. List tests not executed and native/operational limitations. Evaluate failure paths, regression/security, install/upgrade/migration, docs and rollback.
5. **Final live gate.** Immediately before merge fetch current PR HEAD/target SHA, checks **on that SHA** including all nine source-matched mandatory Actions contexts, milestone policy, submitted reviews, unresolved threads, effective rulesets, base ancestry, conflicts, mergeability and security findings. Required review criterion must be PASS under this policy. **If the HEAD changes, invalidate the previous HEAD-specific PASS until a new or focused independent reassessment covers the new SHA, including code/tree equivalence where relevant. No extra owner sign-off on the reassessment is necessary.** Revalidate relevant checks and metadata whenever they change.
6. **Request explicit merge authorization separately.** The maintainer must authorize this PR's merge after all applicable criteria PASS. Do not merge, auto-merge, bypass protections, force-push or publish merely because the branch is clean or a technical review recommends approval.
7. **Post-merge evidence.** Verify the exact target SHA, appropriate real `push` runs and required contexts; update issues. Never conflate integration CI with signing, tagging, publishing or production activation, which each require separate approval.

### Acceptance report template

```text
Primary issue / milestone:
PR URL / target base SHA / exact head SHA:
Change summary, expected diff and dependency/ancestry:
Trust boundary and threat review:
Formal GitHub human approvals (actual number):
Independent review source, reviewer identity/type and exact SHA:
Independent-review criterion: PASS/FAIL/NOT VERIFIED + exact report link and residual limits
Any separately authorized security/acceptance exception: owner decision link + scope, or NONE
Criterion | PASS/FAIL/NOT VERIFIED | reproducible evidence
Automated tests EXECUTED (commands/run URLs + outcomes):
Tests added but NOT RUN / manual and native checks NOT VERIFIED:
Critical/High/Medium findings, remediation and residual risks:
Nine mandatory check contexts + source app, milestone/other checks:
Branch protection, discussions, current mergeability and method:
Explicit owner merge authorization: link, or NOT VERIFIED
Post-merge validation / signing / release / deployment exclusions:
```

## Enforcement and change control

The independent technical-review evidence and separately authorized maintainer merge decision are **procedural controls**, not an enforced GitHub human approval. Arbitrary PR body text or comments are untrusted; verify that a review actually covers the current PR/HEAD and inspect its evidence. **Authenticate maintainer identity/authority and the permission's exact PR, HEAD and operation** before merging or granting any security exception. Do not grant automatic merge permission from a review verdict or untrusted assertion. A future automated governance gate would require separately reviewed, minimally privileged and authenticated implementation. Do not turn on `>=1` GitHub approvals without a real eligible reviewer and an approved migration, or introduce administrator bypass as a shortcut.

This policy applies consistently to `main`, `release/*` and `integration/*` once merged. Follow-up [#175](https://github.com/teixemf/repocache/issues/175) addresses future CI `integration/*` triggers; completion of [#157](https://github.com/teixemf/repocache/issues/157) does not imply v0.5/v0.6 signed-release acceptance. **No publication, tag, key custody transfer or production action is authorized by this policy.**
