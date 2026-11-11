# Acceptance stages — CI implementation, native hosts and release evidence

**Scope:** every maintainer-selected milestone and release (`vMAJOR.MINOR.PATCH`),
including future releases; no version-specific exception is implied.
**Status:** proposed repository-wide policy until accepted on protected `main`.
This process stages delivery and evidence; it does not narrow the accepted
product, OS, CLI, security, compatibility, rollback or release requirements.

## Separate the deliverable from the final deployment proof

**Stage A — implementation acceptance in CI.** Organize work into the smallest
independently useful, reviewable increment of an existing issue. Complete code,
negative/security tests, applicable real APT/DNF or NGINX work in disposable
Linux environments, compatibility, rollback and deterministic integration
checks. Use exact source HEAD, parent/base, current rulesets and every
required/applicable GitHub check. A source-only helper, sandbox transaction,
staged release candidate or non-activating policy module may be integrated
*only if its own explicitly approved, bounded acceptance criteria all PASS*.
It must not expose an unverified privileged/write/production path. Never use
"CI-only" to rename an incomplete live feature into a PASS.

**Stage B — system-level/native acceptance.** For release and feature criteria
that intrinsically require a booted host, perform a coordinated **final**
Debian 13 and AlmaLinux 10 (SELinux enforcing where relevant) campaign on the
assembled, exact, installable candidate. Test actual systemd/NGINX/TLS,
least-privilege installed files and worker, native APT/DNF source changes,
signed package metadata, cache HIT/miss and upstream fallback, restart,
same-version repair, concurrency, power/interruption recovery and foreign
ownership refusal as applicable. GitHub-hosted distro containers are useful
Stage-A evidence, never a substitute for booted VM evidence. If an approved
feature can be completely and faithfully proven in CI, do not require a
redundant VM gate; if a VM is inherently needed, mark it NOT VERIFIED until
run. A booted VM may itself be orchestrated by suitably equipped CI; what
matters is the faithful native environment, not who hosts it.

**Stage C — independent security and publisher acceptance.** Preserve every
original issue-specific mandatory reviewer/owner decision, real private-key
Ed25519 signing outside CI, exact signed candidate verification, authorized
staging/tag/publishing and immutable public readback/postpublication smoke.
Neither Stage A nor Stage B automatically authorizes Stage C. These steps
occur only when their genuine inputs and separately required permissions exist.

## Reusable milestone algorithm

1. Check the protected default branch, original issue criteria, existing PRs,
   actual code, selected release and its current dependency graph. Do not
   invent milestone scope or an already approved production writer.
2. For each requirement, record its **evidence owner**: A (executable in CI),
   B (booted/native system acceptance), C (owner/review/signing/publication),
   or A+B/C where applicable. Record exact observable PASS conditions.
3. Track CI-only independently accepted increments in their existing focused
   PRs; keep a wider parent issue OPEN until its own full criteria PASS.
   If an existing PR mixes independently separable code with unachievable
   host-only acceptance, isolate the safe increment with the least disruptive
   scoped branch/PR change; preserve provenance and dependency/order.
   Do **not** bulk rewrite or retarget stacked branches.
4. Bring the **complete functional code** to Stage A: write the privileged
   install/apply and native fallback mechanisms, integrate them and execute
   available security, package manager, failure-injection and end-to-end CI.
   Deferral of VM testing is **not** deferral of this implementation work.
5. Before asking for VM work, freeze an installable candidate and runbook:
   exact source SHA/asset digests, fixture provenance, install/repair/rollback,
   OS/kernel/systemd/SELinux commands, expected outcomes, negative cases and
   redacted machine-readable logs. Consolidate overlapping native tests into
   one release campaign; carry results back to every affected original issue.
6. After the final booted/native campaign, resolve any FAIL by implementing
   and retesting in CI first, then rerun only impacted native checks. Perform
   separately authorized publisher/release gates, close complete issues and
   the milestone only when all their original mandatory criteria are PASS.

**Evidence states:** PASS = executed at the required environment and exact
revision; FAIL = verified defect; NOT VERIFIED = missing/stale/wrong-environment
test, missing review or absent approval; NOT APPLICABLE = a requirement
explicitly superseded by an authenticated maintainer decision, with provenance.
A VM-only requirement is not a PR Stage-A criterion *only where the
maintainer-approved scope of that PR genuinely excludes native activation*.
An original issue may remain NOT VERIFIED while its safe prerequisite PR
is integrated. Never silently reclassify an applicable criterion to avoid
a merge gate.

## Integration, queue and protected operations

Every Stage-A PR still needs full scoped source/security review, its own
original applicable criteria PASS, exact source/base/check identity,
dependencies, required checks and no blocking risks or review threads.
The current [PR governance](PR_REVIEW_GOVERNANCE.md) controls conditional
`integration/vMAJOR.MINOR.PATCH` merge delegation and queue admission.
An active native queue or green checks are not self-authorization.
Issue-specific independent security review and maintainer merge approval
remain mandatory where agreed. Main/release merges, unusual scope/security
changes, native queue pilots/rulesets, tags, signing, staging, publication,
production or destructive operations retain their separate authorizations.

Do not create an issue or PR solely to hold Stage-B evidence if an existing
release installation/testing issue can own it. Do not claim a milestone is
complete because many small CI PRs merged; a complete operational release
still needs every applicable original B/C criterion. Keep all code, PR,
review and acceptance records in English; identify exact SHA and environment.
