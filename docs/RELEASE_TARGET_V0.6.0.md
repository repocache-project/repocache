# Next public release — v0.6.0 complete server

**Product decision:** Approved by the maintainer in the project conversation on 2026-11-02: **do not publish an intermediate v0.5.0; the next public REPOCACHE version is targeted at v0.6.0** and must install and operate a complete working caching server. This document records the approved routing decision and existing criteria; inclusion in a PR does not itself demonstrate readiness, authorize integration, or amend security/acceptance requirements.

**Authoritative tracking:** [server provisioning #25](https://github.com/teixemf/repocache/issues/25), [real signed candidate #76](https://github.com/teixemf/repocache/issues/76), [offline Release Operator #88](https://github.com/teixemf/repocache/issues/88), [release acceptance policy](RELEASE_ACCEPTANCE_POLICY.md), [development workflow](DEVELOPMENT_WORKFLOW.md). The superseded historical v0.5.0 inventory is preserved in [RELEASE_SCOPE_V0.5.0.md](RELEASE_SCOPE_V0.5.0.md). Re-check live issues/PRs, protected `main`, effective rulesets and execution logs before making a gate decision.

## Release definition: what must work

A release is NOT ready merely because the CLI starts, unit tests pass or the installer can interact with an already configured NGINX instance. On **fresh Debian 13 and AlmaLinux 10**, a verified owner-signed release must support:

1. **Server installation and lifecycle** — safe read-only preflight, approved native package/service provisioning, managed filesystem ownership, repeatable install/upgrade/repair, transactional activation and known-good recovery without adopting or destroying third-party host state.
2. **Real repository caching** — administrator-controlled creation, inspection, enable/disable/removal of supported APT/DNF repositories from validated metadata/configuration without a source-code rebuild; safe upstream DNS changes, TLS hostname verification and pin refresh; generated allowlisted NGINX routes and strict prevention of open-proxy/SSRF exposure.
3. **Durable operation** — storage and repository identity persistence, bounded cache retention/capacity policy, accurate monitoring, logs and rotation; permission isolation, systemd/SELinux boundaries, controlled NGINX validation/reload, TLS/network configuration and recovery after interruption, disk pressure or configuration conflicts.
4. **Atomic client discovery and opt-in usage** — publish only repositories whose routes are successfully activated and validated. Preserve `repocache-client check`, `repos list`, `repos submit` and `repos sync`; `repos sync` remains read-only by default, and any `--apply` must be explicitly requested, safely reversible and tested for direct-upstream APT/DNF fallback.
5. **Operational acceptance** — actual native-target clean-install, metadata and package transfer, repeated verified cache HIT, install-repeat, update, rollback, crash/failure and security-negative tests, plus reproducible English operating documentation. Distinguish booted systemd/SELinux evidence from disposable distro containers.

The v0.6.0 goal is **CLI-first**. Existing TUI behavior/privacy must not regress, but implementing every planned TUI screen is not an independent release gate. User-controlled administrator repository management is core; optional authenticated HTTPS Repository Requests production enablement and automatic post-approval activation are not.

## Existing v0.6.0 functional work (no new feature scope)

| Responsibility | Tracked in existing issues |
| --- | --- |
| Install contract, preflight, native NGINX/systemd, server provisioner | #18, #26, #27, #25 |
| Repository identity/lifecycle, validated NGINX routes and active-only discovery | #95, #28 |
| Durable cache/storage/logs/policies and transactional rollback | #29, #31, #97 |
| TLS/network safety and least-privilege NGINX validation/reload | #30, #64 |
| Client reversible APT/DNF integration and CLI compatibility | #24, #107 |
| Actual both-distro deployment acceptance and operating documentation | #19, #20 |

Each remains open until its **original** applicable acceptance criteria have executed evidence on the correct source and host/target. Partial inert previews, synthetic fixtures, green CI or PR creation are not operational PASS. Coordinate with ongoing PRs and merged changes; do not duplicate or bulk merge stacked work.

## Carry-forward release gates — mandatory, not waived

**#76 and #88 were moved intact from milestone v0.5.0 (#2) to v0.6.0 (#4) on 2026-11-02.** Historic v0.5.0-specific command examples, previous checkpoints and draft plans are preserved for provenance, **not** treated as evidence of a built, tested or signed v0.5.0 candidate.

- The version transition to prove is **immutable public v0.4.0 -> genuine final owner-signed v0.6.0**, *not* a synthetic or unpublished v0.5.0 upgrade. Examine the immutable v0.4.0 source-member inventory, first-party wheel/module provenance, update compatibility policy and real install/repair/rollback; a static source-to-wheel assertion alone is insufficient.
- Preserve **all seven original #76 criteria** and the separately transferred **#74-G4** requirement: owner-approved genuine post-Node24 `release.yml` dispatch on exact reviewed version/tag, successful `unsigned-release-candidate` upload, independent artifact/hash/source identity readback and explicit maintainer acceptance of that evidence *before signing*.
- Preserve **every original #88 criterion**: owner-only Release Operator, encrypted PEM identity, protected passphrase FD, permissions, idempotency/refusal/recovery, correct CLI/JSON/exit behavior, native test evidence, and genuine stage/status/publish checks. Already merged native pre-signing coverage (PR #211) is not a substitute for candidate-dependent execution.
- The approved **owner-held Ed25519 signed legacy schema-1/offline-wheelhouse, eight-asset path** remains the default compatibility baseline. There is **no automatic adoption** of the unmerged source-only/online-dependency profile tracked for v0.7.0 in #79/#83/#84/#85/#112. If an actual v0.6 installer cannot use the existing approved profile, document the incompatibility and obtain a separate security-reviewed owner decision *before* changing artifacts, runtime installation, signatures or acceptance.
- Genuine final-candidate Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 clean install, v0.4.0 upgrade, repair, recovery, rollback, signature/permission/negative tests, exact asset provenance/digests and immutable postpublication public smoke remain mandatory. Current synthetic CI cannot certify these.
- **Only candidate-dependent #88 checks** may be completed with #76 during/after the actual signed-candidate sequence, per the existing narrow maintainer exception. All independently verifiable operator/source prerequisites must PASS first. Any applicable FAIL or NOT VERIFIED gate blocks release.

## Excluded from v0.6.0 without scope change

- #49 production activation of the optional HTTPS Repository Requests listener and #96 automatic activation following approval (v0.7.0). Preserve disabled-by-default intake and existing approval/audit protections; no request or approval may directly create an active NGINX route.
- #94 advanced priority-aware eviction (optional research), #10 advanced migrated-state downgrade research, #21 additional disposable bootstrap mode, #53 independent installed-runtime attestation, and new online/source-only dependency activation (#79/#83/#84/#85/#112). Their **existing nondeferrable** safety, migration and signed-release compatibility obligations still apply wherever relevant.
- Production deployment itself, changes to branch protections, immutable public releases or private signing-key operations are separately authorized actions, not results of PR integration.

## Order and definition of done

1. **Integrate core source safely:** reconcile current `main`, the protected integration lanes, merged preparatory work and overlapping open PRs for #18/#26/#27/#28/#29/#31/#64/#95/#97. No mass retarget, forced merge or duplicate implementation.
2. **Complete the operational system:** native packages and NGINX service, secured repositories, auto-DNS refresh, persistent cache and state, TLS, controlled reload, CLI lifecycle, active-only catalog, opt-in client sync and rollback.
3. **Prove installed functionality:** use the exact packaged candidate on clean Debian 13 and AlmaLinux 10. Fetch authentic test repository metadata and package payloads through the server, repeat requests and measure verified cache reuse, validate APT/DNF fallback, native service controls and failure/recovery on both targets.
4. **Freeze and review final versioned v0.6.0 source:** preserve genuine public-v0.4.0 upgrade compatibility and all exact-revision checks. Version labels or a milestone percentage are not readiness evidence.
5. **Execute #76/#88 genuine release gates** in the separately approved sequence: exact reviewed source/version -> authorized tag -> authorized `release.yml` Node24 dispatch and independently verified unsigned artifact -> explicit G4 evidence acceptance -> separately approved local signing -> separately approved Draft staging -> real signed-candidate acceptance -> exact-byte drift check -> separately approved publication -> public immutable smoke.
6. **Only when all applicable criteria PASS:** record exact SHA, distro/host type, run IDs, asset hashes and evidence in the original issues. FAIL/NOT VERIFIED blocks the relevant merge or publication. No signing key in Actions, no CI-driven publication, no unsanctioned production activation.

## Roadmap housekeeping and concurrency

- Historic v0.5.0 milestone issues and associated PRs are **history**, not evidence that an intermediate public release shipped. Do not delete the milestone, tag, branch or archived evidence to make counts look complete.
- Open PR #139 is a historical test-only cross-PR integration branch targeting an obsolete feature-branch base; do **not** merge it as an independent v0.6 deliverable. Open PR #173 addresses documentation for already closed #157; handle its distinct documentation evidence without blindly retargeting or double-merging. PR #211 has already merged.
- Server development continues in existing issues and focused PRs; in particular avoid overlapping parallel work in protected state (#31), safe DNS/NGINX (#28) and repository reconciliation (#95).
- This decision authorizes roadmap/issue-milestone alignment and ordinary preparatory development only. **Each merge, tag, release dispatch, private-key signature, Draft asset stage, publication, branch-protection modification or production activation requires its own specific maintainer authorization.**
