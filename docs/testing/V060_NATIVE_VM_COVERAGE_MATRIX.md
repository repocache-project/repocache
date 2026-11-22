# v0.6.0 — native VM criterion coverage ledger (15 open issues)

**Generated from the live issue checklists on 2026-11-21 UTC.** This is a *coverage inventory*, not an acceptance certification. No row marked as PASS solely because a test exists. The original unchecked issue criteria stay unchecked.

**Source of truth:** `https://github.com/repocache-project/repocache/issues/<number>` (the actual current bodies); protected `main` observed `f64ea3ac91a308e13dfd6c18c4264f9b5c7e8beb`; assembled v0.6 integration observed `183aeb5b6dc7dccc66b22e444bd82922c007093e`; PR #237 experimental branch observed `9e1d4977ff1e814e20dec685b346c7a46db9de14` before this documentation change.

**Interpretation:** A=CI/implementation, B=booted native Debian 13 / AlmaLinux 10 x86_64 (SELinux enforcing on AlmaLinux), C=owner/publisher/release approval. A+B/C indicates multiple distinct gates. Every row is **NOT VERIFIED for full original acceptance** until attached evidence proves all applicable stages. `VM TEST EXISTS` means test source is present and some *historical* PR #237 six-scenario QEMU results were observed, **not** that the current exact HEAD passes. The six QEMU jobs at the latest PR head were still QUEUED when this ledger was created. In particular, synthetic Ed25519 test keys do not qualify as owner signatures.

## Execution campaigns (single reusable two-distro fleet, not a VM per issue)

| ID | Campaign | Issues | Order | Test boundary |
| --- | --- | --- | --- | --- |
| P0-1 | Installation / systemd / recovery | #19, #20, #26, #27, #31, #64 | 1 | Fresh signed-source install, stock NGINX, worker socket, package/reboot, rollback and foreign owner |
| P0-2 | NGINX / TLS / cache / storage | #28, #29, #30, #95, #97 | 2 | Native signed APT/DNF cache traffic, TLS/SELinux, metrics/logs, pressure, repository lifecycle |
| P0-3 | APT/DNF client / CLI | #24, #107 | 3 | Approved opt-in native source transaction, held locks, fallback and installed CLI |
| P0-4 | Owner-signed release / candidate | #76, #88 | 4 | Immutable exact candidate, real publisher identity, authorised staging and prepublication acceptance |
| P1-1 | Advanced isolation/security (v0.7) | #49, #53, #112, #149 | Later | Real kernel Bubblewrap and SELinux, security activation/integrity |
| P1-2 | Dependencies / migration / regression (v0.7) | #10, #21, #79, #83, #84, #85, #96 | Later | Signed online dependencies, schema/migration, CLI/TUI/rollback |

## Criterion-by-criterion evidence and missing work

**Coverage codes:** T = test scenario in the PR #237 booted-VM harness (incomplete original acceptance); R = existing disposable native-distribution *container* test; U = unit/parser CI; G = VM scenario absent/inadequate; I = blocked on substantive implementation; S = blocked on authentic owner-signed candidate/owner action; D = documentation/CI/procedure, not an inherently VM-dependent criterion. `T` and `R` never mean PASS.

### #19 — test: Verify clean REPOCACHE server deployment on Debian 13 and AlmaLinux 10
Issue: https://github.com/repocache-project/repocache/issues/19 · Campaign: **P0-1** · Source probes: `scripts/ci_pr237_booted_vm.sh`, `scripts/ci_pr237_native_socket_guest.py`, `scripts/ci_pr237_native_package_guest.py`, `scripts/ci_pr237_native_package_interrupt_guest.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 19.01 | All v0.6.0 Stage-A implementation PRs with applicable exact-HEAD CI, regression and security acceptance complete; audited dependency ancestry, no unresolved merge/review/security blockers | A | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 19.02 | Real clean-installable first-operational v0.6.0 artifacts and repeatable, non-destructive, self-checking VM runbook prepared; unsupported legacy installations refused and genuine external ownership preserved | A+B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 19.03 | Native operator test accounts, root-owned service credentials, TLS provenance, intended systemd NGINX service/socket units and installed REPOCACHE server/client transaction binaries staged under reviewed trust boundaries | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 19.04 | Final candidate profile, checksum and issuer fingerprint pinned so every observed VM result identifies exact bytes and source SHA; real owner signing/staging, when required, follows separately authorized release workflow | C | **S** | Use a genuine publisher-signed immutable candidate only under separately authorized owner workflow. |
| 19.05 | All preflight, APT/DNF, service, source-recovery, and fault-injection scripts have already been exercised wherever possible in CI | A | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 19.06 | Fresh supported OS boot, package-manager and kernel/SELinux details, exact artifact digest, installer output, root-owned file/package inventories, verified `nginx -t` and real `systemctl` running/restart statuses | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 19.07 | Root/normal-user permission boundary and unauthorized request refusal; actual TLS validation and restricted upstream/active-only catalog exposure | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 19.08 | Signed metadata and package retrieval by native APT/DNF, repeated NGINX cache HIT with hashes, isolated cache outage and automatically usable upstream fallback/recovery without weakening trust | B | **I** | Complete and integrate the approved production implementation, then exercise it in a VM. |
| 19.09 | Administrator opt-in `repos sync --apply`, repeated idempotent apply, untouched disabled/third-party sources, safe change restoration, native APT/DNF locking and fail-closed SELinux/ACL/xattr behavior | B | **I** | Complete and integrate the approved production implementation, then exercise it in a VM. |
| 19.10 | Live same-version reinstall/repair and interrupted write/reload recovery, preservation of certs/cache/logs/metrics, foreign NGINX refusal and unsupported OS no-write outcomes | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 19.11 | Reproducible per-criterion PASS / FAIL / NOT VERIFIED logs, commands, exact HEAD/candidate, booted-VM identity and final release acceptance link; no positive label based solely on container fixtures | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 19.12 | Both supported distributions have passing install and operational cache tests. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 19.13 | Build/publish pipeline fails if either distribution smoke test fails. | A | **I** | Complete and integrate the approved production implementation, then exercise it in a VM. |
| 19.14 | No external production endpoints, credentials or internal network details appear in fixtures. | A | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 19.15 | Unsupported OS negative tests confirm **zero host mutation** before rejection. | A+B | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |
| 19.16 | Idempotency and failure recovery have automated coverage. | A+B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 19.17 | Existing issue historical item 5 CLI bundle tests remain present and separate (no duplicate implementation). | A | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 19.18 | Link the new public dependencies and issue-specific PRs. | A | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 19.19 | Record PASS/FAIL/NOT VERIFIED results from repeatable Debian 13 and AlmaLinux 10 tests before closure. | B | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |

### #20 — docs: Document server installation, upgrades and recovery for Debian 13 / AlmaLinux 10
Issue: https://github.com/repocache-project/repocache/issues/20 · Campaign: **P0-1** · Source probes: `docs/testing/SERVER_VM_PREFLIGHT_V06.md`, `docs/testing/PR237_BOOTED_VM.md`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 20.01 | Tested install guides for Debian 13 and AlmaLinux 10. | B | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |
| 20.02 | Clear upgrade and rollback instructions, including existing NGINX conflict scenarios. | B | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |
| 20.03 | Troubleshooting guide for TLS, package installation, SELinux, NGINX and disk space. | B | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |
| 20.04 | No production hostnames, secrets, certificate material or internal IPs in examples. | A | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 20.05 | Documentation distinguishes shipped functionality from planned design. | A | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 20.06 | Link the new public dependencies and issue-specific PRs. | A | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 20.07 | Record PASS/FAIL/NOT VERIFIED results from repeatable Debian 13 and AlmaLinux 10 tests before closure. | B | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |

### #24 — feat: Implement opt-in, reversible APT/DNF repository sync
Issue: https://github.com/repocache-project/repocache/issues/24 · Campaign: **P0-3** · Source probes: `scripts/smoke_client_native_held_package_locks.py`, `scripts/smoke_client_source_preflight.py`, `scripts/smoke_client_root_source_boundary.py`, `scripts/ci_v06_vm_client_cli_guest.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 24.01 | Positive and negative tests exercise supported APT and DNF source formats on the target distributions. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 24.02 | Repeated `--apply` is idempotent. | B | **I** | Complete and integrate the approved production implementation, then exercise it in a VM. |
| 24.03 | Errors and interrupted writes restore a valid previous repository configuration. | B | **I** | Complete and integrate the approved production implementation, then exercise it in a VM. |
| 24.04 | `check`, `repos list` and the default `repos sync` do not modify any package manager sources. | A+B | **T** | Inspect exact-HEAD P0-3 guest source-integrity and fail-closed CLI artifact; real approved apply/fallback remains separate. |
| 24.05 | Failover is tested so a REPOCACHE outage does not unnecessarily block access to external repositories. | B | **I** | Complete and integrate the approved production implementation, then exercise it in a VM. |

### #26 — feat: Add strict Debian 13 and AlmaLinux 10 preflight validation
Issue: https://github.com/repocache-project/repocache/issues/26 · Campaign: **P0-1** · Source probes: `scripts/ci_pr237_guest.sh`, `scripts/server_v06_preflight.py`, `scripts/ci_v06_preflight_unsupported_target.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 26.01 | Debian 13 and AlmaLinux 10 positive tests pass. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 26.02 | Debian 12, AlmaLinux 9, other distributions and interpreter mismatches fail before provisioning changes. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |

### #27 — feat: Provision NGINX and its systemd service on supported servers
Issue: https://github.com/repocache-project/repocache/issues/27 · Campaign: **P0-1** · Source probes: `scripts/ci_pr237_native_host_integration.py`, `scripts/ci_pr237_native_package_guest.py`, `scripts/ci_v06_native_nginx_process_footprint.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 27.01 | Fresh Debian 13 starts with an operational NGINX service. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 27.02 | Fresh AlmaLinux 10 starts with an operational NGINX service. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 27.03 | Re-running does not duplicate includes or damage an active service. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 27.04 | Externally managed or conflicting NGINX instances are preserved or explicitly rejected. | A+B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 27.05 | Failed NGINX validation or reload leaves the previous working configuration usable. | A+B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |

### #28 — feat: Generate validated NGINX cache configuration from managed repositories
Issue: https://github.com/repocache-project/repocache/issues/28 · Campaign: **P0-2** · Source probes: `scripts/ci_native_nginx_cache_smoke.py`, `scripts/ci_generated_nginx_route_cache_smoke.py`, `scripts/ci_v06_vm_nginx_cache_guest.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 28.01 | Valid Debian/APT and AlmaLinux/DNF repository examples render into correct routes. | A+B | **T** | Inspect exact-HEAD QEMU P0-2 native HTTPS cache artifact; still require real installed route, signed APT/DNF and production activation. |
| 28.02 | Repository metadata and package artifacts traverse the proxy correctly on both supported OS targets. | B | **T** | Inspect exact-HEAD QEMU P0-2 native HTTPS cache artifact; still require real installed route, signed APT/DNF and production activation. |
| 28.03 | Repeated fetches demonstrate real observable caching without response corruption. | B | **T** | Inspect exact-HEAD QEMU P0-2 native HTTPS cache artifact; still require real installed route, signed APT/DNF and production activation. |
| 28.04 | Invalid hosts, paths and generated configurations are rejected before reload. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 28.05 | Neither unapproved configuration nor client-submitted repository data creates an active route. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |

### #29 — feat: Provision persistent cache storage, permissions, logs and metrics
Issue: https://github.com/repocache-project/repocache/issues/29 · Campaign: **P0-2** · Source probes: `scripts/ci_native_server_storage_bootstrap.py`, `scripts/ci_v06_owned_storage_metrics_runtime.py`, `scripts/ci_native_nginx_metrics_live_rotation_v1.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 29.01 | Debian 13 NGINX reads and writes cache/log/metrics locations correctly. | B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 29.02 | AlmaLinux 10 runs under SELinux enforcing with correct cache and log access. | B | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |
| 29.03 | Directories and files have appropriate ownership/modes; no unnecessary world-write access. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 29.04 | Repeat installation retains cached packages and historical logs. | B | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |

### #30 — feat: Configure server TLS and network exposure safely
Issue: https://github.com/repocache-project/repocache/issues/30 · Campaign: **P0-2** · Source probes: `scripts/ci_pr237_native_socket_guest.py`, `scripts/ci_server_https_catalog_binding_native.py`, `scripts/ci_v06_nginx_tls_rotation_recovery.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 30.01 | HTTPS endpoints pass representative smoke tests on both supported OS releases using disposable test certificates. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 30.02 | Missing, inaccessible or mismatched TLS material fails before configuration activation. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 30.03 | Existing certificates, private keys and firewall rules are not overwritten. | B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 30.04 | Clean installations have documented paths to trustworthy certificate provisioning without distributing secrets. | A | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 30.05 | Exposed listening ports and network boundaries change only with explicit administrator intent. | B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |

### #31 — feat: Make server installation idempotent and rollback-safe
Issue: https://github.com/repocache-project/repocache/issues/31 · Campaign: **P0-1** · Source probes: `scripts/ci_pr237_native_socket_guest.py`, `scripts/ci_pr237_native_package_interrupt_guest.py`, `scripts/ci_pr237_native_journal_reboot.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 31.01 | Reinstalling on both supported OS releases causes no unexpected changes. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 31.02 | Reinstallation/repair of a v0.6.0-managed deployment preserves TLS, cached packages and monitoring history; any unsupported older installation or foreign state is refused without mutation. The v0.4.0 -> v0.6.0 upgrade path is intentionally NOT SUPPORTED. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 31.03 | Failure during staging, syntax validation or reload restores a known-working service state. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 31.04 | Externally owned configuration is preserved or explicitly refused. | A+B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 31.05 | Automated tests exercise interrupted first installations, partial same-version v0.6.0 repair/configuration changes, drift and repeated recovery. | A+B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |

### #64 — security: Design narrowly delegated NGINX validation and reload
Issue: https://github.com/repocache-project/repocache/issues/64 · Campaign: **P0-1** · Source probes: `scripts/ci_pr237_native_socket_guest.py`, `scripts/ci_pr237_synthetic_worker_guest.py`, `scripts/ci_submission_privsep_native.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 64.01 | An authorized operator can validate and reload only the intended managed NGINX unit on Debian 13 and AlmaLinux 10, with an executed end-to-end positive test. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 64.02 | An unauthenticated or unauthorized `repocache` service UID cannot reload NGINX, invoke arbitrary commands or access arbitrary root-owned files. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 64.03 | Attempts to substitute config paths, unit names, executables, environment, arguments, symlinks or helper paths fail closed. | A+B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 64.04 | Invalid NGINX syntax, a failed/timeout reload, unsafe ownership and externally managed NGINX leave the previously working service state usable; all errors are noninteractive and reproducible. | A+B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 64.05 | Unit, integration, privilege-negative, security and native distribution tests execute and PASS on an exact reviewed PR head; real booted systemd and AlmaLinux SELinux coverage is documented and validated before advertising host support. Any missing host test is NOT VERIFIED, never PASS. | B | **T** | Inspect exact-HEAD QEMU artifacts; extend to the full original criterion and pin exact candidate. |
| 64.06 | English operator documentation includes explicit authorization setup/revocation, attack surface, rollback, compatibility and evidence checklist; integration is behind a separate reviewed PR and maintainer merge approval. | A | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |

### #76 — test(release): Gate v0.5.0+ publication on actual signed release candidate acceptance
Issue: https://github.com/repocache-project/repocache/issues/76 · Campaign: **P0-4** · Source probes: `scripts/ci_signed_candidate_native.py`, `scripts/public_release_acceptance.py`, `scripts/rehearse_signed_publisher.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 76.01 | Design reviewed for private key custody, signed-artifact handoff, nonpublisher read-only GitHub token permissions and trust boundaries (no signing key in CI). | A+C | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 76.02 | Reviewed-version matrix explicitly defines first-operational v0.6.0 as CLEAN INSTALL ONLY, with no v0.4.0 upgrade, and tests fail-closed rejection of any older/unapproved installed state. | A | **S** | Use a genuine publisher-signed immutable candidate only under separately authorized owner workflow. |
| 76.03 | End-to-end prepublication actual owner-key signed v0.6.0 artifacts exercise full native Debian 13 and AlmaLinux 10 CLEAN install, same-version repair, interruption/recovery and rollback criteria with reproducible CI run IDs and hashes. | B+C | **S** | Use a genuine publisher-signed immutable candidate only under separately authorized owner workflow. |
| 76.04 | Every stage tracks issue acceptance PASS/FAIL/NOT VERIFIED with mandatory failure blocking publication. | A+C | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 76.05 | Postpublication smoke consumes only the published exact asset identity/digests (no substitute rebuild, no mutable asset overwrite). | C | **S** | Use a genuine publisher-signed immutable candidate only under separately authorized owner workflow. |
| 76.06 | Document operational runbook and exception handling; separate authorization for merge, tag/signing, and publish. | A+C | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 76.07 | Code review, required exact-head CI and explicit maintainer merge approval. | A+C | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 76.08 | **#74-G4: Official post-migration nonpublishing release workflow execution — NOT VERIFIED.** On an explicitly owner-approved, version-matched, nonpublishing candidate/tag (without mutating the immutable v0.4.0 tag or bypassing the workflow guards), execute **the actual** `.github/workflows/release.yml` via its permitted owner-only `workflow_dispatch` route. Capture the exact source/tag SHA, project version, actor, workflow run ID, `assemble` job and successful native Node24 `actions/upload-artifact` step, with no skipped release job, publisher signing key in CI, or publication. **A `tests.yml` rehearsal is NOT sufficient.** | C | **S** | Use a genuine publisher-signed immutable candidate only under separately authorized owner workflow. |
| 76.09 | **#74-G4: Official artifact independent retrieval and integrity — NOT VERIFIED.** Independently retrieve the actual `unsigned-release-candidate` uploaded by that `assemble` job; record artifact ID/digest, source SHA, names/member inventory and independently recomputed SHA-256 checksums for the archive and relevant artifacts, including internal manifest/checksum agreement. Verify the exact expected release source identity and consistency with the approved version/tag, and preserve reproducible run/verification evidence. | C | **S** | Use a genuine publisher-signed immutable candidate only under separately authorized owner workflow. |
| 76.10 | **#74-G4: Owner acceptance of this actual evidence — NOT VERIFIED.** Map the transferred original criterion to PASS/FAIL/NOT VERIFIED on the exact candidate and require explicit maintainer acceptance of the real upload/readback evidence. **Any FAIL or NOT VERIFIED blocks closing #76 and the v0.5.0 release**, regardless of the outcome of signed-candidate tests. This gate must pass *before* authentic owner-held key signing, publication authorization or release publication. | C | **S** | Use a genuine publisher-signed immutable candidate only under separately authorized owner workflow. |

### #88 — feat(release): Automate owner-held offline signing and candidate publication with a workstation release operator
Issue: https://github.com/repocache-project/repocache/issues/88 · Campaign: **P0-4** · Source probes: `scripts/collect_native_candidate_evidence.py`, `.github/workflows/release-operator-native-presign.yml`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 88.01 | `environment check` validates owner authentication, local prerequisites, signer ownership/mode and pinned public fingerprint without exposing secrets. | C | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 88.02 | `candidate prepare` discovers/reuses the *correct* immutable source commit/workflow run and exact unsigned candidate automatically; mismatches fail closed. | A+C | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 88.03 | `candidate sign` authenticates/roundtrips real owner-compatible encrypted Ed25519 PEM through secure local FD/PIN entry and produces original valid manifest/provenance; wrong key/passphrase, symlinks, changed assets and bad permissions fail closed. | C | **S** | Use a genuine publisher-signed immutable candidate only under separately authorized owner workflow. |
| 88.04 | `candidate stage` uses an explicit owner action to create or reuse **only exact-matching draft assets**; staged byte mutation invalidates acceptance. | C | **S** | Use a genuine publisher-signed immutable candidate only under separately authorized owner workflow. |
| 88.05 | `candidate status` aggregates exact-head acceptance evidence for Debian 13 and AlmaLinux 10 from #76 and presents script-friendly, complete JSON without false PASS. | A+C | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |
| 88.06 | `candidate publish` refuses missing/failed/stale acceptance, wrong owner approval, existing immutable release, hash drift and changed asset profile; publication remains separately authorized, with postpublication immutable inventory validation. | C | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 88.07 | Recovery/repeated commands are idempotent for nonpublishing stages; temp credentials/key material never logged or retained, and tests cover network/API failures, interrupted processes and permission errors. | A+C | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 88.08 | Unit/CLI integration/security tests plus disposable native Debian13/AlmaLinux10 checks execute and PASS; documentation includes a simple initial setup, daily operation, dry-run limitations, and rollback/incident guidance. | A+B+C | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 88.09 | Per-criterion traceability PASS/FAIL/NOT VERIFIED, PR review, required exact-head CI and **explicit maintainer merge approval**. This issue itself does not authorize signing, tagging, staging, publishing, a merge or any destructive action. | A+C | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |

### #95 — feat(server): Manage the full lifecycle of dynamically configured repositories
Issue: https://github.com/repocache-project/repocache/issues/95 · Campaign: **P0-2** · Source probes: `scripts/ci_server_signed_dynamic_repository_native.py`, `scripts/ci_server_nginx_active_only_withdraw_v1.py`, `scripts/prepare_server_repository_lifecycle.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 95.01 | On Debian 13 and AlmaLinux 10, adding a new valid supported APT/DNF repository from metadata/configuration alone yields a functioning verified cache route, repeat HIT behavior and correct artifact/metadata integrity, without modifying REPOCACHE source. | B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 95.02 | Auto-generated IDs are unique/stable across restart/reinstall/upgrade; optional custom IDs are validated; duplicates, collisions and malicious identifiers fail closed with no host mutation. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 95.03 | Enable/disable and normal removal update managed NGINX state and atomic client discovery consistently; unvalidated or inactive repositories never appear as usable; failures restore/reconcile prior known-working exposure and publication. | B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 95.04 | Default removal preserves cached bytes and allows safe subsequent recovery/re-addition; explicit authorized force-cleanup deletes only verified REPOCACHE-owned objects for the selected repository, rejects shared/ambiguous cache layouts, symlinks and path traversal, and never affects active transfers/other repositories. | B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 95.05 | Strict allowlisting, URL/path validation, trusted metadata/TLS handling and SSRF/redirect protection reject unsafe upstreams and prevent an open proxy. Operator permissions remain least-privilege; no client can mutate server mappings via a request alone. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 95.06 | Idempotency, interrupted writes, failed `nginx -t`/reload, disk-full, concurrency and rollback cases have executed automated/integration tests; native OS and SELinux evidence is distinguished from synthetic CI. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 95.07 | Docs specify user-visible repository states and migration from an operator-managed NGINX frontend, including existing catalogs, ownership boundaries, upgrades and recovery. Preserve existing approved client command behavior. | A | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |

### #97 — feat(server): Manage native NGINX cache policies and storage pressure safely
Issue: https://github.com/repocache-project/repocache/issues/97 · Campaign: **P0-2** · Source probes: `scripts/ci_nginx_cache_policy_capability.py`, `scripts/ci_server_nginx_enospc_bypass_native.py`, `scripts/ci_server_pressure_nginx_hysteresis_native.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 97.01 | On Debian 13 and AlmaLinux 10 with stock packaged NGINX, global defaults and per-repository override inheritance behave as specified; unsupported directives/independent limits are detected and refused without partial activation. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 97.02 | Under controlled cache churn and pressure, native retention/capacity eviction is observable; priority of capacity over retained-but-evictable cache data is documented and measured, not guessed. | B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 97.03 | Warning/critical conditions, recovery hysteresis, incomplete metrics, alarm/reporting and effective policy status have repeatable tests; NGINX manager timing/soft limits are reported accurately. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 97.04 | Simulated ENOSPC, read-only storage, stalled/upstream-unavailable errors, interrupted config changes and recovery do not corrupt package/metadata integrity or silently break normal client upstream fallback. | A+B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 97.05 | Configuration ownership, path isolation, concurrency, disk permissions and AlmaLinux SELinux enforcing behavior have explicit executed security and native-host test evidence; no unrelated files or NGINX configs are modified. | B | **G** | Implement a self-checking, reversible native guest scenario before asserting coverage. |
| 97.06 | Ordinary install/upgrade preserves cached data and policies, with staged `nginx -t`, rollback/reconciliation and English operator documentation. | B | **R** | Port the existing test to an installed booted guest, retaining native OS/systemd/SELinux checks. |
| 97.07 | No acceptance criterion requires #94 to yield GO; clearly document the native-policy fallback if advanced priorities are NO-GO. | A | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |

### #107 — feat(cli): converge existing commands and enforce architecture contract in CI
Issue: https://github.com/repocache-project/repocache/issues/107 · Campaign: **P0-3** · Source probes: `docs/architecture/CLI_CONFORMANCE.md`, `scripts/ci_pr237_native_socket_guest.py`, `scripts/ci_v06_vm_client_cli_guest.py`. All probes are partial and not necessarily on the merged integration branch.

| ID | Original unchecked acceptance criterion | Stage | Current coverage | Smallest next action |
| --- | --- | --- | --- | --- |
| 107.01 | Supported read-only `repos list/ls`, `repos show/info`, `repo(s)` and `log(s)` aliases on server, with no privileged side effects and consistent help. | A | **U** | Retain exact-HEAD parser/contract CI; add installed CLI integration only if applicable. |
| 107.02 | `--json` before object or after action for finite already-supported server commands; clear refusal for unsupported/unbounded JSON, no accidental mutations. | A | **U** | Retain exact-HEAD parser/contract CI; add installed CLI integration only if applicable. |
| 107.03 | Client global `--json` / `--server` both before and after action, aliases `repo(s)`, `list/ls`, object-only help; original four command contracts remain intact. | A | **T** | Inspect exact-HEAD P0-3 guest source-integrity and fail-closed CLI artifact; real approved apply/fallback remains separate. |
| 107.04 | Explicit syntax and behavior regression tests for both parsers, JSON/error channels, options, no-op help, non-interactive CLI, and no client source modifications. | A | **T** | Inspect exact-HEAD P0-3 guest source-integrity and fail-closed CLI artifact; real approved apply/fallback remains separate. |
| 107.05 | A source-controlled inventory of *registered* current commands and a required CI contract test, forcing contributors to acknowledge any new/renamed command or public alias. | A | **U** | Retain exact-HEAD parser/contract CI; add installed CLI integration only if applicable. |
| 107.06 | Native distribution and semantic security claims marked NOT VERIFIED where only synthetic CI is available. | B | **D** | Verify source, documentation, audit/CI, or maintainer decision independently; do not count as a VM PASS. |
| 107.07 | Migrate remaining flat commands and retired unsafe manual `catalog publish` only together with #95/#28 implementation; do not imply server repository lifecycle exists today. | A+B | **I** | Complete and integrate the approved production implementation, then exercise it in a VM. |
| 107.08 | Reconcile exact shared numeric exit codes/JSON schema with the dedicated client session; preserve approved contracts. | A | **U** | Retain exact-HEAD parser/contract CI; add installed CLI integration only if applicable. |
| 107.09 | Implement future command registry for workstation `repocache-release` with #88, before claiming it available. | A+C | **I** | Complete and integrate the approved production implementation, then exercise it in a VM. |
| 107.10 | Port checks and review conflicts from #42/#52/#46, account for new command registration, and retain operational NGINX safety. | A+B | **I** | Complete and integrate the approved production implementation, then exercise it in a VM. |

### Newly implemented shared-guest P0-3 client non-mutation probe

The **same** PR #237 `smoke` guest also runs `scripts/ci_v06_vm_client_cli_guest.py` as an unprivileged OS user after P0-2. It fingerprints only regular APT/DNF source-definition files, runs the actual source-tree client parser/help and two `repos sync --apply` JSON refusal variants, and requires identical native source inode/mode/mtime/SHA before and after. There is **no client privileged writer**, no catalog network request, no source rewriting, and no claim of successful native `--apply`. The collector indexes only partial #24.04, #107.03 and #107.04 coverage when exact-HEAD QEMU and a verified guest log both exist; every original criterion remains `NOT_VERIFIED`. Native execution of this newly added code is not yet confirmed.

### Newly implemented shared-guest P0-2 cache probe

The existing P0-1 `smoke` QEMU guest now also runs `scripts/ci_v06_vm_nginx_cache_guest.py` **as the non-root disposable guest user** after native NGINX was installed, exercised and stopped. The probe calls the same generated-route syntax validator used in existing container CI, starts only a separate unprivileged loopback HTTPS NGINX process and local fixture backend, and checks synthetic APT/DNF metadata/package MISS/HIT, exact response bytes, denied unapproved routes, rejected POST, and refused unsafe redirects. It does **not** modify the installed service or APT/DNF source files, relax SELinux, install packages from the fixture or assert publisher signatures.

`scripts/collect_v06_vm_campaign_coverage.py` emits `v06-campaign-coverage.json` in the same job evidence bundle, with P0-2 `EXERCISED_PARTIAL` only if the exact-HEAD guest scenario and fixed PASS marker both exist. All original criteria remain `NOT_VERIFIED`. This new P0-2 native execution is **NOT VERIFIED** until the updated six-job QEMU matrix completes.

## Reproducible evidence protocol

1. Pin the full source SHA, immutable qcow2 image SHA, guest `/etc/os-release`, `uname -a`, PID1 systemd, `getenforce`, candidate/issuer fingerprint and exact asset digests; use disposable x86_64 guests. Keep synthetic and authentic publisher signers in separate runs.
2. Execute **P0-1** first through the existing experimental `.github/workflows/pr237-booted-native-vm.yml` only on its current approved PR branch. Do not duplicate or prematurely promote it to a required release workflow. Inspect actual six job artifacts on exact HEAD; fix source or tests before recording any PASS.
3. Once #249/#237 and native installer dependencies are assembled, extend the **same** guest harness with P0-2 and P0-3 phases. Port trusted container tests; make all source edits opt-in and only inside isolated guest disks; assert no foreign changes, idempotency and upstream fallback. Prefer complete installed positive + negative cases over an artificial PASS from a synthetic fixture.
4. Execute **P0-4** only when a real owner-signed immutable release candidate and separately permitted signing/staging inputs are available; never place private signing keys in Actions or claim the synthetic #249 fixture satisfies release acceptance.
5. Leave P1-1/P1-2 scheduled for v0.7; do not silently expand v0.6 scope or claim the current test harness certifies online-dependency sandboxing.
6. Record **per original criterion** `PASS`, `FAIL` or `NOT VERIFIED` with the exact SHA, scenario, command, guest evidence and run URL, linking from #19 to each parent issue. A passing scenario does not imply every linked original checkbox passes. Never close issues solely on the strength of this ledger.

## Coverage accounting

- Open v0.6 issues inventoried: **15**; unchecked source checkboxes inventoried: **106**; no acceptance checkbox altered.
- **D: 18** — Documentation, policy or standalone CI gate — no intrinsic VM
- **G: 10** — No sufficient VM test identified — develop
- **I: 9** — Blocked on assembled feature/real installer behavior
- **R: 26** — CI/container test exists — booted VM NOT VERIFIED
- **S: 9** — Requires owner-signed candidate or owner-only operation
- **T: 30** — VM TEST EXISTS — partial; exact current HEAD NOT VERIFIED
- **U: 4** — CLI/unit regression exists — VM not intrinsic

**Blocking dependencies:** #249 real signed release prerequisite; PR #237 experimental VM code still draft/divergent from integration; #24 native source writer/transaction and #95 managed repository lifecycle require implemented end-to-end behavior; #76/#88 release stages require genuine owner-held signing and distinct authorization. Do not use green container tests or prior synthetic VM runs as substitutes.

**Source-drift rule:** this ledger mirrors the checkboxes as of its generation date; any subsequent edits to issue checklists require a fresh criterion diff before a final campaign. Parent issues are authoritative.
