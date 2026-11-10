# Installed-runtime attestation: threat model and isolated measurement probe

**Primary issue:** #53 · **Target:** v0.7.0 · **Status:** PROPOSED / EXPERIMENTAL, NOT AN ADOPTED INSTALLER OR LAUNCH CONTRACT.

**Related boundaries:** #35 (signed clean rebuild, not at-rest attestation), #31/#18/#25 (native server state and recovery), #79/#83/#84 (future online dependency identity), #112/#149 (candidate execution isolation and native kernel/SELinux acceptance).

## Five distinct questions

| Boundary | Existing mechanism on the accepted source baseline | What it does NOT prove |
| --- | --- | --- |
| Publisher release authenticity | Independent operator-provisioned Ed25519 trust anchor, signed release metadata and pinned offline assets | That the installed Python environment still contains those bytes |
| Installed executable / Python package integrity | Managed-release path/permission observations; reauthentication and a fresh environment for same-version repair | Independent, continuous at-rest identity of all installed executables, Python modules, packages, entry points or importable extras |
| Verification authority integrity | Root-owned launcher and recovery helper verified during privileged bootstrap; root-owned updater lock | Authority of a manifest stored under the service UID, or authenticity of a verifier imported from the suspect runtime |
| Compromised service identity | Unprivileged update service, managed tree checks, separation from root-controlled native server files | Prevention of changes to service-owned active venv and mutable installed.json, including simultaneous mutation of metadata |
| Recovery from a compromised generation | Fresh verified rebuild and transactional prior-generation recovery | That a retained prior generation is independently clean; the prior generation must also be attested before execution |

**Threat assumption:** The dedicated service UID, installed venv, console scripts, package metadata, and its own mutable manifest may all be hostile. The OS, root trust domain, OS-provided Python and independently installed verifier are assumed uncompromised. Root compromise, malicious OS packages, compromised kernel, malicious-but-correctly-hashed upstream wheels and hostile hypervisors are not solved by this proposal. A root-held digest created from an already hostile environment is not an authenticated known-good baseline.

## Candidate architecture (not yet selected for integration)

1. **Trust authority outside the measured generation.** Use a narrowly scoped OS/root-owned verifier, installed and authenticated independently of REPOCACHE package Python. Never import from the managed venv or run its pip, entry points, or Python code with elevated privileges. Do not re-use root-owned *server configuration state* merely because it has restrictive permissions; its own independent authority and update protocol are subject to #31 review.
2. **Authenticated generation baseline.** Bind a root-protected per-generation inventory to a previously owner-verified signed release identity, the supported OS/Python target, exact first-party bytes, approved dependency hashes, installed regular-file metadata, interpreter link policy and all effective import/execution paths. Inventory creation must be independently authorized during a controlled, isolated, not-yet-active install. Never derive a new trusted baseline from service-writable installed.json, a prior mutable venv or an unauthenticated repair request.
3. **Read-only external verification.** An independently authenticated supervisor obtains the allowed, fixed generation identity and a no-follow directory FD; compare every admitted entry, ownership, mode, link type, content digest and unexpected importable file against protected expected entries. Reject missing authority, unknown generation, drift, incomplete scans, unsupported entries, unsafe mounts and scanner errors. The managed service may request a check but cannot set expected bytes, verification keys or an arbitrary filesystem root.
4. **Safe pre-execution boundary.** A successful scan is only a point-in-time measurement: the service UID may replace bytes between check and launch. A real launch gate additionally needs a quiesced generation with ownership transfer/immutable policy, a trusted pinned snapshot or other proven race-resistant execution boundary. This must be reviewed with #112, the launcher, active-generation journal and native OS security policy before activation.
5. **Recovery.** On failure, quarantine or refuse the suspect generation without running it. The next candidate or rollback target must have its own independently authenticated inventory; do not consider the previous service-writable link or manifest a trusted rollback record. Keep NGINX, TLS, cache, logs, APT/DNF and prior known-good runtime untouched until the separately authorized transactional replacement succeeds. If no verified target exists, fail closed with operator recovery rather than silently rebuild from the suspect tree.

### Trade-offs to resolve before wiring an attestor

| Option | Benefit | Main limitation |
| --- | --- | --- |
| Root-protected digest inventory + external scanner | Portable to Debian 13 / AlmaLinux 10, inspectable, little persistent storage | Hashing cost, root provisioning/authorization, and check-to-use race without quiescence |
| Root-owned read-only generations after isolated staging | Reduces service-UID mutation ability and supports stable launch | Requires explicit ownership handoff and writable data/bytecode split; interacts with #31 rollback and #112 sandbox |
| Filesystem verity / immutable image | Stronger file identity and potential efficient page verification | Filesystem/kernel/mount/provisioning differences, operational recovery and SELinux constraints; no blanket support claim |
| Linux IMA/EVM | Kernel-enforced measurement/appraisal | Host-wide policy, keys, native OS configuration, privileged administration and deployment complexity |
| Verify only the signed publisher archive | Already necessary and proven release trust boundary | Not installed-file/package integrity, particularly for generated venv files and post-install writes |

**Working preference:** A root-controlled inventory plus separately installed, minimal verifier, combined with immutable/quiesced generations if supported by the reviewed installer. This is a recommendation for design review, not adoption of an inventory schema, privileged API, immutable filesystem mode or migration command.

## Autonomous incremental implementation

The standalone Python-stdlib module at scripts/runtime_integrity_probe.py provides a **read-only, no-import, no-subprocess** primitive. A caller supplies an already opened directory FD and an already authenticated mapping of relative file path to SHA-256 and exact POSIX mode. It checks the owner UID, no-follow descriptor-relative traversal, same-device entries, directory/writeability constraints, single-link regular files, unexpected files/directories, content hashes, observable mid-scan metadata changes, and explicit entry/byte/depth limits.

This module **does not** construct, sign, deserialize, store or authenticate the expected inventory, and does not open a root-owned authority store. No CLI, launcher, installer, updater, sandbox, recovery helper or service invokes it. Fixture baselines in tests are **synthetic trusted inputs only**. The scanner deliberately rejects all symlinks (including legitimate venv interpreter symlinks), special files and unlisted mutable bytecode. Its finite bounds are fixture/prototype limits, not reviewed production venv ceilings. The scanner cannot defeat an attacker who can alter its code, its expected mapping, the kernel or a mutable generation after measurement. Race observation does not establish atomic scan-and-execute.

The tests in tests/test_runtime_integrity_probe.py use disposable local files and verify positive measurements, modified same-size content, unexpected importable files, removed files, unlisted bytecode, directory drift, symlink/hardlink/special-file refusals, permission drift, invalid expected paths, resource bounds and a visible concurrent mutation. They additionally reject malformed Unicode inventory paths and deterministic file/directory substitutions with symlinks between metadata inspection and no-follow descriptor opening. These negative tests do not establish that a mutable generation remains unchanged after the scan or during launch. No unknown runtime is executed; no root privileges or network are required.

## Dependencies / activation restrictions

- **#31, #18, #25 and v0.6.0:** authoritative generation/journal contract, protected state authority, immutable ownership handoff, service startup and rollback are not finalized here. Do not modify their shared formats or presume their root helper is the attestor.
- **#79, #83, #84:** profile-specific installed dependency/venv identity must be linked to actual authenticated source-only and online wheel locks *only when that profile is approved and integrated*. The approved legacy offline profile remains unchanged.
- **#112, #149:** do not replicate its sandbox or infer its native isolation evidence. No untrusted candidate runtime may be executed as root. Native Debian 13 and AlmaLinux 10, AlmaLinux SELinux enforcing, and real recovery/load/TOCTOU tests are outstanding.
- **Operations and migration:** no automatic enrolment of existing installs, no trust-on-first-use from service-owned state, no privilege escalation, no silent rollback to unverifiable bytes. A separately reviewed authenticated repair/migration procedure, operator runbook, booted native acceptance and independently reviewed design are mandatory before wiring this into the installer.

## Acceptance evidence ledger (full issue #53)

| Original acceptance criterion | Status for full issue | Missing gate |
| --- | --- | --- |
| Documented separation of publisher trust, installed integrity and compromised service UID | NOT VERIFIED (design proposed in this PR) | Review and integration of this threat model |
| Independently trusted installed runtime/package inventory | NOT VERIFIED | Protected authority, complete venv inventory, actual generation identity, native trust checks |
| Reproducible tampering, controlled repair and safe rollback without root execution of untrusted code | NOT VERIFIED | Negative probe tests are only one slice; controlled repair/rollback is not implemented |
| Debian 13 and AlmaLinux 10 native compatibility and recovery | NOT VERIFIED | Booted systems, SELinux enforcing, real managed generation and workload acceptance |
| Operational/upgrade migration and full separately reviewed acceptance matrix | NOT VERIFIED | Inventory migration contract, signed-release fixtures, operator procedures, independent technical review |
| No unsupported security audit / production claims | PASS for this narrowly scoped proposal | Maintain this qualification for later implementation and release |

Run the focused fixture suite with: python -m pytest -q tests/test_runtime_integrity_probe.py

**Security disclosure:** This public proposal intentionally contains no deployment secrets, live attack traces or exploitation steps. Report any actionable vulnerability privately as specified in SECURITY.md. Successful synthetic tests are not a security audit or production approval.
