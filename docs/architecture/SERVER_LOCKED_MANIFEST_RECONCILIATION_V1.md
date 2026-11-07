# Locked protected-manifest versus live NGINX include observation v1

**Tracking:** primary issue #31 / milestone v0.6.0; related #18, #25, #27, #28 and #95. **Dependency fulfilled:** [PR #222](https://github.com/repocache-project/repocache/pull/222) was independently authorized and merged into protected `main` as `955360fb7686f632d7d0090994008e10159f23b3`, providing the protected state schema and recovery implementation. Under the adopted release workflow, this PR targets the protected `integration/v0.6.0` branch (baseline `a1739a42cf5baac78bb3f8beb2bd02ee362447e9`), which already contains the #222 storage core. PR #224 subsequently merged into integration/v0.6.0 as ac13ba3847420560685c2156681fb2379af73d36 on 2026-11-03; the previous OPEN status was historical. Synthetic tests do not verify production installation.

## Fixed-purpose read-only contract

Private fixture-only _inspect_locked_under_root reuses #222's exclusive flock-protected default state directory (preprovisioned 0700 state directory and empty 0600 lock). It refuses a pending journal, temporary state or interrupted transaction WITHOUT recovering it. It reads and validates the protected state under the closed state_schema_version=1 schema, checks the explicit expected_generation, and rejects malformed, symlinked, hardlinked or unsafe protected state.

While the same state lock is held it walks only the fixed etc/nginx/conf.d path using descriptor-relative #220 ancestry checks. The #219 observer hashes the actual, single-link, opened managed NGINX include inode with bounded reads, refusing symlinks, hardlinks, nonregular entries, unsafe metadata and detectable races. An absent state ownership manifest permits only an absent include: a pre-existing include without a manifest is foreign even if its contents match. A recorded manifest requires the include to exist, have the expected owner and match the stored SHA-256, UID, GID, mode, device and inode. Any mismatch is refused as drift. State bytes, path ancestry and locked inode are rechecked before returning.

The result is a redacted diagnostic with generation and fixed flags. ALL write/reload/catalog/operator-approval/provenance/SELinux/NGINX-exposure authorizations remain FALSE. Even a matching manifest and live inode is not a privileged write token or NGINX authorization. There is no nginx -t, service invocation, route generation, root file mutation, catalog write, or automatic recovery.

## Trust and lifecycle limitations

- The private fixture API accepts a caller-supplied root FD and UID. It does NOT prove the FD is OS root or that the caller is an authorized privileged administrator. Never expose it as a generic privileged reader, command, service or permission oracle. A future constrained OS-root helper must independently anchor the real path/UID and authenticate operator permissions and audited request decisions.
- A protected approval source/hash is reference data, not authenticated operator provenance. Neither a stored manifest nor inode match proves NGINX service exposure or approved repository activation.
- Static same-filesystem traversal still rejects legitimate separate /var mounts until explicitly reviewed; ACL/xattr/SELinux, namespace, bind mounts and hostile root behavior remain unresolved.
- Complete native packaged NGINX syntax, controlled reload/rollback, TLS, signed APT/DNF metadata and derived catalog exposure remain separately gated. Do not activate unverified configurations, claim successful full host provisioning, or mutate client sources.
- This PR does not touch #214 repository reconciliation, existing source/CLI files or any running service. Original issues #31 and #18 remain OPEN.


## Current mount namespace root-anchored read entry

The same module now offers inspect_current_namespace_locked_manifest(expected_generation=...). It is strictly read-only and requires an effective UID of 0; it opens '/' itself with O_DIRECTORY | O_NOFOLLOW and descriptor closing semantics rather than accepting a caller-supplied root FD or owner UID. It compares the opened directory identity and owner to the literal '/' in the current process mount namespace **before and after** the locked manifest observation, rejecting substitutions and detectable root changes. The output's current_namespace_root_path_verified=true describes only this narrow property. The private _inspect_locked_under_root entry remains isolated-fixture-only.

UID 0 in a user namespace, chroot or container and '/' in a non-host mount namespace do not prove the *host* root or authenticate an administrator; ACLs, xattrs, mount topology, SELinux enforcing mode and independently trusted approval are still NOT VERIFIED. Neither a successful read nor this new boolean permits any persistent write, service reload or catalog exposure. There is no CLI registration, root install helper or invocation during application startup. Real root-owned preprovisioned paths remain required before the entry can return positively on an actual host; unit tests mock the internal observer and do not claim native host validation.

## Test and acceptance stage

Focused: python -m pytest -q tests/test_server_locked_manifest_reconcile_v1.py

Fixtures exercise Linux directory-FD traversal and flock, no-op and stale-generation behavior, foreign include refusal, symlink/hardlink/FIFO rejection, pending journal/orphan-stage refusal, metadata match/mismatch for every manifest field, and absence of network/process calls. A synthetic positive UID-0 manifest comparison is verified by a pure helper; it is NOT a real privileged NGINX include approval or native root-owned installation demonstration. Exact-HEAD CI must be executed and inspected before any PASS claim. No merge, signing, tagging, publication, deployment or protected operation is authorized.


## Locked candidate pre-staging gate — incremental #31 work

The new read-only preview_current_namespace_locked_candidate function validates
bounded (at most 256 KiB), strict UTF-8, NUL-free candidate bytes against the
actual managed include under the same exclusive protected-state lock. It
refuses foreign includes, manifest/inode drift, stale generations, symlinks,
unsafe directories, pending journals and orphan state stages. It reobserves
live include content/inode while still locked, rejecting changes between
observations, including same-inode content drift that directory metadata
alone cannot detect. This narrows detectable races, but does not defeat
hostile root writers or make results valid after the lock is released. Its redacted
candidate_action is WOULD_CREATE, UNCHANGED or WOULD_REPLACE. No candidate
bytes, digest, identity lease or operator credentials are returned. Existing
write, NGINX validation/reload/exposure and catalog authority flags remain
FALSE; effective root UID in a container is not trusted host-root authority.

This joins the earlier untrusted caller-snapshot candidate preview (#216) to
the real locked live-inode observation (#224). It does NOT stage files, execute
full-context native nginx -t, activate NGINX, commit a manifest or roll back.
After the lock is released, the preview MUST NOT be reused as write authority.
A future reviewed privileged transaction must recheck under the same lock
held across durable staging, native NGINX validation, reload and journalled
rollback. APT/DNF package-manager and systemd operations are not atomically
reversible through rename; separate compensating recovery is still required.
External TLS, cache, logs, metrics, configuration and client sources are
untouched.

Focused tests: python -m pytest -q tests/test_server_locked_manifest_reconcile_v1.py


## Read-only protected-state crash recovery preview — #31 increment

The private _preview_recovery_under_root classifies the existing #222
protected-state journal while holding the exclusive descriptor-pinned lock.
It is an isolated-fixture-only diagnostic, NOT a CLI, a public privileged
recovery API or a mutation/approval capability. Fixed owner-checked journal,
stage, rollback and state bytes are re-read under the lock before returning.

- CLEAN: no pending journal, stage or rollback.
- DISCARD_UNPUBLISHED_JOURNAL: an owned unpublished temporary journal exists.
- ROLLBACK_PENDING_STATE: a published journal matches the old/new state
  digest boundary; a separate explicitly invoked recovery is required.
- Any unowned/malformed file, state drift, conflicting temp, unexpected
  orphan stage/rollback or detectable concurrent change: refuse without
  touching the filesystem.

This classification does not guarantee that subsequent recovery will
succeed. The output contains no journal content, file bytes or secrets;
recovery_executed, authorizes_state_mutation, authorizes_nginx_reload and
authorizes_catalog_publication always remain FALSE. The existing #222
fixture-only mutation API stays separate and is exercised in tests solely
to prove that simulated recovery can return the state to CLEAN.

This journal covers only inert protected JSON state, NOT native NGINX
configuration, full-context nginx -t, reload, TLS, service availability,
package upgrades or active repository discovery. It does not establish
operator approval, host-root, mount/ACL/SELinux provenance or production
readiness. All five original #31 operational criteria remain NOT VERIFIED.

## Integration-lane reconciliation (2026-11-04)

The protected integration/v0.6.0 branch advanced through the accepted
inert native NGINX packaging/prepackage boundary (#27, PR #229, commit
d03192f96ad1ee03623acd674813363340922cb4) and bounded DNS plus inert
NGINX candidate preparation (#28, PR #227, commit
2388476f94f2f4c620d760c5acdcba4c5d2e6f4d). The #31 feature branch
is merged forward with both exact integration commits and retains only its
original three-file feature delta. No privileged native activation or
installer implementation is inferred from these preparatory merges.

The related #95/#214 work has identified an unresolved architectural
boundary: install-v1 supports up to 500 repositories while inert protected
state-v1 stores up to 32, without stable removal tombstones or active-service
observed-state semantics. The stored configuration digest and approval
reference are not by themselves authenticated configuration or operator
authorization. Do not connect this fixture-only preview to a real
privileged writer or NGINX apply until versioned state/config/approval and
activation ownership are jointly reviewed with #95 and #28.


## Current-namespace root-anchored read-only recovery diagnosis — #31

`inspect_current_namespace_locked_recovery()` is a narrow read-only
diagnostic entry point, extending the existing root-anchored manifest
inspection pattern without adding a recovery command, privileged writer or
NGINX service control. It accepts no caller-supplied root FD, UID or path.
It requires effective UID 0 before opening any host path, opens only the
current process mount namespace's literal `/` with the existing no-follow
directory flags, checks that root identity before and after the protected
journal inspection, and always closes its root descriptor on return/error.

The existing private `_preview_recovery_under_root` independently acquires
the state lock and rejects untrusted/malformed journal and state inputs.
The public wrapper reports a `current_namespace_root_path_verified` boolean
only for the observed root of this mount namespace, not for the host root.
A transient report is not a lease or approval for any later mutation.

Tests cover early nonroot refusal with no host path open, actual opened
root identity checked twice, no recovery or mutation authorization, fake
caller-controlled root substitution refusal, and descriptor cleanup on a
synthetic error. These tests do not validate genuine root-managed files,
host mount topology, ACL/xattr/SELinux enforcing, operator provenance or
actual recovery of a native NGINX installation. There is still no CLI
registration, writable recovery helper, staging, `nginx -t`, reload or
catalog writer. The five original #31 operational acceptance criteria
remain NOT VERIFIED; no application or service activation is authorized.
