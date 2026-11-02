# Locked protected-manifest versus live NGINX include observation v1

**Tracking:** primary issue #31 / milestone v0.6.0; related #18, #25, #27 and #95. **Dependency:** unmerged [PR #222](https://github.com/teixemf/repocache/pull/222), its protected state schema and recovery implementation. This increment is a STACKED READ-ONLY DEVELOPMENT PR until #222 receives separate maintainer merge authorization. Synthetic tests do not verify production installation.

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
