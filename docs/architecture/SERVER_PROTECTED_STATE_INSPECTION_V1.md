# Fixed-path server state and managed include inspection — diagnostic v1

**Primary issue:** #31 · **Related:** #18, #25, #27, #95 · **Milestone:** v0.6.0  
**Status:** IMPLEMENTED READ-ONLY DIAGNOSTIC ONLY. Neither a persisted-state writer nor privileged activation.

The new Python function **inspect_default_server_state(document)** validates an existing server-install v1 input with for_apply=True and inspects **only** the default fixed layout: /var/lib/repocache/server and /etc/nginx/conf.d/repocache-managed.conf. Other syntactically valid layouts remain supported by the *configuration schema* but are **not inspected by this first diagnostic**. They fail closed with MANAGED_LAYOUT_NOT_YET_SUPPORTED; no configuration is rewritten.

## Read-only implementation boundary

- Open the filesystem root as a directory descriptor and traverse only fixed, audited path components for the state root and NGINX include parent. Each open is descriptor-relative using O_DIRECTORY, O_NOFOLLOW and O_CLOEXEC. Reject symlinks, non-directories, non-root-owned ancestors, group/other-writable directories and unreviewed device transitions. Compare inode/metadata around each open and recheck the chains after file observation. No mkdir, chmod, chown, unlink, network call, package installation or NGINX command.
- Within the state directory, inspect only the fixed provisional **state-v1.json** basename. A pre-existing file must be root-owned, regular, single-link, mode 0600, and 1–1,048,576 bytes on the same device as the parent. Hash the opened inode, recompare the file identity to its pathname entry and reject symlinks, hardlinks, special files, unsafe modes, oversize content and detectable concurrent changes. Return only presence, byte count and SHA-256, never raw content or an accepted state generation. Absence does not establish a clean host or justify initializing state.
- Inspect the fixed NGINX include via the previously merged server_managed_include_fd_v1 observer, additionally refusing non-root-owned observations. Return only presence and SHA-256. No NGINX mutation or validation.
- Fixed, redacted errors and permanent all-false write/reload/catalog authorization. **verified_static_segments=true** describes only the conservative read-time owner/mode/device checks on these particular path components; it is not a durable identity certificate, proof of manifest authenticity, ACL/xattr/SELinux verification, a lock or mount-namespace attestation.

The private **_inspect_under_root(root_fd, owner_uid=...)** exists solely for isolated tests; caller-supplied root FDs and non-root UIDs are untrusted production inputs. The public function always opens OS root and requires UID 0. Never expose this private fixture interface through an elevated generic file-reader endpoint.

## Deliberate limits and remaining gates

**state-v1.json is a provisional diagnostic filename, not an adopted persisted-state schema.** This PR does not implement a state database, writer, schema parser, authorisation record, ownership manifest, protected generation allocation, lock, journal, rollback or migration. A matching SHA-256 proves neither origin nor authoritative validity. Agree the actual state_schema_version, repository records, trust source and atomic durability protocol with #95/#31 before writing persistent state.

Descriptor-based path checks cannot prevent all races, malicious remounts, bind mounts, ACL/xattr/SELinux conflicts or attacks by already-privileged actors. The deliberately strict no-device-crossing policy can refuse a legitimate separate /var filesystem; support for such mounts requires explicit review and tests. A future privileged engine must revalidate trusted ancestry and manifest/generation under an exclusive lock, implement journalled staging/fsync, full distro-packaged nginx -t, explicit activation and verified rollback before any production operation. A positive diagnostic result is never a privileged write token.

**Verification:** python -m pytest -q tests/test_server_protected_state_inspect_v1.py, with actual disposable Linux directory FDs, symlinks, file modes, hardlinks, FIFOs, byte-size boundaries and simulated concurrent edits. This is not booted-systemd/SELinux or live NGINX acceptance. Original issue #31 and #18 operational criteria remain NOT VERIFIED. The narrow #25 native systemd/SELinux evidence exception stays NOT VERIFIED — OWNER-ACCEPTED RISK, not PASS.
