# Protected server state store v1 — inert journalled core

**Issue:** #31 · **Related:** #18, #25, #27, #28, #95 · **Milestone:** v0.6.0.
**Status:** INTERNAL PERSISTENCE CORE / NOT CONNECTED TO INSTALLATION OR ACTIVATION.

## Authority boundary

This module does **not** create administrator approval, adopt existing NGINX or authorize writes to the NGINX include. It is separate from **server-install input v1** and concurrent #95 / PR #214 read-only reconciliation. Its closed persisted format uses **state_schema_version**, not install schema_version, catalog schema_version or signed-release format. An approval entry stores a reference digest only: such a string cannot establish that an approval was authenticated. Similarly, a manifest record remains inert until actual protected filesystem provenance and inode drift are independently checked.

**There is no public privileged writer.** Internal _commit_under_root and _recover_under_root take caller-provided root directory FDs/UIDs only for disposable Linux fixtures. They are deliberately not CLI, root daemon, install or activation entry points. A future audited narrow root helper must fix UID 0, obtain its own OS root descriptor, independently authenticate operator/request approval beyond the installation document, and recheck live ownership, ACL, mount, SELinux and NGINX state under the same lock. Never connect a submitted install document directly to these internals.

The existing read-only inspect_default_server_state remains read-only. A filename shared with this store does not turn a digest into authority.

## Closed v1 schema

Canonical ASCII-escaped UTF-8 JSON, sorted keys and compact separators, no duplicate keys, bounded at 1 MiB:

- state_schema_version: integer exactly 1.
- state_generation: integer 1 through signed 64-bit maximum; valid absence implies generation zero.
- configuration_sha256: lowercase SHA-256 hex of desired configuration; not authentication.
- repositories: at most 32 records, each with stable normalized unique id, unique canonical_identity_sha256, approval reference with source operator or audited-request and decision_sha256, desired_state active or disabled, and observed_state fixed to not-activated. This module refuses removal or reassignment of previously recorded identities and does not allocate new IDs or verify new approvals.
- ownership_manifest: empty or one closed #216 v1 managed-include record, only the fixed /etc/nginx/conf.d/repocache-managed.conf path. Stored data is not proof of currently owned files; no alternate paths, NGINX writes or deletion are possible.

Unsupported versions/keys/types, stale generation, corrupt journals and unsafe files fail closed. The schema describes *inert* generations, not the authoritative active-service lifecycle database; future migration requires separate review and tests. No implicit legacy import.

## Atomicity, locking and recovery

The pre-existing static path var/lib/repocache/server is resolved via pinned directory descriptors with the previously merged #220 ancestry checks. Final directory mode must be **0700**, with expected UID; parent segments must be owned and non-group/other-writable, on the same filesystem. No directory is created by this module. The empty, preprovisioned single-link, same-device mode 0600 .state-v1.lock must belong to the expected owner. It is never created or replaced here. Cross-process exclusive nonblocking flock serializes commit and recovery. A genuine separate /var mount remains unsupported and is refused, pending a separately reviewed mount policy.

Under the lock the writer validates current protected state, pending recovery, expected generation and fixed file ownership. No-op is byte/payload equivalent except for next generation, and causes no writes. A changed state must use generation +1, preserve existing repository identity and use only fixed, descriptor-relative filenames:

1. Exclusively create .state-v1.pending-tmp, write the canonical previous state (base64) and old/new SHA-256, fsync the file and parent, then atomically rename the complete journal to .state-v1.pending and fsync the parent. A crash during temporary-journal creation cannot change state; recovery checks and discards only a mode/owner-verified, fixed-name orphan temporary journal. An unexpected malformed *published* journal is refused for manual inspection.
2. Exclusively create .state-v1.stage mode 0600; write candidate bytes, fsync it and parent, recheck previous state, then same-filesystem atomic rename onto state-v1.json and fsync parent.
3. Verify and unlink the durable pending journal, fsync directory; return COMMITTED_INERT_STATE, with reload and catalog authorization always false.

Recovery takes the same lock, validates the journal and actual old/new digest and either restores exact canonical previous bytes via fsynced .state-v1.rollback and rename, or (for interrupted first initialization) removes only the exact pending new file. It also removes root/owner-verified incomplete stage files if the current authoritative state still matches the old journal digest; partial rollback writes are safely discarded and rebuilt. A stage unexpectedly surviving after replacement is refused as drift. It cleans verified fixed temporary files and fsyncs the directory. Repeated recovery returns CLEAN; unexpected foreign, orphan, corrupted or changed file is REFUSED instead of adopted or overwritten. Native actual power-loss/fsync error tests are still required. No claim of protection from hostile root, unreviewed bind mounts or unexpected ACL/SELinux overrides.

## Acceptance boundaries

Execute: python -m pytest -q tests/test_server_protected_state_store_v1.py. Tests cover actual disposable Linux directory descriptors, inode/mode/link safety, generation CAS, filesystem lock, malformed schemas, no-op, and faults after journal, stage and replacement durability. Test source alone is not executed evidence. Debian/Alma CI containers are not equivalent to real booted systemd or enforcing SELinux hosts.

**NOT VERIFIED:** trusted operator/request approval; default root-managed directory provisioning; mount/ACL/xattr/SELinux and namespace checks; #95 authoritative ID allocation, reconciliation, observed states and provenance; live manifest/NGINX drift checks; staged full nginx -t, safe service reload/rollback, catalog publication; real Debian 13 and AlmaLinux 10 install/reinstall/upgrade and cache/TLS/metrics preservation. Keep #31 and #18 OPEN. No merge, release, signing, publishing, production activation or protected operation is authorized.
