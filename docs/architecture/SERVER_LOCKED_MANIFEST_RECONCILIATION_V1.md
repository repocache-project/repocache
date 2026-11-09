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


## Proposed v2 persistence bridge — review-only architecture for #31 ↔ #95 ↔ #28

**Status: PROPOSED / NOT ADOPTED / NOT PERSISTED / NOT ACTIVATABLE.**
The existing protected state-v1 schema, 32-item limit, lock/journal and
fixture-only writer **remain byte-for-byte unchanged**. This branch adds a
standalone *pure* proposed v2 snapshot/transition checker,
`preview_proposed_v2_state_transition(...)`. It refuses all mutation,
NGINX reload, active-catalog publication, cache cleanup and authentication
claims. It does not read any real root-owned files, grant approval, migrate
a v1 host or implement the native installation lifecycle.

### Closed proposed snapshot contract

- `state_schema_version=2` (unrecognised and refused by current v1 writer).
  State generation is strictly 1..signed 64-bit max, with expected-generation
  CAS for the proposed next generation. Bootstrap from no prior snapshot
  requires expected generation zero. A v1-to-v2 conversion is **not**
  automatically authorised and requires a separately reviewed migration.
- `configuration_base64`: canonical ASCII-escaped, sorted/compact JSON
  encoding of the complete strictly validated install-v1 document. Decoded
  payload max 1 MiB, no duplicate keys, strict UTF-8, exact canonical
  re-encoding, including full deployment and repo policy/TLS reference
  data (never private TLS key bytes). Document expected generation equals
  the proposed stored generation. The full configuration bytes are retained
  so crash recovery need not trust an unavailable external digest alone.
  `configuration_sha256` must hash those exact canonical decoded bytes.
- `repository_records`: zero to 500 unique, explicit durable IDs with the
  existing shared #95 canonical source/layout identity SHA-256, desired
  active/disabled state and **only** observed `not-activated` (no synthetic
  claim of verified live exposure). These records must match the entire
  validated document exactly, without adopting a partial repository list.
- `id_reservations`: at most 10,000 bounded, uniquely identified and
  unique-identity entries with `allocated` or `retired`. Allocated IDs
  exactly match present repositories. Between full successive snapshots,
  *every* historic reservation must survive unchanged in identity; an
  allocated item may become retired but retired items may never return to
  allocated. The 10,000-record bound is the existing #95 pure planner bound;
  exhaustion **fails closed** pending a separately authorised migration.
  The ledger cannot silently discard history to make room. No removal ever
  authorises deleting cached packages or force-cleanup.
- `approval_reference`: closed source (`operator` or `audited-request`),
  decision digest, exact configuration digest and expected previous generation.
  These are **cross-consistency references, not authenticated approvals**.
  The future privileged interface must authenticate operator identity,
  operator intent and applicable decision scope independently under its own
  OS-root-owned transaction lock, rather than interpreting this JSON
  as trusted input.

The pure checker validates bounds, the precise next-generation CAS,
configuration byte/digest binding, repository and reservation set equality,
immutable historical ID/identity and retirement continuity. It returns
**no decoded configuration bytes, approval digest or identity lease** and
reports authority flags FALSE. A caller-supplied prior snapshot is
untrusted: the checker cannot prove that it includes the entire historically
reserved set. Its `reservation_history_authoritative=false` is not
weakened by a passing check. Existing #95 PR #214 remains the owner of
declarative reconciliation and already-merged #28 owns NGINX candidate
generation; no duplicate implementation is added here.

### v0.6.0 first-operational-release compatibility boundary

The maintainer explicitly confirmed on 2026-11-07 (issue #31) that v0.6.0
is the first operational deployment and **does not upgrade public v0.4.0
or any older server installation**. Automatic v1→v2 migration is therefore
**NOT APPLICABLE** to this first-deployment acceptance path; it is not a
reason to weaken provenance checks or delete old bytes. Encountering any
foreign or legacy v1 protected state, pending transaction or non-owned NGINX
configuration must fail closed without mutation. The earlier lossless
migration discussion remains useful future design analysis, not an approved
migration requirement or permission to overwrite legacy data.

The applicable #31 release gates remain clean native install, idempotent
same-version reinstall/repair and configuration update, preservation of
TLS/cache/metrics/logs, executable NGINX syntax/reload rollback, safe
interruption/retry and foreign-state refusal on booted Debian 13 and
AlmaLinux 10. All host acceptance remains **NOT VERIFIED**; existing
fixture/container PASS results cannot satisfy those gates.

### Required native persistence and activation boundary (NOT IMPLEMENTED)

1. Define and review a new actual persisted v2 format and crash-safe
   journal/recovery plus explicit v1 migration/refusal policy. Verify that
   configured full bytes, immutable reservations and active-status evidence
   fit the protected storage and recovery bounds before any public writer.
2. A constrained privileged helper must acquire its own authenticated
   host-root descriptor and OS-owned lock, independently validate signed
   release/operator decision, pin exact v2 bytes and actual NGINX inode,
   check filesystem/mount/ACL/SELinux provenance, and enforce real
   expected-generation CAS. An untrusted v2 preview is not a write token.
3. Prepare only verified owned managed include files, stage complete NGINX
   context, execute packaged `nginx -t`, use controlled reload with
   durable known-good state and rollback across reload failure.
   Package-manager/systemd effects need separately documented compensation.
4. Publish only verified **actually exposed** enabled repositories into
   the versioned derived active-only catalog, atomically after validation.
   On partial failure preserve/restage known-good host state, catalog and
   cache, refusing foreign configuration and inconsistent exposure.

Applicable #31 operational tests (Debian 13 and AlmaLinux 10 real install,
same-version repeat install/repair with TLS/cache/history retention,
staging/syntax/reload rollback and interrupted recovery) remain
**NOT VERIFIED**. Public pre-v0.6.0 upgrade is **NOT APPLICABLE**.
Original #95 and #28 operational acceptance remains NOT VERIFIED. The
proposed bridge is testable coordination work, not adoption of a new
protected-state format or approval of a native writer.


## Proposed v2 fixture-only durability and rollback rehearsal

**Status: PROTOTYPE / UNADOPTED / NOT A HOST WRITER.** The separate
`server_proposed_state_v2_store.py` contains only private
`_commit_proposed_v2_under_root` and `_recover_proposed_v2_under_root`
functions intended for disposable Linux-FD fixtures. They are **not** in the
CLI, application startup, a privileged service, a production installer, or
a signed-release path. Their caller-supplied FD/UID does **not** establish
host-root or administrator authorization.

The private v2 prototype uses the *existing preprovisioned v1 state lock*,
still requiring the existing owner/mode/pinned-ancestry checks. No new lock
is provisioned. All v2 files are distinct fixed names under the same
protected fixture directory: `state-v2.json`, `.state-v2.pending-tmp`,
`.state-v2.pending`, `.state-v2.stage` and `.state-v2.rollback`. The v2
snapshot ceiling is **4 MiB**, including a complete <=1 MiB validated
canonical configuration payload encoded as Base64 and up to 10,000 retained
ID reservations. The v2 journal ceiling is **6 MiB**, sufficient for an
encoded former 4 MiB state plus bounded metadata; hitting either limit
fails closed. These sizes and filenames are **proposed fixture contracts**,
not approved operational or migration compatibility promises.

Under the exclusive lock the prototype rejects **any v1 state** with
`LEGACY_MIGRATION_REQUIRED`, and rejects pending v1 transactions/stages
with `LEGACY_RECOVERY_REQUIRED`; it never imports, renames, deletes or
adopts v1 data. It refuses pending, orphaned, symlinked, hardlinked, unsafe,
noncanonical, malformed or conflicting v2 files. A complete and frozen
candidate must satisfy the exact proposed v2 generation CAS,
canonical-config/digest/identity/retired-ID rules against **the actual
previous fixture bytes**, rather than a caller-provided prior snapshot.
An effective no-change install with only generation metadata differing
returns `NO_CHANGE_INERT_V2` without replacing the state inode.

For a changed candidate, the prototype fsyncs and publishes a fixed-name
previous-state journal before writing and fsyncing a new temporary stage,
then atomically renames the new state. It never runs `nginx -t`, reload,
package installation or catalog publishing. Explicit rollback under the
same lock checks the published journal hashes, rejects unexpected current
state drift and restores *exact* previous bytes (or initial absence).
Interrupted journal creation, staged writes, replacements, a failed
rollback rename and repeated recoveries are exercised with fault injection
on disposable local directories. The unit tests additionally cover 500
present repositories, a 10,000-entry reservation history, stale CAS,
unchanged state, unsafe symlinks, exclusive-lock contention, and refusal
of any v1-to-v2 migration. This is **not** proof of native power-loss
durability, fsync guarantees on every target filesystem, actual production
root ownership, TLS/cache preservation or systemd/SELinux correctness.

**Explicit architecture gate:** Before any real v2 adoption, an approved
maintainer-reviewed migration/versioning contract must define what to do
with existing v1 state/manifest/journal and require a trusted host-root
operator-authentication path, ACL/xattr/mount/SELinux checks, complete
NGINX syntax/reload/known-good service rollback and active-only atomic
catalog consistency. The suggested private fixture mechanism may need
revision after that review. All original #31 operational acceptance
criteria remain **NOT VERIFIED** and no production use or protected
operation is authorized.


### Reciprocal v1/v2 coexistence refusal

The original v1 store now explicitly refuses **any** of the five fixed v2
snapshot/journal/stage/rollback names under its existing owner-pinned state
lock before accepting a v1 read, commit or recovery. It checks names
without following symlinks and also refuses dangling foreign v2 symlinks.
This closes the inverse conflict in which a v1 fixture writer could
otherwise initialise a new v1 state next to an already present v2 fixture
snapshot, or recover a v1 journal while v2 is interrupted. The proposed
v2 prototype reciprocally refuses any v1 current or pending state.

This safety interlock **does not** migrate v1 data, activate v2, change v1
schema fields, authenticate administrators, adopt foreign paths, or
introduce a public privileged writer. A versioned migration remains an
independent acceptance/approval blocker.


### Cross-process crash recovery in Debian 13 and AlmaLinux 10 containers

The new path-filtered, read-only `Server Protected State Crash Recovery
(Distro Containers)` workflow runs the original v1 tests, locked
manifest inspector tests and proposed v2 fixture tests under native
userspace/Python packages in Debian 13 and AlmaLinux 10 containers.

In eight cases (first install and update at four durable boundaries),
a Linux child process exits with `os._exit(73)` immediately after the
fsynced journal-temp, published journal, state stage, or state rename.
No Python finally/unlock is executed. A separate second process must
acquire the released exclusive lock and recover exactly the previous
state bytes or initial absence, and a new transaction must then work.

This is stronger evidence than same-process exception injection but
still only isolated Linux fixture/container testing. It does not prove
a booted native host, systemd/SELinux, a genuine power cut, actual
NGINX syntax/reload, TLS/cache/metrics retention, foreign live host
ownership or signed administrator approval. Full #31 operational
acceptance remains NOT VERIFIED.


### Locked persisted configuration → existing #28 NGINX candidate

The private `_preview_persisted_v2_nginx_candidate_under_root`
reads and verifies the exact proposed v2 snapshot/digest and generation
**under the existing protected state lock**. Pending journals, legacy v1
state, stale generations, untrusted/oversized pin maps, invalid DNS/IP
pins and state drift refuse the whole preview. It decodes only the
validated canonical install-v1 bytes from the actual locked fixture
state, passes the full document to the **already merged #28 renderer**
and re-reads the persisted bytes before returning. There is no duplicate
#95 lifecycle planner or second NGINX route/approval source.

The output is **still candidate-only**, with host-root, authenticated
operator, actual NGINX include manifest, NGINX syntax, observed exposure,
activation and catalog-publication authority all FALSE. It is neither
an on-host CLI nor an operator permission token.

The two-distro fixture workflow installs **distro-packaged NGINX**
inside its disposable container and executes a separate `nginx -t`
against a generated temporary config containing the persisted
two-layout (APT and DNF) candidate. No running NGINX service is
reloaded, no real managed include/certificate is replaced, and no
catalog is published. Native booted systemd/SELinux, authenticated
activation, actual service rollback and original #31 acceptance
remain NOT VERIFIED.

### Disposable live NGINX reload and compensation probe (#31)

A new focused test in `tests/test_server_proposed_state_v2_store.py`
starts an **actual distro-packaged NGINX master and workers** in a disposable
temporary prefix, using only a Linux Unix-domain listening socket. It stages
the existing #28 renderer's full APT+DNF candidate along with a private
health endpoint, checks `nginx -t`, and probes actual HTTP responses through
the socket. The test then:

1. Stages an invalid directive and confirms `nginx -t` rejects it while the
   previously running worker still serves the known-good health response.
   Only the temporary file is restored; the invalid config is never reloaded.
2. Stages a different syntactically valid health response, reloads that
   isolated NGINX master, and observes the changed live response.
3. Simulates a subsequent failed activation gate, restores the *exact* old
   temporary config bytes, revalidates, reloads, and confirms that the live
   response returns to the known-good state.
4. Asserts that fixture v2 state bytes, journal, and stage remain unchanged
   and terminates the disposable NGINX process even after an assertion error.

This adds an executed **service-process** rollback rehearsal when the
distro-container workflow passes, beyond the prior syntax-only check.
It does **not** implement a privileged installer, host transaction journal,
managed include swap, real systemd reload, SELinux enforcing, catalog
publication, or power-loss recovery. The temporary process can be rolled
back even though there is not yet an *approved durable transaction* linking
the actual include, persisted v2 state, live exposure, and catalog. The five
original #31 operational criteria still require booted native host evidence.

### Read-only v1 migration blockers under the existing shared lock

The private `_preview_v1_migration_blockers_under_root` is a fixture-only
locked diagnosis for an already-existing v1 snapshot. It requires a valid
v1 state, refuses pending v1 journals, orphan stages, conflicting v2 names
(including symlinks), and concurrent lock acquisition. It reads the
protected v1 state twice and returns only a redacted generation, repository
count and manifest count alongside permanently FALSE config-history,
operator, host-root, NGINX, migration, activation and catalog authority
indicators. There is no caller-provided configuration or migration token.

Even a clean v1 state with zero repositories cannot prove a lossless
migration: persisted v1 has no recoverable canonical configuration bytes
or all-time historical ID ledger. This diagnostic deliberately reports
`LEGACY_V1_MIGRATION_BLOCKED` and never writes either version. Executed
fixture tests can verify refusal/nonmutation and lock behavior, but only
a separately approved schema and host transaction can implement actual
migration. This PR does not adopt the proposed v2 persistence format.

### Read-only proposed v2 recovery journal preview

Private `_preview_proposed_v2_recovery_under_root` reuses #31's fixed
state-directory exclusive FD lock and rejects concurrent writers, malformed
snapshots, unsafe files, conflicting legacy v1 state, orphan stage/rollback,
journal-temp collisions and journal/state digest drift. It reads only the
proposed v2 fixture files; it neither invokes recovery nor alters live
NGINX, publishes catalog state, provisions a root helper or deletes bytes.

The bounded report distinguishes a clean state, an unpublished journal
temporary inode, a durable journal before the state replace, and an
interrupted post-replace journal. It discloses no repository details,
configuration bytes, digest, root path or key material. All authorization,
host-service recovery and catalogue/NGINX flags remain FALSE. In particular
a report of an interrupted transaction is **not** an authorization to run
the private recovery function, which itself is still fixture-only.

Tests cover the four fault points on both initial and existing v2 snapshots,
verify byte-for-byte nonmutation, refusal of modified state/orphan stages and
lock contention, and ensure the diagnostic calls no mutating filesystem
operation. CI distro-container results do not prove native systemd/SELinux
safety, power-loss durability or an accepted v1→v2 migration. The v2 format
remains proposed and does not become a shipped persisted-state contract.

### Current namespace v1 migration refusal diagnostic

The internal `inspect_current_namespace_v1_migration_blockers()` entry
uses the same read-only, fixed `/` descriptor and pre/post root-inode
identity checks as existing protected-state diagnostics. It requires effective
UID 0, takes no caller-selected path, UID, root FD, configuration or journal,
and closes the descriptor on both success and failure. It delegates to the
existing exclusive-lock v1 preflight; a pending journal, unsafe filesystem
entry, divergent state or v2 coexistence remains a refusal, not an automatic
repair or migration. The output is only a redacted blocker report with all
migration/NGINX/catalog and operator/host-root authorization fields false.

This function is **not** wired into the CLI, installer, sudo/polkit or a
privileged helper. A container-root namespace is not native host-root proof.
It neither migrates v1 nor advances the five original #31 host acceptance
criteria. Its regression tests cover unprivileged denial before filesystem
access, pinned current-root identity, substituted descriptor refusal and
descriptor cleanup on failure.

### Legacy-state refusal and privileged authority: unresolved gates

**No migration is executed or enabled by this PR.** The v1 snapshot stores a
configuration digest but not independently recoverable canonical config
bytes, and has no all-time ID/tombstone ledger. An operator-supplied document,
approval-reference digest, or #95 preview cannot reconstruct missing
historical authority. With any v1 state/pending files present, the private
v2 prototype deliberately fails closed; with any v2 files present, the
v1 reader/writer/recovery also fail closed. This coexistence guard prevents
unreviewed writes but is not itself an upgrade algorithm.

An eventual reviewed migration would need independently verifiable source
for the exact canonical v1 configuration and full historical ID reservations;
a maintainer-approved policy for legacy data without sufficient provenance;
and a durable journal protocol that explicitly handles crash windows where
both version filenames may coexist. It must not erase v1 to make v2 import
appear successful, invent identities or silently reuse retired IDs. Under the approved first-operational-v0.6.0 scope, this future migration
is **NOT APPLICABLE**. The only safe current behavior when legacy v1 state
is encountered is **refusal without mutation**, not automatic bootstrap,
import, cleanup, or upgrade.

A privileged entry must independently authenticate the administrator's
exact operation, generation, canonical config bytes and decision provenance,
then revalidate the **actual host** OS root, mount namespace, mount topology,
owned directories and include, ACLs, xattrs and SELinux label/policy under
the same locked transaction. Root EUID in a container or a stored
`decision_sha256` is not adequate. The #95 next-generation preview and
#28 rendered candidate are untrusted planning inputs, not write authority.
The privileged transaction must keep its lock through native packaged
full-context `nginx -t`, staged activation, verified live exposure, and
compensating rollback. Cache, certificates, monitoring history, global
NGINX configuration and client sources must remain untouched by default.
If any original criterion lacks native evidence, acceptance remains
**NOT VERIFIED**, independently of green synthetic CI.

### Unpublished proposed-v2 journal provenance guard

Before an unpublished `.state-v2.pending-tmp` can be classified as an
abandoned fixture transaction or discarded by explicit private recovery, its
bounded journal record must validate **and** its embedded previous-state bytes
must match the exact currently persisted state under the exclusive lock.
Malformed temporary journals and mismatched previous-state records fail
closed without deleting the journal or replacing the state. This applies to
both an interrupted first bootstrap (previous state absent) and an interrupted
same-version update. The new tests inject the crash at
`journal_tmp_durable`, substitute a different valid v2 snapshot and verify
that both preview and recovery refuse with `STATE_DRIFT`, preserving bytes.

These checks do not authenticate a host administrator, prove host-root
provenance, or authorize the fixture recovery function for production. The
native NGINX/systemd/SELinux and original applicable #31 acceptance gates
remain **NOT VERIFIED** until separately executed on booted target systems.

### Published proposed-v2 journal stage/rollback preservation

When a published private fixture v2 journal is present, recovery now
validates any staged **or already replaced** next-state bytes against the
journal's next-state digest **and** the pure proposed-v2
generation/identity/retired-reservation transition checker. A changed stage,
or a digest-matched stage/replacement paired with an invalid next-generation
transition, fails closed before recovery modifies any file. A pre-existing rollback file must contain the *exact*
validated previous-state bytes; a mismatch is refused and preserved rather
than deleted and rebuilt. A correctly written rollback file remaining after
an interrupted rename can still be retried.

Read-only preview and private recovery use the same refusal conditions.
Tests inject crashes after the fsynced stage and after replacement, mutate
stage, replaced-state or rollback bytes, and verify refusal and byte-for-byte preservation;
they also construct a journal digest that matches a structurally valid but
semantically invalid next-generation snapshot. Those fixtures do not
establish production filesystem ownership, an authenticated operator,
actual NGINX service exposure or a recovery authorization token. A damaged
rollback requires explicit operator investigation instead of silent
deletion. Booted native acceptance remains NOT VERIFIED.


### Disposable end-to-end lifecycle → v2 journal → live NGINX rehearsal

The #31-specific \`test_v2_lifecycle_nginx_live_sandbox\` connects the
*already merged* #95 explicit repository-change planner, the existing
private proposed-v2 Linux-FD fixture journal, the persisted-v2 locked
#28 NGINX renderer, and a **real but isolated, non-systemd NGINX master**
on a test-owned Unix socket. It tests a disabled add, enable, interrupted
disable/recovery/retry, normal disable and remove. It uses the same
canonical configuration bytes and historical reservations checked by the
fixture store, verifies generation CAS, durable retired-ID records,
stale/reused-ID refusal, active-route fragment inclusion/withdrawal,
packaged \`nginx -t\`, actual sandbox worker reload and response, and
test-owned retained cache bytes. Failure is injected at
\`stage_durable\`: the read-only renderer refuses a pending journal,
the existing NGINX worker stays live, explicit private recovery
preserves exact known-good state, and the intended operation can be
retried without double-applying the generation.

**Limit of this evidence:** state commits and process reloads are two
separate, manually sequenced *test* actions, not one trusted atomic
production transaction. This test **does not** authenticate the operator,
run privileged Linux production services, establish host-root/mount
ancestry/SELinux ownership, expose a real external cache route, validate
signed APT/DNF payload integrity, publish an active-only catalog or
prove power-loss recovery. The health endpoint proves only the local
isolated NGINX worker's response. The proposed v2 format is still
unadopted. Actual host service+state/catalog atomicity remains
NOT VERIFIED pending the reviewed #31/#27/#28/#95 integration design,
root authorization and booted-host tests. The companion #28 PR #251
separately exercises real disposable HTTP cache HIT with TLS.


### Proposed-v2 precommit NGINX candidate under the existing fixture lock

\`_preview_proposed_v2_nginx_before_commit_under_root\` closes an
important *source-level* ordering gap: the older read-only
\`_preview_persisted_v2_nginx_candidate_under_root\` can only render
**after** a v2 state has been durably committed. The new fixture-only
preflight accepts a bounded proposed-v2 snapshot, explicit prior generation
and complete pinned DNS answers, freezes untrusted inputs **before** the
exclusive protected-state lock, refuses legacy state, pending journals,
stale generations, non-monotonic/historically conflicting reservations and
unsafe/extra/missing IP pins, and renders an uncommitted next-generation
NGINX candidate from the *same* canonical proposed configuration bytes
that the private writer would persist.

For an idempotent v2 no-op, the renderer instead uses the **actually
persisted previous generation**, mirroring the private writer's no-op
behavior. It rechecks the protected predecessor bytes before returning,
including detecting an out-of-band writer ignoring the advisory flock.
Nothing is created, staged, committed, reloaded or published. The caller
must not treat the report as a lease: its lock has already been released.
\`authorizes_state_commit\`, NGINX, catalog and cleanup flags are all
false; synthetic approval references and proposed-v2 data never become
trusted operator provenance.

Debian 13 and AlmaLinux 10 disposable-package CI exercises the
precommit candidate with \`nginx -t\`; other regressions verify
bootstrap, parity with postcommit pinned output, final generation/no-op,
invalid and private pins, stale/absent predecessor, old v1 coexistence,
lock contention, interrupted journal recovery, and detection of a
non-cooperating file writer without performing any recovery or mutation.
This is a prerequisite for a future *single, authenticated native
transaction*, not evidence that state commit, NGINX activation and
atomic active-only discovery already form such a transaction.
Booted systemd/SELinux acceptance stays NOT VERIFIED.


### Lifecycle fixture: explicit validation before every durable revision

The end-to-end sandbox lifecycle regression now uses
\`_preview_proposed_v2_nginx_before_commit_under_root\` on *each*
candidate, validates the derived candidate via distro-packaged
\`nginx -t\` in a **separate disposable temporary config**, checks that
neither the stored v2 predecessor nor the currently served NGINX
configuration changed, and only then invokes the private fixture
commit. After commit it compares the locked persisted renderer's
complete upstream/location fragments and pin count to the precommit
result before explicitly reloading the isolated NGINX worker.

An injected interruption during disable requires explicit recovery;
the recovered predecessor is checked and **the old precommit result is
discarded and regenerated** before retrying. This deliberately tests
the ordering required by the future host transaction without adding
an installer, privileged service, authorization token, actual atomic
catalog, or production commit/reload control. It is not a substitute
for genuine booted systemd/SELinux, owner approval or live cache HIT.
