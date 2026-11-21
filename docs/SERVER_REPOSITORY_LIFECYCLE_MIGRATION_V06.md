# v0.6.0 repository lifecycle: operator states, migration and recovery

**Primary acceptance:** issue #95 (AC2/AC3/AC4/AC6/AC7); dependencies
#18, #19, #24, #28, #29, #31 and #64. This is an *acceptance/migration
guide*, not a claim that an installed lifecycle administrator CLI or
privileged service has been released. The stable frontend described in
[PRODUCTION_EXISTING_NGINX.md](PRODUCTION_EXISTING_NGINX.md) remains a
separately operated NGINX integration.

## Repository is the only managed lifecycle object

The accepted data model is a versioned declarative configuration with a
unique durable repository ID, upstream/layout/trust, desired state and
cache policy. Administrators manage **repositories**, not NGINX locations
or a manually editable discovery allowlist. A generated NGINX location
and catalog entry must be derived from the *same approved installed
generation*. Client requests and discovery previews cannot authorize
the server to add or enable a repository.

### Meaning of visible states

| State/evidence | Administrator-visible meaning | Client eligibility |
| --- | --- | --- |
| Proposed add/update, `PLAN_ONLY` | Uncommitted candidate, even if all schema/IP checks succeed | **No** |
| `desired_state=disabled` | Operator intends no serving; retained cache may still exist | **No** |
| `desired_state=active` | Operator requests exposure; **not** proof it is serving | **No**, until trusted native activation and live confirmation |
| Activated + independently observed native NGINX generation | Validated installed mapping; only this generation may be reflected in the published catalog | **Yes**, if current TLS, route, trust and authoritative catalog are all verified |
| Removed, ID historically `retired` | No serving/discovery entry; prior cache bytes remain owned but retained | **No** |
| Pending transaction/recovery, unknown worker outcome | Incomplete or ambiguous activation; no new candidate should be adopted until fixed native reconciliation | **No new advertised route**; preserve or restore the last known-good exposure |
| Explicit force-cleanup requested | Separate destructive intent, **not** part of removal | **Never automatic**; requires trusted owner approval, quiescence and isolation proof |

The adopted initial state-v2 format records `observed_state="not-activated"`
for every repository record. It is a **proposal/state storage field**, not
a production observation. Do not present it as a live status; verification
requires the signed native worker and the actual active NGINX/master/catalog.
A successful `nginx -t` or `nginx -T` alone does not prove a successful
reload, worker drain, route withdrawal or post-reload publication.

Automatic IDs are deterministic suggestions until checked against the
**durable, exclusive-locked, all-time reservation ledger**. Custom IDs,
duplicate canonical upstream/layout identities and malicious selectors must
fail closed. Removed IDs and historical identity digests are retained.
The approved clean-install v2 schema currently refuses silent reuse of a
retired identity even under a fresh ID. Same-publisher recovery/re-addition
with retained cache therefore needs a separately approved identity/cache
policy; do not work around that invariant.

## Existing operator-managed NGINX: no unsafe automatic adoption

The pre-v0.6 frontend may have run against independently owned NGINX
configuration, SSL keys, caches, metrics files and operator-created
catalogs. The v0.6 managed service is a **separate ownership domain**;
it must not silently overwrite or rename those files.

Before planning a migration, an administrator should inventory, without
editing anything:

1. Installed distribution and native NGINX package/unit provenance
   (supported targets **Debian 13 x86_64** and **AlmaLinux 10 x86_64**);
   actual effective unit/drop-ins and foreign NGINX includes.
2. Existing NGINX route-to-upstream mappings, trusted HTTPS endpoints,
   TLS cert/key ownership, signed APT/DNF metadata, explicit fallback and
   local firewall/bind addresses. Keep sensitive key material private.
3. Existing cache zones, path/inode ownership, current active transfers,
   residual disk usage, retention expectations and external cleanup jobs.
   Never assume a cache zone is safe to delete merely because its route
   disappears.
4. Legacy client discovery catalogs and client source files, including
   versioning and current fallback. A previous catalog is **not** a trusted
   current exposure record and cannot be imported as authoritative state.
5. Signed release trust, available disk space, back-ups, rollback ownership
   and a recovery window approved for the operational environment.

A safe read-only NGINX preflight may use `nginx -t` and a suitably
authorized inspection of `nginx -T` as part of existing operating
procedures. The outputs may contain private paths and upstream network
information; sanitize before sharing. Do not alter ownership/permissions
to enable a nonprivileged REPOCACHE service account to read TLS keys.

### Proposed cutover, not a supported in-place migration tool

- Preserve foreign/operator-managed include files, TLS material, caches,
  log rotation and client source files. Refuse collisions with the fixed
  REPOCACHE managed names and unexpected systemd overrides.
- The **initial adopted state-v2 is clean-install-only**. A state-v1
  database/journal, unverified old manifest or incomplete legacy
  installation is a hard stop. No transparent v1-to-v2 ID/history migration
  has been approved; reconstructing tombstones from a route dump is unsafe.
- Construct a complete, validated v2 next generation using the same
  repository contract, historical IDs, trust references and approved
  operator decision. The Stage-A repository builders and candidate
  envelope from PRs #410/#411 only prepare bytes; they are not a native
  installer or a privileged write token.
- A separately signed and reviewed root worker (draft #237, relying on
  #64 security acceptance) must independently check the installed host,
  owner credentials, expected predecessor bytes and trusted files while
  holding its exclusive state lock. It must use a durable journal,
  stage the fixed managed NGINX include, run stock `nginx -t`, execute
  the fixed native reload, confirm actual new-generation TLS/route
  exposure, and only then atomically publish the derived active catalog.
- Transition external client usage **only after** the signed release,
  verified live NGINX exposure, trusted discovery and real APT/DNF
  metadata/package-manager integrity tests pass. Existing client upstream
  fallback remains configured independently; client sources are never
  silently rewritten by server repository changes.
- Legacy NGINX teardown or import is a separate operator-managed
  migration decision. Preserve the old known-good service/backup until
  acceptance, and never run the fixture-only root helpers on the host.

## Everyday lifecycle and loss-of-acknowledgment recovery

- **Add:** validate one supported repository kind/layout, supplied or
  automatic ID and complete public-IP/TLS/trust information, reserve its
  identity under the protected generation lock, activate only after
  actual verified NGINX exposure, publish derived discovery last.
- **Update:** preserve the ID, canonical upstream/layout identity and
  cache namespace. Trust/policy changes require a fresh validated native
  transaction. A changed identity must be refused, not silently rebound.
- **Enable/disable:** desired state is only an intent. A disabled route
  disappears from the installed routing and active-only catalog after
  verified reload; already accepted in-flight transfers may finish under
  prior NGINX workers, while new requests must be rejected.
- **Remove (default):** withdraw route and discovery, permanently tombstone
  the ID and **retain cached bytes/inodes** subject to ordinary global
  pressure/retention policy. Removal does not start a new cleanup timer.
- **Force-cleanup (distinct):** remains **NOT IMPLEMENTED in a trusted
  installed worker**. The read-only inode-bound preflight in
  [SERVER_REPOSITORY_CACHE_CLEANUP_PREVIEW_V1.md](testing/SERVER_REPOSITORY_CACHE_CLEANUP_PREVIEW_V1.md)
  is not deletion authority. The future operation must verify explicit
  scope/ownership, absence of shared objects, no active transfer and
  safe restart/recovery before deleting anything.
- **Failure/unknown outcome:** if validation, native syntax, reload,
  filesystem writes or catalog checks fail, do not advertise the proposed
  generation. Recover the exact prior files and NGINX exposure under the
  trusted journal and recheck catalog, then report the result. If a
  socket reply is lost, **do not assume rollback**: inspect the persisted
  generation and reconcile via the fixed recovery procedure. Never
  replay a stale `apply` blindly or clear a foreign pending journal.

No new public `repocache` or `repocache-client` command syntax is
introduced by this document or the Stage-A code. Use the separately
approved CLI contract; do not invent an operator `repos add` or
`force-clean` command before its implementation and authorization.

## Acceptance status and final booted-host campaign

The following **remain NOT VERIFIED** until their proper evidence exists:
real administrator and installed signed-root worker authorization, full
native state/include/catalog and rollback on booted hosts, foreign NGINX
preservation, installed Debian13/Alma10 systemd+enforcing SELinux,
publisher-signed APT/DNF integrity and default/force-cleanup behavior.
Disposable CI and source-only tests can prove narrower implementation
properties but cannot close the original #95 full acceptance alone.

When the code and required #64 independent security/owner review are ready,
the maintainer will clone the exact accepted source and run the coordinated
native campaign on **Debian 13 and AlmaLinux 10 x86_64 VMs**. Collect
sanitized, copy/paste-friendly command output, exact source/release SHA,
installed package/unit identity and per-criterion PASS/FAIL/NOT VERIFIED.
Do not request VM execution before the remaining non-VM integration and
security gates are resolved.
