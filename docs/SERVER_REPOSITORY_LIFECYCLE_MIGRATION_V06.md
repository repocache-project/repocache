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


## Prepared repository operations before signed native activation (Stage A)

The trusted **checkout-only** operator utility
scripts/prepare_server_repository_lifecycle.py now connects the actual #95
single-generation v2 add/update/enable/disable/remove batch planner to the
exact fixed native #31/#64 proposal format. This is an offline candidate
builder, **not an installed REPOCACHE command or an NGINX operation**. The
five-field native envelope is checked, then only its exact canonical next
state bytes are durably created as a 0600 file for the separately reviewed
#237 native proposal stager. This avoids manually editing base64 v2
snapshots and accidentally losing all-time IDs or tombstones.

With a separately obtained, reviewed *private* canonical predecessor state
and known SHA-256 and generation, prepare an owner-only 0600 JSON request,
for example:

```json
{"operation":"enable","repository_ids":["debian-trixie-main"]}
```

From a trusted checkout with a source Python environment:

```sh
python scripts/prepare_server_repository_lifecycle.py \
  --previous-v2-state /secure/predecessor-v2.json \
  --expected-generation 1 \
  --expected-state-sha256 "$PREDECESSOR_SHA256" \
  --decision-sha256 "$OPERATOR_DECISION_REFERENCE_SHA256" \
  --request /secure/lifecycle-request.json \
  --proposal-output /secure/next-v2.json
```

Supported closed request shapes: add/update accept 1-64 complete repository
objects in proposed_repositories; enable/disable accept 1-500 unique IDs
in repository_ids; remove accepts repository_ids or all_repositories=true.
The existing strict v2 builder verifies all-time ID reservations and
canonical upstream/cache identity; it refuses stale generations, invalid
selectors and conflicting identity reuse. A no-op produces **no file**.
A changed operation creates one new 0600 file without overwriting any
existing path, and reports only expected/new digests, generation and
non-authorizing status. Previous and request files must be regular,
single-linked, locally owned and mode 0600 inside a locally owned,
non-group/world-writable directory; symlinks and malformed requests refuse
without mutation.

**Critical trust boundary:** a previous-state file and a user-supplied
decision SHA-256 are untrusted data, not proof of authenticated installed
state, private owner approval or code signature. Neither this utility nor
its output stages or activates the native worker. The pending #237/#254
signed, authenticated fixed stager **must** verify the output snapshot
digest, the installed predecessor again under the real protected lock,
operator authority, native host, NGINX routing and recoverable catalog
publication. Do not copy a candidate straight into protected NGINX/state
locations. There is no safe operational path until those drafts' mandatory
review/approval and installed native gates pass. The utility is not a
signed v0.6 release asset and is intended only in the reviewed source
checkout.

The source CI runs the real CLI as an independent Python subprocess and
compares its emitted canonical bytes with the pre-existing exact five-field
fixed-native builder. It also checks read-only predecessor retention,
tombstones, auto-ID, no-op, destination collision, malicious requests,
symlinks, hardlinks and file ownership/mode. This Stage-A execution does
not replace any Debian 13 / AlmaLinux 10 booted native VM acceptance.


### Non-mutating offline change review

Before creating a private proposal file, run the same reviewed request with
`--dry-run` **instead of** `--proposal-output`. This is a checkout-only
preview, not the installed `repocache` CLI:

```sh
python scripts/prepare_server_repository_lifecycle.py \\
  --previous-v2-state /secure/predecessor-v2.json \\
  --expected-generation 1 \\
  --expected-state-sha256 "$PREDECESSOR_SHA256" \\
  --decision-sha256 "$OPERATOR_DECISION_REFERENCE_SHA256" \\
  --request /secure/lifecycle-request.json \\
  --dry-run
```

The preview validates the exact proposed native state bytes and reports its
SHA-256, proposed generation and per-repository IDs/results (including
suggested automatic IDs), but **does not create the candidate file**. Repeat
without `--dry-run` and with a new private `--proposal-output` path only after
review. For an automatic exact-byte comparison, provide the digest from the
`--dry-run` report as `--expected-proposed-state-sha256` on the later
create-only command; the tool refuses a different proposed snapshot **before
creating any output file**. See the [review pin walkthrough](testing/SERVER_REPOSITORY_PROPOSAL_REVIEW_PIN.md).
The two reports must agree on predecessor, proposed SHA and IDs; a changed
protected predecessor requires a fresh proposal. No stdout field
contains upstream URLs, signing/trust references, credentials or cache paths.
A preview neither reserves an ID nor authenticates approval, proves deployed
NGINX exposure or authorizes the #237 signed native stager. The original
native lock/CAS, trust, systemd/SELinux and publication gates remain mandatory.


## Exact prepared state → protected transaction fixture

The Stage-A fixture function `commit_fixture_prepared_repository_proposal_under_root`
now consumes **the unchanged canonical v2 bytes** emitted by the offline
`prepare_server_repository_lifecycle.py` operator tool rather than
recomputing the repository change from its request. It independently checks
the pinned predecessor generation/SHA-256 against the actual descriptor-locked
protected v2 ledger and owner manifest, matches the prepared SHA-256 and
decision reference, refuses unrelated deployment policy edits and verifies
the exact fixed native #31/#64 candidate envelope. It derives the matching
NGINX fragment and active-only *fixture* catalog, then delegates to the
existing durable four-resource WAL, which repeats predecessor CAS on a
second lock and preserves the old catalog until the simulated exposure barrier.

Executed subprocess tests cover exact offline output-byte persistence,
remaining tombstones, default cache retention, stale/corrupt proposals,
partial activation refusal and durable rollback. This is a **detached-root
fixture only**, not an installed signed root/NGINX worker: the real `/` is
forbidden; a callback cannot prove NGINX exposure, transfer drain or SELinux.
The original #95 native service, real signed provenance and VM gates remain
mandatory and NOT VERIFIED by fixture CI.
