# Declarative repository ↔ protected-state v1 read-only alignment

**Primary issue:** #95 (v0.6.0) · **Related:** #18, #28, #29, #31, #97, #107.

This PR-only proposal defines a **non-authoritative read-only compatibility
check** between validated install-v1 repository entries and the *inert* protected
state-v1 records from #31. It is not an adopted protected-state extension,
a lifecycle writer, an activation interface, or a security approval.

`preview_declarative_state_alignment(current_document, protected_snapshot,
current_generation=...)` checks closed schemas, exact generation agreement,
same stable IDs, SHA-256 of the #208 canonical source/layout identity, and
the same desired-state intent. It refuses mismatched, missing or extra entries.
Caller-supplied snapshots are **not trusted**; equality does not authenticate
OS-owned files or operator approval and is not a concurrency barrier.

The present state-v1 store supports **at most 32** records, while the
install-v1 contract allows **up to 500**; no larger-scale persistent lifecycle
is implemented by this check. The state-v1 format cannot represent historical
ID tombstones, removed repositories or a real observed active/failed state.
Its `configuration_sha256` has no accepted canonical install-document byte
binding at this interface and **is deliberately NOT claimed verified**.

A future reviewed privileged orchestrator must, under one exclusive protected
transaction lock: independently authenticate the administrator's operation;
read a pinned OS-owned state/ownership manifest; reconcile schema capacity,
persistent ID/tombstone reservations and full configuration digest; check
the actual active NGINX files/inodes, DNS/TLS trust and cache ownership;
stage complete generated configuration; run packaged NGINX validation and
controlled reload; publish an atomic active-only catalog; recover consistent
prior exposure on all failures. It must repeat all validation after lock
acquisition and must not treat a preview or a `desired_state=active` as
proof of actual exposure.

No routine here reads or writes protected files, spawns processes, performs
DNS/network calls, grants service-reload/catalog permission or deletes cached
bytes. A normal remove must retain cache data; forced cleanup requires separate
verified ownership and explicit authorization under #29/#95. Policy inheritance
continues to be inspected by the #214 planner; #97 owns eventual native policy
behavior. CLI commands under #107 must consume future authoritative status,
never this untrusted preview as actual state.

## Suggested focused regression

```console
python -m pytest -q tests/test_server_repository_reconcile_v1.py
```

Tests added in this PR cover matching intent, stale generations, malformed
protected schema, mismatched/missing/extra identities, nonmutation and
non-authorizing output. Test presence is NOT executed evidence. Full original
#95 and #31 acceptance, including real native Debian 13/AlmaLinux 10
NGINX/SELinux/cache/recovery and trusted root authorization, remains
**NOT VERIFIED**.


## Inert persistence transition intent (second increment)

`plan_inert_persistence_transition` requires validated #18 current/proposed
documents, an aligned but **untrusted** #31 state-v1 snapshot and exact
generation. It refuses generation exhaustion, new or removed IDs, and changes
to an existing ID's canonical source/layout identity that #31's current writer
cannot preserve. The output describes the closed state-v1 repository ID,
identity and desired-state projection and conservatively identifies IDs whose
changes would require authenticated administrative review, including global
policy changes affecting omitted repositories. Existing inputs are not
mutated. Activation remains separate from intent.

**Crucially, this is not a persisted configuration transaction or a complete
state-v1 record.** Approval references and the `configuration_sha256` binding
are deliberately omitted, preventing the plan itself from being accepted by
`validate_protected_state` as a directly committable state object. It never
calls `_commit_under_root`; that API remains private to #31 Linux FD fixtures.
A focused test explicitly constructs a *synthetic, non-authenticated* complete
state candidate, calls #31's private fixture writer under a disposable root,
observes durable atomic write, clean recovery and stale-CAS refusal. This
proves schema interoperability in the fixture **only**. It does not approve
any existing host write, NGINX activation or real administrative operation.

The next operational development must first agree with the #31 owner on a
protected, canonical and recoverable configuration payload/digest, durable
tombstone history, capacity (install v1 <=500 vs state v1 <=32), and an
authenticated authorizer under the same state lock. An immutable-identity
migration or force-cleanup is separately blocked pending approved ownership
and recovery design. No PR is merge-ready merely because this fixture passes.


## Declarative lifecycle → inert NGINX candidates (#95 with merged #28)

`preview_declarative_nginx_candidate` composes **the existing** validated
#95 transition planner with #28's already merged
`render_repository_nginx_bundle_candidate`. It accepts current and partial
proposed install-v1 configuration, an untrusted inert state-v1 snapshot,
an exact generation, complete candidate DNS pin sets for **every desired-active
repository** (and none for disabled IDs), and a syntactically valid CA path.
The first step freezes validated declarative input, confirms ID/identity/
desired-state alignment and rejects stale generations, source identity
reassignment, missing persistent IDs or invalid partial updates.
The second delegates to #28 for complete public-address pin validation,
host/SNI/TLS-verifying HTTPS fragments, redirect isolation, NGINX ordering
and bounded output. A missing, extra, unsafe or disabled-repository pin fails
the entire candidate, not only the individual route. No DNS lookup occurs.

The output distinguishes **changes in desired intent**, not live service
state: `desired_new_route_ids`, `desired_withdraw_route_ids`, and
`desired_retained_route_ids` describe the candidate diff against the
current untrusted declaration. They do **not** attest that any route currently
exists or will be activated. Normal desired disablement does not clean a
cache. The output contains only proposed NGINX fragments, never a client
discovery artifact. Every state-write, NGINX-activation, catalog and cache
cleanup authorization remains false; no filesystem, network or subprocess
operation is performed by this function. No `nginx -t` or packaged-NGINX
reload has been executed by this pure adapter. A complete managed include
and cache directives remain independent design/testing work.

Before actual apply, the #31 protected owner must independently authenticate
administrator approval, canonical and recoverable install configuration bytes,
generation and all-time ID/tombstone state **under the same native lock**.
The #28 owner must then pin authorised DNS identities, stage a complete managed
include, validate actual packaged NGINX, control reload/exposure/rollback,
and publish an atomic active-only catalog only after successful exposure.
No authority may be inferred from an untrusted candidate, synthetic approval
hash, desired state or CI-green result.

Focused #95+#28 regression command:

```sh
python3 -m pytest -q tests/test_server_repository_reconcile_v1.py
```

Full PR and distro-specific NGINX tests are separate exact-HEAD evidence
requirements. The original #95 operational AC1–AC7 and #28 live activation
acceptance remain NOT VERIFIED by this composition.


## Exact-HEAD native syntax coverage

The existing #28 `.github/workflows/server-nginx-pins-native.yml`
path filters now include the #95 lifecycle reconciler and its tests.
In its Debian 13 and AlmaLinux 10 disposable packaged-NGINX containers, the
workflow invokes the existing strict #28 pin/redirect tests **plus**
`tests/test_server_repository_reconcile_v1.py`. The latter includes a
fixture-only full `nginx -t` for the two-layout declarative composition,
using a private temporary `nginx.conf` and no running service. On a host
without packaged NGINX, that test is explicitly SKIPPED rather than
misrepresented as PASS.

This syntax fixture cannot verify the privileged managed include, complete
cache zones/HIT, authenticated approval, root ownership, actual reload,
operational rollback or client catalog, which remain NOT VERIFIED.
