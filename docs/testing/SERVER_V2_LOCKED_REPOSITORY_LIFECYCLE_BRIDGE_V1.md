# Protected v2 repository lifecycle transaction bridge (#95)

## Scope and safety boundary

`server_fixture_repository_transaction_v1.py` is an **executable integration
bridge for disposable Linux filesystem fixtures**, not a native root daemon,
installer, administrator command or live service activator. It brings
together existing, independently implemented components:

1. Use the reusable, pure
   `server_repository_v2_transition_v1.py` builder to bind each
   add/update/enable/disable/remove operation to a **canonical predecessor
   digest**, the complete historical ID/identity ledger, an exact generation
   and a validated next-v2 snapshot. The builder neither reads state nor
   grants operator approval, so it can later be reused by the separate
   installed native candidate-staging workflow in PR #237.
2. Read the existing canonical state-v2 snapshot and **all-time**
   repository-ID reservations under the fixed #31 owner-pinned lock.
   Validate the multi-resource owner manifest, reject pending journals,
   legacy v1 coexistence, foreign files and stale generations.
2. Use the existing strict #95 add/update/enable/disable/remove planner.
   For additions without an ID, derive the deterministic suggestion from
   the *locked, persisted* all-time ledger rather than a caller-owned set.
3. Rebuild a complete state-v2 generation: validated canonical install-v1
   configuration, records, historical reservations/tombstones and a bounded
   decision-reference digest. The digest is fixture data, **not operator
   authorization**. Preserve every retired ID and identity.
4. Render all desired-active NGINX upstreams and routes from the same
   proposed configuration and complete public-IP pins. Build exactly one
   matching, private **fixture-only** catalog.
5. Commit state, managed include, catalog and owner manifest with the
   existing same-directory, fsynced, multi-resource WAL. The WAL reopens the
   state under a **new exclusive lock** and performs generation/transition
   checks before any write. A concurrent transition cannot use the older
   planning snapshot to overwrite a later generation.
6. Require a disposable fixture prepublication callback. While it runs,
   the state/include are durable and the old catalog remains intact; a
   failure leaves the WAL for explicit, fail-closed recovery. Callback
   success is not evidence of installed NGINX exposure. Committed results
   still deny host activation, catalog publication and cache deletion.

Normal removal touches only this isolated fixture's state, include and
catalog. It does **not** walk, delete, purge or adopt any cache path.
No force-cleanup is provided by this bridge.

The bridge rejects the live `/` root FD, cannot be called as an installed
worker, does not trust the passed UID, NGINX callbacks or approval digest,
and does not run systemctl or nginx. Its code must not be re-exported as a
privileged mutation endpoint. No new CLI command or client behaviour is
introduced.

## CI tests and failure coverage

Run from the repository root on Linux:

```sh
python -m pytest -q tests/test_server_fixture_repository_transaction_v1.py
```

The tests exercise actual protected fixture file writes rather than
planner-only snapshots: enabling and withdrawing a route, state-v2 generation
and persistent ID preservation, old-catalog retention until the publication
barrier, default-removal byte preservation, auto-ID allocation, idempotent
updates, stale generation and unsafe IP refusal. They also inject a crashed
state replacement and a refused prepublication barrier, verify the pending
WAL blocks subsequent mutations, and perform a clean durable rollback.

CI evidence **must be recorded from the exact PR HEAD**; the presence of
tests does not mean they passed. Container-based tests do not prove
booted systemd/SELinux, installed NGINX reload or real publisher signatures.

## Remaining operational integration and issue gates

The native root-worker and real NGINX/state/catalog WAL are under
development in the separate **draft PR #237** (dependency #31/#64), and
must not be reimplemented in a competing privileged service. This bridge
cannot be substituted for that code. When its original criteria and review
gates pass and it is integrated, the next #95 increment must bind
operator-authorized lifecycle intentions to the **fixed installed candidate
staging contract** and invoke that native worker without caller-selected
paths, callbacks, environment, service units or executables. The worker must
authenticate the operator and installed release, verify the root namespace,
cache ownership, OS/package unit and NGINX include, retain a crash-consistent
journal across service reloads, run actual `nginx -t` and reload, observe
the new live worker/routes, and publish derived discovery only after verified
exposure. Restart/recovery must reconcile the service and public catalog,
not merely roll back shadow bytes.

The accepted state-v2 schema retains historical ID **and identity** digests,
so a removed publisher identity cannot be silently rebound to a different
ID. The issue's safe re-add/recovery promise needs a separately specified,
owner-approved cache namespace and recovery rule before production
force-cleanup or same-identity re-add is enabled.

All original #95 end-to-end acceptance criteria remain OPEN until the
real installed worker, independent native Debian 13 / AlmaLinux 10
systemd/SELinux tests and required signing/authorization are verified.
