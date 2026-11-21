# #95: read-only repository inventory from a locked v2 fixture

This Stage-A function fills a concrete administrator **inspect** gap in the
repository lifecycle: previously, the protected state-v2 ledger and the
generated private NGINX/catalog records were stored, but there was no single
read-only inventory showing which durable IDs are currently allocated,
disabled or historically retired, without leaking the upstream configuration.

`inspect_locked_fixture_repository_inventory_under_root` reads the actual
canonical, 0600, owner-pinned persistent state-v2 under the **existing
exclusive descriptor lock**. It refuses incomplete v1 migration, native
package reconciliation, journal/staging recovery, missing owner records and
unrecognized/altered include/catalog/manifest bytes. It accepts only the
complete four-resource *committed fixture ownership domain* from the merged
#410 transaction (and a caller-pinned exact generation + SHA-256). It
rechecks the state inode and the exact bytes of all owned resources before
unlocking. A second process can reopen a detached fixture root and obtain
the same summary, including the immutable tombstone IDs.

The returned bounded, versioned report contains:

- The exact persisted state generation, state digest and sorted list of
  current repository IDs with `desired_state` (`active` or `disabled`),
  `observed_state=not-activated`, and a shadow-catalog intent marker.
- The sorted list/count of historically `retired` IDs, with no reservation
  identity digest or preserved upstream definition.
- Explicitly false flags for **real NGINX exposure**, public client
  catalog publication, signed operator authority and every mutation action.

This does **not** claim that a desired-active repository is actually
reachable. Even `shadow_catalog_intent=fixture-included` is only the
private fixture's internally consistent proposed catalog; neither a real
`nginx -t`, live reload, TLS handshake nor external client check occurs
here. Such host/exposure proof belongs to the separately reviewed #31/#64
native worker and to booted systemd/SELinux acceptance on Debian13 and
AlmaLinux10. The source API refuses a descriptor of the **real** `/` root
*before* taking the protected state lock. It does not offer a CLI, HTTP
endpoint, arbitrary path selector, cache deletion or root broker.

This output deliberately excludes upstream URLs, IP pins, certificates,
release-key references, client source files, hidden approval digests and
raw state/configuration. Never publish this fixture report as if it were
the actual client discovery catalog: the approved catalog must derive
atomically from verified, active and exposed installed NGINX routes.

## Executable regression evidence

```sh
python -m pytest -q tests/test_server_fixture_repository_inventory_v1.py
```

Tests create real owner-pinned Linux fixture directories and write the
canonical multi-resource WAL. They then drive the merged #95 state-v2
planner through enable, disable and normal removal, confirming a reader
returns the correct sorted current and retired IDs on the actual committed
revision. Additional tests reopen the root FD to simulate a new reader,
reject stale hashes/generations, corrupted includes/catalogs/owner manifest,
native/v2 pending recovery, invalid argument types and live `/` descriptor
before lock, and assert no file writes, NGINX processes or network.

Stage-A source/CI tests are not production NGINX observation, a signed
release/publisher test or final #95 end-to-end acceptance. This isolated
code is packaged in both reviewed v0.6.0 source/upgrade inventories, but
that packaging is not authorization to deploy an installed privileged
service or to alter the approved CLI contract.
