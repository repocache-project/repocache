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
