# Fixed native v2 repository candidate envelope (#95)

## Why this code exists

The approved #95 repository lifecycle needs a safe way to pass a complete,
validated v2 repository transition to the fixed-path native transaction
proposed under #31/#64. That native root worker is being implemented in
**draft PR #237**, with the control protocol in **PR #254**. Neither proposal
is a deployed or independently approved production service.

`render_fixed_native_v2_candidate_envelope` in
`src/repocache/server_repository_reconcile_v1.py` is a **pure,
non-authorizing, IO-free encoding function**. It constructs the exact
canonical bytes of the fixed administrative candidate envelope described by
the current unmerged #31/#64 read contract, rather than adding a second root
service, a new administrator CLI, an arbitrary command endpoint, or a
separate route/catalog allowlist.

The companion
`render_fixed_native_repository_lifecycle_envelope` is the **complete
functional composition** of the merged protected-v2 repository operation
builder (#410) and this exact fixed-native envelope serializer. Given
caller-provided prior canonical v2 bytes, previous SHA-256, expected
generation, a validated add/update/enable/disable/remove intent and an
untrusted decision-reference digest, it constructs the full new state-v2
ledger and encodes the fixed broker intake in a single pure operation.
This includes automatic IDs from the complete all-time tombstone ledger,
persistent existing identity checks and explicit no-op outcomes: a no-op
returns `envelope_bytes=null`, never an unnecessary staging request.

It takes the **caller-supplied** raw canonical previous state-v2 bytes (or
`None` for clean bootstrap), the raw canonical proposed state-v2 bytes,
the expected generation and the expected SHA-256 of the previous bytes.
Both v2 snapshots must satisfy the adopted v0.6.0 state schema. The
existing v2 transition validator independently verifies generation +1,
persistent repository identity and every all-time ID tombstone before
the envelope is returned. For a non-bootstrap request the previous bytes
must exactly match the supplied expected SHA-256.

The output has precisely these five fields, encoded as sorted,
minimal-separator ASCII JSON (no newline):

```json
{
  "request_schema_version": 1,
  "expected_generation": 1,
  "expected_state_sha256": "<64 lowercase hex SHA-256 of previous state>",
  "next_state_base64": "<canonical base64 of next v2 state>",
  "next_state_sha256": "<64 lowercase hex SHA-256 of next state>"
}
```

The specimen above documents the shape only; it is not a valid literal
candidate. Bootstrap requires `expected_generation=0` and
`expected_state_sha256=null`. Next-state bytes are limited to 4 MiB and
the complete envelope to 6 MiB, matching the existing #31/#64 proposal.
The function returns the exact `envelope_bytes`, its digest and explicit
`False` authority flags; it never writes, stages, signs, transmits or
prints candidate bytes itself.

## Intended future integration after dependency acceptance

1. The separately reviewed operator-side lifecycle workflow first reads
   the *actual protected* predecessor under the authenticated lock and
   computes its exact digest. The #95 reusable v2 builder from **merged
   PR #410** and this serializer are now joined by
   `render_fixed_native_repository_lifecycle_envelope`.
2. Use the combined function **only as deterministic preparation**. A
   reviewed fixed-path, owner-verified staging mechanism must separately
   accept the output. No caller-selected service, executable, environment,
   filesystem path, callback or arbitrary native request is added here.
3. The installed #31/#64 root worker, **independently** of these caller
   inputs, authenticates the operator and its installed code/host, reads
   the fixed intake, re-reads the protected ledger under the exclusive lock
   and checks exact predecessor bytes, all-time tombstones and generation.
   It must run full NGINX syntax/reload/exposure validation and the durable
   state/include/catalog journal before publication, with rollback/recovery.

Never use this helper's result as root/operator authorization. A forged
previous state and a matching forged digest can pass a pure function; only
the authenticated installed root worker may decide whether those bytes
match protected persisted state. Even a valid envelope does not prove
actual NGINX routes, signed publisher metadata, an active client catalog,
cache ownership, or installed service/SELinux behavior.

The original #95 end-to-end acceptance criteria remain OPEN. This is a
bounded Stage-A implementation increment without native host mutation.
The #64 independent security review and issue-specific maintainer decision
still block production root broker integration. A withdrawn publisher
identity remains historically reserved under the approved v2 schema:
safe same-identity re-add/cache reuse needs a separate explicit approved
policy, not silent weakening of the ledger.

## CI verification

```sh
python -m pytest -q tests/test_server_repository_reconcile_v1.py
python -m pytest -q tests/test_server_proposed_state_v2_store.py
```

Regression cases check exact ASCII/base64/JSON byte shape, SHA-256 and
generation binding, clean bootstrap, tombstones across removal, strict
identity continuity, stale and forged digests, noncanonical or duplicate
JSON keys, bounded input types and zero OS/network/process effects. Additional
CI cases execute the **real merged #410 builder** through the combined
operation-to-native-wire pipeline: add with automatic ID, enable, disable,
update without identity reassignment, remove with permanent tombstone,
idempotent no-op and stale/malicious intent refusal. The
source-state generation is not proof of actual installed host readiness.

For the **full native wire compatibility** gate, the accepted and
exact-SHA-pinned #237/#254 code must be tested together with this output
against its real fixed intake in an isolated Linux environment. Passing
these contract tests alone does not complete that cross-PR gate or
authorize a protected merge, signing, release, or VM operation.
