# Non-activating repository batch state preview (#95)

`repocache.server_repository_state_batch_v1.plan_mixed_repository_states` is
an internal, pure Stage-A planning helper for up to 64 unique repository IDs.
Unlike the existing homogeneous `plan_batch_repository_states` operation,
this input may enable one repository while disabling another in the same
uncommitted candidate. It reuses the strict install schema and the individual
repository state planner to prepare one candidate for multiple explicit `active` or
`disabled` requests. Repeated requests for an already-matching state are
no-ops; duplicate, unknown, invalid or stale targets refuse the entire batch.
No partial candidate is returned on refusal.

**Do not treat desired state as live state.** This helper does not read or
authenticate protected storage, check operator privileges, run `nginx -t`,
reload NGINX, write a catalog, delete caches or modify APT/DNF sources.
All authority flags are false. An eventual privileged #31/#95 transaction
must recheck current generation, approval, repository ownership, address pins,
NGINX acceptance and actual route health, then publish an active-only catalog
atomically or restore the previous working generation.

This is not a public CLI command and does not complete #95 native acceptance.
The corresponding tests are
`tests/test_server_repository_state_batch_v1.py`.

## One-generation mixed state proposals for native staging

The already-implemented `plan_mixed_repository_states` preview can now be
used by the **existing** canonical v2 batch builder and offline operator
proposal preparer. One request may simultaneously enable one repository
and disable another, with **one** candidate generation, full prior-state
SHA-256 compare-and-swap and complete historical ID/identity preservation.
It serializes using the **unchanged five-field fixed #31/#64 native candidate
format**; no additional privileged operation, API or public client CLI has
been introduced.

The source-only `scripts/prepare_server_repository_lifecycle.py` accepts
this strict JSON request (in a private operator-owned 0600 file):

```json
{
  "operation": "set-states",
  "state_changes": [
    {"repository_id": "debian-trixie-main", "desired_state": "disabled"},
    {"repository_id": "almalinux-baseos", "desired_state": "active"}
  ]
}
```

The list must contain **1–64** exact objects with unique existing repository
IDs and `active`/`disabled` states. Any duplicate/unknown/unsafe ID,
unallocated identity, stale generation/SHA, extra selector, ambiguous JSON
key or invalid state rejects the **whole** request. The canonical protected
v2 transition is revalidated after the pure plan. A no-op emits **no**
envelope or proposal file and does not advance a generation.

Use the preparer's existing `--dry-run` first to inspect the candidate
digest, then create with `--expected-proposed-state-sha256` for exact-byte
review binding. The output remains an untrusted **full next v2 snapshot**,
which an authenticated installed worker must independently verify and
stage against the current protected predecessor; mere possession of an
output file or decision digest grants no root or service authority.
Existing `add`, `update`, `enable`, `disable` and `remove`
requests retain their previous contracts and cannot include
`state_changes`.

CI regression commands:

```sh
PYTHONPATH=src python3 -m pytest -q \
  tests/test_server_repository_state_batch_v1.py \
  tests/test_server_repository_v2_batch_transition_v1.py \
  tests/test_server_offline_lifecycle_proposal_v1.py
```

This closes only the **pure canonical v2 + review-bound native-intake-data
handoff** gap in #95. It does not claim an actually active NGINX route, a
trusted administrator identity, a successful real DNS/TLS/metadata probe,
publisher signatures, safe force-cleanup, production deployment or native
systemd/SELinux acceptance of this new mixed-state scenario.
