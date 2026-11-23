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
