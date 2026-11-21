# #95: one-generation protected-state v2 repository batch builder

The v0.6.0 repository lifecycle now has separate, CI-tested pure batch
planners for add, update, enable, disable and remove. Those are merely
untrusted documents, not durable ID reservations or a complete protected
state transaction. The new
`plan_repository_v2_batch_transition` in the already-packaged
`server_repository_v2_transition_v1.py` bridges those planners to the
**same adopted canonical state-v2 ledger as individual operations**, with
all-or-nothing semantics and **exactly one next generation** for a changed
batch. No administrator CLI or privileged endpoint is added.

## Input/identity/transaction contract

The caller supplies a full prior v2 canonical snapshot and its exact
SHA-256, the expected generation, a bounded decision-reference digest,
one operation and exactly one relevant selector shape:

- `add` / `update`: a tuple of 1–64 complete/partial-ID repository
  objects respectively, no `repository_ids` or `all_repositories`.
  Automatic IDs are resolved against the validated **all-time**
  protected history including retired IDs, never a caller-supplied list.
- `enable` / `disable`: a tuple of 1–500 validated, distinct managed
  IDs. Already-correct and unknown valid IDs get explicit no-op outcomes
  without a false claim of actual live NGINX exposure.
- `remove`: an explicit, unique tuple of up to 500 managed IDs or
  `all_repositories=True`; missing valid selectors are reported as
  `ALREADY_ABSENT`. Normal removal **never** deletes cache bytes.

The function first canonicalizes/validates the complete v2 predecessor
and compares its generation and SHA-256. Next it invokes the existing
strict batch planner. If nothing actually changes, it returns
`proposed_snapshot=None` and does **not** increment generation or propose
a WAL. If changed, it builds exactly one next v2 snapshot containing the
complete validated install configuration, active/disabled records,
unchanged identity digests, all allocated and retired historic
reservations/tombstones and the new decision-reference digest. It checks
the full v2 transition validator before returning. Duplicate/historical
IDs, duplicate origin identities, in-place cache source rebinding, stale
SHA/generation, unexpected selectors and invalid objects refuse the
whole proposal with fixed, redacted errors. No partial result escapes.

This is still a **pure/IO-free Stage-A proposal**. Caller-provided source
bytes/digests are not proof of installed ownership or operator approval.
Only a separately authenticated signed #31/#64 native root worker may
re-read the actual protected ledger while holding the native lock, verify
TLS/pins and ownership, generate native routes and publish the actual
observed active catalog atomically with a durable WAL. The #64 independent
security review and explicit owner approval remain mandatory. Do not
re-export this planner as a privileged API, invoke NGINX, adopt a removed
identity under another ID or modify existing public CLI commands.

## Executable tests / evidence limits

```sh
python -m pytest -q tests/test_server_repository_v2_batch_transition_v1.py
```

The tests exercise auto-ID additions with all-time reservations,
multi-update without identity changes, enabling/disabling and removal of
two APT/DNF repositories in one generation, missing/repeated selectors,
conflicts, stale generation/whole-state digest, no-op handling, historical
retention and strict false authorization flags. A genuine detached Linux
fixture runs **the merged four-resource state/include/catalog/owner-manifest
WAL** with two enabled repository entries in one committed generation,
then retires both in a second committed generation, demonstrating correct
all-or-nothing private catalog/ID correspondence and no pending journal.
This is **not** proof of installed native worker/NGINX exposure, signed
publisher metadata, actual cache purge or booted systemd/SELinux testing.

Original #95 acceptance criteria remain open for the full signed and
installed implementation; source-only stage-A CI cannot close them.
