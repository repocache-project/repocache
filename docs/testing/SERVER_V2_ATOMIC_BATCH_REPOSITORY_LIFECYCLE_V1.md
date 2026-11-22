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

## Fixed native candidate handoff, still no native authority

The companion `render_fixed_native_repository_batch_envelope` in the
already-packaged `server_repository_reconcile_v1.py` joins this complete
batch builder to the exact five-field fixed native candidate intake
serializer introduced by merged PR #411. For one changed batch it
returns **one canonical ASCII/base64 envelope**, with the expected
predecessor generation/hash and the SHA-256 of the exact full next v2
state. A no-op returns `envelope_bytes=None`, so it cannot
accidentally request an extra state generation or service reload.
The envelope contains no user-selected file path, executable, callback
or arbitrary privileged operation.

This is only a byte-serialization bridge. It does not write the fixed
admin candidate file or attest who approved a change. The independently
reviewed native #31/#64 worker must authenticate the operator and
installed host, reload/read the actual protected state under its own
lock, revalidate the complete batch, and verify live NGINX exposure
before publishing its active discovery catalog.

## Executable tests / evidence limits

```sh
python -m pytest -q tests/test_server_repository_v2_batch_transition_v1.py
```

The tests exercise auto-ID additions with all-time reservations,
multi-update without identity changes, enabling/disabling and removal of
two APT/DNF repositories in one generation, missing/repeated selectors,
conflicts, stale generation/whole-state digest, no-op handling, historical
retention and strict false authorization flags. Additional tests pass
the whole two-repository batch into the fixed native candidate byte
envelope, validate one five-field canonical wire, digest/CAS binding,
idempotent no-op, tamper refusal and permanent tombstones. A genuine detached Linux
fixture runs **the merged four-resource state/include/catalog/owner-manifest
WAL** with two enabled repository entries in one committed generation,
then retires both in a second committed generation, demonstrating correct
all-or-nothing private catalog/ID correspondence and no pending journal.
This is **not** proof of installed native worker/NGINX exposure, signed
publisher metadata, actual cache purge or booted systemd/SELinux testing.

Original #95 acceptance criteria remain open for the full signed and
installed implementation; source-only stage-A CI cannot close them.

## Locked full-batch four-resource fixture transaction

`commit_fixture_repository_batch_under_root` in the existing
`server_fixture_repository_transaction_v1.py` exercises the same
**complete v2 batch** against an actual protected, owner-pinned detached
Linux fixture directory. It reads the canonical ledger and its all-time
ID reservations under the first exclusive lock, constructs a single batch
candidate, derives the managed NGINX include and shadow discovery catalog from
the same active IDs, and passes the whole generation to the existing
state/include/catalog/owner-manifest persistent WAL. The WAL takes its own
lock, verifies the exact prior generation and SHA-256 again, keeps the
previous catalog during the fixture prepublication barrier, and atomically
commits or records recoverable rollback evidence. No-op batches do not write
new WAL bytes or advance the generation. One invalid member or bad pin
rejects the whole batch before mutation. All-repository removal retires
historical IDs but never deletes cached objects.

The private fixture callback is not a real NGINX readiness attestation.
No administrator authentication, installed privileged writer, native
service reload, real catalog publication or cache purge is authorized.
The actual `/` root is always refused. Never import this fixture entrypoint
in privileged production code.

Additional test coverage:

```sh
python -m pytest -q tests/test_server_fixture_repository_transaction_v1.py
```

The batch scenarios assert one durable generation for two-repository
enablement, coherent shadow routes/catalog, entire-repository removal with
retained bytes, two-source auto-ID allocation from persisted history, stale
or malicious selector rejection with no filesystem mutation, repeat no-op,
prepublication callback refusal and a simulated crash followed by exact
four-resource WAL rollback. These are **Stage-A fixture tests**, not
booted Debian/AlmaLinux acceptance or independent security review.


## Owner-locked fixture v2-to-native candidate handoff (#95)

The internal prepare_locked_fixture_native_batch_envelope_under_root entrypoint
extends the exact-byte fixed #31/#64 candidate serialization with the actual
persisted, owner-pinned fixture v2 state and immutable historical ID ledger.
One exclusive descriptor lock verifies the canonical predecessor, its SHA-256
and generation, the complete state/include/catalog/owner manifest, recovery
markers and state inode metadata. It constructs a complete one-generation
batch through the existing lifecycle builder, then rechecks all four resources
before releasing the lock. No-op batches return no envelope and do not stage
new work. A separately executed four-resource WAL regression demonstrates
that the resulting native intake proposes the exact bytes committed by the
protected fixture transaction, not just an abstract candidate plan.

This is a nonprivileged, detached-fixture-only read/prepare bridge: real '/'
is refused, and no native candidate is written to an installed intake path.
An envelope is not an approval, lock lease, actual NGINX syntax/reload result
or published active client catalog. The future separately reviewed #237/#254
fixed-identity native worker must independently authenticate its operator,
verify the installed protected predecessor under its own lock, apply/rollback
the real NGINX transaction and prove active exposure before publication.
The original #95 native service, force-cleanup, real signed publisher and
booted Debian 13 / AlmaLinux 10 gates remain NOT VERIFIED.
