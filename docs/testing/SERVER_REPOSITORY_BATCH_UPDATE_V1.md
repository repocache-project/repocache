# #95 — identity-preserving atomic repository configuration batch

`plan_batch_repository_updates` is an internal **inert** v0.6 Stage-A
helper for 1–64 complete validated administrator update proposals. It
reuses the frozen repository-v1 configuration validator and existing
single-update planner. Every repository retains its previously assigned
ID **and canonical source/layout identity**. Changing signing-key
references, allowed-host policy, desired state or cache overrides may
produce a new candidate; source URL/layout reassignments fail the *entire
batch* so an old cached object is not silently adopted by a different
publisher/source or package namespace. A source migration requires a
separately authenticated add and retirement transaction with explicit
cache isolation/retention—not reinterpretation of an existing ID.

The helper validates each proposal before copying, refuses unknown,
repeated, malformed, overlarge, unallocated and stale inputs. It reports
per-target no-op/change outcomes and highlights changed repositories
that were active or become active as **candidates requiring live route
reconciliation**. This list is neither proof of exposure nor approval
to publish discovery or reuse a pre-existing cache.

Tests:
`python -m pytest -q tests/test_server_repository_batch_update_v1.py`.
They verify atomic two-repository APT/DNF policy and key-rotation
proposals, unchanged idempotence, secure identity boundaries, failed
second update, duplicate input and no host/network side effects.

**NOT VERIFIED for original issue #95:** the independently authorized
administrator, durable state-v2/owner ledger, NGINX zone and protected
catalog transaction, native effective cache/key validation, failed
reload rollback, restart/upgrade and SELinux/systemd acceptance on
booted Debian 13 and AlmaLinux 10. This helper does not introduce a
CLI command or privileged service and cannot close the issue.
