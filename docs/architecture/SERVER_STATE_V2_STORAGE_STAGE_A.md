# Adopted v0.6.0 state-v2 persistence — independent Stage-A storage core

## Provenance and scope

The approved initial schema is recorded in the maintainer's decision on
issue [#31](https://github.com/repocache-project/repocache/issues/31).
This PR extracts the **exact existing** non-installed, fixture-scoped
persistence and recovery implementation from the larger Draft PR #237,
without changing its approved schema or duplicating the algorithm. This
allows the stable storage core to be tested and integrated separately
from the still-blocked, independently reviewed privileged boundary #64.

It is **not** a production installer or a root broker. All private fixture
write functions reject a current-namespace `/` root FD. The only
current-namespace entry points are read-only inspections and provide no
authorization to mutate the host or expose cached repositories.

## Persistent storage and recovery

The canonical v2 state has seven closed fields:

- `state_schema_version: 2` and monotonic `state_generation`,
  initial durable generation 1.
- `configuration_base64` containing a strict canonical complete v1
  install document; `configuration_sha256` is its exact digest.
- `repository_records` with canonical identity digest and desired state,
  at most 500 currently present repositories.
- `id_reservations` with up to 10,000 historically allocated/tombstoned
  stable repository IDs; retired IDs remain unavailable.
- `approval_reference` binding a known digest and prior-generation
  intent, but **not** authenticating the administrator or native authority.

The state store uses the existing owner-pinned protected namespace and
exclusive file lock, canonical bounded JSON, descriptor-relative no-follow
reads, fail-closed ownership checks, strict compare-and-swap generations,
durably fsynced stage/journal, recovery of exact previous bytes and
idempotent unchanged operations. It refuses any coexistence with legacy
v1 state/journals, native APT/DNF pending effects or ambiguous unowned
files. A hostile or interrupted state cannot silently become approved.

Related *fixture-only* shadow multi-resource WAL tests exercise a state,
NGINX include, derived client catalog and manifest under one protected
state lock. Recovery refuses drift and preserves the previous consistent
generation. Read-only locked digest, preview and catalog-binding APIs
never assert live service activation. All shadow resources stay under
the disposable state fixture; no public NGINX configuration or catalog is
written by this PR.

## Executable CI evidence

The dedicated native userspace workflow runs on Debian 13 (system Python
3.13) and AlmaLinux 10 (system Python 3.12), with real Linux filesystem,
inodes, locks, process-exit injection and distro-provided NGINX syntax
checks, against:

```sh
PYTHONPATH=src python3 -B -m pytest -q -rs \
  tests/test_server_proposed_state_v2_store.py \
  tests/test_server_locked_manifest_reconcile_v1.py \
  tests/test_server_protected_state_store_v1.py
```

The original PR #237 retains byte-identical copies temporarily for
compatibility with its Draft root-control/native-activation changes.
Once this standalone core is integrated into the protected canonical
branch, PR #237 must reconcile its base so those files disappear from
its effective diff; any divergence must be reviewed explicitly. The two
PRs do **not** represent alternative state writers.

## Mandatory acceptance exclusions

Original #31 criteria remain OPEN: this Stage-A fixture evidence cannot
prove an installed root authenticated transaction, a booted Debian 13 or
SELinux-enforcing AlmaLinux 10 host, real NGINX reload and rollback,
signed APT/DNF package safety, native cache preservation, or genuine
operator approval. The root-control code #254 and its independent #64
security review/merge approval remain separate and mandatory. Stage-B
native VM evidence belongs to #19; release signing and publication
remain owner-held #76/#88 operations. No automatic journal deletion,
migration from v0.4.0 or destructive cache cleanup is introduced.
