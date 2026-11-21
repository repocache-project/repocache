# Read-only per-repository NGINX cache force-cleanup preview (Stage A)

**Primary issue:** #95, coordinating #29 and #31, v0.6.0.

Normal removal of a managed repository must withdraw its exposure and
discovery but retain its cached package bytes indefinitely, subject to
ordinary native cache-manager limits and storage pressure. Explicit
force-cleanup is a separate potentially destructive operation; an
untrusted caller-supplied repository ID and a filesystem scan do not
authorize it.

## Fixture-only read-only evidence

The internal API preview_repository_cache_cleanup_under_root accepts a
pre-existing descriptor to a detached, caller-owned **test fixture**
namespace. The real OS root descriptor is categorically refused. It
verifies the existing fixed root-owned cache marker and exact inode
marker for the validated repository ID using the same descriptor-pinned
primitives as the already-integrated protected cache bootstrap. It does
not use caller-controlled paths outside the closed identifier schema.

It then inspects the private per-repository native cache path for the
expected **levels=1:2** lowercase hexadecimal directory structure and
32-character hex cache filenames. Every directory or file is inspected
through an O_NOFOLLOW/O_DIRECTORY or O_NOFOLLOW/O_NONBLOCK descriptor,
without reading cached package payload bytes. Entries with unexpected
type, symlinks, hardlinks, unverified ACL/xattrs, mount changes, wrong
UID/GID, group/world writes or unstable identity are rejected. Unknown
content never results in a partial cleanup estimate. A global 20,000
entry cap, recursion fixed to two levels, and bounded byte sums prevent
unbounded positive previews. The implementation does not remove,
rename, truncate, chmod, chown or open cached content for writing.

A successful preview returns exactly an observed file count, directory
count, apparent payload bytes from stat(2), and allocated block bytes
from st_blocks. These are **not** promised reclaimable space or proof
that a cache file is unused. It cannot ensure live NGINX cache manager
quiescence, retained-package integrity, signed operator approval,
SELinux contexts, installed host provenance or a safe removal
transaction. All authorizes_* flags are false. A missing/foreign
repository marker is a hard refusal, never an estimated zero cache.

The two-distro CI workflow constructs genuine protected fixture roots
with the existing bootstrap and executes adversarial filesystem tests
as UID/GID 65534. Both Debian 13 and AlmaLinux 10 runs are userspace
containers, not booted native host/SELinux acceptance.

## Joined protected-v2 retirement and cache ownership preflight

`preview_locked_retired_repository_cache_cleanup_under_root` provides a
**functional read-only integration** between two previously separate
fixture boundaries. It acquires the existing owner-pinned exclusive
protected state-v2 lock, refuses legacy/multi-resource recovery, reads
the actual canonical persisted v2 snapshot and requires:

- An exact caller-pinned generation and exact SHA-256 of those persisted
  bytes; an untrusted caller-provided history is never accepted.
- The selected repository ID is a permanent `retired` reservation in
  `id_reservations`, absent from current `repository_records`.
- The existing fixed cache-root and repository ownership markers,
  inode identity and expected native NGINX levels=1:2 cache layout
  successfully pass the earlier bounded filesystem preview.
- The protected ledger remains byte-identical with no newly pending
  journal after the scan, while the same state lock is held throughout.
- Both the earlier state-only fixture and the **committed, four-resource
  state/include/catalog/manifest domain** from merged #410 are supported
  in read-only mode. A completed #410 owner manifest is validated against
  exact state/include/catalog bytes, not confused with an interrupted
  multi-resource journal. Unknown, mismatched or partial owner resources
  fail closed; outstanding multi-resource and v2 state journals block
  the scan independently of retired-ID status.

An allocated/active/unknown ID fails **before any cache scan**. A
changed generation or state digest, foreign/symlinked cached object,
pending recovery journal or lock contention fails closed. Only the
selected repository's observed counts and allocated/apparent bytes
are returned. The preflight does not open cached payload for writing,
unlink anything, change state, stage a catalogue or reload NGINX.

This is still a **detached test-root fixture API**, not an approved
production broker. The state record `retired` does **not** prove that
a live NGINX worker has drained, the origin is unshared, the operator
authorized irreversible deletion, or that the installed signed root
control service is the caller. A passing report cannot be used as an
unlink or force-cleanup token. All authority flags are false; the
root lock is released before return. The future native owner must
re-derive and revalidate cache ownership, active transfer quiescence
and selected identity at the actual destructive transaction boundary.

CI regression command:

```sh
python -m pytest -q tests/test_server_repository_cache_cleanup_preview_v1.py
```

The protected-v2 tests use **actual durable fixture filesystem commits**
for a present APT repository, then retire it through the merged #95
v2 operation planner. A second scenario uses the exact committed #410
multi-resource WAL with a derived catalog and checks that tampered owner
manifests and pending WAL markers never become cleanup authority. They inspect its retained package cache while
the state lock is held, reject still-allocated state and unsafe objects,
and verify journal refusal and byte-for-byte cache preservation. This
is useful Stage-A evidence, not installed native systemd/SELinux proof.

## Requirements before any real force-cleanup feature

A future, separately reviewed installed root worker must prove the
operator's explicit force-cleanup request, authenticated repository
identity and active/retired state, trusted root/cache ownership and
SELinux context, actual NGINX cache quiescence, a transaction journal
and restart-safe rollback or irreversibility policy. It must check
exact bytes and ownership *at the instant of destructive action*;
this read-only preview cannot be upgraded into permission to unlink.
No direct deletion of unknown opaque NGINX cache objects is approved.

The v0.6.0 original #95 force-cleanup, selective isolation and native
Debian 13 / AlmaLinux 10 end-to-end criteria remain NOT VERIFIED; final
host acceptance belongs to #19. This preview does not expose any CLI
command, root broker or production-operation switch.
