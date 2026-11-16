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
