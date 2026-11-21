# Per-repository native NGINX cache ownership fixture v1 (#29/#95)

**Stage A implementation; not a host installer, service activation, cache
deletion permission or proof of a complete server.** Native booted Debian 13
and enforcing SELinux AlmaLinux 10 acceptance remains NOT VERIFIED.

The integrated fixed-cache/bootstrap primitive first creates and authenticates
`/var/cache/nginx/repocache-managed` with a root-owned marker in the
non-worker-writable parent. The new
`server_native_repository_cache_v1.bootstrap_repository_cache_under_root`
creates or verifies one exact subordinate `<repository_id>` directory at mode
0700 owned by the nominated cache account **inside a detached fixture root**.
IDs must match the closed server v1 identifier grammar. No operator-supplied
path, shell command, native package manager or network operation is available.

## Durable ownership and retention

Each repository's inode, device, UID, GID, mode and ID are recorded in a
canonical root-owned 0600 file in the *trusted parent* of the worker-writable
cache root. That placement prevents the NGINX account from rewriting the
evidence by editing its own cache subtree. Readers open directories and
markers descriptor-relative with no symlink following, compare named and
opened inode identities, reject hard links, noncanonical records, unexpected
xattrs/SELinux labels, insecure modes, foreign existing directories and
owner-marker mismatches. They recheck pinned ancestry before returning.

A fresh create fsyncs the directory, ownership and marker in order. **An
interruption before the owner marker is durable intentionally hard-stops
re-entry**: an apparently empty or foreign directory must never be
silently adopted, deleted or recreated. An interruption after the durable
marker is safe to inspect and repeat. A repeat preserves the existing inode
and every cached object without unlinking, renaming or chmod of stored data.
New repositories receive separate directory names; no cleanup API exists.

This *does not* authenticate the repository's approval, state-v2 generation,
all-time ID reservations, installed signed NGINX binary, SELinux context,
mounted filesystem, daemon ownership or per-repository cache attribution.
NGINX must actually be configured to use these paths within the future
protected #31/#28 transaction. A destructive #95 force-cleanup still requires
independent proof that no shared cache objects exist and a separately
approved, crash-recoverable root transaction; neither is present here.

A signed installed host worker must also prove identity of the native cache
service user, active server state and protected transaction lock, and must not
reuse fixture root descriptors as production authorization.

## Executed CI contract

The two-distro disposable NGINX storage workflow runs
`tests/test_server_native_repository_cache_v1.py` along with the existing
native root bootstrap suite on Debian 13 and AlmaLinux 10 container
userspaces. The tests exercise actual Linux inodes, mode/owner markers,
separate repositories, cached-byte retention, forged/missing ownership,
symlinks and crashes at durable boundaries. Systemd is not PID1, SELinux
enforcing is not tested and no actual NGINX cache service is activated.

Focused local smoke:

```sh
PYTHONPATH=src python3 -B -m pytest -q \
  tests/test_server_native_repository_cache_v1.py
```

Original #29 operational acceptance and the final #19 VM campaign remain
OPEN / NOT VERIFIED, irrespective of Stage A fixture checks.


## Locked correlation of active repository routes with owned cache roots (#95)

The additional `preview_locked_active_repository_cache_roots_under_root`
is a **read-only, detached-fixture** acceptance gate for the data-driven
repository lifecycle. It reads the complete committed state-v2 +
private NGINX include/catalog/owner manifest under the existing exclusive
protected-state FD lock; rejects incomplete recovery, legacy state, stale
generation/digest, inconsistent owner manifest and any unexpected change
of resource bytes or state inode.

Its set of required cache roots is derived **exclusively from
`repository_records` whose `desired_state` is `active`**, never a
caller-maintained allowlist. For each such ID, it reopens the native
NGINX cache parent under pinned root descriptors and verifies the fixed
root-owned cache marker and each repository's exact private inode/ownership
marker, UID/GID/mode and no-symlink directory. If even one desired-active
repository is missing a safe root, the **entire preflight fails**; no
partially accepted set is returned. Disabled/removed repositories need
not own an active cache root, and removal does not delete retained bytes.
The full cache parent is checked even when no repository is active.

This checks root ownership **without traversing individual active files**:
NGINX may write temporary cache content during in-flight transfers, and a
strict cleanup-style file scan is inappropriate as an activation guard.
Actual NGINX worker mode, live exposure/reload, TLS, signed APT/DNF
metadata, shared cache namespace, SELinux, effective service UID/GID
provenance and trusted operator identity remain **NOT VERIFIED**.
No success report grants state commit, cache bootstrap, public catalog
publication, NGINX activation or force cleanup. The real `/` descriptor
is rejected **before** touching the protected-state lock.

CI can execute this real inode/marker/ledger fixture behavior:

```sh
python -m pytest -q tests/test_server_native_repository_cache_v1.py
```

Tests commit actual persistent v2 generations via the merged multi-resource
WAL; validate inactive, one- and multi-repository active sets; reject
missing, forged and symlinked cache marker/roots, pending WAL and stale
state; preserve cached package bytes/inode after disable/remove; and
assert read-only execution. This is prerequisite source evidence, not a
production host-root privilege or Debian13/Alma10 systemd/SELinux PASS.

The independently reviewed native #31/#64 worker must repeat these
preconditions with its **authenticated root**, trusted OS NGINX package and
locked installed state, then actually activate the NGINX generation and
observe its catalog. Never call this fixture routine as a privileged
production endpoint.


### CI runtime compatibility repair (test harness only)

The existing native owned-cache/metrics NGINX smoke imports the shared
`trusted_fixture_origin` from the generated-route smoke. The latter
recently added **two required in-flight transfer barrier Events**, while the
existing metrics smoke still called it with only the request counter and
lock. Its two-distro Actions job failed with a Python `TypeError` before
NGINX started, unrelated to a cache-root ownership failure. The shared
CI-only HTTPS origin now supports **both events omitted** (legacy metrics
smoke, no held-transfer case), or **both explicitly supplied** (strict
worker-drain scenario). Supplying only one event, or an invalid event
type, is refused rather than silently reducing the worker-drain guard.

No production renderer, upstream/TLS policy, journal, user CLI, privilege
boundary or active runtime service was changed by this compatibility fix.
The previously failing Debian13/AlmaLinux10 native owned-cache/metrics job
must PASS at the same source HEAD before this PR can enter the queue.
