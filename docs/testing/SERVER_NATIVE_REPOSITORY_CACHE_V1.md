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
