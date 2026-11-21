# Stage-A managed NGINX include promotion and restoration fixture (#27)

This is a **functional, non-activating filesystem transaction primitive**
for the eventual NGINX provisioning engine, not only a read-only mock.
It creates a named candidate, fsyncs it, pins an existing owned file with
a hard link, atomically promotes the candidate at the **fixed**
`/etc/nginx/conf.d/repocache-managed.conf` path relative to a supplied root
directory descriptor, invokes an injected syntax-validation callback and
**always restores** the prior file inode or prior absence. It fsyncs directory
publication and restoration and refuses leftover stage/rollback names.

## Safety boundaries

`src/repocache/server_native_nginx_managed_rehearsal_v1.py` deliberately
exports **no** host-running CLI, service controller, privileged broker or
persistent activation capability. Its private fixture-root operation does not
authenticate:

- a current host root or mount namespace, real operator approval or systemd;
- an authoritative #31 manifest and its generation or an external #31 state
  lock held for the **entire** transaction;
- the material to be rendered, trust in its digest, TLS secrets, live process
  identity, SELinux context, actual network routes or an NGINX reload;
- rollback of a multi-resource or power-loss transaction.

An exact current-namespace root directory FD is explicitly rejected unless
this is the guarded disposable root Docker CI fixture, with the CI environment
marker, Docker sentinel and non-systemd PID 1. This defense does not replace
#64 authentication and does not grant production root access.

The caller-supplied expected SHA-256 is a **test fixture precondition**, not
a proof of ownership. A real executor must first authenticate the package,
root, operator, protected v2 state, manifest and lock through #31/#64, then
add durable multi-resource journaling and actual post-reload health proofs
before it can reuse these lower-level operations.

The fixed basename is the only permitted live include name. All path
traversal uses dirfd, O_DIRECTORY/O_NOFOLLOW and root-ownership-safe
directory checks. Writes use O_EXCL/O_NOFOLLOW, bounded bytes, strict
mode/owner checks and explicit fsync. File identity and bytes are rechecked
around the transaction. Existing unmanaged files, symlinks, hard-linked
files, unsafe modes and leftover stage/rollback files are refused.

If syntax fails, the fixture restores the original inode/absence before
returning a fixed error code. If replacement or restoration itself cannot
be proven safe, the function **fails closed**: it does not silently discard
unreconciled objects or represent recovery as successful. A complete crash
recovery algorithm remains #31's responsibility; only the specifically
backed-up post-promotion fixture phase is supported below.

## Bounded post-promotion crash recovery (Stage A)

The new private `recover_interrupted_owned_include_fixture_under_root`
function handles **exactly one** previously unrecoverable state of the
test-only include transaction: a separate process exits after atomic
promotion of a candidate, leaving a single-linked, previously managed
backup inode at `.repocache-managed.rollback`, the candidate still at
`repocache-managed.conf`, and no `.repocache-managed.stage`.

The recovery accepts two independently supplied trusted SHA-256 values:
the **prior owned include** and the expected **promoted candidate**.
Before changing any name, it validates each file's bounded content,
owner/group, mode, single link and identity through no-follow dirfds,
checks both exact hashes, rejects every other stage/backup shape and
rechecks the ancestor chain. Only then does it atomically rename the
known-good backup over the exact candidate, fsync the directory and
verify the original inode and bytes are restored. It never deletes an
unknown stage, fabricates the expected digest, recovers the first-install
(no-prior-backup) case or silently retries an ambiguous operation.

**This is not a production crash recovery algorithm.** The test-only
caller must already hold an authenticated external state lock, but this
function does not check or grant that lock. Even a passing recovery
does not authenticate the host root, protected #31 v2 generation or
manifest ownership, pending native package effects, signed publisher,
real systemd/SELinux context or active NGINX worker health. It neither
runs `systemctl` nor reloads NGINX; real host-root invocation remains
refused outside the disposable Docker guard. A post-`rename`,
pre-`fsync` power failure can still be ambiguous and must be
independently reconciled by #31/#64, not automatically treated as PASS.

The native Debian 13 / AlmaLinux 10 CI workflow now forks a separate
Python process, promotes a real managed include and exits that process
with `os._exit(73)` from the syntax callback, deliberately bypassing
all Python `finally` blocks. The parent verifies the actual orphaned
backup and candidate, confirms the real distribution NGINX parser,
recovers the original file **at the original inode**, repeats a real
NGINX syntax check, and rejects an unsupported second recovery.
No live service reload or host package recovery is claimed.

Regression coverage also deliberately poisons both digests, introduces
a stale stage, replaces a backup with a symlink or hardlink, changes the
candidate after the crash, simulates `os.replace` I/O failure and
forbids a current host-root recovery. Every such case must fail
closed without changing the candidate/known-good backup.

## CI evidence and execution

The workflow `.github/workflows/server-v06-nginx-managed-restore.yml`
installs stock native NGINX **inside fresh Debian 13 and AlmaLinux 10
Docker images** with a read-only source checkout. Its test-only entrypoint
refuses non-Docker/root context, booted systemd PID 1, a pre-mounted include
directory and pre-existing managed transaction names.

For **each** distribution it uses real stock `/usr/sbin/nginx -t -q`:

1. Promote an initial valid managed candidate and restore the empty state.
2. Promote an intentionally invalid NGINX directive; require the **real
   parser** to fail; restore absence and revalidate stock NGINX syntax.
3. Create an explicitly owned previous include in the image and perform
   success/failure/success replacement rehearsals. Assert the previous
   **original inode and bytes** are preserved and the original configuration
   remains syntactically valid.
4. Reject a conflicting foreign include without changing its contents.
5. Reject an interrupted pending stage without automatically adopting it.
6. Crash a separate process after the owned candidate has been promoted,
   recover the digest-pinned backup inode under explicit fixture constraints,
   and refuse unsupported repeated recovery or foreign drift.

Local pure-fixture regressions (no packages/services):

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_server_native_nginx_managed_rehearsal_v1.py
```

No workflow job invokes systemctl, listens on a network port, publishes
discovery or installs NGINX on a host. The Docker setup is the **only** native
package installation in this increment. The result is structured, redacted
JSON with `DISPOSABLE_NATIVE_MANAGED_INCLUDE_RESTORE_PASS`.

## Criterion ledger

| #27 criterion / safety property | Stage-A target | Final issue state |
| --- | --- | --- |
| Managed NGINX include creation and repeat replacement without duplicates | PASS only when both real-distro CI jobs and Python tests pass | Booted host **NOT VERIFIED** |
| Foreign, symlink, hard-linked, unsafe-mode and interrupted path refusal | PASS only when tested | Authoritative manifest integration **NOT VERIFIED** |
| Failed real NGINX syntax validation preserves the previous include | PASS only when executed inside disposable image | Active-service rollback **NOT VERIFIED** |
| Installed operational Debian 13 / AlmaLinux 10 native systemd service | Not exercised | **NOT VERIFIED** |
| Native SELinux enforcing, real root/approval, locked state-v2 transaction | Not exercised | **NOT VERIFIED** |

Keep issue #27 open until the authenticated production transaction and
the coordinated native host tests (#19) satisfy the original AC1–AC5.
