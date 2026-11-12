# Fixed protected state namespace bootstrap — real fixture filesystem writes (#31)

The v0.6.0 protected-state transaction and native pre-package inspection require
a pre-provisioned /var/lib/repocache/server directory (mode 0700) and an empty
single-link .state-v1.lock file (mode 0600). The prior implementation could
only read an already existing protected namespace.

This increment adds a **real, descriptor-relative, fsync-persisted bootstrap**
for those exact names, not a mock directory-plan. In disposable Linux fixture
roots, it creates root-owned-by-expected-UID directories, persists the lock,
then executes the existing #31 exclusive lock/identity checks. It never accepts
operator-supplied target names, never changes ownership on pre-existing paths,
and never modifies NGINX, packages, TLS, cache, logs, client sources or service
units. A second call validates existing ownership, mode, inode, lock and
cross-process lock; it does not replace the lock or overwrite state.

The sole internal API takes a **caller-supplied root directory descriptor and
expected UID** for reproducible isolated Linux tests. These values are NOT
authorization or host-root provenance. There is no installed entry point,
signed image, automatic service activation or privileged worker. Do not invoke
it on a real system: a future reviewed signed installer, security boundary and
host-root/SELinux/mount/ownership proof must establish authority first.

An interrupted bootstrap is recoverable *only if the complete durable lock
already exists*. A crash after one directory but before lock publication
leaves an explicitly ambiguous partial footprint. Re-entry fails closed and
requires separately reviewed operator reconciliation; it is **never** silently
adopted or deleted. This intentionally avoids misrepresenting non-atomic
directory creation as a fully crash-recoverable server installation.

The existing #31 state WAL, v2 activation, native APT/DNF package journal,
signed server installation, NGINX activation, SELinux, booted Debian 13 /
AlmaLinux 10 and same-version repair remain separate gates. No source path
here grants arbitrary root writes, even when a test fixture succeeds.

Test through CI: python -m pytest -q
tests/test_server_protected_namespace_bootstrap_v1.py
