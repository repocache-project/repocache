# Retained native package-effects lock scope (issue #27, Stage A)

A native NGINX package transaction is *not* atomically reversible. The existing
durable pending marker in the root-owned #31 state namespace was previously
written under a short-lived exclusive state lock. Releasing that lock before
APT/DNF effects creates a concurrency gap: a second repository or NGINX state
writer might run while the package manager is still modifying the host.

The new internal
\`_retain_native_package_journal_lock_under_root(root_fd, owner_uid, distribution)\`
context writes the **same unchanged canonical durable pending marker before
yielding**, then retains the *same* #31 exclusive lock throughout the entire
nested scope. The existing preparer is implemented through this context and
keeps its old short-lived behavior. The pinned lock and marker are never
replaced or cleaned implicitly. If the nested operation fails, the persistent
marker blocks re-entry until a separately designed audited recovery. Existing
protected state, unknown files, interrupted journals, wrong origin/mode,
symlinks and concurrent locks are refused.

This Stage-A internal API deliberately **does not execute any native package
manager, accept package names or trust sources, validate signatures, authenticate
an operator, authorize an install, enable NGINX or claim actual host-root
provenance**. An arbitrary caller-supplied root FD, UID or fixture callback is
not authority. An independently authenticated installed fixed-operation
helper, signed package trust, privileges and real systemd/SELinux integration
remain mandatory before any production APT/DNF invocation.

The approved future execution order is: independent root/package/ownership
preflight; obtain the protected lock; fail-closed generation-zero check;
persist and fsync the irreversible-effects marker; re-verify fixed signed
sources/payloads; invoke only the reviewed fixed native package transaction
*while retaining the lock*; validate installed NGINX, systemd and TLS; commit
protected owned state; then separately reconcile the marker after actual
package-state audit. An interruption at any stage is a hard stop, never
automatic package rollback or marker unlink.

CI evidence for this bounded change uses actual Linux file locks and fsync
in disposable Debian 13 and AlmaLinux 10 containers; the tests force a
second lock attempt, crash after the marker, native-action exception and
prepublication journal faults. They never run APT/DNF under this context.
Booted native host, SELinux enforcing, real repeated install, package recovery
and service activation remain NOT VERIFIED for parent #27/#25/#19.

Test:
\`python3 -m pytest -q tests/test_server_native_nginx_package_journal_v1.py\`
