# Read-only native NGINX package-effects reconciliation evidence (#27/#31)

**Stage A.** Native APT and DNF transactions are not atomic. The existing
fixed package-effects journal in the protected #31 state namespace is fsynced
*before* any native package manager is called. The new
`server_native_package_effects_observe_v1.py` verifies that the exact pending
marker is still intact, while holding the same protected state lock. This
closes a reproducibility gap after a package transaction or interruption;
it **never declares that package effects were reconciled**.

An observed
`NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION` report proves only that
one preexisting root-owned marker matches the fixed v1 canonical schema,
expected Debian/APT or AlmaLinux/DNF identity and zero-generation state,
and continues to block re-entry. The module refuses both missing and extra
pending-temp files, a separate in-flight protected-state transaction,
nonzero existing managed state, unexpected distro/manager/package fields,
duplicate/noncanonical JSON, symlinks, weak modes, foreign inodes and
concurrent lock ownership. Every error uses a fixed, redacted code.

The public current-namespace observer can be invoked only as root and
rechecks the pinned `/` inode before and during observation, without writing
any file or starting an executable. Matching its own current mount namespace
does **not** authenticate the actual host, installation provenance, systemd,
native NGINX, SELinux, operator intent or root delegation. A detached-root
test adapter allows real Linux inode/crash scenarios without touching the
installed namespace. Both entry points are internal functions, not an
installed CLI or root worker.

The disposable Debian 13 / AlmaLinux 10 native package transaction CI
now calls the current-namespace observer **after the real native NGINX
package transaction, package database check, durable state marker and
re-entry refusal**. A valid pending record is not cleared. Its report cannot
turn a package transaction into production PASS, cannot uninstall anything
and cannot grant permission to retry. The test records only the positive
observation of a still-pending journal; the initial prepackage marker may
legitimately exist even if package installation failed or never began.

## Evidence and refusal tests

```sh
PYTHONPATH=src python3 -B -m pytest -q \
  tests/test_server_native_package_effects_observe_v1.py
```

The native lock-scope workflow runs the tests in actual disposable Linux
Debian 13 and AlmaLinux 10 userspaces, covering same-lock exclusion,
incomplete publication, mismatched identities, forged/corrupt marker,
symlink, unsafe mode, protected state collision, no subprocess calls and
repeatable immutable observations. The full native journaled install CI
retains the pending marker even after the actual container package success.

No automatic journal clearance or native host repair is authorized.
Such a mechanism would require an audited package-database reconciliation,
#31 transaction integration, independent #64 security review/approval,
signed host installer and native systemd/SELinux rollback tests. Final
booted VM acceptance is owned by #19 and remains **NOT VERIFIED**.

Original #27/#31 operational criteria remain OPEN. This is not a release
or Merge Queue approval for privileged code.
