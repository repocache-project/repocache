# Native NGINX syntax-failure rehearsal with durable package journal (#27)

## Purpose

The existing journaled native package installation CI can install NGINX
from approved authenticated APT/DNF repositories and validate the default
configuration in disposable Debian 13 and AlmaLinux 10 containers. This
additional negative-path test verifies what happens when **real, freshly
installed stock NGINX** rejects a syntactically invalid configuration
after the package transaction has already completed.

The distinction matters: successfully returning from APT/DNF is not proof
that a complete REPOCACHE server is installed or that an uncommitted native
package-effects journal may be removed. NGINX syntax validation is another
mandatory gate, and failure must not be confused with full rollback.

## Exact Stage-A execution

`.github/workflows/server-v06-nginx-syntax-failure.yml` runs one Docker
container per supported userspace with its source checkout mounted read-only.
It rejects pre-existing NGINX, a prior REPOCACHE state tree, a systemd PID 1,
unsupported distro/Python/architecture, a missing container marker and a
non-root test process before writing. It performs, in order:

1. Create the protected generation-zero namespace and lock; validate the
   fresh local ownership boundary without installation authority.
2. Persist a root-owned pending package-effects marker under the retained
   exclusive state lock.
3. Run the genuine official-source APT/DNF metadata refresh, NGINX native
   package installation and package-owner check. Before each subprocess,
   independently confirm the lock is unavailable through another descriptor
   and the pending marker is unchanged.
4. When the exact `/usr/sbin/nginx -t -q` subprocess is reached, inject
   a deliberately invalid directive **only inside the disposable image's
   stock nginx.conf** and observe a nonzero **real NGINX parser** exit.
   Restore the original bytes to that same inode in a `finally` block.
5. Require the installer to stop with
   `CONTAINER_NGINX_CONFIG_VALIDATION_FAILED`; verify the actual package
   database and vendor unit, restored config SHA-256 and a successful new
   `nginx -t -q` invocation on the original image configuration.
6. Require the native-effects journal to **remain pending**, reject a
   repeat generation-zero transaction and prohibit automatic marker removal.

The test's redacted JSON result includes
`DISPOSABLE_NATIVE_SYNTAX_FAILURE_RECOVERY_PASS`. The two matrix jobs
must finish successfully and emit the associated PASS marker. The test
does **not** restore the package database, since native APT/DNF effects
cannot be rolled back by an atomic JSON state update.

Local mock/negative regressions:

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_ci_v06_native_nginx_syntax_failure.py
```

## Security and acceptance limitations

This script is **test-only** and intentionally lacks any production
entrypoint or privilege delegation. It is **not suitable for execution on
a real host, VM, developer workstation or mounted system filesystem**.
Only its disposable image fixture is deliberately modified, and it does not
invoke `systemctl`, reload a daemon or activate repository routes.
No credentials, private keys, host addresses or package-manager logs are
exposed in the result JSON.

**PASS in Stage A only after exact-HEAD CI:** deterministic post-package
real NGINX syntax refusal, restoration of the test fixture's bytes, durable
pending package-effects marker, no silent reinstall/reentry and preserved
exclusive locking across the package transaction.

**NOT VERIFIED:** audited host package-effects reconciliation, real
same-version repair/idempotency, full managed configuration rollback,
authorized root worker/host identity, booted systemd service activation,
Debian 13 and AlmaLinux 10 native VM operation, SELinux enforcing,
publisher-signed artifacts or production installation.

Keep #27 open. The complete authenticated installer and recovery depend
on #31/#64, and the final booted host campaign is owned by #19. Do not
interpret a green Docker workflow as permission to proceed with VM install.
