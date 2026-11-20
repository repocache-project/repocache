# Foreign NGINX footprint refusal — two-distro Stage-A test (#27)

The `server-v06-journaled-native-package.yml` matrix executes a separate
negative test in **disposable Debian 13 and AlmaLinux 10 Docker images**,
independently of the existing clean-host native package-install rehearsal.

## What this test actually executes

After installing only the Python test prerequisite (no NGINX package), each
fresh image injects two **independent, deliberately unmanaged** footprints:

1. `/etc/nginx/nginx.conf`, representing a pre-existing foreign configuration.
2. `/usr/sbin/nginx`, representing a foreign executable without approved
   distribution ownership.

For each case, the CI driver is called with the disposable-only marker and
the source checkout mounted read-only. It **must** return a nonzero exit,
`DISPOSABLE_HOST_NOT_FRESH`, `FAIL`, and
`authorizes_host_installation=false`. The test checks that the foreign
file's inode, ownership, mode, size, modification time and SHA-256 are unchanged.
It also requires the protected REPOCACHE state tree and NGINX log directory
to remain absent. The fixture is removed by the test itself **only inside
the disposable container**, before injecting the next independent case.

The Python regression test
`tests/test_ci_v06_foreign_nginx_guard.py` also injects foreign paths into
the driver's early environment checks and asserts that no protected state
bootstrap, package rehearsal or even subsequent read-only preflight is reached.
Unlike this synthetic test, the matrix tests actual foreign files on both
distribution userspaces.

Review the exact commit's **Journaled real native NGINX install** jobs and
the marker:

`PASS: foreign NGINX config and executable refused before state or native package effects (CI only)`

Run the local regression check with:

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_ci_v06_foreign_nginx_guard.py
```

## Acceptance boundary

**Stage A, subject to exact-HEAD CI:** pre-existing foreign configuration
and executable reject the disposable package installer **before** its
protected namespace bootstrap or native APT/DNF transaction, with the fixture
preserved. The separately tested signed native package installation and
journaled crash/reentry boundary remain unchanged.

**NOT VERIFIED / not implemented by this test:** authorization of a real
root-owned host installer, package-effects reconciliation/rollback, complete
NGINX configuration ownership, existing third-party instance migration,
idempotent installed-server repair, service enable/start/reload or recovery,
Debian 13 booted systemd acceptance, AlmaLinux 10 SELinux enforcing,
and production candidate acceptance.

This test creates **no host installer** and provides no permission to run
its fixture-writing shell on a real server or VM. The actual #27 original
operational acceptance remains open pending the #31/#64 trusted transaction
and the consolidated #19 booted-host campaign.
