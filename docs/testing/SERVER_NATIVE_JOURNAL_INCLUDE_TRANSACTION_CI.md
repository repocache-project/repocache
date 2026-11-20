# Native package journal + NGINX include promotion under one lock (#27)

This Stage-A acceptance test combines previously **separate** functional
boundaries; it is not a production installer. The issue #27 "failed
validation/reload leaves the previous configuration usable" requirement must
eventually be tested on an actual managed booted host. Before any such
privileged installation can be permitted, the code must demonstrate that
the intended managed include can be syntax-checked while the native
package-effects marker is durable and the **same protected state lock**
remains continuously held.

## CI execution / exact scope

`.github/workflows/server-v06-native-journal-include.yml` uses a clean
`debian:trixie-slim` or `almalinux:10` Docker container for each job. The
GitHub source checkout is mounted **read-only**. Python and necessary
stock native facilities are installed inside the disposable image. The
test-only script checks the exact container sentinel, non-systemd PID 1,
supported OS/architecture, no prior protected state and no existing
NGINX footprint **before native package mutations**.

The script `scripts/ci_v06_native_nginx_journal_include_transaction.py`
then performs:

1. Create and verify the generation-zero root-owned protected namespace
   and locked journal directory **inside the disposable container**.
2. Inspect conservative fresh NGINX ownership and read-only protected
   prepackage state. Reject existing foreign NGINX and any ambiguous input.
3. Durably prepare the native APT/DNF package-effects pending marker,
   retain its exclusive lock, and install the actual distribution NGINX
   package using the existing stock-package trust test runner. Every
   native subprocess proves the marker and independent lock contention.
4. **Before releasing that same lock**, use the merged private #27
   descriptor-bound managed-include primitive at the fixed
   `/etc/nginx/conf.d/repocache-managed.conf` path. Verify native
   `/usr/sbin/nginx -t -q` accepts a valid include and rejects an
   invalid directive while the lock remains contended.
5. Exercise both fresh absence and a specifically fixture-owned prior
   include, repeating valid/invalid/valid candidates and checking that
   the old inode, bytes, mode and owner (or original absence) were
   restored each time; no stage/backup files remain after successful
   restoration. Refuse a foreign include for which the caller has no
   expected previous digest without touching the existing file.
6. Prove the original **durable native marker bytes remain unchanged**
   during all syntax operations, even when the real parser fails. Release
   the lock without removing the marker. The locked second package
   transaction is then refused until **independent reconciliation**.
7. Validate the preserved previous include and stock NGINX syntax once
   more, with the native lock already released; this last check does
   **not** claim an exclusive lock, any production service or authority.

The package manager and NGINX in this test are actual distro binaries.
An operator-supplied host root is **never** a valid invocation context.
No production-state v2 migration, service reload, systemd PID1, SELinux
enforcing, signing or network publish is attempted.

## Security and rollback boundaries

The pending APT/DNF-effects marker is **not** evidence that installed
packages were rolled back. Even after valid NGINX syntax and successful
fixture restoration, it must remain pending. The locked fixture does not
authenticate the current installed host, real host root, operator consent,
native artifact signature, protected state-v2 generation, TLS key identity,
application catalog state or any service health proof. Nothing in this
workflow creates a reusable privilege token, bypasses the still-pending
root-control security review #64, or grants host NGINX activation.

The include is deliberately restored even after **successful** syntax;
the rehearsal does not commit candidates. A future reviewed #31/#64
production writer must stage all resources, maintain the real host lock
and journal through activation, authenticate provenance, verify active
services/SELinux and preserve known-working host state. The original
issue #27 requires booted Debian 13/AlmaLinux 10 acceptance under #19.

Run source-only focused tests:

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_ci_v06_native_nginx_journal_include_transaction.py
```

## Acceptance scope

| Criterion | Stage-A evidence target | Full original #27 |
| --- | --- | --- |
| Real APT/DNF package plus valid and invalid managed include in **one** retained lock | PASS only if both real distro jobs succeed | **NOT VERIFIED** on host |
| Previous known owned include inode/bytes/mode and initial absence restored | PASS only after executed parse/recovery | **NOT VERIFIED** active service |
| Unknown/foreign include and early native retry refused | PASS only when true native marker is retained and checks fail closed | **NOT VERIFIED** host ownership |
| Native package effects journal stays pending after failed syntax | PASS only if durable marker survives | **NOT VERIFIED** full package rollback |
| Booted systemd, SELinux enforcing, signed installed root helper, actual privileged reload and active-only routing | Not exercised; deliberately false | **NOT VERIFIED** |

**Do not close #27** or request premature VM tests based on this
disposable-container proof. The dependency PRs #237 and #254 remain
separate and subject to their issue-specific protection gates.
