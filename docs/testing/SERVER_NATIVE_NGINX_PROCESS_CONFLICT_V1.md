# Refuse a live NGINX process even without on-disk package markers (#27)

The fresh native NGINX ownership gate previously checked only a fixed set
of pathname markers. A removed or relocated executable/configuration can
leave a **still-running NGINX master** in the kernel process table. Treating
the missing pathname as a fresh server could incorrectly proceed to APT/DNF
metadata and eventually overwrite an externally managed service.

## Functional change

`server_native_nginx_ownership_v1.inspect_fresh_nginx_footprint`
checks existing fixed paths first. If there are no known path conflicts and
all path reads succeeded, it inspects `/proc/<pid>/comm` with a bounded,
read-only, O_NOFOLLOW, nonblocking descriptor-based scan. It refuses
`nginx` and `nginx:` process-name prefixes *before* any native repository
metadata request. Access failures, unexpected process names/report codes,
unsafe links, or excessive PID counts produce a separate fail-closed
`NGINX_PROCESS_SCAN_UNVERIFIED` result. It never emits PIDs, process
command-line arguments, environment variables, paths, or contents.

A privileged (EUID 0) scan also checks the kernel's read-only
`/proc/<pid>/exe` symlink after the bounded `comm` read. A native executable
whose final path component is exactly `nginx` (including the kernel's
` (deleted)` suffix after unlinking) blocks installation even when the
process renamed its `comm` to a harmless-looking value. Unreadable executable
links fail closed as `PROCESS_SCAN_UNVERIFIED`; vanished processes and kernel
threads without an executable do not produce a false conflict. No executable
target is opened, followed, returned or logged. Unprivileged scans preserve
their earlier, weaker `comm`-only behavior and cannot serve as install proof.
The targeted executable-name check is intentionally not a complete binary
identity or cross-namespace inventory.

This is intentionally a **conservative early refusal**, not proof of no
NGINX instance: process names and executable filenames can be altered,
a process can appear after
the scan, there may be separate mount/PID namespaces, and other service
implementations or listeners may exist. Consequently the familiar
`FRESH_NGINX_FOOTPRINT_NOT_OBSERVED` result remains `NOT VERIFIED`,
and no outcome authorizes package writes, a service reload, an ownership
takeover or catalog publication. The future authenticated root transaction
must repeat all relevant checks while holding its correct state lock.

## Real native CI and regression evidence

`.github/workflows/server-v06-nginx-process-refusal.yml` runs fresh
Debian 13 and AlmaLinux 10 disposable Docker userspaces, with source
mounted **read-only** and distro-native NGINX packages installed only
inside those images. The CI script rejects execution outside the explicit
disposable container context, checks non-systemd PID1 and a clean
initial process scan, then starts a **real stock NGINX master** with a
temporary isolated configuration/listener.

With that master running, it simulates the absence of every fixed
filesystem marker using an injected lstat callback, while the
production-default **real /proc scan remains enabled**. The fresh
preparation must return `NGINX_RUNNING_PROCESS_REFUSED` and invoke
neither the metadata probe nor any APT/DNF manager. The NGINX fixture
process is terminated in a finally block. The native CI reports
`CI_REAL_NGINX_PROCESS_CONFLICT_REFUSED` and explicit false host
installation, booted systemd and SELinux flags.

The journaled native APT/DNF late-recheck workflow also runs a disposable
executable named `nginx`, renames its live kernel process name, and verifies
it still causes pre-manager refusal under the retained protected lock; native
install proceeds only after the fixture exits.

Unit regressions cover two distro inputs, real process-name variants,
symlinked comm files, disappearing PIDs, /proc denial, scan bounds,
unexpected injected values, preserved filesystem-conflict precedence
and non-disclosure of error data.

Run locally without any native NGINX privileges:

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_server_native_nginx_ownership_v1.py
```

## Acceptance ledger / release boundary

- **Stage-A PASS only after exact-HEAD CI:** running native NGINX process
  denies fresh ownership even when disk markers are synthetically absent,
  no metadata/package manager is reached, and security regressions pass.
- **Issue #27 AC4 partially evidenced:** conflicting NGINX is refused in
  this specific runtime-process scenario; other active service/namespace
  conflicts still require authenticated live host checks.
- **NOT VERIFIED:** authoritative host package/root identity, privileged
  installed-host ownership, APT/DNF/recovery integration with #31/#64,
  real systemd activation on booted Debian 13/AlmaLinux 10, AlmaLinux
  SELinux enforcing, installed-host repeat/idempotence and the full
  native rollback requirements. Keep #27 open until coordinated #19 VM
  acceptance is complete.

The workflow is **CI only**, not a published script or a privilege source.
No real host package, daemon, service or protected namespace is modified.
