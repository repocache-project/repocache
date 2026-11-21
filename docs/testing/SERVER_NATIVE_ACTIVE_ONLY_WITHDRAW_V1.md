# Native active-only NGINX and derived discovery withdrawal

**Primary issue #95, coordinating #28, release v0.6.0.**

The server cannot advertise a repository after it becomes disabled.
This CI integration checks the actual approved repository renderer and
the automatically derived read-only client catalog against real stock
Debian 13 and AlmaLinux 10 NGINX parser output. It uses three successive
candidate states: two repositories active, one disabled, then both
re-enabled. The production renderer first validates public upstream
pins, source layout and policy; NGINX -T parses the full candidate.

In the disabled phase the removed route and catalog mapping must both
disappear. A forged parser dump containing the disabled route is refused
by the existing catalog candidate validator. A private cached-object
sentinel keeps the same inode and SHA-256 across all three candidates,
demonstrating that route withdrawal never requires deletion.

The test drops to UID/GID 65534 inside disposable distro containers.
Every configuration, scratch cache and temporary file remains private;
the original parser-only candidate phase remains read-only. A separate
nonroot, loopback-only NGINX master is started and reloaded exclusively
inside this disposable container; no public upstream is contacted.
A positive nginx -T result is not proof of the actual installed route
configuration, trusted request approval or published client discovery.

Still NOT VERIFIED: installed privileged NGINX route activation, installed
root worker and atomic WAL, true NGINX cache-loader reuse, native
systemd/SELinux on booted Debian 13 and AlmaLinux 10, and signed
APT/DNF client fallback. Original #95 and native acceptance #19 remain
open; this candidate CI provides no production authority.

## Additional real nonroot NGINX worker-generation checks (Stage A)

The same two-distro CI workflow now also starts a **disposable NGINX
master under UID 65534** with an independent loopback-only listener,
then exercises four live route states: both APT/DNF routes present,
DNF disabled, DNF removed, original validated configuration restored.
Before each private reload, real stock NGINX syntax is checked.
Following a SIGHUP sent only to that exact child process, the test
observes that the former worker generation has drained before
asserting HTTP 204 (active) or HTTP 404 (absent) for each repository.
An unknown route remains 404, and an existing private cache sentinel
retains its inode and SHA-256 through every transition.

The runtime probe is deliberately injected with test-only `return 204`
inside the **already validated** locations, and validated public DNS
pins are remapped to an unreachable **loopback** port after rendering.
This prevents public network I/O, while checking the real NGINX
route-selection and reload semantics for each state. It does **not**
exercise upstream package signatures, cache HIT/MISS or actual NGINX
cache-manager persistence, which already have separate CI fixtures.

Only the ephemeral, nonroot, disposable master is signalled or
terminated, never the installed NGINX unit. This is not a production
installer, verified root host state, authorized database transaction,
published client catalog, crash/restart recovery, or booted-systemd/
SELinux acceptance. Original #95 AC1/AC3/AC4/AC6 remain open wherever
those real operational properties are required.
