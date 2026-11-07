# Disposable native NGINX cache/TLS smoke — #28 / #27

This test executes real distribution-packaged NGINX on **Debian 13**
and **AlmaLinux 10** as a non-root process in disposable Docker containers.
The workflow installs native nginx, Python, OpenSSL and CA certificates
from the OS repositories, then runs with no external network, a read-only
root/checkout, dropped capabilities, and a temporary TLS key which never
leaves the container.

The independent test validates generated #28 APT/DNF **candidate** fragments
using real `nginx -t`, with synthetic PUBLIC pinned addresses; this
never activates a route or publishes discovery. Production origin-pinning
continues to reject loopback/private addresses.

A separate **test-only local** NGINX TLS proxy/cache configuration
connects to a loopback HTTP fixture. Real HTTPS requests verify a trusted
short-lived certificate, exact bytes for two APT objects and two DNF objects,
and an observed MISS followed by HIT with one backend fetch/object. It
also checks unapproved route refusal, non-GET denial, ignored upstream
X-Accel-Redirect and rejection of upstream 3xx redirects. No real package
manager, signed repository metadata or production endpoint is contacted.

A checked-in script **is not execution evidence**. Exact-HEAD GitHub Actions
job logs for both platforms are required to claim scoped PASS.

The original complete-server acceptance remains **NOT VERIFIED**: actual
administrator-authorized routing/catalog, real signed upstream APT/DNF
transfer through a managed route, native package transaction, booted
systemd and enforcing SELinux, external service/TLS, cache ownership and
capacity, staged reload/rollback and host preservation. No privileged
production operations, GitHub releases or publication are performed.

## Proposed native cache-zone candidate rendering

The #28 renderer now emits one independent stock proxy_cache_path and
cache key zone for every desired-active repository. Paths derive from the
strict requested cache_root and validated repository ID. The conservative
keys_zone is 1 MiB per repository. The global inactive_seconds and
max_size_bytes values are inherited unless each respective per-repository
override is present. Read-only candidates use 60s HTTP 200 GET/HEAD
cache validity while respecting upstream Cache-Control, with concurrent
fill locking and Authorization/Cookie request cache bypass + no-store.

**Security:** even nginx -t can create cache directories when parsing a
candidate. The test uses only non-root disposable, temporary fixture paths.
A real privileged apply MUST separately verify every cache ancestor,
symlinks/mount/ACL/xattr/SELinux, native capabilities and total zone memory;
it must validate/reload under #31 with rollback, and derive catalog routes
only from successfully active state under #95/#28. This renderer does not
provision ownership, activate NGINX, publish catalog data or guarantee
stock NGINX cache-manager or disk-pressure behavior. The 1 MiB zone
is a conservative initial bound and is NOT evidence of live key capacity.

## Exercise the actual generated production candidate in isolation

A second disposable execution in `scripts/ci_generated_nginx_route_cache_smoke.py`
first lets the unchanged production candidate renderer validate the required
PUBLIC numeric pin for both APT/DNF upstreams. **After** validation and
solely for this Docker-only runtime test, it replaces exactly two numeric
upstream endpoint lines with a loopback TLS server. The public-IP/SSRF
policy in production remains unchanged and refuses localhost/private pins.
A generated candidate uses per-repository cache directories in the ephemeral
container root, real trusted temporary upstream HTTPS certificate, approved
`proxy_ssl_name` and observed upstream SNI, and the exact generated
proxy/cache location directives. Real NGINX then serves each of four APT/DNF
metadata/package fixture bytes on a `MISS` followed by `HIT` from the
separate per-repository caches, with only one origin GET. Repeat negative
checks show authenticated/cookie responses are never cached, and invalid
paths, 3xx and X-Accel redirects remain blocked. A test-only readout header
reports NGINX's real `$upstream_cache_status`.

This **narrows the earlier code/fixture gap** but remains a deliberate,
visible *test-only numeric pin transformation*. It does not establish that a
trusted live DNS resolver supplied the public candidate addresses, that
native signed APT/DNF upstream metadata is valid, that an authenticated
operator/state generation authorized activation or that a real server was
installed. Never promote the loopback substitution to production code or
allow a user-supplied IP through the strict pin validator.
