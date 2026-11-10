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

An install-v1 `cache_root` may be a canonical filesystem path yet still
contain characters that alter an unquoted NGINX `proxy_cache_path`
directive. The candidate renderer therefore independently restricts the
exact cache-root token to ASCII letters, digits, slash, underscore, dot,
plus and hyphen. It refuses whitespace, semicolons, quotes, comments,
variables and other configuration metacharacters before fragment emission.
The normal install-v1 document validator intentionally has a broader path
contract; this additional NGINX-context check does not replace trusted
filesystem ownership and containment verification.

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


## Actual two-phase reload and route rollback (disposable only)

The generated-fragment test now extends the native live NGINX data-plane
fixture beyond a mere syntax refusal. While the stock NGINX master process
serves verified-TLS APT/DNF metadata and an existing cached HIT, the test:

1. Checks a fixed candidate-only route is absent in the running generation.
2. Writes a temporary config derived from the exact tested generated
   candidate, adds **one fixed test-only route**, executes the real
   distro-packaged `nginx -t`, then a real `nginx -s reload` against the
   isolated process and waits for the new route to return HTTP 204.
3. Verifies the original signed-shape metadata still comes from its cache
   with HIT after the validated route change.
4. Writes back the exact original config bytes, validates them with real
   `nginx -t`, performs a second actual `nginx -s reload`, observes
   the temporary route disappear (404), and confirms exact on-disk config
   bytes, live TLS/cache HIT and unchanged upstream request count.

An earlier negative test deliberately damages a TLS validation directive,
shows real `nginx -t` rejects it, and verifies the previous live NGINX
configuration continues to serve cached data **without sending a reload**.
These are **two real non-root reloads and a route rollback inside an
isolated disposable process**, not a booted systemd host or a rollback of a
failed privileged reload. They do not establish privileged operator
authorization, root-owned state/managed include provenance, atomic catalog
publication, crash durability, SELinux, production TLS trust or service
manager recovery. Running this test must never touch a host NGINX service.


## Active-only client discovery candidate from exact stock NGINX dump (#28/#95)

`server_derived_catalog_candidate_v1.preview_derived_catalog_from_nginx_dump`
is a **pure candidate renderer**. It independently revalidates the closed
server install-v1 configuration, derives its full desired-active repository
set and strict numeric-IP-pinned NGINX fragments, requires one exact
configuration occurrence of both generated fragments, and rejects missing,
duplicate, disabled, unknown or shadowed `/__repocache/repos/<id>/`
routes and foreign managed upstream names. It derives the existing client
schema-1 `{upstream,cache}` mappings directly from each approved repository
record and the validated deployment HTTPS hostname/port; it never creates a
separate operator-maintained route or approval allowlist.

The existing disposable Debian 13/AlmaLinux 10 stock-NGINX smoke now uses a
**second, isolated, unmodified project fragment** to obtain a genuine
`nginx -T` dump before building a non-publishable discovery candidate.
The running cache MISS/HIT test still uses its independently documented
temporary localhost origin substitution. The preview uses the original
8.8.8.8 numeric pin solely for NGINX syntax/parsing: it does NOT connect
to that address or activate the preview file. Unit/security tests require
the complete active-only ID set, correct client schema, non-default HTTPS
port, exact fragment presence, no duplicate/foreign locations and no
successful result for invalid syntax, malformed/oversized dump or unsafe
address pins.

**Not an activation proof:** both `nginx_t_exit_code` and
`nginx_dump_text` are *caller-supplied values*. Even successful exact
matching cannot attest a signed installed host, verified DNS response,
operator authorization, actual active HTTP exposure, certificate trust,
live systemd service, SELinux, or authoritative protected v2 generation.
The result explicitly sets all privileged/publication/active-exposure
flags to false. It MUST NOT be passed directly to the existing
`catalog.publish_catalog` or served to clients. A future fixed root
transaction must itself execute and independently authenticate the live
NGINX syntax/active routes and must publish the client artifact atomically
only after the validated actual service state is exposed, with documented
recovery and no second approval database. Issue #95/#31 operational
acceptance remains NOT VERIFIED; these are executable integration
prerequisites only.
