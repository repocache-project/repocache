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

## Real upstream redirect-status denial matrix (Stage A, #28)

The disposable generated-pins HTTPS smoke now drives the **actual packaged
NGINX** on both Debian 13 and AlmaLinux 10 through a full redirect matrix:
301, 302, 303, 307 and 308 from each APT and DNF upstream route. For
every code, two requests must both produce HTTP **502** through the
project-generated NGINX location; the response must never contain a
followable Location header, foreign-host string or successful cache HIT.
The synthetic origin must observe both attempts, proving that redirect
denial was not accidentally cached as a successful repository artifact.

All traffic stays inside the disposable no-network container. The malicious
Location points to a reserved `.invalid` name; no real foreign endpoint is
contacted. The pre-existing X-Accel-Redirect suppression, HTTPS SNI,
signed-shape metadata/DEB/RPM HIT/MISS, failed nginx -t preservation, live
temporary reload, rollback and EACCES cache-off recovery tests are retained.

This validates Stage-A response handling in native NGINX userland. It
does **not** authenticate real OS publisher metadata, operator approval,
host namespace, installed TLS CA, production socket, systemd, SELinux or
the automatic activation/rollback authority that remains NOT VERIFIED for
#28, #27 and #19. No installed exposure or VM GO is implied.


## Real HEAD/GET cache parity on both supported native NGINX binaries (#28)

The generated-fragment HTTPS smoke additionally performs an actual client
`HEAD` against each *already warm* APT and DNF metadata/package object on
Debian 13 and AlmaLinux 10 distro-packaged NGINX. It requires 200, no
response body, the correct cached Content-Length, NGINX `HIT`, no extra
upstream retrieval, and an unchanged subsequent `GET` body/cache HIT.
This guards against a regression where package-manager HEAD queries corrupt
or bypass a previously cached signed-shape artefact. All responses are
fixture bytes, not real publisher-signed metadata, and the traffic uses
fixed test-only loopback TLS and a non-root isolated process. Production
operator ownership, actual signed APT/DNF retrieval and booted VM remain
NOT VERIFIED until the consolidated #19 campaign.


## Actual live repository withdrawal, retained cache and re-addition (#95)

The same isolated Debian 13 and AlmaLinux 10 native NGINX data-plane
smoke now covers an **actual in-process route removal**, rather than only
comparing static nginx -T output. It warms the DNF metadata cache to an
observed HIT and records every fixture cache object's SHA-256 and inode.
It invokes the reviewed #95 batch removal planner with the DNF ID,
requires cache retention and no state-write/purge authority, then renders
the **reduced project NGINX candidate** from its complete proposed document
while retaining the APT repository.
The generated candidate must contain exactly one cache zone, no former DNF
route or upstream, and still deny NGINX activation.

Before any reload, it validates the reduced candidate with real packaged
nginx -t, validates its unmodified public-pin form with nginx -T, and
obtains a **non-publishable** derived client catalog containing only the APT
entry. The live test changes only its private non-root NGINX instance,
performs nginx -s reload, waits for the old worker generation to drain,
and then verifies all of the following together:

- Removed DNF HTTPS route returns 404 (no stale worker still serving it).
- Independently managed APT cached metadata remains a real HIT.
- Every previously cached DNF fixture file keeps its original bytes,
  SHA-256 and inode throughout normal removal.
- The running isolated NGINX master remains alive.

Finally, another real nginx -t and reload restore the **exact** original
configuration bytes. DNF requests again return the expected fixture bytes
with a subsequent cache HIT; APT remains available without a refetch.
The first re-addition request is intentionally *not* required to HIT:
re-creating an NGINX cache zone does not guarantee immediate reuse of
in-memory cache keys even if retained disk bytes survive.

The test uses the same explicit **test-only** loopback rewrite *after*
strict public pin validation as the existing native smoke. It executes
without host network, privileges, source writes, actual package management,
installed service mutation, client source application or catalog publication.
This verifies the #95 **data-plane and byte-retention prerequisite** only.
Authenticated protected-state commits, durable retired IDs, cross-resource
journal and atomic active-only catalog publication, native systemd/SELinux,
live operator approval and signed APT/DNF payload acceptance remain
**NOT VERIFIED**. A passing container test is not release/VM GO.
