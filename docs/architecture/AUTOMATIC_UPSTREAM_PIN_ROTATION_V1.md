# Automatic upstream IP rotation — implementation guard for #28/#95

**Scope:** v0.6.0 managed repository backend. **Status:** approved
operator requirement; implementation **PARTIAL / NOT OPERATIONAL**.
This file is an implementation note in draft PR #215, not evidence of
adoption or of production activation. The maintainer explicitly selected
**Option A with automatic updates**: no administrator shall need to
maintain upstream IP addresses manually when approved mirrors change DNS.

## Contract

- An administrator approves and manages repository metadata and its exact
  HTTPS hostname/allowed-host identities. IP addresses are **not** a routine
  operator-maintained input or a second user-managed repository object.
- A trusted managed-service scheduler periodically resolves all required
  A/AAAA destinations for already-approved, enabled repositories. Its
  interval is bounded (recommended minimum five minutes) with per-host
  jitter, network-failure backoff and reload deduplication. There is no
  DNS TTL claim: the standard `getaddrinfo` API does not return TTLs.
- Every observed address must pass public-destination policy. **One**
  private, loopback, link-local, metadata, multicast, reserved,
  IPv4-mapped or malformed address rejects the **entire** proposed refresh.
  DNS failure cannot authorize a hostname fallback or partially overwrite
  the current trusted pin set.
- A safe changed answer set is only a **candidate**. Compare with the
  authenticated last-known-good state while holding its exclusive lock,
  using the expected generation. Persist only via the #31 transaction
  journal and the #28/#95 native activation engine.
- NGINX must connect **only to numeric, controlled pin destinations**,
  never independently resolve the approved hostname at proxy-request
  time. The original approved DNS name remains the HTTP Host and the
  TLS verification/SNI name; verification remains enabled using a
  validated CA bundle. Reject arbitrary redirect origins and unapproved
  dynamic `proxy_pass`/open proxy patterns. Prove the final configuration
  on each supported distro's packaged NGINX, including IPv6.
- Stage on owned paths, check complete config with `nginx -t`, reload,
  verify observed exposure and package-manager metadata integrity, then
  atomically derive/publish the catalog from actually active mappings.
  On any failure, restore/reconcile last-known-good pins, NGINX, catalog
  and protected generation. Do not mutate client APT/DNF source files.
- Rebinding to a new **public IP for the same approved hostname** needs
  no routine human action. Changing the allowed hostname, trust material,
  repository identity, or authorization remains a distinct controlled
  administrator operation. Existing-NGINX adoption or host firewall
  mutation is never implicit.

## Staged delivery / evidence

| Work item | Acceptance |
| --- | --- |
| Strict, bounded, complete caller-supplied DNS snapshot rejection | Implemented in PR #215; scope is static only |
| Explicit, bounded DNS refresh of approved active hosts | Draft pure candidate-generation + opt-in DNS resolver in PR #215; CI/independent review required |
| Semantic no-op detection and changed pin candidate | Draft PR #215; CI/independent review required |
| Periodic daemon/timer with jitter, backoff and safe recovery | NOT IMPLEMENTED |
| Protected state/ID authorization, locking, journalling and generation | NOT IMPLEMENTED |
| Deterministic candidate NGINX upstream/location fragments (literal IP, hostname TLS, redirect denial) | Draft pure renderer in PR #215; `nginx -t` check is conditional on a packaged NGINX installation; not production SSRF proof |
| Actual pinned NGINX runtime enforcement, staging/reload/rollback | NOT IMPLEMENTED |
| Atomic verified exposure and derived catalog, native cache HIT/integrity | NOT IMPLEMENTED |
| Native Debian 13 + AlmaLinux 10 systemd/SELinux/NGINX evidence | NOT VERIFIED |

**Security boundary:** the draft `propose_automatic_upstream_refresh`
function is not the scheduler and does not install a timer, update
NGINX, authorize a route, perform a connection, persist pins or publish
a catalog. The function's outputs are not approval provenance. Never
enable an operational command based only on this module.

**Safety fallback:** if DNS is unsafe or unreachable, keep the trusted
last-known-good configuration rather than authorizing new destinations.
Availability is not guaranteed: old pins may stop working, and APT/DNF
upstream fallback must be verified separately on actual clients.

## Candidate fragment notes

The bounded, purely functional `server_nginx_pin_render_v1.render_pinned_upstream_fragments` returns a proposed `http{}` upstream block and separate `server{}` route and redirect-denial locations. Both are **inactive strings**, not a trusted install document or deployed include. The input CA file reference and upstream URL path must be NGINX-directive-safe (no semicolons, whitespace, percent escaping, variables or shell syntax), in addition to the strict installation schema. Redirect responses (301/302/303/307/308) are intercepted and mapped to 502; `proxy_redirect off` alone would not have prevented a client from following an unapproved redirect. Only GET and HEAD are forwarded. TLS hostname/SNI comes from the approved upstream hostname, while the NGINX server group contains only numeric pinned IPs. No generic HTTP proxy is exposed.

Integration must validate that the final managed NGINX configuration uses **only** these destinations; must not combine the fragments with dynamic host-based fallback. The CA bundle must be an existing, correctly owned, verified operating-system trust store; the path string alone is not evidence. Separately configure robust metadata/artifact freshness, APT/DNF signed metadata and cache correctness through the full #28/#95 engine. Do not install this fragment in a production listener until full native TLS tests, ownership, transaction rollback and catalog consistency are demonstrated.
