# Managed repository NGINX bundle v1 — candidate only (#28)

**Target:** v0.6.0 / PR #227. **Status:** source and tests are proposed on the feature branch; exact-HEAD execution and operational acceptance are separate gates.

## Scope and authority

`server_nginx_repository_bundle_v1.render_repository_nginx_bundle_candidate` is
a pure representation adapter for the **reviewed v1 server installation
document** (#18) and repository-centric lifecycle contract (#95).
It does not implement #95's trusted ID/approval ledger or #31's privileged
writer, transaction journal, rollback, or live NGINX ownership checks.
Routes are derived from a repository, never a second administrator-managed
entity. A caller-supplied `desired_state: active` is **not** proven operator
approval. `expected_state_generation` is a necessary freshness comparison,
not a credential or a lock.

The adapter validates the entire closed install schema, rejects stale generation,
requires stable IDs for every desired-active repository, and demands an **exact**
repository-ID-to-complete-DNS-pin mapping. Unknown/disabled/missing pin entries
refuse the entire bundle. Each repository is passed through the existing
strict numeric-destination, original Host/SNI, TLS-verifying, redirect-denying
NGINX fragment renderer (#215); output is sorted by ID to avoid
configuration-order nondeterminism. Output is bounded to 1 MiB.
The CA path is syntax-validated even if no repository is active, but the
actual CA file's trust/ownership remains an independent native acceptance gate.

Return fields `proposed_repository_ids`, `http_upstream_fragment`, and
`server_location_fragment` are **inert proposals**. They are *not* a
complete managed include, a certified mapping, an active route inventory or a
client discovery catalog. The result always includes
`trusted_state_provenance_verified=false`,
`operator_approval_verified=false`,
`active_exposure_verified=false`,
`authorizes_nginx_activation=false` and
`authorizes_catalog_publication=false`.
Do not persist these flags as evidence of a privileged transaction.

## Boundaries before activation

- #95 owns authoritative repository identity, explicit administrator intent,
  approval, lifecycle and active/disabled status. Pure #95 reconciliation
  previews and this NGINX adapter must never independently authorize writes.
- #31 owns the exclusively locked protected-state generation CAS, manifest
  ownership comparison and durable journalled staged activation/rollback.
- #27 owns native NGINX provisioning and non-adoption of foreign service state.
- #29/#97 own per-repository cache ownership, cache-key/policy semantics,
  retention/pressure and safely supported packaged NGINX directives.
- #28 owns final managed NGINX route derivation, strict no-SSRF/open-proxy
  integration, stage `nginx -t`, verified reload/exposure, and atomic
  read-only discovery generated **only after verified successful activation**.

This increment deliberately does **not** add `proxy_cache` or announce cache
HIT and metadata-integrity acceptance. A complete cache key, zone and policy
require the #29/#97 contracts and native packaged-version testing.
It also does not expose a callable service or write a configuration file.

## Evidence boundary

Focused synthetic and NGINX-container test command:

```sh
python3 -m pytest -q tests/test_server_nginx_repository_bundle_v1.py
```

The native NGINX pin workflow on both Debian 13 and AlmaLinux 10 executes
this alongside existing HTTPS pin/redirect tests. Security negatives cover
unsafe DNS answers, incomplete or extra IDs, generation drift, missing IDs,
malformed upstream URLs, CA syntax, disabled repository exclusion,
determinism, error redaction and prohibited filesystem/service/network
side effects. A disposable `nginx -t` checks only fragments embedded in
a deliberately isolated synthetic NGINX configuration.

**NOT VERIFIED** until executed at exact current SHA: all newly added tests,
trusted authorizations, actual complete managed include and cache keys,
real staged `nginx -t` / reload / rollback, atomic active-only discovery,
package/metadata correctness and repeated cache HIT, booted systemd and
SELinux enforcing evidence on both supported native hosts.
