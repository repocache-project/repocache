# #95 — exact-HTTPS active-only catalog transitions under stock nginx -T

The disposable Debian 13 and AlmaLinux 10 stock-NGINX smoke now
exercises the real parser on four configurations derived **exclusively
from versioned repository metadata**, all bound to the same temporary
TLS listener and valid test-only certificate:

1. Both independent APT and DNF repository mappings active.
2. DNF explicitly disabled; only APT remains advertised as a candidate.
3. DNF removed from the desired repository document, still only APT.
4. Original two-repository config restored in the fixture.

Each phase regenerates the complete, exact HTTPS server block and
HTTP upstream/cache declarations, runs distribution `nginx -T`,
and checks that the **read-only, non-authorizing** client catalog
projection exactly matches the approved active IDs. No second catalog
allowlist is introduced.

Two negative checks use real NGINX parser acceptance as their baseline.
First, the previously valid *two-route* dump is rejected when checked
against the now-disabled DNF repository document. Second, a malicious
additional DNF location is placed into the generated **one-route**
HTTPS server block. Stock `nginx -T` accepts that configuration, but
the derived-catalog checker must reject the unauthorised route rather
than incorrectly advertising its APT-only candidate as safe.

**PASS scope when CI is green:** stock-NGINX syntax and fail-closed
catalog/HTTPS candidate correspondence on two distribution containers.
**NOT VERIFIED:** installed root ownership and generations,
authenticated operator authorization, real active NGINX listener/TLS
handshake, atomic catalog publication and protected state-v2
transaction/recovery. The test does not start a real service or access
any external repository; native signed APT/DNF and cache HIT are
covered independently. The original issue #95 is not closed.

## Protected v2 catalog binding now requires the full HTTPS context

The private read-only `server_proposed_v2_locked_catalog_binding_v1.py`
previously accepted an untrusted route/upstream-only `nginx -T`-shaped
string. It now requires the entire exact generated HTTPS server context,
including the selected listener, TLS certificate/key references, SNI and
active-only locations, before deriving client-schema candidate bytes.
The same exclusive fixture state lock covers validated state-v2 bytes,
the generation/SHA and an optional complete four-resource owner manifest.
If the fixture state/include/catalog ownership domain is present, the
manifest and derived active set must match. Pending journals, changed
state/inode, malformed or missing owner resources, forged TLS listener,
extra routes and route-only dump strings are refused without writes.

The check deliberately does not run NGINX or authenticate the claimed
`nginx -T` text. It does not verify the actual TLS certificate, handshake,
running NGINX master, installed root or administrator. The **privileged
native worker** must independently authenticate those facts under its
real host transaction before a catalog can be published.

```sh
python -m pytest -q tests/test_server_proposed_state_v2_store.py
```

CI scenarios verify deterministic exact-HTTPS client catalog mapping,
single-state and complete multi-resource ownership, unchanged protected
bytes, stale SHA/generation, forged/missing owner manifest, pending WAL,
listener/SNI/TLS drift and previously accepted route-only claims.
