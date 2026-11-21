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
