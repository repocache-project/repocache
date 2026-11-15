# Host-root refusal for fixture-only TLS material verification (#30)

The descriptor-pinned TLS pair checker accepts only a **detached fixture
root**. Before descending into fixed `etc/repocache/tls` or opening
private-key descriptors, it now compares the supplied directory descriptor's
device/inode with Linux `/`. The live root is always rejected with the
static `TLS_MATERIAL_LIVE_ROOT_FORBIDDEN` error. The check runs before
any certificate/key load and never emits sensitive paths or bytes.

Real Linux regression tests open the actual root descriptor and verify
early refusal, including when a private-key walk is instrumented to fail
if called. The existing fixture roots and real ephemeral OpenSSL identity
tests remain supported.

This is a **negative trust-boundary fix**, not an installed TLS verifier.
An authenticated root helper, issuer/key provenance, SELinux enforcing
labels, service state, operator authority, NGINX deployment and both booted
native targets remain NOT VERIFIED under issue #30/#19.
