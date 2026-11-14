# Compiled APT/DNF source TLS trust refusal (Stage A)

**Primary issue #24; v0.6.0.**

The existing real APT/DNF signed-repository/fallback CI tests prove
that the compiler's generated client source prefers the cache and falls
back to upstream when the cache is unavailable. Successful fallback must
**not** become an excuse to disable TLS verification.

This change adds a fifth *negative* phase to that same full CI smoke.
The fixture generates a second unrelated, short-lived certificate
authority. Both cache and upstream remain healthy HTTPS endpoints
using the first authority. The exact compiler-produced APT deb822 or
DNF repo source is replayed with the wrong trusted CA only in the
disposable native package-manager invocation. All HTTP requests must
be blocked by TLS handshake; native command must fail. A code-zero
result or a request accepted by either endpoint is a hard failure.

Debian APT and AlmaLinux DNF run this negative case after the existing
preferred, cache-failure fallback, recovery and both-failed phases.
Fresh metadata directories are used. No unsafe APT/DNF flags to
disable signature or TLS checking are introduced; no production source
or key is altered. All ephemeral private CA keys stay in container
scratch and are **not** publisher keys.

The test demonstrates native package-manager trust refusal for a
synthetic source and generated source candidate. It cannot prove
production package publisher identity, real client root authorization,
booted native systemd/SELinux or installed-source rollback; those
original #24/#19 criteria remain NOT VERIFIED.
