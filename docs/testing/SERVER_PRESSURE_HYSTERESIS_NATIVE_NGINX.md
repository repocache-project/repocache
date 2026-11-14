# Real native NGINX pressure bypass and recovery syntax (Stage A)

**Issue #97; release v0.6.0; coordinating #28 and #24.**

The existing cache-pressure reducer can propose bypassing cache writes
under a known critical disk condition and retaining the bypass while
telemetry is stale or hysteresis has not cleared. The existing repository
NGINX renderer turns this proposal into proxy_cache off at active
approved locations, preserving upstream TLS/pin and cache-path policy.

This new integration verifies the whole pipeline using actual packaged
NGINX -T parsers on Debian 13 and AlmaLinux 10 with private rootless
configurations. It checks five transitions: healthy, critical, stale
telemetry, warning recovery hold and finally completed normal recovery.
All generated candidates must pass actual NGINX syntax; critical
bypasses both active repositories, stale/warning never clear the bypass,
and verified recovery returns byte-for-byte to the original normal
generated fragment. Invalid negative free-space measurements refuse.

No NGINX master is started, reloaded or signalled; no cache data or
APT/DNF source is written, and no server root privilege is exercised.
Public pins remain validated but no upstream is contacted. This is an
untrusted policy and *candidate configuration* test, not proof that
bypassing cache in a running service actually recovers low disk space
or that client upstream fallback works. NGINX cache-manager behavior,
authentic telemetry, installed systemd/SELinux, signed APT/DNF integrity
and full native acceptance remain NOT VERIFIED (#97/#19).
