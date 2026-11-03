# Bounded DNS refresh scheduling v1 — candidate-only increment (#28)

**Release:** v0.6.0. **Status:** implemented in feature branch; exact-HEAD CI and review remain separate. This is not an installed systemd timer, trusted-state authority, production NGINX controller or service acceptance.

## Purpose

The approved Option A requires normal upstream DNS/IP rotations without manual IP maintenance. Merged PR #215 provides strict public A/AAAA destination validation, deterministic candidate pin planning and inert NGINX TLS/SNI fragments. This increment introduces:

- **server_bounded_dns_v1.bounded_getaddrinfo**: libc A/AAAA resolution in a short-lived isolated Python subprocess; eight-second default and fifteen-second maximum per-lookup deadline, no shell, no inherited file descriptors, constrained child environment, bounded JSON response and redacted failures. A blocked lookup cannot permanently stall a polling loop. It performs DNS only, never HTTP.
- **server_dns_refresh_schedule_v1.refresh_due**: monotonic per-repository scheduling hints with a fifteen-second shared real-monotonic DNS cycle budget across all allowed hosts, at least five minutes between successful refreshes, stable per-repository 0–60-second jitter, exponential bounded failure retries of 60–3600 seconds, changed/no-op candidate recognition and immediate reconsideration on trusted generation change. Unsafe, partial, timed-out or failed DNS (including budget exhaustion between hosts) yields a retry hint, not any new pin authorization. The bounded production path uses the built-in subprocess resolver; injected resolvers are for test composition and are not execution-bounded by this helper.

The scheduler does not sleep, install a timer, write persistent state, mutate NGINX or invoke a service. Its slots are untrusted ephemeral scheduling metadata. The returned candidate is not evidence of administrator approval. A slot whose next due time is farther into the future than its policy-allowed horizon is discarded and refreshed immediately; an untrusted or wrong-epoch scheduling hint must never suppress DNS rotation indefinitely. This is not clock authentication or process-resume recovery.

## Mandatory operational integration

Activation remains blocked pending concurrent #31 PR #222 protected-state writer/journal and #224 locked manifest-inode reconciliation, and the #95 trusted repository identity/authorization model. Do not duplicate or merge their unfinished work.

The next integration must use (1) a privilege-separated real systemd timer/service loading only approved enabled hostnames from an authenticated generation; (2) an exclusively locked, root-verified state/manifest and generation CAS; (3) durable staged NGINX configuration with packaged nginx -t, verified reload, rollback after any failure or crash, and foreign ownership refusal; (4) active-only atomically derived catalog and native APT/DNF metadata, cache HIT and fallback verification; (5) booted Debian 13 and AlmaLinux 10 hosts, including enforcing SELinux, ACL/xattr/mount checks and fault injection.

No DNS TTL is claimed: getaddrinfo does not expose one. The minimum refresh interval is a policy lower bound, not a promise of immediate DNS propagation. Old last-known-good pins must survive failure, although their availability is not guaranteed.

Both authorizes_nginx_activation and authorizes_catalog_publication are always false in this candidate-only component. A future privileged transaction must independently reacquire the lock, reread authoritative state and validate every input, never treat these outputs as capabilities.

## Testing boundary

Focused command:

    python -m pytest -q tests/test_server_bounded_dns_v1.py tests/test_server_dns_refresh_schedule_v1.py

Tests cover isolated local localhost DNS, simulated timeouts/child errors and malformed worker records, unsafe/private IP rejection, a shared multi-host cycle deadline and reduced remaining per-host timeout, deterministic jitter and backoff, generation changes, no-op and scheduling without file/NGINX/HTTP side effects. Full CI on the exact PR HEAD is required before treating the code tests as PASS.

**Not verified:** installed timer, protected provenance, transactional NGINX reload/recovery, catalog exposure, real package caching/integrity, native booted host systemd/SELinux acceptance. Keep issues #28, #31 and #95 open. No merge, release signing, publication or production activation authorized.
