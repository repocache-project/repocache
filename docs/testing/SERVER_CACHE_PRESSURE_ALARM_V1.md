# Read-only cache-pressure alert transitions (#97 / #29)

The baseline stock NGINX policy already classifies actual filesystem
free bytes and inodes with warning/critical thresholds and hysteresis.
This independent, deterministic alarm reducer converts validated observations
into finite event codes and closed next-state records. It prevents repeated
alerts at a constant pressure level, emits explicit recovery transitions
only on complete telemetry, flags telemetry loss once, and preserves the
last confirmed warning/critical alarm while metrics are incomplete.
Known read-only storage or zero free inodes escalates immediately even
if other samples are missing.

Actual disk counters from Linux statvfs exercise the exact arithmetic
in the Debian 13 and AlmaLinux 10 disposable-native tests. Inputs and
previous status are still caller-supplied, NOT a trusted host manifest.
Event codes are NOT published automatically, and next_state is NOT persisted
into the #31 privileged WAL. A later authorized root worker must authenticate
its measurements, save state and rate-limit/emit real operator alerts.

No cache eviction, upstream fallback, NGINX service reload, filesystem
mutation or client-source edit occurs. Original #97 native ENOSPC,
manager eviction, tested rescue, persistence, SELinux and #19 booted
acceptance remain NOT VERIFIED.

## Inert pressure-to-NGINX cache-bypass candidate (Stage A, #97)

`preview_cache_pressure_nginx_recovery_candidate()` connects the existing
strict cache pressure alarm to the previously validated per-repository
stock-NGINX `proxy_cache off;` renderer. It is a **pure proposal only**:
it reads no host paths, authenticates no user, performs no filesystem
mutation, invokes no NGINX command and does not publish any catalog.

Only repositories with `desired_state=active`, present in the complete
strict numeric-pinned bundle, can appear in its candidate. Confirmed
critical free bytes, exhausted inodes or a directly observed write refusal
propose bypass for those active repositories. A warning, unknown telemetry
or an unverified prior critical alarm retains the last caller-supplied
bypass selection; an incomplete measurement never clears it. A **complete**
normal measurement beyond the configured hysteresis margin may propose
restoring native cache mode. The exact generated NGINX upstream, TLS
verification/pins and cache-zone policy cannot change. The current
`min_free` capability remains explicitly unverified without separate
native NGINX validation.

All telemetry, previous alarm history, previous cache-bypass selection,
active repository state and pinned addresses are **untrusted caller data**.
The strictly typed, size-bounded prior bypass IDs are validated against
the desired-active repository set before any output is offered. The
returned alarm and generated config contain explicit false provenance,
operator approval, host-root, applied exposure and activation flags.
No persistent alarm or measured actual NGINX cache occupancy is claimed.

**Outstanding Stage A and native acceptance:** A production broker would
need to authenticate root-owned durable state, exact installed config,
operator authorization, real cache filesystem writability and volume
ownership, hold the protected lock through staged `nginx -t`, atomic
reload, health validation, rollback and catalog reconciliation, and then
verify ENOSPC, read-only mounts, delayed manager eviction, stuck workers,
TLS/source fallback, native Debian 13 and SELinux enforcing AlmaLinux 10.
These requirements are NOT VERIFIED; #97 and #19 remain open. A standalone
CLI/control plane must not consume this candidate as a trusted capability.


## Bounded, replayable alarm sequence (#97)

A non-activating pressure-alarm candidate must never emit a next_state whose
sequence counter is invalid as the next call's previous state. The signed
64-bit upper boundary is finite: sequence `MAX_INT - 2` may emit
`MAX_INT - 1`, but that terminal state deliberately refuses further
increment with static `CACHE_ALARM_SEQUENCE_EXHAUSTED` rather than emitting
an unreplayable `MAX_INT`. This is fail-closed source-only behavior, not
an operator reset instruction or durable state authorization. Persisted
sequence rollover and real alarm delivery remain #97/#31 operational gates.
