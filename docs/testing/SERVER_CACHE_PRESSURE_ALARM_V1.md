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
