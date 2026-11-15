# Cache pressure observation and alarm candidate (Stage A)

**Issue #97**, coordinating #29 and #14, release v0.6.0.

The existing fixed-cache Linux statvfs sensor and the deterministic
cache-pressure alarm reducer have different security obligations. This
read-only bridge now tests them **together**, retaining all incomplete
telemetry and prior-alarm hysteresis safeguards. Observing free bytes and
inodes is not the same as observing NGINX writable cache storage, active
cache occupancy, SELinux authorizations, service health or real package
download fallback.

The bridge reads only the fixed per-installation managed cache layout
using existing O_NOFOLLOW and descriptor rechecks, validates the caller's
prior candidate state and thresholds, and invokes the existing alarm
reducer with measurements_complete=False unconditionally. A confirmed
free-space threshold breach, zero inodes or read-only mount can still
raise CRITICAL. Missing cache, mismatched ownership, unknown mount flags
or otherwise incomplete telemetry cannot dismiss a previous warning or
critical alert or report NORMAL. No alert is emitted or state persisted.

The native Debian13 and Alma10 CI runs the actual Linux fstatvfs interface
from a detached cache fixture under UID/GID 65534, with injected known
disk states, broken directory ownership and forged-alarm negative tests.
All returned authority fields remain false; there is no root writer,
systemd service, NGINX cache toggle, package source rewrite or network.

Future installed diagnostics must separately authenticate root/cache
provenance, trusted persisted previous alarms, NGINX writability,
SELinux policy and actual notification delivery. Host/client recovery
and signed APT/DNF package fallback remain **NOT VERIFIED** in #97/#19.
