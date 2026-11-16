# Selected cache occupancy and conservative filesystem pressure (#97/#29)

The v0.6.0 Stage-A read-only observability path now joins two independent
descriptor-pinned native fixture observations: verified REPOCACHE-owned
per-repository cache file counts and allocated bytes, plus fixed cache-root
`statvfs` free-space/inode data reduced through the existing conservative
warning/critical hysteresis alarm. The new
`preview_observed_cache_pressure_alarm_with_selected_usage` is an inert
candidate, not a native metrics service.

## Verified semantics

- Accept a nonempty set of **caller-selected** 1–500 valid repository IDs,
  with a fixed detached-root descriptor and explicit owner identities.
  The underlying owner markers, inode structure, NGINX cache layout,
  file types and mode restrictions are validated using the same existing
  read-only cache cleanup preflight as PR #355.
- Reject the **entire combined result** on an unknown, missing, duplicated,
  foreign, changing or unsafe repository. Never substitute zero occupancy
  for an unobserved repository, and never call a subset a complete inventory.
- Retain exact file/directory counts, apparent bytes and allocated file
  blocks for the verified subset. The cache-root free-space observation
  is a separate metric that can also reflect unrelated usage and quotas;
  allocated blocks are **not** guaranteed reclaimable space.
- Preserve the alarm reducer's explicit incomplete telemetry: live NGINX
  worker writability, authoritative previous state and atomic sampling
  across repositories are unverified. Thus a positive free-space value
  cannot silently clear an earlier critical/warning alarm or imply an
  authoritative NORMAL state. Known critical free bytes and unavailable
  inodes can still justify an inert critical candidate.
- Reassert non-authorizing flags on both observations, including no NGINX
  reload, cache cleanup, client fallback change, state commit or operator
  alert publication.

The existing unprivileged Debian 13 and AlmaLinux 10 GitHub Actions
cache-preflight job runs actual Linux file descriptors and ownership markers,
real files/blocks and bytes, simulated critical `fstatvfs`, missing and
untrusted repositories, invalid IDs and forged observation results. The
module has no installed service entrypoint or privileged writer.

## Still NOT VERIFIED

This is not an authenticated, atomically locked full installed cache
inventory. A fixture root is not provenance for an operator-managed host.
Actual NGINX manager activity/ENOSPC, meaningful quota enforcement,
systemd service integration, AlmaLinux SELinux enforcing, authoritative
alarm persistence and delivered operator notifications, native cleanup,
host rollback and real APT/DNF fallback remain to be verified under the
original #97/#29/#19 acceptance criteria. No real production cache or
metrics sink is changed by this implementation.
