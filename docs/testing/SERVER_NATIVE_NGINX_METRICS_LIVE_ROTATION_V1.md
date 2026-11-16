# Native packaged NGINX metrics across actual logrotate/reopen (Stage A)

**Primary issue:** #29, v0.6.0. Complements existing independent #14
live logging, #29 stock logrotate archive and #28 NGINX fragment syntax tests.
None of those former tests directly proved that real NGINX request metrics
survive a stock logrotate process that signals NGINX to reopen its log.

## Disposable integration sequence

The dedicated CI workflow installs packaged NGINX, logrotate and Python on
both Debian 13 and AlmaLinux 10, then switches to UID/GID 65534. The script
requires explicit disposable Docker context and env
REPOCACHE_DISPOSABLE_NGINX_ROTATION_CI=1. The test creates its own private
0700 scratch root, private temp directories and an explicitly preprovisioned
0600 metrics log. **NGINX might create a missing initial log with less
restrictive permissions; the managed installer must never assume that an
absent metrics file will be created securely by NGINX.**

It composes the existing opt-in metrics candidate from the validated
repository configuration with exactly one desired-active route and a
disabled/unapproved location. It first verifies that stock nginx -t accepts
the candidate and refuses intentionally broken staging. It then launches
one nonprivileged NGINX process on a private 127.0.0.1 high port, requests
the active/inactive routes and verifies only expected metrics are recorded.
The existing audit log must continue receiving requests.

The harness consumes the existing real logrotate profile. **Only in this
disposable fixture**, it maps the fixed root-owned log to a private file,
maps root-owned create permissions to the unprivileged test account and
maps the fixed installed-systemd reopen action to the running test NGINX
process's private nginx -s reopen argv. It calls the real packaged
logrotate binary with --force twice, verifying both uncompressed and
compressed archive files, private 0600 modes, the new live log, exact
per-repository labels and no secret request URI in recorded metrics. The
existing CLI metrics parser must recover all six original records across
the two archives and current log without inventing incomplete history.

## Explicit exclusions

No candidate is deployed. No host service or systemd unit is started,
reloaded, signalled, stopped or modified; no production cache, log, APT/DNF
source or TLS file is touched. Port binding is loopback-only inside the
throwaway container, not a publicly exposed listener.

This is Stage-A integration evidence only. An installed root worker must
prove owned log paths, vendor NGINX identity and correct credentialed
systemd reopen. Actual AlmaLinux SELinux enforcing, booted native host
logging, cache preservation, signed installation, repair and interruption
recovery still require the consolidated #19 native VM campaign. This PR
does not close #29 or imply production log permissions are validated.
