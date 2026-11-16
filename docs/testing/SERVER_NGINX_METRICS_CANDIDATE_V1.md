# Managed repository NGINX metrics candidate — #29 / v0.6

This Stage-A feature creates a deterministic, opt-in NGINX access-log
candidate derived from the **same validated repository-centric install-v1
document** as the route generator. The administrator's existing
deployment.logging.metrics_opt_in flag must be an actual Boolean. Only
desired-active repositories with validated persistent IDs receive a fixed
per-route metrics label and access_log statement. Disabled and absent
repositories never produce a log statement. Opt-out produces no NGINX
logging fragment and never activates logging by default.

The format is intentionally aligned with the pre-existing REPOCACHE
core.metrics parser and with the approved #14 six-field JSON log. It
contains only time_iso8601, a prevalidated fixed route prefix, status,
upstream_cache_status, body_bytes_sent and request_time. No request URL,
query, Authorization, cookies, IP address, User-Agent or credentials
are emitted. The path is fixed to
/var/log/nginx/repocache-managed/metrics.jsonl and MUST have separately
verified root ownership and log rotation per #29.

A rootless Debian 13/AlmaLinux 10 CI test uses actual distro-packaged
NGINX in disposable, network-isolated Docker, binds a temporary loopback
HTTP listener, inserts the validated logging directives only into its
private test configuration, executes nginx -t and makes an HTTP request
containing a deliberately private query parameter. It confirms only the
approved route produces a structured log record, no request path or secret
appears and the actual REPOCACHE metrics parser reports one real request
and the exact response bytes. No backend cache is exercised in this smoke,
so its hit_rate remains UNKNOWN (not a fabricated HIT). Existing
cache-hit tests remain separately governed by #28/#97.

This is a CANDIDATE, not an installed configuration. It deliberately does
not alter existing audit logging inheritance, add an administrator-facing
route or access log, declare exposure, write any production files, send
network data beyond container loopback, change the existing CLI default
metrics location, update source keys or enable NGINX. A future approved
#28/#31/#64 privileged transaction must combine the validated candidate
with the authoritative route bundle and existing audit format without
clobbering inherited audit logs; independently verify host-root,
manifest/SELinux and native NGINX full context; then atomically activate
and validate before the CLI can be configured to read this fixed path.

All native installed-service, log rotation, metric retention, SELinux
enforcing, power/reload rollback and final server operational acceptance
criteria of #29/#19 remain NOT VERIFIED. This PR alone is not VM GO.
