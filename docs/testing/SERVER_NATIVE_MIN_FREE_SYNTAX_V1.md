# Stock packaged NGINX min_free syntax observation (Stage A)

**Primary issue:** #97, milestone v0.6.0. **Scope:** two disposable,
non-root NGINX parser observations only. This is not a configuration activator.

## Why this matters

The native cache manager recognizes inactive and max_size as normal eviction
controls; min_free cannot be assumed available on every installed binary.
The existing NGINX renderer conditionally emits min_free only when its caller
selects that candidate. A caller boolean never proves actual installed-host
capability, package identity or administrative authorization.

The guarded probe tests baseline stock proxy_cache_path syntax with nginx -t,
then repeats after adding only min_free=1m. A failed baseline is a hard refusal.
If baseline succeeds but min_free fails, the bounded report accurately records
DISPOSABLE_SYNTAX_NOT_ACCEPTED; it does not silently enable min_free or
disable safety controls.

## Execution and output

The new server-native-min-free-syntax workflow installs stock NGINX and
Python using distribution package managers in throwaway Debian 13 and
AlmaLinux 10 containers. It drops privileges to UID/GID 65534 before running
the negative unittest suite and actual packaged NGINX parser.

Run only within an explicitly marked throwaway Docker container as non-root,
with REPOCACHE_DISPOSABLE_NGINX_MIN_FREE_PROBE=1 and PYTHONPATH=src:

    python3 -B -m repocache.server_native_min_free_syntax_probe_v1

The probe refuses root, missing explicit opt-in, absent Docker marker,
unrecognized distribution identity or binary path, invalid private scratch
paths, execution errors, timeouts, and any baseline syntax failure. It only
invokes a packaged NGINX path with -t -p and -c against a bounded, temporary
private configuration; stdout and stderr of the parser are suppressed.
It does not start or reload NGINX, open ports, modify installed NGINX
configuration, cache or package sources, or change systemd/SELinux state.

Its single machine-readable JSON object distinguishes
MIN_FREE_DISPOSABLE_SYNTAX_ACCEPTED and
MIN_FREE_DISPOSABLE_SYNTAX_NOT_ACCEPTED. The report's fields always deny
host binary provenance, SELinux, production root authority and authorization
to activate/reload/mutate, irrespective of the disposable syntax outcome.

## Release gates unchanged

A deployed root worker must independently verify fixed package/binary
identity, config ownership, host capability, and exact staged nginx -t before
controlled reload and recovery. Actual disk-pressure churn, capacity versus
inactivity eviction, hysteresis, upstream fallback, and both native host
distributions (with AlmaLinux SELinux enforcing) remain NOT VERIFIED under
#97/#19. A parser accepting min_free does not prove actual cache-manager
behavior or an instantaneous max_size quota.
