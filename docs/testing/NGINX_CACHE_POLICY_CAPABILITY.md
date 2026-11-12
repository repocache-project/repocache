# Stock NGINX cache-policy capability — Debian 13 / AlmaLinux 10

**Issue:** #97. **Scope:** non-activating, native-distribution container evidence
for accepted `server-install-v1` global and per-repository cache configuration.

The existing NGINX renderer remains the **single** source of the actual
cache policy candidate; this change does not create a second policy or
repository registry. The disposable
`scripts/ci_nginx_cache_policy_capability.py` fixture renders two desired
active candidate repositories from the existing example (Debian APT and
AlmaLinux DNF), applies one explicit per-repository override, leaves the
other repository inheriting the original global inactive and size limits,
and tests the *actual* generated fragment with distribution-packaged
`nginx -t` on both supported userspaces. It verifies separate zones,
unmodified upstream pin validation, no activation/publication permissions,
and a malformed cache policy that must fail NGINX parsing.

The same native parser tests `min_free=8m` **in a test-only copy** of the
validated configuration. If supported, a capability can be observed for
that exact binary. If unsupported, the test reports the feature as
`NOT VERIFIED` and demonstrates that the original candidate remains
syntactically valid; it does not silently activate a different policy.
Do not infer support from `nginx -v` or the distribution name.
The test never adds a `min_free` field to the accepted declarative
contract, never installs or reloads the host service and never edits
real `/etc/nginx` configuration.

The native smoke executes unprivileged in a disposable Docker container
with `--network none`, `--read-only`, `--cap-drop ALL`, no-new-privileges,
a bounded `/tmp` tmpfs and a read-only checkout. NGINX parser side effects
are restricted to that private temporary fixture. It uses an inert public
numeric candidate pin only for syntax validation; no upstream connections
or production endpoint trust claim is made.

**Reference:** <https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path>.
Official NGINX documentation describes `inactive`, `max_size` and
`min_free`, with `min_free` introduced in NGINX 1.19.1.
Native NGINX capacity limits are **asynchronous cache-manager policy**,
not synchronous hard quotas; neither unreferenced byte retention nor
capacity-pressure eviction is proven by `nginx -t`.

**Stage A acceptance:** exact-source CI of
`.github/workflows/native-nginx-cache-smoke.yml` should execute the
script, verify inherited/overridden directives on Debian 13 and AlmaLinux
10, report per-binary `min_free` support honestly, and confirm malformed
policy refusal. A checked-in script without successful run logs is
**NOT VERIFIED**.

**Remaining #97 original acceptance — NOT VERIFIED:** live native cache
manager eviction/inactivity under churn and pressure, actual warning/critical
telemetry and hysteresis integration, ENOSPC/read-only disk recovery, disk
mount/owner/SELinux enforcing, resource-concurrent manager control,
configured high-water/low-water action, active NGINX reload rollback,
cache/log preservation, real signed APT/DNF upstream fallback and one
booted Debian 13 / AlmaLinux 10 final acceptance campaign (#19).
The separate optional priority algorithm #94 cannot be promoted by
this source-only test.
