# #97 — conservative partial-observation critical-alarm recovery

**Scope:** deterministic Stage-A cache policy preview only. A measured
free-byte counter does not prove NGINX can write: available inode counts,
actual writable mount, cache-manager state and prior authenticated alarms
may still be unknown. A partially measured sample must not downgrade a
previously critical state to warning merely because the byte count is
above the critical hysteresis boundary.

The pure `preview_cache_pressure` reducer therefore holds
`critical / CRITICAL_RECOVERY_OBSERVATION_INCOMPLETE` when the
provisional result would be warning and the previous level was
critical, unless both the explicit telemetry-completeness assertion
and disk-writability observation are true. An actual known critical
free-byte observation or read-only disk still immediately escalates;
complete measurements retain normal warning/recovery hysteresis.
When free bytes are entirely unavailable the pure preview still
returns `unknown` as before; the independent
`evaluate_cache_pressure_alarm` reducer retains the authenticated
prior severity separately (subject to its own required host trust).

The source change does **not** introduce disk access, live NGINX
metrics, automatic cache deletion, policy application, NGINX reload,
upstream fallback, published operator alerts, source rewrites or a
trusted state store. All authority fields remain false. Consumers
must not use a preview result as approval to suppress writes or
change external exposure. Tests explicitly cover partial data,
known hard failure, complete recovery, unknown free space and no
authorization.

`python -m pytest -q tests/test_server_cache_pressure_policy_v1.py`

Original #97 capacity behavior under native cache churn, real
package integrity and fallback, per-repository stock NGINX policy,
SELinux enforcing and booted Debian 13 / AlmaLinux 10 remain
**NOT VERIFIED**.
