# Stock-NGINX cache pressure policy preview — issue #97

**Status:** pure non-authorizing observation policy; no native NGINX
installation, retention activation, real disk measurement, cache deletion,
client fallback or release acceptance is claimed.

The reviewed server-install-v1 contract already owns global `inactive_seconds`
and `max_size_bytes` with per-repository overrides; #95 owns its effective
inherited policy reconciliation. This independent #97 increment introduces
`preview_cache_pressure` only. It deliberately **does not** implement a
second source of repository policy truth or duplicate #29's filesystem/log
health observation.

The caller must supply a measured filesystem `free_bytes` (or `None`),
strict positive `warning_free_bytes >= critical_free_bytes`,
nonnegative explicit `recovery_margin_bytes`, preceding state and typed
read-only writability/measurement-completeness observations. Boolean values
are refused as integers. Values are bounded to signed 64-bit integers.
Escalation happens immediately when measured space falls to the threshold or
when storage is explicitly not writable. Alarm recovery requires a strictly
larger free-space result than the respective threshold plus margin; on an
unreliable or missing observation the status becomes `unknown`, **never
silently zero or healthy**. An independently known critical/low-space
condition remains visible even with incomplete unrelated measurements.

The result is a **pure status preview**, with no path, process, service,
network or cache object access. It returns no eviction decision and always
sets native manager verification, actual cache occupancy, client failover,
NGINX policy apply, source rewrite and cleanup authorization to FALSE.
It does not promise that `max_size` is an instantaneous hard limit, that
NGINX packaged builds support `min_free`, that cache manager timing meets an
SLO or that a client can reach upstream after ENOSPC. No proprietary NGINX
module or priority-aware #94 eviction algorithm is introduced.

Tests: `python -m pytest -q tests/test_server_cache_pressure_policy_v1.py`.
Tests cover threshold edges, recovery hysteresis, incomplete telemetry,
read-only observations, invalid inputs, overflow bounds, absence of side
effects and repeated deterministic results. A test source file is not
execution evidence until its exact SHA and CI logs are examined.

**Original #97 criteria still NOT VERIFIED:** packaged NGINX native capacity
and inherited override application on Debian 13/AlmaLinux 10; measured native
eviction under churn, thresholds/alerts and end-to-end recovery; ENOSPC,
SELinux enforcing, filesystem ownership/locks and native systemd/NGINX
rollback; real client fallback. Integrate with #29 measurements, #28
rendering, #31 transactions, #95 repository identities and #19 native
release tests only after independent authorization/review. Do not merge
or activate production from this pure preview.
