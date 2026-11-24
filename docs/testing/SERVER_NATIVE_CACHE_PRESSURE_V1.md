# Read-only native cache pressure classification (issue #97)

This source-only Stage-A increment evaluates complete filesystem/cache
observations against the **existing** strict install-v1
`deployment.cache_policy.disk_pressure.warning_free_bytes` and
`critical_free_bytes` policy. It does not install, restart or reconfigure
NGINX, poll system files, read secrets or modify client APT/DNF sources.

`repocache.server_cache_pressure_v1.evaluate_cache_pressure` receives a
validated proposed install document, three caller-collected integer
measurements (filesystem total/free and cache bytes used), an explicit
completeness indicator, the previous alert level and a nonnegative
`recovery_hysteresis_bytes` value. The hysteresis input is **not yet
persisted** in install-v1, and this function is not wired into the CLI
or systemd runtime. A future installed metrics collector must prove that
all three measurements describe the **same filesystem, time window and
cache ownership scope**; a partial or uncertain sample must be flagged
incomplete, not guessed as zero.

## Deterministic alert states

- **normal**: free bytes at or above the warning threshold;
- **warning**: free bytes below warning and at or above critical;
- **critical**: free bytes below critical;
- **unknown**: missing or incomplete observations. Invalid, contradictory,
  negative, boolean or overlong integers fail closed with redacted fixed
  error codes instead of silently being treated as zero.

Escalation to warning/critical is immediate. Recovery from warning to
normal requires `free >= warning + hysteresis`; recovery from critical
requires `free >= critical + hysteresis` before warning can replace it,
and the normal threshold plus hysteresis before normal can replace it.
Hysteresis is a caller-selected operational input, with zero disabling it.
The output contains a **read-only alert recommendation**, not an
authorization for cache deletion, NGINX reload, client-source changes or
automatic upstream fallback. A `normal` classification reports only
that this bounded sample is not currently in a pressure alert; it does not
prove NGINX capacity or that future writes will succeed.

`max_size` remains a soft, eventually enforced stock NGINX cache-manager
policy. This evaluator neither measures eviction under load nor guarantees
write availability, successful upstream fallback, SELinux labelling,
managed storage isolation, immutable historical cache retention, or a
production capacity alarm. Those #29/#97/#19 native acceptance criteria
remain **NOT VERIFIED** until the installed collector, systemd/SELinux
host tests, actual NGINX manager and failover integration are completed.
Never delete opaque cache objects directly to satisfy a pressure alarm.

## Repeatable source-only regression

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_server_cache_pressure_v1.py
```

This runs a full boundary/state matrix, missing/inconsistent-metric refusals,
hysteresis recovery and immediate escalation, strict install schema checks,
read-only side-effect guards and redacted output contracts. Follow the
normal exact-SHA CI before integration; CI is not a substituted booted
Debian 13/AlmaLinux 10 native cache-pressure acceptance.
