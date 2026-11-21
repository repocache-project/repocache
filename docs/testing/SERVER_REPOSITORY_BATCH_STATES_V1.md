# #95 — inert batch enable/disable repository intent (Stage A)

The reviewed v0.6 server lifecycle treats a repository as the only
administrator-facing managed object. This pure multi-target helper
`plan_batch_repository_states` represents independent enable/disable
requests in **one strictly validated candidate document**. It validates
the expected generation and every identifier before proposing any
change. An absent but syntactically valid ID yields target-local
`NOT_FOUND`; already-at-target-state is an idempotent no-op.

This is **not** a published CLI, a transaction, installed NGINX
activation, verified availability or a client catalog update. An
`ACTIVE_CANDIDATE` outcome changes only the requested administrative
desired state, not the actual exposed route. The service must still
authenticate the administrator, reread protected state under the #31
lock, prove permitted upstream/trust/pins/ownership, stage a complete
NGINX candidate, independently validate its actual live generation and
publish only an observed active-only catalog atomically. Do not
distribute a discovery entry on this planner's output.

Tests: `python -m pytest -q tests/test_server_repository_batch_states_v1.py`.
They exercise two-repository enable/disable/repetition, mixed absent
targets, malformed/bulk selectors, stale generation and host mutation
denial. All original #95 AC3 installed, failed-reload and booted-OS
criteria remain **NOT VERIFIED**. The helper cannot make a cache route
live on Debian 13 or AlmaLinux 10 or claim systemd/SELinux support.
