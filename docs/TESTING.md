# Testing and Evidence

Public pull-request CI must run Python and bundle smoke tests using disposable environments, including both Debian 13 and AlmaLinux 10. Tests are not equivalent to a security audit or live host compatibility certification.

Run the relevant unit, CLI, install, upgrade, signature, failover, concurrency, crash/recovery and offline-dependency tests on the exact reviewed source revision. Inspect job steps and logs, not merely workflow labels. Public v0.4.0 explicitly does not support pre-public in-place migrations. Run negative policy tests to ensure old installations are refused; confirm the historical prototype is absent from the distributed archive and cannot run. Synthetic migration/recovery tests verify mechanics, not actual prior-version compatibility. Do not present the superseded historical migration criterion as PASS.

An actual signed release, ruleset enforcement and a positive production readiness decision require separate owner approval and evidence. Never assert real systemd or SELinux host tests were executed when they were deferred.

**First operational v0.6.0 (owner decision 2026-11-07):** the old public v0.4.0 -> v0.6.0 compatibility/upgrade path is explicitly unsupported and is not an acceptance test. Verify fresh signed v0.6.0 installs, same-version repair, fail-closed refusal of legacy state, native NGINX/SELinux operations and future recovery. Historical v0.4.0 publication evidence remains intact; the old executable is not run as a v0.6.0 gate.


## Supplemental CI impact and handoff

The optional client container labs and booted VM workflows use the same
read-only `scripts/ci_supplemental_test_impact.py` selector. It compares the
complete exact HEAD and current PR base with Git (not the 300-file event
path-filter list). Only reviewed isolated client modules/fixtures and
scenario-specific test changes can narrow the execution. Server-private
runtime changes still request all native scenarios. Shared source, packaging,
trust, CLI, dependencies, common harness, workflow/selector changes,
unclassified paths, deleted/renamed files, file type/mode changes, stale base or unverified diff
select the full campaign. Both target distros and existing image digests
remain unchanged. Manual dispatch always selects the complete matrix of
the dispatched workflow; release promotions and stabilization PRs also
select full supplemental coverage. Do not rely on classification alone:
inspect imports, runtime interfaces, risk and original acceptance. Run an
additional applicable scenario or full manual workflow if needed; no
unselected check is PASS evidence. A selector job failure blocks applicable
acceptance rather than silently authorizing a skip.

First-attempt PR events cancel only superseded disposable runs in the
same workflow and PR. Retries, manual acceptance and other events are
isolated. The nine required checks, other live required contexts, protected
rulesets, release/signing and final coordinated booted-host acceptance
remain unchanged.

At handoff, record UTC time, outstanding run links and a conservative
completion window based on recent comparable completed runs including
queue delay. If there is independent approved work that will not invalidate
in-flight evidence, recommend immediate resumption even while CI is pending.
If the next action depends on results, recommend resumption near the
estimated completion time; recheck live status and do not claim certainty
or unattended monitoring. Track actual completed durations and selected
job counts before asserting a speedup. Never create work just to fill a
waiting interval, restart a valuable native run needlessly or merge without
all applicable evidence.
