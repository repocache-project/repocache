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

## Booted VM performance and evidence

Native VM jobs probe real KVM initialization before choosing acceleration.
If the disposable GitHub-hosted runner has a root-owned KVM device with
the kvm group, QEMU may run under the existing unprivileged runner UID
with that group for the process only. Hosted root sudo launches only the
fixed setpriv executable, which drops to the original nonroot UID/GID,
retains only the device supplementary group, drops all capabilities and
sets no-new-privs before executing QEMU. No global device permission
change, root QEMU or guest privilege change is permitted. KVM selection
requires a successful probe and an explicit QMP query-kvm response with
both present and enabled true; otherwise use unprivileged TCG. The runner
evidence records the access mode, selected acceleration and resources.
Activation VMs increase their CPU and memory budgets only when the runner
has spare capacity and either KVM is confirmed or the platform is
AlmaLinux. Debian TCG retains its original 2 vCPU / 3072 MiB budget.
These are tuning defaults pending controlled measurements.

Each harness phase emits start/end markers and bounded phase-times.tsv
evidence (elapsed seconds); the summary includes those timings even on
failure. The AlmaLinux activation prerequisites use a single DNF
transaction without moving the signed product installation into that
transaction. Reboot readiness polls for a valid changed kernel boot ID,
rather than assuming an arbitrary sleep proves a reboot. Existing exact
boot-ID comparisons, signed-install checks and SELinux enforcing
assertions remain mandatory.

Compare complete native runs on exact HEADs and record KVM/TCG, phase
times and total wall time before reporting a speedup. Keep the existing
chained committed and pending-WAL reboot checks on the same guest:
splitting them requires proof of equivalent durable state and evidence.
Do not cache mutable guest disks, signing identities, or package trust
state. The full image integrity checks and current acceptance matrices
remain unchanged.
