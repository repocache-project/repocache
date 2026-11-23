# Booted repository lifecycle acceptance increment (#95 / #28)

This test extends the existing [PR #237 booted QEMU harness](PR237_BOOTED_VM.md)
without creating a new privileged entrypoint, server CLI command, or lifecycle
implementation. The `native-lifecycle` scenario is a **separate, throwaway
guest** from the existing `native-installer` repair/WAL scenario so neither
one replays an unreviewed staged recovery proposal.

## Exact execution

In each pinned **x86_64 Debian 13** and **AlmaLinux 10** QEMU guest (SELinux
**Enforcing** on AlmaLinux), the test executes the existing authenticated
Ed25519 *disposable guest-only* worker placement, real APT/DNF NGINX package
install, systemd boot/reboot, native fixed AF_UNIX root broker, and live HTTPS
health/catalog endpoint. The guest then:

1. Activates the installed, signed-fixture generation-one baseline containing
   two **disabled** repositories and verifies the public HTTPS discovery is
   empty and exactly matches the root-owned published catalog.
2. Uses the existing checkout-only `prepare_offline_lifecycle` to propose an
   additional **disabled** APT repository, with a new HTTPS upstream and
   **automatic ID**. Rejects an unsafe repository selector without producing
   a candidate. Checks that proposal preparation/staging alone cannot alter
   live state, NGINX or public discovery.
3. Pins the canonical candidate SHA and exact predecessor SHA to the
   existing authenticated native staging contract. The **installed root
   worker**, not the offline planner, then applies the entire new generation,
   reloads actual vendor NGINX, checks TLS exposure and publishes the
   active-only catalog. Verifies durable allocation and unchanged prior IDs.
4. Normal-removes the newly allocated ID through the same independently
   checked staging/installed-worker path. Verifies a durable **retired**
   reservation, inactive-only public HTTPS discovery, preserved synthetic
   cache-marker bytes and inode, clean WAL, and unchanged vendor NGINX files.
5. Refuses stale replay of a previously authentic proposal and verifies
   service restart cannot resurrect the retired repository. Confirms
   `RECOVER_V2/CLEAN` and `RELOAD_V2` against the installed systemd service.

The workflow collects `native-v2-repository-lifecycle.txt`, exact source
SHA, OS/kernel/systemd/SELinux facts and a bounded summary; the evidence
collector marks partial coverage **only** if both guest end markers and
the completed exact-SHA scenario are observed. Failed, missing or stale
evidence is `NOT_VERIFIED`. No keys, VM disk or guest source data are
uploaded. All nine protected CI checks stay mandatory; this QEMU workflow
is extra, not a replacement.

## Interpretation

Successful runs will prove only **native functional subcases** of #95 and
#28: generation-bound ID allocation/removal, actual installed transaction
with the strictly **inactive** catalog, stale authorization refusal,
normal-removal nondeletion, native systemd/NGINX/TLS and SELinux environment
observation. The synthetic marker is **not** proof of real cached-object
ownership, active transfers or authorized force-cleanup. Inactive-only routes
are deliberately not accessible.

The original acceptance remains **OPEN / NOT VERIFIED** for active
administrator-approved APT/DNF HTTPS upstreams, native verified metadata
and package integrity, actual managed route MISS/HIT, production-grade
cache-object attribution and safe force-cleanup/quiescence, complete
end-to-end migration/recovery guarantees and Stage-C owner-key signed
publisher acceptance. This scenario never treats disposable trust as a
real release signature or grants host/production activation authority.

Local static/coverage regression command:

```sh
PYTHONPATH=src python -m pytest -q tests/test_v06_vm_campaign_coverage.py
```

Booted execution is through `.github/workflows/pr237-booted-native-vm.yml`
and `scripts/ci_pr237_booted_vm.sh` only; tests must be evaluated at the
actual exact PR HEAD and real two-distro workflow run.
