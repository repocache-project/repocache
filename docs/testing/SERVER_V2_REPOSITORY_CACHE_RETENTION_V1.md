# #95 — cross-process state-v2 retired repository ID and retained cache

This bounded Stage-A regression joins two previously independent Linux
fixture primitives: protected on-disk **state-v2** with a versioned,
immutable all-time repository-ID reservation ledger, and per-repository
NGINX cache directories with inode-pinned external ownership markers.

Both Debian 13 and AlmaLinux 10 container jobs create a *newly detached*
private root and run actual Linux FD-locked state-v2 fixture commits:
APT/DNF entries are added, DNF is retired, and its reservation changes to
`retired` while its cached bytes and inode remain intact. A **separate
Python interpreter** reopens the same root descriptor, reads the persisted
ledger under recovery lock and re-adopts only the exact previous
cache-directory/marker identity. It must not create or purge the
retired cache. Attempts to resurrect the retired ID—even with the
identical origin—or bind it to a different publisher path must be
refused with **no journal, generation or cache alteration**.

A new, separate DNF repository may be given a distinct identifier and
source, preserving the old tombstone and historical cache. A second
test deliberately interrupts a retirement after its durable journal,
proves subsequent writes refuse until explicit recovery, confirms the
previous state and cached bytes remain intact, and only then retries.

This test does **not** authorize installed state-v2 activation: all
fixture operations are bound to a newly created detached pytest root,
with no privileged host service, real operator approval, root mount
identity, NGINX route publication, actual transfer quiescence,
force-cleanup, production signing, real SELinux or booted systemd.
The original #95 AC2/AC4/AC6 acceptance remains NOT VERIFIED until
joined to a correctly authenticated installed transaction and booted
Debian 13/AlmaLinux 10 acceptance. No changes to public CLI or
signed-release inventories.
