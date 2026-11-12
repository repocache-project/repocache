# Crash-recoverable paired fallback configuration — Stage A for #24

**Status:** restricted source-only **test-root** transaction implementation.
`client/recoverable_fallback_pair_lab.py` is **not** installed, imported by the
public CLI, or permitted to write the actual host `/etc`. A protected UID 0
private fixture plus two independent test markers are required before any
source changes. This document is not production source-write approval.

## Why the APT source and mirror need one logical transaction

APT `mirror+file:/etc/apt/mirrors/repocache-ID.list` requires two managed
resources: the original signed `.list` or deb822 `.sources` file and the
private trusted mirrorlist companion. A crash after writing one but before
the other can temporarily break APT. The transaction journal is durably
fsynced before either destination is changed and contains exact before/after
content, source inode, pending replacement inodes, mirror inode, metadata
and an explicit phase; the protected journal lives under the preprovisioned
root-owned 0700 client state path. DNF5 uses the same engine with one
source resource and no companion.

The sandbox applies a unique immutable approved candidate only while holding
a nonblocking exclusive root-owned client transaction lock. It validates
the route/source/selected-entry digest against the pinned protected state
and compiles the native fallback from preserved upstream and signature
selectors. It never accepts raw file paths, proposed source bytes, catalog
data or arbitrary shell commands as authority.

**Crash boundaries:** after journal arm, after mirror rename, after source
rename, during rollback after durable restore intent, after restored-source
rename and after mirror deletion. The recovery procedure reopens allowlisted
parents by nofollow directory file descriptors, examines bytes **and**
device/inode identity of each resource, and only deletes verified transaction
temps. A foreign edit (including equal-content new inode) fails closed and
preserves evidence. A completed transaction is idempotently read back and
requires an explicit operator restore, not an automatic revert on restart.

All source/companion and journal fsyncs are mandatory, as is preservation
of file owner, group and mode. Unknown ACL/xattr/security/SELinux state
causes refusal; source writes with unreviewed labels are not made. This
does **not** establish true power-loss durability, native package manager
serialization, equal-privilege race immunity or production installation
readiness. Ordinary Linux `rename` is not compare-and-swap.

## Evidence and tests

- `tests/test_client_recoverable_fallback_pair.py`: invalid identifiers,
  ambiguous base64/journal fields, no-root write refusal, inode-vs-content
  identity, deterministic failpoints and untrusted failure payloads.
- `scripts/smoke_client_recoverable_pair.py`: positive and negative
  **real UID=0** paired source+mirror and DNF source-only simulations
  under a disposable `/tmp` private root; normal apply + repeated no-op,
  explicit restore, each interrupted apply/restore step, SIGKILL and
  foreign inode/hardlink/lock refusal.
- `.github/workflows/client-helper-preview.yml`: Debian 13 and AlmaLinux
  10 distribution containers running actual Linux filesystems and OS Python.
  These are *not* booted OS, native SELinux enforcing or real installed
  package-manager effects.

## Production gates still NOT VERIFIED

1. Authentic administrator-issued exact-route UC-45 consent and per-client
   owned manifest; actual installed certificate/issuer trust and active
   server catalog (#28/#95).
2. Reviewed installed, OS-authorized root helper and coordination with
   native APT/dpkg and DNF5/RPM locks; hostile same-privilege filesystem
   races must not allow a write over a foreign file.
3. Tested metadata/ACL/xattr/SELinux labels preservation on true target OS,
   atomic multi-resource failure policy with on-disk two-generation snapshots
   and published bounded recovery/repair interface.
4. Installed `repocache-client repos sync --apply` idempotence and source
   changes from an actual live approved catalog, with signed APT/DNF
   cache/upstream fallback and publisher key acceptance.
5. Final single booted Debian 13 + AlmaLinux 10 enforcing-SELinux VM
   campaign (#19) and independent authentic release/publisher gates
   (#76/#88).

The original #24 issue remains OPEN; none of these production tasks is
passed by a sandbox, even with green GitHub CI.
