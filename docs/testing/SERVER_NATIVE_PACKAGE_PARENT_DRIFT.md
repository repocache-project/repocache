# Native package effects and shared-parent directory churn (#27)

This Stage-A change fixes a lock-release refusal found by the actual combined
Debian 13 / AlmaLinux 10 NGINX installation rehearsal. The existing #31
exclusive state lock checked exact full stat identities of all ancestors
(including timestamps and link count). APT/DNF legitimately create unrelated
directories under /var and /var/lib while holding the state lock. That can
produce a false refusal **after irreversible package changes**.

The existing state store now accepts an explicit internal boolean
allow_native_package_parent_changes. The normal path remains STRICT.
Only the retained native-effects journal scope opts into the new mode; the
standalone prepare-only journal keeps the original strict checks.

The special exit check continues to compare both named and pinned directory
descriptors. Only /var and /var/lib may change link count, size and
timestamps, and each must retain exactly the same device, inode, file type,
mode, UID and GID. The REPOCACHE-owned /var/lib/repocache ancestor must be
byte-for-byte unchanged. The state leaf must preserve structural identity
but may change timestamps when recording its pending journal. The exact
single-link lock file is independently rechecked throughout.

Tests cover real Linux descriptor locks and durable journals, unrelated
native child creation, unsafe inode/symlink replacement, permission drift,
changes under protected state, invalid flags and concurrent lock denial.

This is internal fixture-only execution. It cannot authenticate host-root
provenance or operator permission, cannot approve package signatures, cannot
enable/reload NGINX and is not an installed server helper. Future #64 security
review and #19 booted native acceptance remain mandatory. No VM GO or release
acceptance is implied.
