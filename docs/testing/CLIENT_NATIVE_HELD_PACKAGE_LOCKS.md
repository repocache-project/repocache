# Held native APT/DNF package lock primitive — Stage A (#24)

A read-only \`/proc/locks\` snapshot cannot protect a future client source
writer against a package manager starting immediately after inspection.
\`client.native_package_lock_observation.hold_existing_native_package_locks\`
adds a **real scoped nonblocking Linux kernel lock** over the fixed, already
existing lock-file set for Debian APT/dpkg or AlmaLinux DNF5/RPM.

For each canonical lock path it anchors directory traversal with no symlink
following, verifies safe owner/mode and one-link regular inode, opens a
pre-existing file without creating it, and acquires **both**
\`fcntl.flock(LOCK_EX|LOCK_NB)\` and POSIX \`fcntl.lockf\` byte-range locks.
It rejects any missing, foreign, changed or busy inode; on any error it
attempts to close all earlier descriptors and releases held locks. There is
no wait, retry, file write, package invocation or native source modification.

The context manager yields **no authorization token**. It never asserts
that the current native APT/DNF version is proven to use precisely these
locks, nor that a source write is safe or permitted. The caller must keep
the entire authenticated transaction and durable journal within its lock
scope, with extra package-manager, SELinux, root namespace, route consent,
ownership and rollback checks. No installed REPOCACHE client command calls
this helper; \`repos sync --apply\` remains disabled.

Tests use **real cross-process Linux locks** and verify conflict and release
for both kernel locking families. They also cover a busy later lock
releasing earlier locks, missing files with no creation, symlink/hardlink,
mutable parent, mode and size refusals, and unchanged caller exception
propagation. Native disposable Debian13/AlmaLinux10 CI runs the exact same
scope under root in a private \`/tmp\` fixture and records a fixed PASS per
manager, not a host authorization.

**NOT VERIFIED:** installed real APT/DNF lock graph, native package-manager
exclusion across an actual source commit, client root operator consent,
protected multi-resource source/mirror transaction, SELinux enforcing
and final signed v0.6.0 Debian 13 / AlmaLinux 10 booted VM campaign.
This Stage-A increment is not the real client writer and cannot close #24.
