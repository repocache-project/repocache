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


## Full lock-set pathname revalidation

After acquiring every lock, the primitive re-resolves all canonical
pathnames from the trusted root and compares each named inode and its
metadata with the held descriptor. A clean scope exit repeats that check.
An earlier lock replaced during acquisition of a later one cannot reach
the caller; a replacement or unsafe parent during the scope cannot
report clean completion. Failure releases the held locks without opening,
creating or deleting any replacement. Caller exceptions remain intact.

These are conservative drift detection checks, **not a race-free lease
against arbitrary same-privilege writers** and not authorization to
modify host sources. No second descriptor on the held file is opened
during the recheck, avoiding POSIX lock release on close. The actual
privileged commit and its native package-manager exclusion remain
separate mandatory acceptance gates.


The paired transaction fixture now obtains all fixed package-manager
lock inodes in its private tree under the client transaction lock, and
revalidates the complete set before durable journal, source/mirror
publication, rollback and cleanup transitions. Busy locks refuse
apply and restore before staging. The Debian booted guest invokes real
apt-get update with empty isolated sources and private lists/cache paths
and requires a lock-specific denial. This demonstrates one actual APT
lock-family interaction, not proof of the entire installed APT/DNF lock
graph or all possible concurrent administrators. The real host writer
and DNF process exclusion remain unaccepted.

## Process-local scope exclusion

Traditional POSIX record locks belong to the process, not an individual
file descriptor. Closing a second descriptor for the same inode can drop
the outer POSIX lock even if a nested BSD lock acquisition was refused.
The helper therefore rejects nested or concurrent scopes in the same
process before opening any lock file; its guard is released only after
descriptor cleanup. Revalidation also refuses use by a different process
(e.g. an inherited callback after fork). Regression tests exercise actual
cross-process POSIX and BSD contention after nested refusal and verify
normal acquisition after exit.

The caller must not independently open and close any of the held native
lock inodes in the same process or transfer the scope across fork.
This change does not attest the actual DNF/APT lock graph or authorize
host source writes.

## Native RPMDB contention (booted AlmaLinux fixture)

The existing signed-RPM fallback VM exercise now holds both POSIX and BSD
locks on the RPM-created transaction lock of its isolated RPMDB before
attempting the disposable OpenPGP key import using the actual native RPM
binary. A positive exclusion result requires either a kernel-reported
blocked POSIX waiter matching the child PID and exact device/inode, or a
lock-specific native refusal naming that lock and the contention error.
A mere timeout or unrelated SELinux/command failure is not accepted.
The child is reaped before releasing the lock; the same key import must
then succeed and native RPM must verify the signed fixture. The guarded
fixture does not use the host RPMDB, change system trust or install a
package. This establishes only the RPMDB lock interaction, not DNF5's
complete lock graph, path lifecycle or installed source-writer exclusion.
The actual booted execution is required before claiming PASS.
