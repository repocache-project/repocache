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

## Installed DNF transaction lock lifecycle (booted AlmaLinux fixture)

The booted AlmaLinux image used in run 45603393341 did not provide
`/usr/bin/dnf5`. Do not install a different manager or call DNF4 evidence
DNF5 evidence. Select the native executable and identify the version.
DNF4 uses its actual live-PID `rpmdb_lock.pid` under the isolated
persistdir, with `exit_on_lock=1`; require exit 200 and the exact live
owner PID, unchanged lock inode and PID bytes. DNF5, where installed,
uses `run/dnf/rpmtransaction.lock` and the held BSD/POSIX inode locks;
require native lock-specific refusal and unchanged inode. Release only
the fixture's own lock and rerun the same signed local RPM transaction
in RPM TEST mode with all repositories and plugins disabled. The private
RPMDB package inventory and absent payload must remain unchanged.
Record actual manager version and lock lifecycle. Neither probe installs
packages, changes host package sources or trusts publisher keys.

These transaction locks do not prove exclusion of earlier configuration
or repository reads. The production source-writer remains unapproved.
Upstream implementation references:
https://github.com/rpm-software-management/dnf/blob/master/dnf/lock.py
and https://github.com/rpm-software-management/dnf5/blob/main/libdnf5/base/transaction.cpp.
Actual native outcomes at the new HEAD remain NOT VERIFIED until the VM runs.

## Exact local administrator review before consent

The internal `review_current_candidate` operation re-reads the protected
pending record, exact source inode/digest/attributes and current authenticated
catalog under the client transaction lock. It returns the exact source
selection, upstream, cache route and route digest only to the trusted local
root caller, with proposed source digest and whether a companion is required.
No original source bytes, key material or attribute values are emitted.
Do not log the review object or expose it via public status: even a canonical
repository path can contain sensitive identifiers. The separate approval call
still requires explicit consent to the exact route and independently repeats
validation. Review itself neither creates an approval nor edits any source.
The public CLI remains unchanged; no claim of an enabled production writer.

## Native APT source-read ordering

The Debian 13.3 / APT 3.0.3 disposable local root experiment (2026-11-25)
held POSIX and BSD locks simultaneously on all four fixed APT/dpkg lock
inodes. With empty sources, actual apt-get update refused the private lists
lock; with a deliberately malformed private .list it instead refused source
parsing before reporting any lock error. Restoring the empty file restored
the lock refusal; releasing the locks permitted the same empty update.
This demonstrates that these four locks do not exclude early source reads.

The guarded Debian booted privileged-client fixture now repeats that
sequence under the actual REPOCACHE lock primitive and its full-set
revalidation callback. APT_CONFIG points to an exclusive disposable
configuration before APT loads normal config; all status, lists, archives,
logs and source paths are private, with no repository/network access.
Neither installed host sources nor packages may change. A lock failure,
parse error, restored lock failure and post-release success are all required;
a generic nonzero exit or timeout is insufficient. Actual booted evidence
is NOT VERIFIED until execution. This is negative synchronization evidence,
not a new native-writer authorization: publication and rollback must remain
safe for already-read source snapshots, and lock acquisition alone cannot
be treated as an exclusion lease. No installed source-write path is added.


### Earlier-reader rollback interleaving

A real APT process can retain a parsed source across the interval before it
acquires the lists lock. The local Debian 13.3 / APT 3.0.3 experiment traced
only its own direct child at entry to fcntl(F_SETLK) for its private lists
lock. The parent acquired the actual four-inode REPOCACHE held lock scope,
atomically restored the source and released every lock before resuming APT.
Three fresh signed HTTPS fixture cases passed in the local component
harness (the exact lock module blob was verified):

- Retain the cache+upstream mirror file: the earlier reader succeeds but
  still reaches the preferred cache.
- Remove the mirror file after restoring the source: the earlier reader
  fails with the exact missing mirror / download failure, despite the
  upstream being available; no origin is reached.
- Atomically replace the mirror with original upstream-only contents
  before restoring the source: the earlier reader successfully retrieves
  signed upstream metadata and makes zero cache-origin requests.

The existing x86-64 Debian booted guest now repeats this deterministic
interleaving with a bounded child-only ptrace barrier and separate
disposable signed HTTPS origins. It never attaches to an existing
process, changes ptrace policy, installs a package or edits host sources.
Both native acceptance and retained companion lifecycle remain NOT
VERIFIED. The current sandbox recovery semantics are unchanged. A real
writer needs a durable owner-bound journal for neutralizing an exposed
companion, preserving the approved original upstream and trust, refusing
foreign state, surviving interruptions, avoiding path reuse across
approvals and retaining earlier-reader safety. Retaining a previous
cache route unchanged is not a revocation solution. A reader that has
already fetched the old mirror contents is outside this particular proof.
Do not remove the production apply guard or claim complete concurrency,
revocation or power-loss acceptance from this test.

## Atomic private DNF4 PID claim and reader distinction

The supported AlmaLinux VM's native DNF4 differs from DNF5: its RPMDB
PID record is ephemeral, not the stable DNF5 kernel-lock pathname. The
booted signed-RPM test retains the prior manual lock control and adds a
fixture-only atomic no-replace publication of a durable live PID, with
real BSD/POSIX locks on the existing isolated RPMDB transaction inode.
It refuses foreign or stale PID records, checks exact ownership and
inode/bytes, and releases only its own claim. A real DNF4 TEST transaction
must refuse with the live owner PID while a cache-only repolist still reads
a disabled private repository definition. The post-release TEST transaction
must succeed without any installed package change. A separate real SIGKILL
leaves the child PID record, which the next claim must preserve and refuse.
The test harness removes only its own proven dead-child fixture record.

This remains a guarded test, not an installed writer, comprehensive DNF4
metadata/download lock graph, automatic stale-record recovery or safe
source-mutation lease. DNF4 and DNF5 evidence must remain distinct.
Actual booted results are required; no production lock or source is touched.

## DNF4 scope integrated with the marked source journal

The private DNF4 lock protocol is shared by the signed RPM exercise and
an explicitly reserved marked AlmaLinux VM pair root. A reserved root
never silently falls back to DNF5 locks. The native RPM lock inode is
created by RPM in a separate private RPMDB and moved into the marked
fixture; a real installed DNF4 ProcessLock owner must prevent journal
intent/publication. The same labelled source journal then executes a real
SIGKILL while holding its own live PID claim. Recovery must refuse the
remaining stale PID record without changing the source or journal. Only
the fixture owner, having reaped its exact child, removes that fixture
record; recovery then restores bytes, SELinux label and user xattrs, and
an actual DNF4 ProcessLock can acquire the same persistdir again.
This test uses the existing synthetic catalog-bound label fixture; it does
not claim a native CLI transaction or production stale-PID cleanup policy,
actual signed upstream catalog, full read exclusion or host source writes.
The shared code lives in the existing sandbox-only module, not the
installed helper inventory. Exact native evidence remains required.

## Real catalog-bound DNF4 journal and pre-parsed native reader

The signed-RPM native AlmaLinux exercise additionally uses the actual HTTPS
catalog and fixture CA for preparation/approval, refuses a foreign CA and
withdrawn/changed route before marked journal intent, and kills the real
catalog-bound publication after source replacement. Two native DNF4 Python
Base/Repo instances read the exact generated inline baseurl list before the
parent restores the labelled source. Only the child's private mount namespace
binds the ephemeral metadata key at its compiled absolute key URI; no host
key or source is altered. Both readers pause before metadata/network work.
The journal refuses stale PID recovery, then only the fixture owner removes
its reaped child's exact record and restores bytes, label and xattr with
catalog offline. One already parsed reader must fail over to the signed
upstream RPM when cache is unavailable; the other is expected to still
use a healthy former cache. A fresh reader must use the signed upstream
only. All three transfers require independent native RPM signature and
payload digest verification. This is not a production revocation solution:
a file rewrite cannot revoke already parsed inline DNF URLs. Preserve the
installed apply guard and original operational acceptance requirements.
