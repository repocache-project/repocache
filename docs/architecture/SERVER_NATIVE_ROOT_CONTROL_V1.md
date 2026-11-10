# Fixed Linux root-control boundary — issue #64 (v0.6.0)

**Status: implementation prerequisite, NOT a production service or a reload
authorization.** Primary issue #64, coordinated with #31 PR #237, #27 PR #252,
#28 PR #251 and #95 PR #214. This is a narrow, separate source/test increment
on a branch targeting `integration/v0.6.0`.

## Threat model and native mechanism

The future server management broker must run as root from an independently
authenticated and verified **root-owned installed** image. It must be reached
only through an explicit operator-controlled Unix socket; the service account
must have neither that socket's access nor generic sudo/systemctl capabilities.

This prototype chooses **Linux AF_UNIX SOCK_SEQPACKET** rather than accepting
command-line arguments, shell strings, open JSON requests or a user-controlled
file path. It reads peer credentials from **SO_PEERCRED** (pid/uid/gid), and
kernel connection-time supplementary groups via **SO_PEERGROUPS**. The trusted
operator policy is a provisioned local `repocache-admin` Unix group. The
`repocache` service UID is explicitly refused even if accidentally made a
member. The protected installed daemon must run under UID/EUID/saved UID 0;
host-root provenance is a **separate** requirement. A correctly credentialed
root peer has pre-existing OS administrative powers; it is not evidence of
release or application approval. If either local identity is missing, group
introspection is unavailable, credentials are truncated or a non-Linux socket
is presented, refuse.

Only two **single-frame** exact operation requests exist:
- `apply-v2\n`: eventual authenticated transaction orchestration (NOT implemented)
- `recover-v2\n`: eventual explicit recorded known-good recovery (NOT implemented)

Packets are bounded to 32 bytes, with timeout and kernel truncation checks.
The returned operation code is a **classification only**: all state-write,
NGINX-reload and catalog-publication authority flags remain false. There is
no production dispatcher or installed helper. A separate **non-installed,
always-denying** socket-activated worker skeleton now checks systemd's single
FD 3 handoff, fixed `/run/repocache/server-control.sock` listener identity,
root-owned runtime directory and socket mode/ownership, and rejects all
applies/recoveries with a nonzero exit. No systemd unit or socket is supplied,
installed, enabled or activated. There is no mutable root-owned file, no arbitrary
unit/config/executable/input path, no caller-supplied env, no trust in
`--yes`, request hashes, approval references, client submissions or state
snapshots. The code does not spawn, run or mutate anything.

## Independent requirements before an installed native broker

1. **Admin authentication and socket protection.** Native systemd socket
   activation and root-owned worker configuration must be reviewed separately.
   The matching systemd-native policy is a root:root
   `0755` **non-writable parent directory** created by `DirectoryMode`,
   and a root:`repocache-admin` `0660` Unix socket created by
   `SocketUser/SocketGroup/SocketMode`. Admin users can traverse and connect
   but cannot replace the socket pathname; the service UID is excluded. The deployed administrator
   must explicitly provision/revoke membership and verify the effective
   client process' **kernel credentials**. Do not enable the socket until
   actual, audited distro service packaging, module provenance, secure Python
   import path, ACL/SELinux labels and effective unit/drop-in ownership are
   verified. A Unix group name and a set of data bytes are not independently
   authenticated approval for a configuration.
2. **Fixed worker.** Only a reviewed immutable dispatch may act on a selected
   operation. It must re-read the v2 state under the same owner-pinned
   exclusive lock, authenticate the operator's intended exact-generation
   configuration and signed/reviewed trust roots, reject stale/historic IDs,
   validate NGINX and cache ownership/SELinux/ACL/mounts, stage managed
   fragments without altering foreign configuration, run a fixed distro
   `nginx -t`, perform a bounded fixed-unit systemd reload, verify actual
   exposure and atomically publish only active, approved derived catalog.
   Crash/power-loss, invalid syntax, failed reload and inconsistent
   publication must preserve/recover the known-good service and data.
3. **Isolation.** Package installation under APT/DNF is its own non-atomic
   transaction. Never hand a writable request body to a privileged subprocess
   or treat a credential check as authority to overwrite NGINX, TLS,
   monitoring, cache or client APT/DNF sources. Re-run host provenance
   and ownership immediately before every root mutation.
4. **Revocation and evidence.** Revoke socket access by removal from the
   provisioned admin group, ending old sessions, and disabling the separate
   broker socket/unit. Only operators who still possess privileged root
   control may revoke or alter the underlying OS policy. Audit only static
   codes, UID, operation and exact revision; never log keys, credentials,
   private configuration, requests, source bytes or tokens.

The full native implementation is **not yet deployed**; this is a documented
policy and protocol source only. Do **not** copy this module into a root
executable and assume it is production-safe. Root EUID inside Docker is not
trusted host-root provenance, and `SO_PEERCRED` proves only local socket
kernel process identity. The no-activation safety flags must not be promoted
into host permissions. No sudoers, systemd, SELinux or host package files
are installed by this PR.

## Tests and acceptance

The `server-root-control-protocol-native.yml` workflow executes unit and
negative socket/worker tests on disposable Debian 13 and AlmaLinux 10 userspaces.
It covers the actual Linux peercred read, incorrect socket type, exact
command whitelist, truncation, service account refusal, missing local policy,
unprivileged worker denial and pure group/identity decisions. It additionally
checks abstract/wrong-type listeners, permissive/symlink/foreign socket
metadata, missing systemd activation FD and rejection of all root worker
operations. A disposable root-owned AF_UNIX listener test also verifies that
a valid kernel listener is accepted only while its filesystem entry retains
the expected owner/mode/group, then refuses a symlink substitution at the
same pathname. This is a synthetic native socket-path test, NOT booted
systemd/SELinux acceptance. The worker deliberately returns a nonzero status even for a
successfully authenticated request: a refused operation must never be
mistaken for a completed administrative change.

Test files merely present is **NOT VERIFIED** until inspected exact-HEAD
pytest logs. An `authorize_fixed_root_request` success is **not** an executed
root operation. The original issue #64 positive authorized managed
NGINX validation/reload, negative privilege/foreign-host checks, failed
reload compensation and booted systemd/SELinux end-to-end tests remain
**NOT VERIFIED**. Initial root-only schema and operator policy are
architectural prerequisites, not acceptance, merge permission or release.

No production listener, server activation, systemd enablement, signing,
tagging, Merge Queue admission, ruleset modification or publication is
authorized by this document.

## Non-installed systemd reference units and ownership correction

The **reference only** `docs/examples/systemd/repocache-control.socket`
and `repocache-control.service` are deliberately excluded from any
installer, distribution activation, package manifest and `[Install]`
section. The service references the fixed
`/usr/libexec/repocache/server-control-worker` binary **which is NOT
provided or installed** by this branch. This reference must **not** be
copied to `/etc/systemd/system` or enabled: no production worker,
installed signed provenance, SELinux policy or full state/NGINX/catalog
transaction has yet passed acceptance.

The socket uses `ListenSequentialPacket=/run/repocache/server-control.sock`,
`Accept=no`, `SocketUser=root`, `SocketGroup=repocache-admin`,
`SocketMode=0660` and `DirectoryMode=0755`. Upstream systemd
`DirectoryMode` creates parent directories root-owned; it does **not**
assign `SocketGroup` to the directory. Accordingly, the worker now
rejects anything other than **root:root 0755** on `/run/repocache`,
and **root:repocache-admin 0660** on the Unix socket. An administrator
group having write permission on the parent would be able to replace the
socket path: `0775` or root:admin `0750` are deliberately refused.
The run-time metadata checks still require independent installed unit,
mount/ACL/xattr/SELinux, binary/import provenance and kernel/root
namespace evidence before any host mutation.

The reference service is `Type=oneshot`, root-owned, fixed
`ExecStart`, no `ReadWritePaths`, read-only protected filesystem,
restricted to AF_UNIX, bounded by a short start timeout, with
`NoNewPrivileges` and an empty `[Install]` section (absent).
Even a manually invoked inert worker always exits nonzero after reading
one authenticated request. The future real executor must be separately
reviewed, installed and accepted; these reference templates cannot
grant privileged reload authority. Their strictly closed static contents
are tested on both distro CI containers, **not** booted systemd PID 1
or AlmaLinux enforcing SELinux.

Do not provision or alter a real admin group, deploy/enable units, modify
protected paths, grant root privileges or perform a reload as part of
this PR. Native installation support remains NOT VERIFIED.
