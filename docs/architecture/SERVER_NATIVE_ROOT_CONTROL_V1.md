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


## Necessary booted Linux root/namespace preflight (no host attestation)

The worker now executes the private fixed-path
`server_root_control_host_preflight_v1.require_native_host_preconditions`
after validating its systemd-activated root-owned listening socket and
before reading any administrative request. It refuses non-root effective,
real or saved UID/GID, non-systemd PID 1, differing worker/PID1 mount,
user or PID namespaces, rootless/subordinate user namespace UID maps,
missing or group-writable systemd runtime directories, or unreadable
kernel procfs facts. All reads are bounded and value-redacted; callers
cannot supply a path, namespace, unit, command or required identity.

**Critically, this is only a necessary-context refusal filter.** PID1
can be `systemd` *inside a privileged container*, and a container can
share root UID mappings and namespace inodes with its own PID1. These
observations do not attest that the code was installed from an approved,
signed REPOCACHE release, that it runs on the intended physical or virtual
host, or that the effective NGINX unit and SELinux policy are protected.
The report explicitly sets `host_root_provenance_verified=False`,
`signed_installed_binary_verified=False`,
`effective_systemd_unit_verified=False`,
`selinux_acl_mount_ownership_verified=False` and all host-write,
NGINX-reload and catalog-publication authority flags to false. The
worker **still unconditionally returns nonzero with no host side effect**.

CI tests include synthetic PID1, namespaces, UID/GID, procfs and runtime
ownership failures plus actual Linux procfs observation in disposable
Debian 13 and AlmaLinux 10 userspaces. These tests are neither a booted
systemd/PID1 end-to-end acceptance nor proof of enforcing SELinux.
A future positive host activation remains blocked until an independently
verified signed-installed worker and unit provenance, no foreign NGINX,
fixed transaction path/lock, durable multi-resource compensation and
operator-authorized service/catalog activation have passed native acceptance.


## Authenticated operator response on the inert Unix control channel

The uninstalled worker now returns a **single small, fixed-schema JSON
denial packet**, terminated by one newline, on the *already authenticated*
Linux AF_UNIX `SOCK_SEQPACKET` connection. This is deliberately separate
from stdout, which belongs to the service journal and is not a reliable
client return channel. The permitted request names are still only exact
`apply-v2\\n` and `recover-v2\\n`; the reply is always
`ROOT_TRANSACTION_NOT_IMPLEMENTED`, with all write, reload, catalog and
operator-action flags **false**. The worker always exits nonzero regardless
of successful reply delivery. It does not run a privileged dispatcher.

No reply is sent for rejected identities, invalid packets, unsafe socket
layouts or host-context failures; those paths close the connection and
write only a fixed redacted error to the worker journal. The response
channel uses a three-second bounded send and refuses short writes,
transport errors and timeouts. A successful socket send does not prove
that the remote operator accepted the packet. The fixed response contains
no state bytes, file names, credentials, user claims or untrusted client
text.

Unit tests exercise real kernel sequential-packet receive of the complete
single frame, absent acknowledgment on authentication failure, and
failure-to-send refusals. This is protocol usability for an **inert
security prerequisite**, not a completed CLI, installed worker or
production NGINX authorization. Booted native systemd and enforcing
AlmaLinux 10 SELinux remain NOT VERIFIED.


## Non-installed fixed client: authenticated refusal is not a successful action

The optional private \`server_root_control_client_v1.py\` is an exact two-operation
Linux AF_UNIX \`SOCK_SEQPACKET\` test consumer, NOT a \`repocache\` CLI command.
The caller may select only the Python enum-like exact operation names
\`APPLY_V2\` and \`RECOVER_V2\`; the implementation fixes both their wire
messages and the control pathname. A 3-second deadline protects connect,
send and receive. The path's necessary root-owned, non-group-writable
metadata is checked before connect; after connect, the Linux kernel's
\`SO_PEERCRED\` must identify a root peer. The client accepts just ONE
bounded newline-terminated JSON response whose closed keys, version,
operation identity and **all-false** operation/authority flags match the
inert worker. Any \`success\`, authorization flag, extra field, truncated
reply, invalid peer, malformed payload or foreign socket fails closed with
a static diagnostic code, never an ambiguous successful apply.

The client never confers operator group membership or authorization. Neither
root UID from \`SO_PEERCRED\` nor a fixed path can prove that the peer is
the signed installed REPOCACHE binary or the host PID1 namespace. The client
does not run an external executable or read protected state. Both the
client and server are uninstalled prototypes and **no real request can
succeed**; \`ROOT_TRANSACTION_NOT_IMPLEMENTED\` remains a denial.
Separate kernel/socket tests run in disposable Debian 13 and AlmaLinux 10
containers, without installing systemd units or modifying real NGINX.


## Closed canonical denial-packet validation

The inert two-operation socket client now rejects duplicate JSON keys at
every nesting depth, nonfinite numbers, alternate numeric spellings, unusual
whitespace, Unicode escaping, reordered keys and any other noncanonical wire
form. It requires the exact one-line compact, ASCII, sorted-key, newline-ended
response emitted by the non-installed root worker. This prevents distinct
client parsers from interpreting an ostensibly identical denial differently
when the root transaction is later implemented. Every permitted response
still explicitly reports NOT_IMPLEMENTED and all authority flags false.
This parser does not authenticate installed code or authorize any write.


## Fixed default NGINX syntax invocation (no service action)

The uninstalled private module `server_root_control_native_syntax_v1.py`
adds a concrete low-level prerequisite for a future privileged transaction.
It invokes only distro-native `/usr/sbin/nginx -t -c /etc/nginx/nginx.conf`
with `shell=False`, no caller arguments, a fixed sanitized environment,
`cwd=/`, closed inherited descriptors and a 10-second deadline.
Both executable and top-level configuration must be regular root-owned
files behind non-group-writable root-owned ancestors, without leaf symlinks
or hard links. Their metadata is rechecked after running NGINX; detected
replacements fail closed. Standard input, output and error are `/dev/null`;
fatal NGINX private diagnostics cannot appear in returned reports.

An `nginx -t` syntax check may itself read existing config/TLS secrets and
touch NGINX log files; it is **not** guaranteed mutation-free on a real host.
It checks the *currently installed default* configuration, **not** an owned
REPOCACHE staged candidate. Includes, service provenance, SELinux and real
exposure remain separately unverified. An exit status zero is a narrow
observation, never a commit lease. All authority flags remain false.
The systemd socket worker still returns `ROOT_TRANSACTION_NOT_IMPLEMENTED`;
the new syntax module is **not imported/invoked by the dispatcher**.

The existing two-distro root-control native CI now installs authenticated
distro-native NGINX only in disposable Debian 13 and AlmaLinux 10
containers, tests the fixed executable, malformed default syntax rejection
and restores the original container config bytes. Unit tests enforce argv,
no shell/env inheritance, deadline, unsafe path/root refusal, inode-drift
checks and zero delegated authority.

A future broker must separately verify signed installed REPOCACHE code,
independent administrator authorization, native NGINX package/unit
provenance, staged owned full-context candidate, mount/ACL/xattr/SELinux
integrity, locked durable #31 state/NGINX/catalog WAL, known-good rollback,
and actual active service exposure before any controlled reload/catalog.
No host installation, socket activation, grant, service reload or actual
catalog publication was performed by this change.


## Independent TLS certificate/private-key pair validation (uninstalled)

The private `server_root_control_pinned_tls_pair_v1.py` helper addresses a
**measured native AlmaLinux 10 security gap**: packaged NGINX may return
successful `nginx -t` with a missing, malformed or mismatched TLS key.
The future root transaction MUST independently verify the selected
operator-provided certificate/private-key pair **before** staging a managed
NGINX reload. The new helper accepts **already opened, read-only CLOEXEC
file descriptors**, not a filesystem pathname, shell command or socket
request. It rejects a same-FD pair, non-regular/unowned/unsafe-mode or
multiply-linked files, oversized credentials, writable descriptors and
content/inode/metadata drift. The certificate and key are passed to
Python's TLS backend through pinned Linux `/proc/self/fd/N` references;
`load_cert_chain(password="")` uses no interactive passphrase prompt.
Underlying OpenSSL diagnostics, file paths, PEM data and SHA-256 digests
are never emitted or returned. Synthetic actual OpenSSL pair, mismatched
key and invalid key tests run in both distro CI containers.

**Hard security limit:** The helper is private, uninstalled and **not
called by the root socket worker**. Its current test seam accepts an
explicit expected file owner UID, which is not independently authenticated.
It verifies only opened-descriptor properties and pair loading, NOT the
trustworthiness of certificate issuer, expiry, SAN/hostname, ownership
of directory ancestors, nofollow/protected path resolution, mount, ACL,
SELinux, signed installed code, native host root, live NGINX listener or
user intent. Successful SSLContext loading does not prove any of these.
Never expose the descriptor or UID arguments to a service account or
socket request, or use a report to authorize write/reload/publication.
The future protected #31 transaction must derive and open both credentials
from the **locked canonical v2 state** using audited root dirfd traversal,
check ownership/ACL/SELinux/mount/symlink/foreign-state policy and all
TLS trust/hostname/expiry requirements, then retain the immutable verified
operation context through the actual rollback-capable reload. This module
does not substitute for that work or local booted-VM acceptance.

## Bounded real fixed `nginx -T` dump prerequisite (non-installed)

The private `server_root_control_full_context_v1` module invokes exactly
`/usr/sbin/nginx -T -c /etc/nginx/nginx.conf` under root only. It verifies
fixed executable/config metadata and their trusted ancestors before and
after the command; there is no caller-selected config/argument, shell,
inherited environment, stdin, stderr forwarding, or service signal.
A deadline and select-based incremental stdout consumption cap output at
4 MiB *before it is accumulated*. The private dump is never returned by
the public report: only its length and SHA-256 are exposed. Failure,
timeout, unexpected inode changes, empty/oversized or nonzero output
are refused via static redacted codes. No private NGINX config/TLS path
content reaches logs or the admin socket.

IMPORTANT: `nginx -T` may itself read secrets and create log/cache files.
The fixed default `nginx.conf` check does NOT authenticate all referenced
include files, mounted paths or actual active systemd service/NGINX
listeners. An operator-controlled but otherwise untrusted include could
still produce unsafe side effects; this module remains **uninstalled**
and is NEVER wired into the root worker or any host transaction. Root
inside the disposable CI container does not prove installed host root.
Source/unit tests assert exact argv, bounded output, timeout/cleanup,
nonroot/unsafe ownership/identity-change denial and that private stdout
is never serialized. The existing explicitly disposable test-only smoke
exercises real distro-packaged `nginx -T` success, deliberately broken
default syntax refusal and exact restoration in Debian 13 and AlmaLinux
10 CI images. It MUST NOT be run on a real VM or operator host.

Future authorized broker work must bind this *private* native dump to the
retained v2 FD lock and #31 generated NGINX/client catalog consistency
check, and independently verify provenance, all included-file ownership,
SELinux/ACL/mounts, verified running exposure, signed installed code and
operator intent before any commit, systemd reload or catalog publication.
The status remains **NOT VERIFIED** at real installed-host scope.


## Combined fixed native NGINX pre-reload observation (not installed)

The private `server_root_control_pre_reload_v1` module composes the
already merged #27 exact effective vendor `nginx.service` observer with #64's
necessary native root/PID1 preflight, fixed `nginx -t` and bounded private
`nginx -T`. It checks native host prerequisites again and compares the
effective unit's master PID and vendor unit digest before and after the
inspection. It rejects a changed effective unit, untrusted status, malformed
digest, failed syntax/full-context, root identity mismatch and unsupported
distribution with fixed redacted errors.

This is **not** a snapshot lock, an attestation, or a reload transaction.
The native helpers can have filesystem side effects despite being observations,
and their output can race between checks. No independent included-file,
package/signature, TLS trust, SELinux/ACL/mount, operator approval or actual
live-routing proof is established. The report explicitly denies write,
`systemctl`, reload and catalog-publication authority. Nothing imports this
module into the socket worker, and all actual operations remain deliberately
`ROOT_TRANSACTION_NOT_IMPLEMENTED`.

For the later installed host-root executor, this prerequisite must run only
after signed binary/unit provenance, authenticated administrator intent and
retained #31 exclusive state-v2 lock/WAL are established, with active
exposure verification and durable rollback before active-only publication.
The two-distro GitHub Actions tests here use mocked service observations and
never invoke native systemd or reload. Booted native VM acceptance is
**NOT VERIFIED**.
