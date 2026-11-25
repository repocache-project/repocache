# Signed native storage roots and dedicated service sandbox (#29)

The existing explicit authenticated NGINX activation prepares two fixed,
owner-marked directories while the existing protected state lock is held,
after signed worker/package/configuration checks and before systemd start:
`/var/cache/nginx/repocache-managed` (packaged worker UID/GID, 0700) and
`/var/log/nginx/repocache-managed` (root:root, 0750). The signed unit keeps
ProtectSystem=strict, with only these exact directories added to its
existing runtime-directory write exception. Parent directories and
/etc/nginx must remain read-only in the actual master's mount namespace;
the two permitted leaf mount views must identify the same host inodes.

The root-owned parent contains a separate 0600 inode/ownership marker for
each root. Both roots are preflighted before creation. Symlinks, unowned
or incomplete roots, changed marker contents, writable ancestry, foreign
mount boundaries (including same-device bind mounts), extra xattrs and
read-only storage are refused. Repeat activation verifies rather than
recreates, relabels or deletes existing data. A partial mkdir/marker
interruption fails closed and requires operator inspection; no automatic
adoption or deletion is authorized.

On AlmaLinux 10, enforcing SELinux is mandatory. Stock policy lookup
must give httpd_cache_t and httpd_log_t respectively; only newly created
inodes may be assigned their matching policy context through the pinned
descriptor. Existing mismatched labels fail closed; no policy changes,
recursive relabel, setenforce or permissive workaround. The package
installer also validates the fixed cache parent, including a label
assignment only when it itself created that parent.

This is not a second root-control protocol. The existing signed installer
retains its lock, and a failed post-start mount observation uses its
existing compensation. The fixture-only storage APIs remain unchanged.
No per-repository cache activation, metrics-file creation/rotation,
automatic pressure decision, signed client fallback, full repair or
publisher acceptance is claimed. Booted tests must establish the actual
unit mount restrictions and label support on both target distributions;
actual confined NGINX worker cache/log access is a subsequent managed
configuration transaction gate.

## Active-set storage preparation prerequisite

The internal signed-host preparation now supports the complete validated
desired-active repository set and fixed opt-in metrics file. Only the
two already reviewed cache/log roots are accepted. It verifies both
external root markers and every requested child before creating anything.
Each repository's mode-0700 worker-owned directory has an independent
root-owned 0600 inode marker outside the worker-writable cache root.
New cache directories are prepared root-owned in the protected parent,
published with Linux renameat2(RENAME_NOREPLACE), then assigned worker
ownership on the original pinned descriptor. No racing foreign target is
overwritten or chowned. Metrics is created exclusively in the existing
root-owned log directory, mode 0600, with an independent external marker.
SELinux policy lookup and label assignment apply only to fresh inodes.
Partial/foreign data, stages, hardlinks, symlinks, label/mount drift and
nonfixed layout are refused. Repeats and disabling/opt-out retain data.

No installed CLI/socket authorization or active-route exposure is added.
The internal creation entry requires the authenticated caller's existing
state lock; native signed host and confined real worker verification
remain mandatory before enabling it from the fixed APPLY transaction.

The booted signed-installation campaign exercises the actual installed
zipapp preparation under the native state lock and actual dedicated
systemd service with the fixed cache and metrics paths. A disposable
VM-only loopback origin substitution tests MISS/HIT, exact payload bytes,
worker UID/GID, enforcing httpd_t, and metrics writes. The socket remains
stopped; the fixture restores the original managed include and requires
the original committed generation, resource hashes and cache/history
preservation on repeat. This does not exercise authoritative active
repository APPLY/catalog publication and must not remove that guard.

The read-only active-set verifier additionally binds each marked repository
cache directory and opt-in metrics inode to the actual dedicated service
mount view. It pins the PID1 and service roots, requires distinct mount
namespaces, a read-only shared parent and writable intended leaf mount,
refuses child mount substitution and verifies the same owner-marked inode
before and after service-view inspection. It cannot create, adopt, relabel
or delete data, and reports no worker write proof. The signed booted VM
fixture exercises it under the state lock before and after the real worker
cache/metrics exercise. The production APPLY guard remains unchanged.

The managed main context explicitly selects the distro's fixed packaged
worker and group (`www-data www-data` on Debian, `nginx nginx` on
AlmaLinux), matching the storage owner. The build-time default is not
sufficient: the booted Debian test at b8fb7ce observed a UID mismatch.
The signed bootstrap file and ownership marker remain unchanged.
Only the two closed deterministic managed main byte sequences are
recognized; the native dispatcher, installer, and recovery journal bind
the actual distro and refuse a cross-distro worker identity or switch.
AlmaLinux's prior HTTP 502 remains unresolved pending bounded native
upstream diagnostics; no SELinux booleans, policy or trust checks are
relaxed. No active-route guard is removed.

On a failed upstream request the disposable AlmaLinux guest also attempts a
read-only recent AVC lookup and reports only whether an enforcing NGINX
worker denial of the fixture TCP connection was observed. Missing audit
support, unmatched events or excessive output are NOT VERIFIED, not a
negative security finding. No raw audit records are emitted. On an
unexpected socket refusal the guest reports only state/WAL file presence
alongside the existing systemd status; these observations do not establish
the cause, commit, rollback or recovery. All original assertions remain
mandatory; diagnostic output cannot convert a failed run to PASS.

The fixed worker now records a closed set of native transaction refusal codes
locally in the service journal, including the original live-apply failure
before compensation. Unknown exceptions are mapped to a generic code;
no raw exception, path, NGINX output or request contents are emitted. The
socket reply and exit semantics are unchanged. Disposable guest diagnostics
accept only these exact codes. If recent auditd lookup does not establish
an enforcing AVC, the guest also checks the current boot's kernel journal
for the request interval, accepting only the matching worker PID, TCP
port, domain and enforcing denial. No policy, boolean or service permissions
are changed, and missing evidence is still NOT VERIFIED.

At `cb8b4aa`, the confined Debian first APPLY failed in the native
owned-context probe and rolled back. NGINX -T initializes temporary
paths, including the distribution's compiled-in defaults; a read-only
vendor path is one hypothesis, not yet the established native cause.
The fixed owned probe now drains stdout and stderr independently under
one deadline, with a separate 16 KiB stderr limit, and maps failures
only to closed permission/read-only or exact vendor temporary-path
categories. The legacy vendor probe still discards stderr. No raw child
stderr reaches the journal or client. The socket remains generic and
all syntax, exact dump, provenance, rollback and confinement gates remain
unchanged. No SELinux or filesystem permission change is introduced.

### Debian managed-context scratch paths

The Debian booted worker refused first APPLY with a read-only filesystem
error at `c2be994` and safely restored the bootstrap. The Debian 13 native
NGINX binary emits `chown("path", uid) failed`, not just the earlier generic
classifier shape. Native syntax checks initialize the compiled-in temporary
directories, including ownership changes when the managed context switches
from the package build-time default user to www-data. The exact failing path
in that older run was not captured; this change removes the identified
dependency on vendor temporary directories for the Debian managed context.

The five fixed HTTP scratch paths use the existing root-owned, writable
`/run/repocache-nginx` domain. No new writable mount, vendor ownership change,
SELinux change, signed bootstrap change or caller-selectable path is added.
The probe checks runtime/child metadata, same-mount identity and xattrs
before/after the native command; inactive installer retry permits only empty
fixed scratch directories and otherwise refuses. Runtime data are transient,
not repository cache/log data; systemd owns cleanup. The actual socket still
refuses active repository routes. Before activating real Debian cache routes,
verify bounded buffering and disk-backed cache behavior; do not treat tmpfs
as package cache storage. AlmaLinux managed bytes are unchanged. The guest
checks vendor temp metadata before and after failed reload compensation and
confined APPLY. Native validation of this increment remains required.

The prior exact AlmaLinux native activation completed all confined inactive
route apply/reload/reboot/repair scenarios, but its actual HTTPS storage
fixture still failed with 502/EACCES and no matched AVC. Both stock httpd
network booleans were off. The disposable AlmaLinux activation guest now
uses the distro's SETools Python package (test-only) to obtain an unambiguous
TCP port context from the loaded kernel policy and the libselinux public
access-decision API to observe name_connect for the actual enforcing NGINX
worker context, both fixture port 8008 and production HTTPS port 443. This
reports only ALLOW/DENY/NOT_VERIFIED, not raw contexts or policy text, and
is not a substitute for the matching kernel AVC or successful upstream
traffic. No policy module, port label, boolean, privilege or production
dependency change is authorized or introduced.
