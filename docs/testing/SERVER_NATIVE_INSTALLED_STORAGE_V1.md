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

### Booted evidence and SELinux port-policy lookup

At exact HEAD 04f6b0237ed69ccfd7ca8a6c5a4bb4ad25f964ab the Debian 13 VM
([activation job](https://github.com/repocache-project/repocache/actions/runs/45668019622/job/139395641801)) passed the confined first APPLY, vendor temporary-directory
identity preservation, repeat/reload, negative authorization/storage cases,
WAL interruption/reboot recovery, inactive repair, actual MISS/HIT and
retained cache/metrics fixture. This does not establish authoritative active
route publication. The AlmaLinux 10.3 enforcing VM
([activation job](https://github.com/repocache-project/repocache/actions/runs/45668019622/job/139395641739)) passed the corresponding inactive-route and recovery
cases, but again failed the HTTPS storage fixture with 502/EACCES.
Both port decisions and the matching AVC were NOT VERIFIED.

The diagnostic now follows the actual first-match ordering of the loaded
binary policy instead of incorrectly rejecting overlapping generic and
specific port ranges. Linux security_port_sid traverses OCON_PORT in order;
SETools SELinuxPolicy.portcons() walks the same linked list. See
https://code.googlesource.com/linux/torvalds/linux/+/72116efd6307077546c93e0432a197876cedff70/security/selinux/ss/services.c
and https://sources.debian.org/src/setools/4.5.1-1.1/setools/policyrep/selinuxpolicy.pxi/ .
The guest reports bounded diagnostic stages on unavailable observations,
rechecks the selected contexts, worker identity and enforcing mode, and
matches the actual NGINX connect-to-endpoint errno format with the worker
PID and request interval. No raw labels or journal contents are reported.
No production permission/policy change, active-route enablement or test
acceptance waiver is introduced. A confirmed stock-policy denial requires
an explicitly reviewed least-privilege operational design; do not globally
enable httpd network booleans as an installer workaround.

### Large uncached responses and transient scratch

A disposable local Debian 13.3 / packaged NGINX 1.26.3 experiment used a
10 MiB object, a slow loopback reader, explicit private temporary paths,
proxy buffering, the renderer's cookie bypass and disk cache configured
with use_temp_path=off. With the stock default proxy temp limit, the
BYPASS response logged a proxy temporary-file spill. With
proxy_max_temp_file_size 0, the same BYPASS response completed without
that spill; normal MISS/HIT also delivered identical SHA-256 bytes and
persisted the large cache object on disk (10486290 bytes including NGINX
metadata). Both runs preserved exact payload bytes. This is a component
experiment, not confined systemd/SELinux or a real package signature test.

The inert route renderer now emits this fixed native limit in every
repository location, including cache-off recovery. No new writable path
or permission is needed; slow uncached responses use backpressure rather
than unbounded temporary package spooling into /run. Cacheable objects
still use their own marked disk-backed repository root, as required by
use_temp_path=off. The generated HTTPS runtime regression denies proxy
scratch writes, transfers exact 10 MiB BYPASS/MISS/HIT/cache-off responses,
checks actual cache bytes and exact upstream count. Native CI evidence
for this change remains NOT VERIFIED. This does not bound every HTTP
request body, overall memory/connection pressure, upstream timeout, disk
cache pressure or authorize active-route publication.

### Maintainer-authorized isolated SELinux egress experiment (2026-11-25)

The explicit 19:32 UTC decision authorizes implementation, review and
validation in isolated environments only. The dedicated test policy uses
an independently labelled byte-identical copy of the packaged NGINX,
separate read-only and writable fixture types, and the native init
transition under NoNewPrivileges. It does not add permissions to httpd_t,
change global booleans or relabel the vendor executable. SELinux HTTP
port-type permission is not an endpoint allowlist; exact-address/port
restriction is independently exercised with nftables ONLY in a fresh
loopback-only network namespace. A non-HTTP-port negative canary is
intentionally admitted by the packet layer to test SELinux independently;
a second address on the permitted port must be blocked by the packet layer.
Require actual confined PID, no effective capabilities, verified TLS,
MISS/HIT and exact bytes, both negative canaries untouched, and cleanup
with unchanged stock booleans/vendor identity. No rule is installed by
the production installer. Native execution NOT VERIFIED until CI.

This is a first scoped experiment, not a completed production SELinux
architecture. The signed actual dedicated service remains unchanged and
its stock-policy egress failure is not waived. Future work must bind
service-specific executable provenance to the signed package, support
validated custom HTTPS ports without global port relabels, constrain
new outbound connections to exact approved IP/port tuples while preserving
client ingress, journal policy/generation changes and validate recovery,
reboot, withdrawal, repair and foreign-service noninterference. No
production activation or global network-policy change authorized.


The next isolated experiment adds a second HTTPS endpoint at `127.0.0.2:8008`
under unchanged stock SELinux port labels. The namespace-local packet filter
must reject it before approval, allow only its exact address/port tuple after
an atomic replacement, and reject crossed address/port pairs. A deliberately
invalid replacement must leave the prior rules effective. Withdrawal must
reject a fresh uncached upstream connection while preserving the original
endpoint. This does not revoke cached data or already-established flows and
does not establish support for arbitrary SELinux port types. The installed
service remains unchanged; this new experiment requires exact-head native CI.

The following isolated increment uses an actual non-root NGINX master and
worker instead of single-process mode. It observes the expected native RPM
owner and verifies the copied executable inode, process start identity,
UID/GID, SELinux domain, no effective/permitted capabilities, NoNewPrivileges
and network namespace for both processes. A real HUP reload must preserve
the master identity and converge to a new confined worker. Fresh uncached
positive and negative connections after a failed packet-filter replacement
and after reload must preserve the exact approved tuple. This is a stronger
fixture only; RPM owner observation is not independent signature proof.
The production root-master unit, authenticated executable placement,
transactional policy installation and installed cache egress remain unaccepted.

The isolated AlmaLinux activation campaign now signs a separate, fixed
fixture-only policy envelope with the existing disposable Ed25519 identity
before deleting the private key. The envelope binds the exact policy bytes,
combined source identity, authenticated release archive/manifest and signed
NGINX unit. The guarded guest re-authenticates the installed signed worker,
uses its existing root-owned test trust anchor, and rejects altered policy,
identity and signature before compiling or installing the temporary module.
Only authenticated in-memory policy bytes are compiled. The supplemental
envelope is not a release asset, and no policy files are added to the product
inventory or installed by the production installer. This does not authenticate
the native RPM payload independently, authorize an installed service
transition, or replace the outstanding signed installed-service acceptance.

The same authenticated temporary module is also tested with an independent
forking root-master lifecycle, the four-capability bounding set CHOWN,
KILL, SETGID and SETUID, and zero effective/permitted/ambient worker
capabilities. NGINX must itself assign its private cache/temp directories to
the worker account and retain a root-owned PID file. The private namespace
uses default-deny fresh egress including root (only root health requests to
the fixed listener and exact worker upstream tuples allowed). A root-origin
negative connection, cache MISS/HIT, HUP worker replacement and tuple
withdrawal must all pass; the original zero-capability probe remains.
This is an isolated fixture, not a transition of the installed signed unit.
