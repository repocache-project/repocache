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

The first forking root-master attempt timed out during transient unit start.
The corrected fixture uses a distinct unit and root-owned separately labelled
PID directory, granting init only the fixture PID read/search permissions.
The systemd start is asynchronous with a bounded active+health check and
captures scoped status, journal, NGINX errors and relevant AVCs before
cleanup. The PID-label hypothesis remains subject to real native evidence.
Before either probe, the fixture independently queries signed official AlmaLinux
metadata for the exact installed nginx-core NEVRA, downloads only that HTTPS
RPM, verifies its signature with the distro key in an isolated RPMDB and
compares the signed SHA-256 executable digest against the installed bytes.
Unavailable exact payload or mismatched trust/identity refuses the test;
no package installation, host RPMDB change or shipped policy is authorized.

The exact previous AlmaLinux run independently verified the distro-signed
RPM and booted the root master (systemd active). All three workers/cache
children failed setuid with EPERM. The exact cause is still unverified.
The next test preserves the four-capability boundary and NoNewPrivileges,
sets the native NGINX early log to stderr rather than the vendor log,
records master credentials, namespace map and capability-policy decisions,
and on failure runs a separate bounded native credential-drop canary in
that same isolated domain and namespace, without loosening any permissions.

An independent alternative uses the verified installed unit bytes as input,
requires the exact reviewed service contract, and derives a distinct
runtime-only unit with a nonroot master, zero capabilities, private paths
and private network namespace. It retains the original forking type,
ExecStartPre/ExecStart/ExecReload/ExecStop lifecycle and hardening directives.
It tests positive and negative TLS/cache/egress, native reload and exact
runtime unit removal; it does not change or enable the installed signed
unit, adopt a new production architecture or waive the failing root probe.

The prior exact AlmaLinux run established the signed-unit-derived nonroot
forking lifecycle, native reload/stop and unchanged signed installed unit.
The privileged master was active but CapEff/CapPrm were 0x61 while CapBnd
was 0xe1: CAP_SETUID was missing. The cause is not yet established. Replace
the unavailable sesearch command with a loaded-kernel libselinux capability
decision, and ensure an optional diagnostic failure cannot prevent the
credential canary or conceal the original start failure.

The successful nonroot derived lifecycle now additionally executes the
authenticated installed worker's actual closed repository renderer on a
fixed private APT/DNF document. Only after normal validation does the
harness replace the two public dummy pins with exact private loopback
tuples. It checks per-repository HTTPS MISS/HIT and cache files, rejects
POST and upstream redirect, and withdraws DNF with a new rendered
candidate, real reload and old-worker drain while APT remains usable.
The fixture does not publish a catalog, mutate the installed signed unit,
grant an operational route, or validate a production egress transaction.

### Root-master credential setup and signed-derived comparison

Exact prior native evidence: the installed authenticated repository renderer
passed the nonroot isolated APT/DNF MISS/HIT, POST/redirect and DNF withdrawal
tests. The root-master and independent Python credential canary both began
with CapEff/CapPrm=0x61 and CapBnd=0xe1, despite the enforcing kernel policy
allowing self setuid/setgid. The canary successfully changed groups but
setuid returned EPERM. The upstream systemd v257 exec-invoke.c
keep_seccomp_privileges path explicitly drops CAP_SETUID after enforce_user
when an explicit UID is selected and it is not ambient. This is a
source-backed hypothesis, not yet a verified diagnosis of the guest build.
The corrected fixture omits explicit User=root/Group=root, matching the
signed installed unit's default identity, retains NNP, seccomp and exactly
the same four-capability bound, and asserts actual root/worker credentials.
The transient root path retains its direct cache directory; the derived
root path uses separately owned cache zones under a traversal-only parent.
After transient success the signed-unit-derived root variant must also pass
the actual rendered routes, reload/drain, withdrawal, native stop and
readback of the unchanged installed unit. No production service changes
or broadened capabilities, policy, firewall or publisher claim are made.

### Peer-network ingress and exact egress bridge

The exact prior AlmaLinux 10.3 enforcing campaign proved all four isolated
variants, including implicit-root signed-derived startup, exact master and
worker capabilities, native reload/stop, route withdrawal and cleanup.
The actual stock-policy installed service nevertheless returned 502/EACCES;
loaded SELinux policy denied name_connect on 443 and 8008 and a correlated AVC
remains unverified. No production solution is inferred from that contrast.

The root signed-derived experiment now retains its loopback controls and
adds a second private namespace linked only by a veth pair. The service
and peer have no default routes or host links; the peer serves TLS on two
fixed documentation-range addresses and acts as an actual HTTPS client.
The authenticated renderer's dummy public pins are replaced only in the
fixture with the two peer tuples. A default-deny namespace-local output
chain permits only the selected worker tuples and established responses,
plus the existing root loopback health exception. Crossed tuples and root
fresh egress must fail, actual client ingress and cache MISS/HIT must pass,
and withdrawal must drain the old worker, remove DNF and retain fresh APT
access from the peer. All resources are disposable; the production signed
unit, package, vendor labels, global policy/booleans and host firewall are
unchanged. This is not a production network namespace provisioning, routing,
policy/WAL installation or active catalog design. The original installed
service failure is not waived; new native execution is required.

### Descriptor-bound executable candidate staging (decision A)

The signed worker candidate contains an internal, root-only primitive for
placing the exact independently authenticated NGINX package bytes into a
retained owned directory. It never overwrites, executes, copies vendor
capabilities or changes a SELinux label. A pending leaf causes fail-closed
refusal, including a broken symlink. Repeated exact staging retains the
existing inode only when the caller provides its previously authenticated
owned device/inode; equal bytes alone never authorize adoption. Its input
digest must come from native package authentication;
the primitive does not authenticate a digest supplied by an operator.
The existing guarded AlmaLinux signed-derived fixture invokes it from the
authenticated worker ZIP after checking the installed native executable
against the exact signed RPM. Actual process/domain/namespace checks still
follow. No production placement or automatic repair is enabled; Debian
package payload binding, fixed installed location, durable receipt and
lifecycle integration remain NOT VERIFIED.

### Peer denial evidence

The previous enforcing VM reached the remote crossed-tuple negative but
logged an upstream connect timeout, not an immediate connection refusal.
A transport status alone is insufficient evidence of packet enforcement.
The peer negatives now require an increment of the exact namespace-local
named kernel deny counter for each request, unchanged peer origin counts,
and HTTP 502 or 504. The fresh root connect negative also requires a
counter increment. This changes neither the candidate allowlist nor its
default-deny policy, nor installed service acceptance criteria. Native
revalidation is required.

### Closed namespace rule readback candidate

A pure verifier compares the complete namespace ruleset with the
already authenticated candidate using the fixed stateless nft listing
and numeric priority (see nft(8)). It ignores whitespace and the known
fixed spelling of the numeric filter priority, TCP protocol and named
counter only. Additional tables, rules, verdicts, policy changes,
reordered tuples, UID or destination changes refuse. No rule, namespace
or host trust is inferred from this parser alone. The private native
fixture binds the namespace identity, checks the old complete ruleset,
syntax-checks a single atomic table replacement, rechecks the old
ruleset and verifies the new complete ruleset. Installed lifecycle and
WAL compensation still require their own authority and native evidence.

### Native executable payload and durable candidate receipt

The candidate now has bounded, non-extracting Debian data-tar inspection
for the exact regular root-owned NGINX member, and exact-version/architecture
SHA-256 comparison against separately authenticated APT metadata. These
pure checks cannot authenticate a supplied package by themselves. The
root-only placement primitive may bind a separate executable inode to
native package identity/payload digest and authenticated release source
and archive digests in one fixed mode-0600 receipt. Repeat requires that
same canonical receipt and exact inode/digest; any unknown copy, partial
receipt or changed identity is refused, never overwritten or adopted.
No service activation, package-manager command, relabel or policy change
is performed by the primitive. Native installer orchestration, exact
signed package verification and reboot/rollback remain separate gates.
