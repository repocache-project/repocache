# Native NGINX package preview and signed-metadata probe v1 (#27)

**Status:** unmerged, non-installing #27 development implementation.
The `server_native_package_plan_v1.py` preview is intentionally inert.
The separate `server_native_package_trust_v1.py` can explicitly query actual
native APT/DNF signed repository metadata and NGINX candidates but **cannot
authorize** an install or claim package payload authenticity. Neither module
delivers operational NGINX installation, service activation or server
provisioning.

## Fixed package intent

| Supported host | Native manager | Distribution-supplied package |
| --- | --- | --- |
| Debian 13 / Python 3.13 | APT | nginx |
| AlmaLinux 10 / Python 3.12 | DNF | nginx |

The preview_nginx_packages function revalidates the closed v1 install schema
and native OS/Python identity, then returns only the fixed package selection
and five **NOT VERIFIED** gates. The operator cannot submit package names,
shell commands, repositories, trusted keys or flags through
deployment.native_packages, which permits only policy=explicit-review. The
package list is a reviewed target, not proof that a package is available,
authentic, current or safe to install.

The report is deterministic, contains only static English remediation and
allowlisted package names, and always returns can_install=false,
all_verified=false and authorizes_installation=false. It never invokes
APT/DNF, refreshes metadata, contacts a network service, writes files,
checks package trust, claims NGINX ownership or asks for privilege. It is not
yet wired into the public deployment preflight command, which remains a
separate partial, permanently non-authorizing observation.

## Native signed-metadata probe (development-only; not an install gate)

`server_native_package_trust_v1.inspect_native_nginx_metadata()` is a
separately invoked, non-installing **native package-manager probe**. It is not
wired into #26's strictly no-network preflight or any privileged provisioning
entrypoint. It rejects unsupported OS/Python or unreviewed v1 policy before
external execution. It uses a newly created temporary directory per run and
the fixed distro package-manager binaries, a stripped environment, bounded
timeouts and static redacted diagnostics. Scratch contents are removed after
the attempt; external network access and temporary files **do occur**.

For Debian 13 the probe uses fixed official Debian trixie/trixie-updates and
trixie-security source endpoints, the OS-owned Debian archive keyring and
apt-secure signature validation through a fresh isolated `apt-get update`.
Insecure/unauthenticated/downgrade-to-insecure metadata and partial-update
success are explicitly refused. It then checks `apt-cache policy nginx`
against those same fresh lists, requiring an actual candidate.

For AlmaLinux 10 it selects the fixed official BaseOS/AppStream HTTPS
repositories, a preflight-checked root-owned AlmaLinux 10 key and **requires
both RPM package GPG checks and GPG-signed repository metadata**. The AlmaLinux 10 native manager is **DNF4** (not DNF5): the probe uses
`--noplugins`, `--disablerepo=*` with explicit fixed-repository re-enabling,
`gpgcheck=1` for RPM packages and `repo_gpgcheck=1` for metadata. DNF5-only
`--no-plugins` and `pkg_gpgcheck` are not accepted by the distribution's
DNF4. The DNF refresh occurs with a private installroot, repository
configuration, cache and log directory. The subsequent `repoquery --available` must find the
literal `nginx` package. Hosts whose official repository/mirror fails the
required metadata signature gate are **NOT VERIFIED**, even if DNF normally
accepts that repository with `repo_gpgcheck=0`; we do not silently lower the
requirement. GitHub-hosted synthetic fixtures cannot establish whether the
actual supported distribution repositories meet this policy.

An empty successful query, or APT explicitly reporting `Candidate: (none)`
for NGINX, yields `NATIVE_PACKAGE_NOT_AVAILABLE`. Check availability in the
authenticated distribution repositories. An invalid or ambiguous query
response yields `NATIVE_MANAGER_OUTPUT_INVALID`. In that case, inspect the
native manager diagnostics before treating the package as absent. Both
outcomes withhold installation authority and omit raw manager output.

The probe's PASS means only that **at the time of the read-only probe**
native authenticated metadata was refreshed and an NGINX candidate was
observed from its fixed allowed repositories. It is **not** proof of the
downloaded RPM/DEB payload signature, of package transaction dependencies
or final host readiness. It always returns `can_install=false`,
`payload_signature_verified=false` and `authorizes_installation=false`.
No package is downloaded for installation, installed or staged for activation;
no persistent host package-manager sources/cache are deliberately modified.

**Caveats:** a privileged execution helper must independently re-check
signatures, origins and actual package payloads immediately before the native
transaction. Distro mirror changes may require a reviewed configuration
update; this prototype intentionally refuses arbitrary operator sources.
The source scan prevents common unsafe signing-key ownership and symlink
patterns but does not substitute for complete root/LSM/namespace and
distribution package-trust acceptance.


## Conservative fresh-NGINX ownership gate (development-only)

The internal, non-installing
`server_native_nginx_ownership_v1.inspect_fresh_nginx_footprint()` gate
revalidates the supported OS, schema and `new-managed-only` policy before
reading fixed known NGINX paths. A fresh-install request must explicitly
declare `expected_state_generation: 0`. The gate refuses any existing
NGINX binary, configuration, conventional service unit, service override,
PID or cache/log namespace; even a dangling symlink counts as present.
An inaccessible path also fails closed. Fixed observations contain no
operator-provided path data, no reads of configuration or key contents, and
no subprocess or network operations. The probe does not adopt an existing
NGINX deployment merely because the files are root-owned or contain a
REPOCACHE-like name.

`prepare_fresh_native_nginx()` can subsequently perform the already
implemented signed native metadata check **only if** the initial footprint
inspection observed no known artifacts. It never invokes an installation
command. A positive footprint snapshot is reported **NOT VERIFIED** for
installation purposes: it does not prove that all processes, alternate
service names, listeners, package-manager ownership, protected manifests,
mount namespaces, inodes, SELinux contexts or concurrent changes are safe.
Even when the native metadata probe reports PASS, the combined report
always has `can_install=false`, `authorizes_package_transaction=false`
and `authorizes_nginx_activation=false`.

This is one conservative early rejection step, **not** a privileged installer
or the complete ownership acceptance criterion. Before any actual package
change, a separately approved root helper still needs locked protected-state
verification (#31), current process/port/systemd ownership checks (#26),
fresh APT/DNF metadata and RPM/DEB payload authentication, a reviewed
non-atomic native package transaction/recovery procedure and fresh-host
configuration ownership. Before service activation, staged complete-context
`nginx -t`, atomic managed include changes and tested recovery are mandatory
under #27/#28/#31. No pre-existing NGINX adoption is supported.

## Disposable native package payload rehearsal (unmerged)

`server_native_package_payload_v1.rehearse_native_nginx_downloads()`
extends the existing fresh-host refusal and signed metadata observation with
an **explicit download-only** rehearsal in a second private, disposable
workspace. It uses the same fixed official distro repositories, key material,
source isolation, timeouts and sanitized subprocess environment, and refreshes
signed metadata again immediately before the download-only action.
Debian 13 uses `apt-get --download-only --no-install-recommends install nginx`
with isolated APT lists, cache, archives and empty dpkg status; APT binds
downloaded .deb hashes to its signed Release/Packages index, and `dpkg-deb
--field` observes the package name without executing maintainer scripts.
AlmaLinux 10 uses DNF4 `install --downloadonly --downloaddir=...`, a
private installroot and signed BaseOS/AppStream. Downloaded RPMs undergo an
additional `rpmkeys --checksig` verification after import of the already
preflight-validated distro **public** key into a private temporary RPM
database. Digest-only OK is **not** sufficient. No host rpmdb or package
cache is intentionally changed.

The stage rejects missing/ambiguous nginx payloads, unexpected or linked
files, empty/truncated downloads, signature errors, resource limits and
native command failures. It reports a bounded package count only (not
repository URLs, payload names, bytes or raw native output), and deletes
all temporary packages afterward. Even a successful download-only
rehearsal leaves `can_install=false`,
`authorizes_package_installation=false`,
`host_package_transaction_performed=false` and
`authorizes_nginx_activation=false`. Debian .deb bytes rely on the
APT signed-index hash chain; they are not claimed to have individual RPM-like
OpenPGP signatures. These early-download observations **cannot** be reused
as trust or authorization for a later privileged transaction, which must
recheck trust, ownership and live state under the actual protected lock,
repeat/rebind packages, record non-atomic failures and test systemd/SELinux
and recovery. CI userspace success is not real host operational acceptance.

## Mandatory downstream execution boundary (not implemented)

Before a privileged native transaction (#27), implement and separately test
all of the following, failing closed with redacted actionable errors:

1. Check effective supported OS, system Python and existing/unmanaged NGINX
   conflicts on the actual host. Never take over a third-party NGINX service.
2. Review enabled distribution-approved APT/DNF sources, provenance of
   trusted signing keys, and effective native repository/package signature
   verification. Reject third-party substitutions, trusted=yes, unsigned
   sources, gpgcheck=0, repo_gpgcheck=0 where required by approved policy,
   disabled verification, unavailable or stale metadata and offline failures.
   Native APT/DNF is authoritative; do not build a second signature verifier.
3. Verify the exact selected nginx package's availability and trusted native
   source, reporting missing/untrusted packages without leaking repository
   credentials or unreviewed source URLs. Any planning-time results may be
   stale and are **not** install approval.
4. On a **separately authorized** privileged operation, repeat the relevant
   trust and availability checks; document irreversible native package effects
   and handle partial transactions (#31). Reject failed checks before any
   NGINX/REPOCACHE configuration, service, TLS or firewall activation.
5. Only after existing-NGINX ownership, staged complete-context nginx -t,
   rollback and controlled reload gates have been proved, perform separately
   approved service activation. Preserve the previous configuration on failure.

## Disposable distro metadata validation

The PR adds `scripts/smoke_server_native_package_metadata.py` and the focused
`.github/workflows/server-native-nginx-metadata.yml` matrix. The workflow
runs the **actual native** APT/DNF metadata verification in short-lived
Debian 13 and AlmaLinux 10 Docker images and requires both to observe a trusted
NGINX candidate. When missing, the smoke step exits nonzero with a bounded,
redacted failure classification; it never prints manager stdout/stderr. The
CI-only bootstrap may install OS Python and root CA certificates **inside the
disposable container**, not on the GitHub runner or any production host.
A green result proves only tested distribution userspace/network trust at that
CI revision; a red result is not waived by earlier mocked pytest success.
Actual booted host systemd/SELinux, privilege-bounded native package transactions,
transaction-time signature rechecks and failure recovery remain untested and mandatory.

The original #27 criteria remain NOT VERIFIED: booted Debian 13 and AlmaLinux
10 installed NGINX service acceptance, re-run idempotence, no third-party
adoption, failed config/reload recovery and systemd/SELinux behavior. Tests of
this pure preview cannot satisfy those operational criteria, nor #26's
missing-package diagnostic acceptance. Do not close #26, #27, #18 or #25 based
on this source-only increment.


## Fresh-host pre-package state boundary (non-authorizing)

The initial #27 implementation had a **real sequencing conflict**: the
conservative NGINX footprint scan refused
`/var/lib/repocache/server`, while the #31 protected state store requires
that root-owned directory (0700) and its preprovisioned mode-0600 lock before
reading state. The full locked-manifest reconciler also traverses
`/etc/nginx/conf.d`, which cannot exist on a genuinely fresh host without
NGINX provisioning. A synthetic mocked PASS did not prove the proposed
pre-package positive branch was reachable on a fresh native host.

The new internal `server_native_nginx_prepackage_state_v1.py` explicitly
separates that stage. It opens the current namespace's fixed `/` as root,
reuses #31's pinned exclusive state lock and validated journal/state readers,
and demands **no previously committed generation**, **no pending journal**,
**no orphan stage/rollback** and no observed state creation between two reads.
It does not access or require `/etc/nginx/conf.d` before NGINX exists. It
does not create the state directory/lock, write state, run subprocesses, make
network requests, download/install packages or invoke recovery. A missing
preprovisioned directory or unsafe lock is a redacted refusal, not permission
to create or adopt it.

`server_native_nginx_local_boundary_v1.inspect_native_nginx_local_boundary()`
keeps all **NGINX** footprint markers strict, but exempts exactly the code-owned
protected-state root from the old *NGINX conflict* classification, delegating
its ownership, ancestry, permissions, symlink/mount checks, lock and journal
verification to the same #31 storage primitives. An externally modified,
inaccessible, symlinked, mounted or foreign state is not adopted simply
because its path is known. The standalone network metadata and download-only
rehearsals retain their original conservative footprint refusal; this new
check is **not automatically invoked by #26** and does not change the
network-free server preflight.

An observed `LOCKED_PREPACKAGE_STATE_ABSENT` snapshot is only a read-only
result. The exclusive lock is released before returning and the result
cannot be used as a write token. A real privileged installer must separately
validate operator consent **and OS authorization**, a native host/root
namespace, process/listener/systemd/SELinux state, immutable package
selection, APT/DNF signatures and actual payloads under the held lock.
It must create a distinct durable non-atomic native package-transaction
journal before possible package-manager side effects, report/recover
partial transactions, and only then perform the full #31 live include
reconciliation, staged complete-context `nginx -t`, controlled reload and
rollback. UID 0 alone never proves trusted host-root authority. No root
helper, directory provisioner or native package transaction exists in this
increment.

Focused synthetic checks:
`python -m pytest -q tests/test_server_native_nginx_prepackage_state_v1.py tests/test_server_native_nginx_local_boundary_v1.py`.
The tests cover preprovisioned path acceptance strictly under a mock #31
reader, journal/recovery refusal, existing state, races, root errors and
lack of install authority. They are not live native booted-host evidence.
All five original #27 operational acceptance criteria remain NOT VERIFIED.

## CI userspace reachability of the pre-package locked snapshot

The existing `server-native-nginx-metadata.yml` matrix now runs a second
smoke check on **disposable** Debian 13 and AlmaLinux 10 images. Only after
successful non-installing signed-metadata and download-only rehearsal does
the test container preprovision the literal #31 state directory with mode
0700 and a new empty mode-0600 lock. It first confirms neither the managed
state root nor `/etc/nginx` is already present. The standalone
`scripts/smoke_server_native_nginx_prepackage_state.py` then performs actual
read-only state-lock observations with OS distribution Python and confirms
that a preprovisioned protected root is distinguishable from foreign NGINX,
while **all** install/reload/host-root authority remains false.

This is a user-namespace/container root fixture, not installation on a booted
native systemd or AlmaLinux SELinux-enforcing host. The write in the workflow
is confined to its short-lived Docker image and never to the GitHub runner's
filesystem or a deployed REPOCACHE host. No package transaction, real
service activation, privileged helper delegation, or native journal/recovery
has yet been validated by this test.

## Genuine native package install rehearsal, ephemeral containers only

The new `native-container-install` job runs **after** the existing signed
metadata, download-only and real #31 lock checks passed. It starts a brand-new
throwaway Debian 13 or AlmaLinux 10 Docker image with the repository bind mount
read-only. In this test container alone,
`scripts/smoke_server_native_nginx_container_install.py` requires a literal
CI-only opt-in, the Docker sentinel and root EUID before allowing *any*
native package-manager command. These are deliberate test misfire guards,
**not** a security boundary for running this script on a real server.

For Debian, it reuses the official HTTPS apt-secure sources and OS-owned
archive key in `_apt_commands` with current **container**
`/var/lib/dpkg/status`, authenticated fresh lists, no external sources,
unsigned fallback or package-manager input from the install document.
For AlmaLinux, it reuses the official signed BaseOS/AppStream DNF4 profile
with `gpgcheck=1`, `repo_gpgcheck=1`, TLS validation, disabled unreviewed
repositories/plugins and only removes the scratch-installroot override
because the *container itself* is the disposable install target.

The script executes a native `apt-get install nginx` or `dnf install nginx`
inside that disposable image, checks actual package-manager ownership/status,
then runs only `/usr/sbin/nginx -t -q` to validate the distro-default
configuration syntax. It never explicitly starts or reloads a service,
changes a real host, publishes catalog entries, installs REPOCACHE or
modifies production protected state. Distribution post-install scripts are
still package-manager code running **inside the isolated container**;
the evidence does not claim that such scripts never request service actions.
All native manager output is suppressed to redacted static error codes.
Unit tests cover the exact fixed commands, signed-source restrictions and
container/root/foreign-NGINX refusals.

A PASS on this job is meaningful **container package transaction and
distro-default NGINX syntax** evidence only. It is not the #27 native-host
acceptance test: Docker does not demonstrate systemd PID1, real SELinux
enforcement, host-native privilege authorization, production APT/DNF
transaction journalling/recovery, idempotent deploy/upgrade, managed
include ownership, full-context NGINX validation, safe reload or rollback.
No such test result is reused as evidence of these missing criteria.

## Fixture-only durable native package-effects pending marker

Native package-manager installation is **not atomic** with the existing
#31 state-v1.json transaction: a crash may leave RPM/DPKG package databases,
package scripts, systemd preset state or NGINX files only partially changed.
The new internal
`server_native_nginx_package_journal_v1._prepare_native_journal_under_root`
records this possibility **before** any such effect. It is an internal
caller-FD/owner-UID **test fixture primitive**, not a privileged host entry,
service activation path or operator approval. The caller-supplied root FD is
not authenticated and must never be exposed through the server CLI or a
generic root delegation endpoint.

The v1 marker is a canonical, bounded root/owner-only mode-0600 file at the
fixed #31 directory name `.native-nginx-v1.pending`. It declares only the
fixed `nginx` operation and the two supported distro/native manager pairs,
generation zero and
`native_package_effects=REQUIRES_EXPLICIT_RECONCILIATION`. It stores no
credentials, package-manager stdout/stderr or claimed approval. While holding
the **same #31 pinned exclusive state lock**, the internal writer refuses
existing state, pending #31 recovery, orphan stage/rollback, a pre-existing
native pending file or a dangling native temporary. It fsyncs an exclusively
created temporary journal inode and directory, atomically links the durable
pending inode without overwrite, fsyncs, unlinks the temporary name and
fsyncs again. No package manager is called, and the resulting report never
authorizes installation, service reload or deletion.

An interrupted write may leave only the temporary name or both hard links
and a partially published record; *every* such case must be treated as
**unreconciled native effects** and never automatically discarded. The
pre-package read-only check refuses either native marker even when the #31
normal state generation is still absent. Synthetic fault injection tests
exercise the three durable publication boundaries and repeated/concurrent
refusal with real Linux descriptor/inode/lock fixtures. This mechanism does
not yet expose an authorized host-root writer; it does not hold the lock
across an actual APT/DNF transaction, validate live package provenance, or
solve irreversible native package effects.

**Next integration prerequisite:** a separately operator-authorized fixed
native root helper must authenticate its own execution, OS/root namespace,
approved exact install document, already verified native signed package
bytes, current NGINX/service/port ownership and preflight; then hold the
correct lock through durable journal publication, package-manager execution,
post-state verification and a separately audited *non-automatic*
reconciliation path. This cannot be delegated to a previously returned
read-only snapshot or a synthetic root fixture. The #31 state writer and
live-manifest reconcile must also reject any unreconciled #27 package marker
before they acquire mutation authority; this is a dependency, not something
the current read-only #31 inspection has proved. No unreviewed implicit
rollback/purge of distro packages or service takeover is permitted.


## Bounded native distribution signing-key file identity (#27)

Before a native APT/DNF metadata probe, the fixed distribution keyring
leaf must be root-owned, regular, non-writable by unprivileged users,
**single-link**, non-empty and at most 1 MiB. Parent directories remain
fixed, root-owned, non-symlink and non-group/world-writable. A hard-linked
trust-anchor leaf or oversized key file is refused before *any* repository
metadata traffic, even if all paths look familiar. Existing supported
Debian 13 and AlmaLinux 10 native keyring files must satisfy this bound;
positive CI checks do not prove an installed host key was signed by its
own distribution or authorize an NGINX package transaction. Privileged
fresh package installation, rollback and booted-host acceptance remain
separate review and native tests.


### Download-only native package architecture compatibility (Stage A)

In addition to signed native metadata and RPM signatures, download-only
rehearsal checks every package's declared architecture against the observed
native machine architecture. DEB dependencies may use the matching native
architecture or `all`; RPM dependencies may use the native architecture
or `noarch`. Unknown machines and foreign headers fail closed as
`NATIVE_PAYLOAD_SET_UNSAFE`. The maintainer-approved v0.6.0 server host policy
is x86_64 only (#26, 2026-11-19). Native preparation refuses other machines
before repository access; the download stage accepts only amd64/all DEBs or
x86_64/noarch RPMs. This is not host installation authorization, a publisher
signature claim or booted-VM acceptance.

### Native negative metadata diagnostics (Stage A, #26 AC3 / #27)

The metadata smoke runs two controlled faults through the existing production
metadata diagnostic function in each disposable distro image. Native commands
execute and retain signature/TLS enforcement. No package is installed by these
cases, and the no-network/no-write #26 preflight remains unchanged.

- After authenticated metadata refresh, native APT/DNF queries a fixed absent
  test package name. The actual empty candidate response must produce
  `NATIVE_PACKAGE_NOT_AVAILABLE` with English guidance and no install authority.
  This tests the missing-candidate diagnostic, not a claim that official NGINX
  is currently unavailable.
- In a separate fresh scratch workspace, the generated source references an
  invalid test public key instead of the distribution key. The OS key itself
  is untouched. APT/DNF must refuse metadata authentication before any candidate
  query and return the redacted `NATIVE_MANAGER_FAILED` diagnostic. A network,
  TLS or option error cannot qualify as signature-refusal evidence.

The workflow requires both successful negative-case markers before the later
container-install job. Unit tests reject accidental candidate success, native
success with a bad key, a different failure cause and unexpected source files.
These are scratch-only fault injections with real package-manager responses,
not deployed-host trust, native-effects
reconciliation, booted systemd/SELinux or full #26/#27 issue acceptance.



### Fail-closed live-service pre-WAL gate (#27)

A successful authenticated native APT/DNF installation intentionally leaves
the vendor `nginx.service` **disabled and inactive**. It does not authorize
service activation, opening listeners, firewall changes or NGINX takeover.
A separate deliberate, reviewed systemd activation remains necessary before
an administrator can apply an active managed repository generation.

The live fixed-root `APPLY_V2` path now observes the effective running
vendor NGINX unit **before publishing its durable v2 WAL or modifying** the
managed include, state, manifest or discovery catalog. It requires the exact
vendor unit identity, a real nonzero main PID, kernel-observed NGINX executable
identity and a bounded vendor unit digest. Inactive, unreadable, foreign or
ambiguous unit observations fail closed with the fixed redacted
`NATIVE_V2_NGINX_NOT_ACTIVE_BEFORE_WAL` diagnostic. The later native reload still
rechecks the effective unit, and a concurrent service failure after the
pre-WAL observation remains subject to normal WAL-held compensation and
explicit recovery.

This guard does **not** start, unmask or enable services and does not turn
read-only observations into privileged authority. Disposable root-FD tests
prove absence of persistent changes on the early refusal. They are not
evidence of booted Debian 13 / AlmaLinux 10 systemd/SELinux acceptance or
full #27 first-operational-service completion; those retain separate native
and release acceptance requirements.

### Dedicated REPOCACHE-owned native NGINX service (issue #27)

The approved new-managed-only contract has a narrower safe implementation than
modifying or shadowing the distributor's existing `nginx.service`. In this
implementation, the vendor service and its `/etc/nginx/nginx.conf` remain
unmodified, disabled and inactive. A **different** fixed service,
`repocache-nginx.service`, runs the authenticated distro `/usr/sbin/nginx`
binary with `-c /etc/nginx/repocache.conf`. REPOCACHE neither creates a
drop-in for `nginx.service` nor bypasses package file-integrity verification.

The isolated unit and its deterministic bootstrap configuration are members of
the same authenticated release archive as the fixed root-control worker. The
existing installation verifies signed source/manifest and installs the
root-owned `repocache-nginx.service` unit through the same exclusive
placement lock and collision/alias refusal as the other REPOCACHE units.
The bootstrap config is independently checked against exact reviewed bytes
from that archive and securely placed at the **new**, initially absent
`/etc/nginx/repocache.conf` leaf only during separately requested activation,
not during the APT/DNF package transaction. A foreign file, link, unexpected
existing content (including a byte-identical file), untrusted ancestry or
changed signed source is refused. The installation records a durable,
root-owned, config-digest-bound first-use ownership-intent marker under the
existing protected state lock before creating the private config; interruption
can retry only the exact signed bytes. Any unrecognized competing marker is
refused, never implicitly migrated or adopted.
The stock package-owned `/etc/nginx/nginx.conf` stays byte-for-byte intact.

The only bootstrap NGINX listener is the signed, closed fixed configuration:
IPv4 loopback `127.0.0.1:8008` with a constant private test endpoint returning
204 and all other routes returning 404. There is **no public HTTP/HTTPS
listener**, no repository catalog, no managed TLS, no managed include, and no
open firewall rule. The installer independently checks `nginx -t -q -c
/etc/nginx/repocache.conf` and rechecks the signed config bytes before start.
Full managed HTTPS routing remains a separate atomic, reviewable deployment
stage; this private bootstrap is not production service completion.

An explicitly invoked signed-worker `--activate-native-nginx` action shares
the protected package/state lock and checks (a) durable completed native package
receipt, vendor unit and native APT/DNF file integrity, (b) vendor nginx.service
disabled/inactive, (c) installed signed REPOCACHE worker and exact service-unit
bytes, (d) no conflicting WAL or managed state, (e) exact effective PID1
`repocache-nginx.service` identity with no overrides, (f) root-owned
fixed private configuration and successful native syntax validation. Only then
does it perform fixed daemon-reload/start/enable operations *on the owned unit*.
Positive operation rechecks systemd properties, real NGINX master executable
inode, listener bootstrap bytes and vendor package provenance. On failure it
attempts a stop **only of the verified REPOCACHE-owned master**, disables its
unit, then verifies the inactive/disabled state. Ambiguous compensation refuses
with a redacted RECOVERY_REQUIRED diagnostic. A repeated healthy invocation
remains a no-op.

The new `Server native NGINX activation in booted VMs` workflow reuses the
test-only signed source, real distro-native package installation and QEMU
Debian 13 / AlmaLinux 10 with enforcing SELinux. It asserts refusal of a foreign
config symlink, injected enable failure and safe service rollback, activation of
the independently owned unit, live loopback HTTP 204, disabled vendor service,
unchanged package/vendor config hashes, idempotence and a genuine kernel reboot.
Never substitute these signatures for the maintainer's later Stage-C
publisher-signed candidate acceptance.

**Deferred separately:** current `APPLY_V2`/`RELOAD_V2` still operate with
their original strict fixed vendor-unit verification. They must **not** be
redirected to the new service without a separate atomic and recoverable managed
configuration/TLS upgrade, verified process/config/unit identity and explicit
security tests. Original issue #27 complete initial deployment and dependent
#28/#30/#31 end-to-end acceptance remain NOT VERIFIED until that integration.


### Shared owned-service identity and legacy transaction isolation (#27)

The bootstrap installer and the upcoming managed transaction share
`inspect_effective_owned_nginx_unit`, a fixed read-only observation of
`repocache-nginx.service` (PID1, exact effective unit properties, no aliases or
drop-ins, stable master PID and kernel executable identity). Its report grants
no systemctl, reload or installation authority. Signed installed unit/config
bytes, native package receipt, protected ownership and filesystem observations
remain separate mandatory gates.

The existing vendor-based V2 path is deliberately not redirected. Under the
same exclusive state lock, any entry in the bootstrap configuration ownership
marker namespace blocks legacy APPLY_V2, RELOAD_V2 and RECOVER_V2 before their
filesystem or service effects. Malformed and dangling marker entries also
refuse; no marker or WAL is deleted. An ambiguous existing WAL must never be
recovered against an assumed vendor unit. This guard does not change the
legacy no-claim transaction or its existing fixture-only tests.

The next increment must implement a WAL-bound transition to an explicitly
owned route include outside the vendor's automatically loaded conf.d domain,
with complete candidate syntax/dump verification, private unit identity,
appropriate writable cache directories under the systemd sandbox, and exact
bootstrap/managed rollback. Existing fixed deployment-path contracts must
be reconciled without permitting caller-selected paths. This increment
does not activate managed routes, change TLS or close #27.

### Dedicated complete-context candidate (#27)

The new pure owned-service candidate uses the fixed
`/etc/nginx/repocache-managed.conf` include, **outside** the vendor's automatic
`conf.d` include domain. It refuses the legacy generated-include path and all
other paths rather than silently remapping a reviewed deployment document.
The deterministic new main context is a separate candidate; it does not
modify the signed bootstrap archive member or its digest-bound ownership
marker. A managed context replaces the private test listener with the exact
TLS/route-generation include and derives the active-only catalog through the
existing renderer. A failed first transition must restore the exact signed
loopback bootstrap, not leave an empty HTTPS config.

The complete-context comparison accepts only the exact fixed main file and
the exact expected dedicated include in their native `nginx -T` sections
(or just the signed bootstrap section before first apply/after rollback).
Foreign/default sections, duplicate includes, changed bytes and omitted
sections fail closed. It is a pure comparison, not an authenticated
native command result or authorization. The existing real-parser regression
now runs `nginx -T` against the complete dedicated context with disposable
test paths as well as the prior vendor-style syntax fixture.

The installer and candidate use one shared immutable bootstrap byte string;
the signed archive inventory, actual bootstrap file and ownership marker
digest are unchanged. **Not yet wired to host APPLY/RELOAD/RECOVER:** native
fixed private syntax/dump execution under an audited ownership lease, WAL
version/domain separation and atomic main/include/state/catalog rollback,
sandbox/cache and SELinux provisioning, actual HTTPS generation and
publication remain mandatory. No production exposure is enabled.

### Fixed private native syntax/dump prerequisite

The dedicated context now has a bounded private native probe using only
`/usr/sbin/nginx -T -c /etc/nginx/repocache.conf`; `-T` includes syntax
validation. It never selects the vendor configuration or accepts a path,
executable, environment or command from a socket peer. Before and after the
command, the fixed binary, main file, expected include (or its absence) and
parent identities are rechecked. A transaction-side prerequisite verifies
the current root namespace, pinned configuration directory, exact expected
bytes and the unique existing bootstrap ownership marker before the
command, then compares every native dump section and rechecks those facts
afterward. The raw dump remains internal; no command output is published.
The original vendor probe retains its prior behavior.

This code remains an internal prerequisite, not a live managed apply path:
the caller must retain the protected lock and supply only renderer- or
WAL-verified bytes, and independently verify signed unit/package provenance,
runtime identity and the remaining host prerequisites. The new tests mock
native execution for drift/refusal cases, in addition to the disposable
real-parser test above. No activation, reload, catalog publication or
privileged operation is exposed by this increment.

### Dedicated versioned WAL domain (fixture prerequisite)

The private NGINX transaction requires a separate five-resource WAL
(domain `repocache-nginx.service`, schema version 2): state-v2, exact main
configuration, dedicated route include, public catalog and a distinct
ownership manifest. The manifest pins the main configuration as well as the
other resources. A first-generation WAL preserves the immutable signed
loopback bootstrap bytes, not an absent/default vendor configuration.
A managed previous generation must match the dedicated manifest, fixed
layout and active-only catalog semantics. Candidate generation must pass the
existing state-transition rules. Unknown domains, wrong versions, changed
hashes, ambiguous or foreign resource states fail closed.

The protected private fixture-only publisher exercises exclusive temp
creation, fsync, exact pre-publication drift checks, atomic WAL rename and
directory fsync. It refuses the actual root namespace and never changes any
target resource, starts or reloads NGINX, or publishes a catalog. An
unpublished journal may describe only unchanged previous bytes; after
publication each resource may be exactly old or candidate, never foreign.
Existing legacy v1/v2 state-only and vendor transaction entry points refuse
the new journal/manifest namespace (including dangling artifacts).

This is not the authenticated live transaction. Wiring the protected lock
through the actual five-resource writes, distinct stage names, runtime
reload, verified TLS/catalog exposure and first/managed rollback is still
required. No recovery-complete or native activation result is claimed.
