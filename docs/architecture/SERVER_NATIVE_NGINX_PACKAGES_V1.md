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

The fixture publisher also exercises a previously committed, exactly
manifest-bound generation. The dedicated prepublication gate may recognize
its own manifest, but still refuses state-only, shadow, legacy vendor and
dedicated pending journals. A rename-fault regression verifies that a
durable unpublished temporary journal leaves the bootstrap and all other
resources unchanged, and is refused on a fresh apply rather than discarded
or adopted by another domain.

### Five-resource filesystem transaction and crash compensation (fixture only)

The dedicated fixture engine now writes all five resources under the retained
protected lock with separate fixed stage names. The durable WAL precedes
any target change. The route include precedes its referencing main config;
the catalog and manifest are last. Exact old/new byte identities are checked
throughout, pinned leaf directories retain structural identity, and the
vendor include directory and bootstrap claim remain unchanged. Recovery
validates the entire resource set and all stage metadata before cleanup.
It restores the previous main before removing the first managed include,
then verifies the complete prior byte set before removing the WAL. A valid
unpublished WAL may be discarded only with unchanged resources and no
staging artifacts; malformed unpublished records remain for inspection.

Executed tests are required for first/repeat commit, interruption after
each resource, recovery of partial/complete stages, foreign resource/stage
refusal, and ordinary write failure under the retained lock. These helpers
refuse the real root namespace and never invoke NGINX, systemd or network
commands. The result is filesystem-only fixture evidence: the live
transaction must still bind authenticated reload, TLS generation and
catalog exposure, cache permissions and SELinux to WAL completion.

Every target mutation now rechecks the exact published WAL and absence of a
competing temporary WAL. Apply additionally checks the entire expected
intermediate resource set, not only the resource about to be written.
Compensation requires the original WAL and byte-exact old resources;
an unlink/fsync uncertainty or changed WAL cannot be reported as a
successful rollback. A real child-process SIGKILL regression at the catalog
boundary, followed by interrupted recovery and retry, exercises lock release
and both first-generation and previously managed recovery in fixtures.


The retained layout check also revalidates competing transaction domains
before every target effect, including compensation. A changed unpublished
WAL is refused before rename; no target may change on this path. Regression
tests cover competing state-stage drift after the first resource write,
unpublished WAL drift, and empty private stages left at exclusive creation.


### Dedicated live-WAL assembly (development branch; not dispatched)

The private live transaction adds a version-3 record in the existing owned
service domain. It binds the previous five-resource snapshot and candidate
hashes, and explicitly allows a temporarily absent catalog only after
durable WAL publication. Version-2 filesystem fixture journals keep their
original old/new-only rules; fixture recovery refuses version-3 records.

Under the retained protected state lock, prepare the fixed root-owned intake
using generation/digest CAS and deterministic rendering. Validate the
trusted certificate/key pair before any durable effect. Withdraw the old
catalog before modifying routes, write the include before the main config,
validate the exact dedicated context, and request only the fixed
`repocache-nginx.service` reload. Recheck the signed unit identity, exact
context, certificate leaf and live generation before publishing the
active-only catalog; prove its exact live bytes, then persist the manifest
and clear the WAL. A failed apply restores the old context, checks the old
generation (including private bootstrap HTTP 204 on first-install rollback),
and only then restores and verifies the previous catalog. Uncertain
compensation retains the WAL. If the old catalog cannot be verified after
publication, withdraw it again only while the exact WAL/resources remain
owned. An unpublished live record is discarded only after proving the
unchanged previous resources and runtime; a missing record is not proof of
compensation. Explicit same-generation reload/no-change does not write
resources or clear pending records.

These are private assembly functions, not an exposed socket operation.
Before enabling dispatch, prove the authenticated installed caller, retained
actual-root layout and package receipt, deterministic candidate recheck at
the WAL boundary, kernel listener ownership, storage confinement and
SELinux labels; handle inactive-service recovery, installer repair and
booted fault/reboot tests. No host activation, publisher signature,
complete #27/#64 acceptance or production support is claimed by this
source increment.

The private generation/catalog probe additionally requires the single exact
configured TCP listener inode to be held by the signed unit's observed
NGINX master, in the same kernel network namespace. Re-observe process,
unit and listener identity before and after exposure, refuse competing
listeners on that port in either family, and do not accept a matching TLS
certificate alone as service identity. The existing signed-test activation
guest exercises the real bootstrap listener and refusal of a disposable
foreign listener, including after reboot. Managed TLS listener acceptance
and access from the confined installed socket worker remain native gates.


### Confined dedicated broker: nonmutating operations and outstanding write boundary (historical; superseded below)

The existing socket protocol and kernel peer credential checks remain unchanged.
The authenticated installer persists its canonical local placement receipt, with
the original digest-bound completion marker, before completing fresh placement.
An exact re-authenticated repeat can fill an absent receipt without adopting a
foreign file. For the dedicated domain, the broker rechecks that receipt,
fixed worker/unit hashes, root ownership, modes, ACL/xattrs, the loaded
systemd unit identities and its own MainPID under the original state lock.
This is installation-local provenance, not an independent publisher signature.
Any entry in the reserved dedicated claim namespace selects only the dedicated
domain; malformed claims never fall back to the distributor's NGINX.

The socket may observe clean state, verify an exact already-committed intake
(no change), or validate/reload the exact committed generation with disabled
repositories, subject to current host/package/receipt/mount/TLS checks. It
requires the existing shared /etc/nginx parent and owned configuration files
to remain read-only in the broker's mount namespace. It grants no new
write authority there. A new candidate or pending WAL is refused before
mutation; clean observation and replay cannot invoke the mutating engine.
Active routes remain gated on installed storage and actual service access.
The optional dedicated runtime-directory write exception is limited to the
existing fixed /run/repocache-nginx leaf for native syntax inspection.

The current fixed managed files are siblings of distributor files directly
under /etc/nginx. Atomic replacement requires write access to their parent;
a read-write bind of individual files does not permit atomic replacement
of their directory entries. Broadening the socket's write exception to
/etc/nginx would therefore weaken the isolation boundary. A dedicated
root-owned config directory (for example /etc/nginx/repocache.d), with only
that exact directory writable, is the proposed resolution. Its path contract
and signed-unit/bootstrap migration need an explicit maintainer decision
before adoption. No path contract, legacy fallback, or permission waiver is
adopted by this increment. Complete mutating socket APPLY/RECOVER and
managed installer repair remain blocked until this boundary is resolved.
The booted activation guest tests the restricted socket operations and
refusals through the installed broker, in addition to the separate root-only
live WAL fault/reboot rehearsal. New test results are not inferred from
earlier green runs.


### Approved isolated configuration directory and fixed live socket dispatch

The maintainer authorized the dedicated configuration path change on
2026-11-24. The signed dedicated unit and native syntax probe now use
/etc/nginx/repocache.d/repocache.conf and the managed renderer requires
/etc/nginx/repocache.d/repocache-managed.conf as the reviewed generated_include.
The parent is root-owned mode 0755; only the dedicated leaf is added to the
socket worker's existing writable path set. The shared /etc/nginx parent
must remain read-only in the actual worker mount namespace. The existing
legacy conf.d exception remains for the independently supported vendor-mode
transaction, not a fallback for a dedicated claim. The actual dedicated
NGINX service itself does not receive config-write permission.

A path-bound bootstrap claim uses SHA-256 over the fixed new directory
(with a NUL separator) and the signed bootstrap bytes. First activation
writes durable intent before directory creation, refuses a pre-existing
unclaimed directory (including symlinks and matching content), and refuses
old sibling config files, partial stages and old claim markers. Existing
installations using the old experimental path are explicitly rejected;
there is no silent adoption, relocation, deletion or downgrade. A migration
of an installed old-path managed generation would require separate verified
preservation of the old signed unit, WAL, configuration and TLS/catalog.
Do not manually relocate files to bypass the refusal.

The dedicated dispatch uses the existing kernel-authorized fixed operations
and retained state lock. APPLY validates the fixed private intake and CAS,
checks the inactive-repository prerequisite against both the exact candidate
and predecessor, and performs the version-3 WAL transaction. RECOVER checks
the WAL's closed prior snapshot (not a partially written current snapshot)
before actual compensation. RELOAD validates and reloads the exact committed
generation. Existing stable reply codes are retained. No fallback or arbitrary
filesystem/command arguments are accepted. The host boundary checks matching
PID1 path identity, shared parent read-only and dedicated leaf writable,
receipt and package provenance, metadata and enforcing SELinux (including
the stock httpd_config_t type on the dedicated configuration leaf/files).
The VM harness uses the actual installed socket for initial apply and
post-reboot rollback, and keeps the separate root-only fault injection for
the interrupted generation.

Active repositories remain refused until #450 storage and runtime access
are verified in a combined candidate. Installer repeat of an existing
managed generation and recovery from an inactive dedicated service remain
separate gates. No production deployment, genuine publisher signature, or
exact-new-HEAD native PASS is claimed until those results exist.

The maintainer reconfirmed the isolated path contract on 2026-11-25
in the trusted project conversation (recorded in #451). The combined
#450/#451 booted activation rehearsal asserts storage reports for initial
and repeated activation, refuses a deliberately unsafe ownership-marker
mode in the disposable guest without changing the running master or
storage root, restores only the fixture marker mode, and checks native
storage and service mount identity again after actual reboot and WAL
recovery. These are ownership/mount/continuity checks, not actual cache
worker write or active-route acceptance. No live active-route guard is
removed by this increment. Exact new-HEAD execution is required.

The confined dedicated broker now checks the exact fixed cache/log roots
and markers against PID1's mount view, reuses the existing installer
storage verifier with creation disabled in that original view, and binds
the two leaves to the authenticated active NGINX master's writable leaf
mounts and read-only parent mounts before any fixed operation. No new
writable paths, protocol or general namespace access are granted. Storage
marker drift refuses APPLY/RELOAD/RECOVER before effects; the booted VM
checks exact managed resource hashes and prior TLS generation continuity.
Active-route activation remains disabled until actual cache/log worker
access is demonstrated. Exact new-HEAD native execution is required.

Authenticated activation repeat now recognizes a clean already-active
managed generation with disabled repository routes. It reuses the closed
owned layout, native syntax/TLS, kernel listener, exact public catalog,
package and fixed storage verification under the existing lock. The
installer supplies only the exact unit bytes independently authenticated
and audited from the release; socket dispatch still uses its embedded unit.
No bootstrap replacement, reload, daemon restart, storage creation or
pending journal adoption occurs on this path. Booted tests reauthenticate
and repeat before and after WAL recovery/reboot and refuse unsafe include
permissions without altering prior service or resource bytes. Inactive
managed repair and active repository operation remain separate gates.

### Authenticated repair of an enabled but inactive managed service

The existing explicit signed installer activation path may now restart an
already enabled, exactly authenticated and inactive dedicated service with
a clean committed disabled-repository generation. It verifies the inactive
effective unit and exact signed unit inode, retained layout and closed
resource snapshot, native package and storage, syntax and TLS identity
before starting only the dedicated unit. It cleans only the inert native
syntax PID file while the unit remains verified inactive. After startup it
requires the exact kernel listener, TLS generation, catalog, storage mounts
and the existing active-repeat verification. The same generation and
enablement must be preserved; no resource or storage creation occurs.
A failed post-start check compensates by stopping only the exact
authenticated service if the original resource and unit identities remain
intact, and verifies the original inactive/enabled state. Unknown process,
unit or resource drift reports recovery required instead of stopping an
unverified master. Disabled service, active repositories, pending WAL and
foreign/legacy cases remain refused. Booted VM tests inject a post-start
fault, require real stop compensation, then reauthenticate and restart the
unchanged generation after actual reboot. New exact-HEAD evidence is
required; this is not active-repository or publisher acceptance.


### Candidate egress bound to the owned generation (decision A)

The maintainer approved the installable candidate architecture on
2026-11-26, exclusively for isolated implementation, review and validation
(#451 comment 7191836320). No production activation or global SELinux,
routing or firewall modification is authorized.

The signed worker now reconstructs the exact origin IP/port tuples from
the same validated repository configuration and canonical numeric upstream
fragment already bound by the owned manifest and WAL. It re-renders each
selected base origin's pins through the existing strict renderer; disabled,
extra, missing, noncanonical or unsafe tuples and port drift refuse the
snapshot. Alternate allowed DNS hosts never create extra connect permission.
No secondary allowlist, DNS re-resolution on rollback, or new WAL schema is
needed to derive this candidate. The exact include hash remains the durable
binding; the candidate reports its upstream fragment hash and generation.

The pure namespace-only nft candidate has a fixed table, default-deny
output, established TCP replies, root-only local listener health and fresh
worker connections to exact pairs. No independent address/port sets or
unrestricted root/DNS egress. It does not invoke nft, install a module,
create a namespace, configure ingress/routing or authorize exposure.
An authenticated signed-test worker supplies the candidate rules to the
existing isolated peer-namespace probe, substituting only the two known
private peer addresses consistently in renderer and rules after normal
validation. The probe exercises actual HTTPS MISS/HIT, denial of crossed
tuples/root fresh connections and generation withdrawal after worker drain.

This increment is not an installed-policy controller. Existing live active
route refusal is preserved. Remaining work: authenticated native executable
and dedicated SELinux type placement, verified private network namespace
and administrator-selected ingress/routing, native rule identity/readback
and foreign-process refusal, durable application/compensation of rules
at WAL boundaries, reboot/repair and exact installed-service cache/log
and catalog evidence on both supported distributions. Never apply the
candidate rules to the host namespace or promote the disposable test policy.


The authenticated fixed executable placement uses the existing retained
native-package-effects state lock contract while creating and removing
private APT and isolated RPM workspaces under /var/lib. The shared /var
and /var/lib parents may undergo normal metadata churn, but must retain
their pinned device, inode, type, mode and ownership; the private
/var/lib/repocache ancestor remains strictly unchanged, and the state
directory and lock retain their existing identity checks. Ordinary state
transactions continue to use the strict default lock. No new trust
anchor, service activation, policy or network permission is granted.
The existing booted candidate placement/reboot test and detached-root
lock regressions must pass on the corrected revision.


### Closed signed namespace-unit candidate

The authenticated worker derives an inert unit candidate from its embedded
signed dedicated unit. A closed contract rejects changed commands,
permissions, unknown options, duplicate directives and unexpected sections.
All four NGINX operations use the fixed staged executable path; the
candidate binds the fixed service namespace, IPv4/IPv6/Unix address families
and the previously exercised root-master capability subset. A privileged
listener port additionally proposes CAP_NET_BIND_SERVICE; native permission
and SELinux policy for that case remain unverified. Existing fixed writable
paths, no-new-privileges, service identity and systemd lifecycle are preserved.
The trusted future caller must bind the port to the authenticated generation.
The installed signed unit is not replaced or activated by this renderer.

The existing guarded booted fixture now derives its root-master test unit
from the same candidate renderer, substituting only the private fixture
paths and namespace. Both target guests also derive the candidate directly
from the authenticated installed worker, compare the signed unit identity
and require the same candidate digest after reboot. This is not a deployed
domain, policy/namespace provisioner, WAL transition or actual installed
cache acceptance. Existing active-route refusal and stock service checks
remain in force. Exact-head native tests and the installed AlmaLinux data
plane still require acceptance; do not suppress its upstream failure.


### Fixed kernel namespace readback

The signed worker has a separate read-only native observer for the fixed
`/run/netns/repocache-nginx` service namespace. It requires standalone
native root preconditions, descriptor-walked root-owned non-writable
parents, and a regular namespace handle. Linux nsfs ioctls verify the
network namespace type and owning initial user namespace, rejecting the
PID1 and caller network namespaces. A fixed native nsenter invocation
inherits the retained descriptor and enters only that network namespace
in a child to list the complete nft ruleset. The child has fixed arguments,
environment, output bound and timeout; no shell, mutation or path input.
Both readings must match the closed authenticated candidate, and parent,
namespace and fixed executable identities must remain unchanged.

The guarded AlmaLinux VM now uses the exact fixed namespace name and
the installed authenticated worker observer for prior/replacement rules,
including host and wrong-type handle refusal. Unit tests cover descriptor
replacement, policy and program drift, owner/type/host rejection, malformed
candidate and bounded listing. This does not establish exclusive ownership,
ingress, service identity, installed dedicated domain or a durable
generation-bound kernel transaction. The caller must retain the ownership
and WAL lock; the observer cannot authorize activation or a firewall change.
No global host rule, vendor service, SELinux boolean or label is modified
by the observer. The actual installed AlmaLinux upstream gate remains
mandatory and is not waived by a successful isolated test.



### Authenticated dedicated-domain policy and executable label

The reviewed SELinux policy candidate is now a closed v0.6 source asset
and a fixed member of the deterministic authenticated root worker.
It uses stable REPOCACHE-specific types, with the same policy permissions
as the existing private enforcing fixture. The reader requires the fixed
installed zip; it is not a general policy parser or policy installer.
No stock HTTP domain permission, global boolean or vendor file label
is modified.

The optional internal AlmaLinux staging mode derives the policy digest
from the authenticated archive, requires enforcing mode and a separately
verified loaded policy, and labels only the exclusively created pending
executable inode before publication. The fixed context and signed policy
digest are bound into the existing executable receipt together with the
native package and signed release identities. Repeat staging verifies the
same inode, bytes, metadata and label; it never relabels an existing
leaf or adopts an unlabelled receipt. Incomplete placement or label
failure is preserved and refused. Debian retains the existing unlabeled
placement. Receipt and policy source consistency are not kernel policy
attestation or authorization to activate.

The guarded AlmaLinux VM compiles the actual authenticated policy bytes
and loads only the dedicated module. The previous signed-derived
root-master peer test now uses the fixed authenticated installed
executable and its stable domain, rather than a copied fixture binary.
Private configuration/storage and a never-enabled runtime-only unit
remain isolated; the existing signed service and stock policy are
unchanged. The fixed namespace egress, positive/negative TLS routes,
worker drain, reload, capability and domain continuity, and cleanup
assertions are retained. The staged executable and dedicated module
remain in this disposable guest for reboot verification. Actual installed
service transition, owned path contexts, durable WAL-bound egress,
ingress and installed data plane remain separate mandatory acceptance
gates. The existing actual upstream test is not suppressed.


### Descriptor-bound policy replacement

The fixed namespace reader and new internal replacement operation share a
retained nsfs descriptor, parent identity and fixed native program checks.
Replacement requires a caller-retained ownership witness and exact namespace
identity, full prior ruleset readback, nft validation, a repeated prior
readback, one atomic delete-and-create batch for the dedicated table and
repeated complete proposed readback. The batch is reconstructed from the
closed grammar; no arbitrary command text, flush, shell or host namespace
operation is accepted. Exact repeats do not write. Unknown policy, identity
or ownership drift is refused without an automatic retry or guess.

The WAL-bound internal operation reconstructs both policies from the
existing durable v3 journal and exact current resource bytes under the
caller's lock; it requires withdrawn catalog, complete proposed bytes and
rechecks layout, WAL, resources and namespace ownership at the mutation
boundary. Compensation only replaces exact proposed policy with prior
policy before losing the proposed bytes. Partial or foreign evidence is
refused. No live dispatch, catalog publication, namespace provisioning or
installed service transition is enabled by this increment.

The guarded native fixed-executable fixture now exercises the authenticated
worker's retained-fd replacement in its privately created namespace,
rather than issuing the replacement through ip netns exec. It verifies
foreign namespace identity refusal, idempotence, prior/replacement complete
readback, unchanged host rules and real packet behavior. The fixture uses
its existing isolated addresses and does not certify production namespace
exclusivity or WAL-driven native activation. A concurrent privileged
netlink administrator remains outside the lease model; the service and
namespace ownership lifecycle and complete WAL recovery ordering are
separate mandatory gates. Root-container synthetic label tests are now
explicitly executed in the existing root-control protocol workflow.


### Fresh dedicated storage and actual service candidate

The dedicated storage profile separates a root-owned traversal-only cache
parent (0711) from worker-owned per-repository private directories (0700).
The confined master can initialize the existing fixed cache paths without
DAC_OVERRIDE or DAC_READ_SEARCH. The log root and metrics file remain
root-owned. On enforcing AlmaLinux, only fresh owned leaves receive the
fixed dedicated rw context; native vendor parents retain their original
labels and are traversed using search-only permissions. The original
profile remains unchanged and a dedicated preparation refuses a legacy
root or marker rather than reinterpreting it.

The authenticated unit renderer also derives a closed runtime drop-in
for the existing service name: reset all four Exec directives before
selecting the authenticated executable, explicitly use stderr for startup,
and preserve the original sandbox while adding the fixed network namespace
and minimal capabilities. Neither renderer grants installation authority.

The guarded Alma VM campaign now tests the actual owned systemd service,
fixed configuration, TLS material and fresh marked cache/log roots under
the dedicated domain, rather than expecting the legacy httpd_t service
to acquire unsupported upstream access. It preserves the verified empty
legacy fixture roots and markers by same-parent no-replace renames,
temporarily assigns the dedicated ro/PID contexts only to its own fixture
resources, derives the drop-in and exact egress from the signed worker,
and starts the service in a loopback-only namespace. A private TLS origin
exercises real MISS/HIT, metrics and repeat storage verification. The
test must stop the candidate, preserve its evidence, restore the exact
previous resource bytes, labels, storage and legacy service, and confirm
host rules/vendor/signature identity unchanged. This is not a production
migration or a durable label/unit/namespace WAL. The known legacy
httpd_t upstream failure remains unsupported, and final durable installed
activation, active publication and reboot acceptance remain open.


### Exact persistent service-profile observation

The installed authenticated worker can now separately observe the proposed
dedicated profile's exact signed base unit and single fixed persistent drop-in
under /etc/systemd/system/repocache-nginx.service.d/90-repocache-dedicated.conf.
Read the closed rendered bytes through retained descriptors, reject additional
leaves, unsafe metadata, symlinks and hardlinks, recheck both files around
two fixed PID1 observations and verify the active master uses the dedicated
executable inode. The legacy observer continues to reject every drop-in.
The observation has no service or file-write authority; callers must prove
the executable receipt, namespace/egress, SELinux contexts, ownership lock
and WAL generation separately. The port must come from that trusted generation.

The guarded Alma VM uses the fixed persistent location only for its existing
temporary transition and verifies inactive, active and repeat observation
from the authenticated worker before restoring the legacy fixture. This is
not a durable transition, boot-time namespace lifecycle, or active-route
dispatch; the broker remains unchanged and no policy or vendor grant expands.


### Receipt-bound drop-in placement candidate

Under a retained protected state lock, prepare the one fixed drop-in in a
hidden same-parent staging directory outside PID1's drop-in lookup. The
canonical private receipt records the authenticated base and rendered bytes
digests, port and exact directory/file identities before atomic no-replace
publication. A complete receipt-bound stage can resume after interruption;
unowned identical bytes, partial stages without a receipt, collisions and
identity drift are refused and preserved. Verify-only mode never completes
a pending stage. The operation neither reloads PID1 nor authorizes service
activation, label changes, namespace creation or a live generation commit.
The caller must still prove the signed release, inactive service, executable
receipt, SELinux/namespace ownership and WAL generation before use. No
installed dispatcher calls this primitive yet; detached tests exercise exact
resume and foreign refusal. The guarded native AlmaLinux service fixture
now kills a signed-worker child at the receipt/publication boundary under
the caller's state lock, proves verify-only refusal and exact inode resume,
then exercises actual PID1 startup and cache using the resulting profile.
It verifies the same receipt before fixture-only cleanup; an incomplete
placement is preserved and must not trigger a legacy restart. This remains
a temporary isolated candidate transition, not reboot-time activation or
the generation-bound WAL lifecycle.


### Initial service namespace policy

The fixed namespace actuator now has a separate initial-publication
candidate: require the caller's fresh namespace identity and ownership
witness, an empty complete kernel ruleset, closed canonical policy, native
syntax check, a repeated empty readback and one descriptor-bound nft
transaction. Any existing table, including identical bytes, is refused;
a repeat requires read-only evidence, not adoption. No flush, deletion,
host interface/routing change or arbitrary command is available. The
guarded AlmaLinux service fixture exercises this from the authenticated
worker on its newly created loopback-only namespace, checks refusal of
repeat initialization and unchanged host rules before actual service start.
Durable boot-scoped namespace ownership, generation-bound creation/recovery
and administrator ingress remain separate gates.


### Boot-specific namespace intent

The locked preparation candidate persists a canonical root-private receipt
before initial policy mutation, binding the current kernel boot UUID,
fixed namespace identity, generation and full manifest digest, executable
and drop-in receipt digests, and canonical closed nft policy digest.
The caller must prove each of these independently, including fresh namespace
ownership and service exclusion. A complete matching intent can resume
from an empty namespace or verify the exact already-installed policy;
verify-only never installs pending rules. Missing intent with existing
rules, a different boot, inode, generation, receipt or policy all refuse
without adoption or automatic cleanup. The guarded native fixture uses a
distinct synthetic loopback generation, kills a signed-worker child
after the receipt is durable, verifies refusal in read-only mode and
resumes the same policy. It also binds the resulting receipt and rules
to the actual service MainPID namespace before fixture-only cleanup.
This proves neither authoritative committed/WAL generation activation nor
reboot-time recreation; those require the separate installed lifecycle
and explicit ingress/routing authorization. The broker remains unchanged.


The committed-generation adapter retains the exact five resources and
reconstructs the canonical policy from the authenticated manifest under
the existing state lock. It refuses every pending WAL, foreign domain
or orphan stage before any boot receipt preparation, and rechecks the
same bytes throughout the caller's ownership witness. The generation-zero
bootstrap has a domain-separated digest of its exact resource inventory.
The adapter passes only this independently derived generation/rules and
manifest digest to the boot-intent primitive; no DNS or duplicate
allowlist is used. The native fixture also verifies actual committed
disabled-generation evidence before its synthetic route experiment.
A pending WAL must still be recovered without starting an unverified
service; the boot-time unit and stale boot reconciliation are not yet
implemented. No live dispatch or active catalog authority is introduced.


### Explicit boot receipt rollover

A separate opt-in candidate supports the same committed generation on a
new kernel boot, only with the trusted lifecycle caller's independently
verified fresh-namespace creation witness and complete empty kernel
ruleset. Compare the old canonical intent with the new intent: the boot
UUID must change, and all generation, manifest, profile, executable and
policy digests must remain identical. A same-boot inode substitution or
unmatched generation is refused. Preserve the previous exact receipt in
a fixed boot-UUID-named history leaf before publishing the next intent by
one fsynced same-directory replacement. A complete archive and stage may
resume only with the exact previous current receipt and fresh empty
namespace still present. Foreign or partial evidence is not removed or
adopted, and a missing current record with history cannot silently reset.
Read-only mode never rolls over. No automatic history pruning, namespace
creation, installed boot service, ingress or actual reboot acceptance is
claimed by this candidate; detached tests cover both publication sides.


### Fixed loopback namespace creation

The isolated lifecycle candidate now calls the native fixed iproute2
creation operation itself, under the caller's retained state lock and
service exclusion. It refuses a nonempty namespace directory (including
any pre-existing same-name namespace) before creation; no other named
namespace is affected by iproute2's directory mount setup. It verifies
the exact new nsfs descriptor and initially down loopback as the only
link, and enables only that loopback through the retained fd. Repeat
link/rules readback and boot/program identity checks are mandatory.
No host routes, interfaces, veth, forwarding, global firewall rules,
cleanup or service start are provided. A partial creation without a
verified identity is preserved and refused, not silently adopted.
The guarded signed AlmaLinux fixture uses this primitive instead of
direct guest ip commands; it verifies refusal on repetition and
unchanged host rules before the profile and boot-intent steps.
The production lifecycle, actual reboot-time recreation and explicit
administrator ingress remain separate mandatory gates.


### Real reboot witness for committed boot intent

The AlmaLinux enforcing disposable native activation campaign adds one
additional real reboot after the existing signed-worker service/WAL
exercise. It stops and disables the fixture-owned service, stages its
exact signed profile and creates the fixed namespace under the retained
state lock, deriving the default-deny rules from the actual committed
disabled-route generation. It preserves the boot receipt and independent
release/profile/resource hashes. After the kernel reboot it requires a
different boot UUID, no existing fixed namespace, an inactive disabled
service and unchanged committed resources. The signed worker explicitly
recreates the empty loopback-only namespace and rolls over the exact
prior receipt only after default stale-boot refusal without creating a
namespace;
it verifies the archived prior bytes and current policy. The fixture
binds the native package completion receipt and hashes of stateless host
firewall rules and SELinux booleans across the actual reboot, before any
namespace recreation, then verifies that its operations leave them
unchanged. Exact fixture-only cleanup then
restores the prior enabled legacy service and generation health.
This is a manual controlled lifecycle witness, not an installed
automatic boot provisioner or acceptance of active authoritative routes.
Ambiguous or failed fixture preparation is preserved and fails the
campaign. No production service or boot activation authority is added.


The fresh committed-boot orchestration retains the exact five-resource
scope before and across fixed loopback namespace creation and policy
preparation. It refuses non-loopback listeners, active destinations,
pending WAL/stages,
unverified owner or changed boot intent before policy preparation.
The read-only intent preflight checks prior canonical bindings and
requires explicit stale-boot rollover before any new namespace is
created; the observed previous receipt is compared again at the policy
mutation boundary. The signed native reboot witness exercises this
composition. Ambiguous pending rollover and same-boot creation remain
refused. This internal path requires an authenticated stopped-service
caller and grants no installed dispatch or service start authority.


### Inactive live-WAL rollback preparation

A stopped-service lifecycle caller may prepare the exact previous v3
WAL resource bytes under the original protected lock and fixed layout.
The caller must authenticate service exclusion, release, package and
storage identity; the preparation rechecks that stopped ownership and
the same published WAL before and after target writes. It refuses an
active-route predecessor, unpublished or changed WAL, foreign resources
and unsafe stages. The catalog remains withdrawn, even after all prior
configuration/state/manifest bytes have been restored. The original
published WAL remains durable across retries and power interruption.
This is a recovery preparation, not evidence of native syntax, namespace
ownership, service start, health or rollback completion. No installed
dispatch or catalog publication is enabled. A subsequent authenticated
runtime recovery must verify the prior service before final publication
and WAL removal.

The disposable signed-test VM now repeats its interrupted generation
after the existing active reboot recovery, stops only the owned service,
and exercises the new prior-byte preparation through the installed
authenticated worker on both distributions. It checks the same WAL inode,
exact prior non-catalog hashes and continued catalog absence before an
explicit fixture-only start. The existing confined recovery then verifies
the prior generation and completes catalog publication and WAL removal.
This adds native evidence for the preparation/composition, not an
installed inactive recovery entry point or automatic boot provisioner.

A separate internal finalizer now requires the exact withdrawn prior
resources, the same published v3 WAL, an authenticated active-unit
witness and actual prior-generation health/listener/TLS observation
before writing the previous catalog. It verifies the published catalog
and exact runtime again before clearing the journal. A failed check may
withdraw only the exact owned catalog while the same WAL and other
resources remain intact; a foreign change or uncertain unlink never
produces a successful recovery report.

The existing explicit signed native activation command now invokes this
sequence only for an already enabled, inactive, exactly owned unit and
a published v3 WAL. It re-audits the installed signed payload, retains
the original lock, checks the native package/vendor/storage/unit and
validates the prior syntax before start. It neither enables a disabled
unit nor changes broker privileges or the public command contract.
If start or runtime verification fails, only an exact owned active
process with the same pending WAL and withdrawn prior resources can
be stopped. An uncertain journal unlink or changed process is not
compensated by stopping or declaring success. Both booted guests
exercise the existing signed entry point, including failure before
start and exact retry; this does not establish automatic dedicated
namespace boot ordering or active authoritative routes.


For a published v3 WAL whose prior files have already been restored while
the signed owned service is stopped, a separate retained generation scope
now requires the exact WAL, exact prior bytes, withdrawn catalog and absence
of stages. It derives only the prior canonical boot-policy identity (the
same identity as the committed predecessor), not the proposed policy. The
existing fresh loopback namespace/receipt creation sequence is shared; it
retains the WAL and stopped-owner guard before and after each operation.
Active predecessors, partial bytes, foreign stages, mismatched receipts
and same-boot adoption remain refused. This internal candidate operation
neither starts the service nor clears the WAL or publishes the catalog;
installed dispatch, real boot ordering and native recovery evidence remain
separate.

A separate readback-only prior-WAL policy check uses the same retained scope
and refuses all preparation/rollover operations. The enforcing AlmaLinux
guest now retains the existing committed-boot test and adds a second native
reboot scenario: interrupt an actual live signed-test generation, stop the
fixture, prepare the prior bytes, retain the exact WAL inode/hash and
withdrawn catalog through fresh namespace creation and reboot rollover,
refuse committed-path adoption, verify the resulting closed policy without
mutation, and restore the fixture's original legacy service using explicit
authenticated recovery after exact profile cleanup. This is candidate kernel
and recovery evidence only when executed, not installed dedicated activation
or active upstream ingress authority.

The installed signed worker has an additional read-only active master
observer. It retains the fixed network namespace descriptor, binds the
exact signed unit and expected executable inode to the kernel process,
checks initial-user-namespace membership, the dedicated SELinux master
domain, root credentials, no-new-privileges and the exact minimal
capability masks (including low-port binding only when needed), and
repeats process/unit/namespace observations. The actual enforcing native
fixture now uses it during the active boot-receipt check. This does not
prove the effective SELinux policy, worker credentials, storage, listener
or TLS, which remain independently checked; no start or stop authority
follows from the observation.

For the loopback-only dedicated candidate, a separate native health witness
uses the retained namespace descriptor and exact active master observation
to prove a unique listener inode on the expected port. Only the existing
fixed local health/catalog protocol may execute in a bounded single-threaded
child after entering that descriptor's network namespace. The parent never
changes its namespace; the same master, listener, namespace and caller's
receipt/policy guard are verified again after the child is reaped. The legacy
host-network listener check remains unchanged in scope. The witness grants
no activation, mutation or publication authority and is not wired to the
confined socket dispatcher.

The enforcing signed-worker service fixture exercises the retained
namespace health witness against the real dedicated master and its local
TLS generation marker, and requires refusal of a mismatched certificate
leaf. It rechecks the exact boot policy before and after the observation.
The synthetic fixture does not publish its routes as an authoritative
catalog, and this test does not establish durable installed activation.

If initialization is interrupted after the prepared-WAL boot receipt
becomes durable, the same-boot resume path requires that existing exact
receipt and a separately verified stopped owner. It cannot create or
adopt a receipt, roll over another boot, change the generation, or publish
the catalog. The native pending-WAL reboot fixture injects SIGKILL at
this boundary, proves that verify-only refuses the empty policy, resumes
the exact receipt, and then exercises the subsequent real reboot.

The reboot readback reuses a closed, read-only executable receipt verifier
with independently pinned receipt, package, binary and signed release
identity. Placement and readback share the exact receipt identity fields.
Readback does not create, repair, relabel or adopt an executable, and
rejects absent/foreign/pending evidence and inode or metadata drift.
The native reboot fixture supplies its separately authenticated placement
proof; an installed boot caller still needs independent trusted pins.

The committed-generation reboot fixture additionally starts the actual
signed dedicated service after closed namespace recreation. It uses the
unmodified committed main/include/catalog and independently verified TLS,
not a rewritten test route. The disposable fixture prepares fresh
dedicated-labelled storage and exact owned read-only labels while stopped,
then verifies the actual systemd master, listener, TLS generation and
catalog from inside the recreated namespace. It stops the service and
restores the original fixture-owned storage and labels only on success;
any ambiguous failure retains evidence. This is still explicit
test-harness sequencing, not automatic installed boot dispatch or
persistent storage migration.

The isolated candidate now executes the fixed committed-generation start
sequence inside the installed signed worker while retaining the protected
state layout. It refuses a pending WAL, bootstrap, enabled unit, non-loopback
listener or active upstream routes. Existing boot policy, signed unit,
authenticated ownership, dedicated storage and TLS are checked before start;
after the package audit, the stopped owner, TLS, storage and prepared
egress policy are rechecked before issuing the fixed start. PID1 runs the exact native ExecStartPre and the worker verifies actual
master, listener, TLS, catalog and storage afterwards. On failure only an
exact still-owned active master may be stopped; ambiguous ownership or
generation drift is recovery-required. No new CLI, socket operation,
automatic boot enablement or production activation is introduced.


### Fixed transient scratch for the managed AlmaLinux context

The native activation run at `adc3c6f6f6d345e23a732df348f883d42113d85c`
refused the committed dedicated start because the packaged build selected
`/var/lib/nginx/tmp/client_body`. The managed main now binds all five HTTP
temporary paths to the existing root-owned `/run/repocache-nginx` domain
on both distributions; the signed bootstrap is unchanged. On AlmaLinux the
fixed scratch preparation verifies retained descriptors, mount, owner,
mode and native SELinux type and labels only fresh empty inodes. The
legacy syntax path uses the stock runtime type; the dedicated profile
uses its already-authenticated writable type, not its PID type. Existing
foreign/partial leaves are refused, not relabelled, and no vendor files,
SELinux rules, systemd permissions or persistent cache paths are changed.
The isolated committed start requires all five prepared leaves and
rechecks identity across the actual start and TLS/catalog witness, including
the signed master's private mount view. The previous unreleased Alma managed
main (without explicit scratch paths) is not silently adopted by the new
renderer/WAL validator. Native legacy reboot, dedicated start and systemd
runtime cleanup remain NOT
VERIFIED at the new revision until executed guest evidence is inspected.


### Prepared prior-generation dedicated start (isolated candidate)

The internal signed lifecycle candidate can explicitly start a managed,
disabled-route, loopback-only prior generation from an exact published v3
WAL and its already prepared, withdrawn resources. It reuses the committed
start's fixed unit, native package, receipt, namespace/egress, TLS, storage,
scratch, listener and master checks. A pending or changed WAL cannot enter
the committed path. The prepared path never changes the WAL, catalog,
enablement or configuration, and reports recovery still required. A failed
start is compensated only for a still-exact owned master; uncertain or
foreign state is retained. The disposable native witness requires an
actual start after namespace reboot rollover, a fresh TLS catalog 404,
and preservation of the exact WAL and prior resources across stop.
This is not installed pending-WAL dispatch or recovery finalization.
Publication and journal removal remain a separate unverified phase.


### Dedicated prepared-WAL finalization candidate

The private lifecycle finalizer for a running AlmaLinux dedicated candidate
re-establishes exact prepared prior resources, authenticated owner, signed
namespace/master, boot policy, package, TLS, storage and scratch mounts
under the original lock. It requires a disabled-route loopback generation
and a fresh pinned HTTPS withdrawal witness before catalog publication.
It then observes the same listener and exact prior catalog before unlinking
the exact v3 WAL. On failure it may withdraw only the exact prior catalog
under the still-published WAL and unchanged other resources; foreign or
missing authority is not adopted. This internal increment does not wire
installed dispatch, start/stop, automatic boot or production activation.
Booted finalization and interruption/retry acceptance remain necessary;
the earlier prepared-start witness is not finalization evidence.

A separate native AlmaLinux enforcing scenario extends the existing boot
campaign without replacing the legacy recovery scenario. It creates a fresh
real interrupted WAL, prepares the prior state, reboots, and starts the
signed dedicated service with the catalog withdrawn. The test injects a
failure only after actual published HTTPS health/catalog observation, requires
the exact WAL and withdrawal to survive compensation, retries, observes
the same listener and exact prior catalog, and refuses completed-WAL replay.
The original service and labels are restored only after successful exact
readback. The new boot IDs and phase logs are distinct from the earlier
legacy recovery witness. Execution evidence is required; the scenario itself
does not certify installed dispatch or automatic boot.

The dedicated finalizer assigns the exact fixed read-only SELinux context to
its newly created 0600 catalog stage before publication, verifies the label
on the published leaf and parent during ownership checks, and does not
relabel an existing catalog or change policy. Graceful legacy reload
observation uses the existing 12-second budget for generation convergence
rather than stopping after three fast stale-generation probes; other
refusals retain the previous three-attempt limit. Native harness diagnostics
report fixed redacted transaction codes; the disposable data fixture resets
its own start-rate counter only after restoring exact authenticated bytes.

Legacy vendor-service APPLY, explicit reload and compensating recovery retain
the observed vendor unit digest and master PID across fresh HTTPS readback.
Only a valid empty 204 carrying the known adjacent generation may be retried
within the existing 12-second convergence window; TLS, malformed response,
foreign generation or identity failure still refuses immediately. Rollback
diagnostics use the fixed local redacted vocabulary without extending the
socket protocol. The independent disposable interrupted-generation witness
also observes bounded convergence on the same signed unit, retaining the
actual interrupt and exact durable WAL/catalog assertions.

The prepared-WAL finalizer also recognizes the exact prior catalog already
published under an unchanged v3 WAL after interruption. It requires the
existing exact SELinux label and all authenticated owner, master, storage,
policy and resource checks before withdrawing that catalog. Fresh pinned
404 and 200 observations remain mandatory before WAL removal. A foreign
catalog, changed label, missing WAL or uncertain owner is not adopted.
The booted enforcing fixture separately exercises ordinary post-publication
exception compensation and a real SIGKILL after actual published HTTPS
readback, followed by a fresh locked retry. This remains a private
prepared-profile recovery primitive; no installed activation selection,
automatic boot, active route or new public authority is introduced.

### Composed recovery of a prepared dedicated profile

The authenticated lifecycle caller can now select a stopped or already
running prepared profile under the same original state lock. The fixed
vendor service must remain inactive and disabled and the owned unit
disabled. Only the exact prior withdrawn resources or (for an active
retry) exact previously published resources and valid v3 WAL are eligible.
A stopped profile starts through the existing verified primitive; the
finalizer must retain that same signed unit/drop-in, master and listener.
An active retry never starts another master. Any uncertain service state,
foreign bytes, changed owner or failed finalization is refused without
vendor fallback, enablement or a speculative stop. Independently
authenticated release/package/executable/profile pins and boot intent
remain prerequisites; this is not a public installer selector or a
namespace/label migration. The enforcing guest exercises the composed
stopped path with an injected boundary refusal after real start, then
retains all existing compensation and SIGKILL assertions and resumes
the active service through the same composed operation.

### Authenticated installer-to-worker recovery handoff

The private installer bridge re-authenticates the signed source and native
RPM payload before invoking the fixed installed worker in an isolated
root Python process. The trusted lifecycle caller supplies independent
executable, profile, boot and WAL pins, not digests read from the receipts
being verified. The first phase holds the native-package-effects lock
while using private scratch, and makes no protected resource change.
The child acquires its own exclusive state lock and rechecks exact signed
placement, worker/unit bytes, native executable and package identity,
executable receipt, profile, boot intent and WAL. It retains that lock
through composed recovery; no directory fd is treated as a transferable
lock capability. Drift across the read-only authentication handoff refuses.
The booted enforcing fixture calls the actual installer bridge for the
SIGKILL retry and repeats the old WAL pin to prove refusal. This remains
private prepared-profile recovery, not a public installer selector,
automatic boot, ingress, provisioning or pre-existing storage migration.
A failed or lost child reply does not imply rollback; inspect retained
authoritative state and WAL before any retry.

### Retained post-reboot recovery selection

The private installer can also select an already prepared managed v3 WAL
after explicit boot rollover without a fixture proof file. Under the same
protected lock it requires exact prior resources (catalog withdrawn or
exactly republished), inactive routes, a fixed namespace and canonical
prior-boot archives. It reconstructs the current boot intent from the WAL
generation/manifest, canonical loopback-only rules, live kernel boot and
namespace identities, and the independent archived executable/profile
bindings. All retained archives (bounded to 64) must agree; an incomplete
rollover, missing history, mismatched current receipt or rule readback
refuses. The selector writes nothing. It does not adopt first-boot intent
or authorize creation, public activation, storage migration or new routes.

Archived intent is root-owned installation-local evidence, not a release
signature. The authenticated parent still verifies source and native RPM;
the isolated installed child independently checks the exact reconstructed
pins, package, signed unit, runtime and WAL under its fresh lock before
recovery. The VM SIGKILL retry invokes this selection with release identity
only; the explicit old-WAL replay test remains. Native acceptance requires
successful execution at the exact reviewed revision.

### Authenticated first-boot namespace preparation

The private installer now uses its authenticated worker/RPM handoff for
an absent namespace of an already prepared, managed committed generation.
The trusted caller supplies the independent generation manifest,
executable and profile pins. The parent refuses WAL or boot intent
collisions before package scratch work. A separate fixed child entry
reacquires the protected lock, rechecks the exact signed placement,
RPM identity and digest, executable and profile receipts, exact
committed resources, and both disabled/inactive units. It calls the
existing closed loopback-only creation primitive, then verifies the
same receipt and policy read-only. No same-boot adoption or rollover,
service start, enablement, policy loading, storage migration, public
CLI or new socket authority is introduced. The booted enforcing
fixture uses this path for the committed first-boot namespace, including
wrong-generation and repeat refusal, before the existing reboot witness.

### Authenticated explicit start of the prepared committed profile

The private signed installer handoff can now start an already prepared
committed loopback generation, with independent manifest, boot,
executable and profile receipt pins. The fixed installed child takes a
fresh exclusive lock; it refuses a pending WAL or changed committed
resources, rechecks the signed placement and RPM executable, and
requires the vendor unit disabled/inactive and owned unit disabled.
The existing dedicated start primitive still owns syntax validation,
stopped-unit checks, live master/listener/TLS/catalog/SELinux and mount
verification, and exact-owner failure compensation. The bridge reports
the pinned manifest and boot identities, does not enable the service
and cannot adopt an already running master. A failed or lost child
reply does not establish service state; inspect authoritative evidence
before retry. The enforcing VM uses the actual authenticated start
after reboot rollover and tests foreign pins and active replay.
No public CLI or socket operation, automatic boot, active route,
ingress, migration or production activation is added.

### Authenticated committed boot rollover

The private installer can explicitly recreate the absent namespace after
a different boot for an already prepared committed loopback generation.
In addition to release, executable, profile and manifest pins, its
caller supplies the prior boot receipt digest. The parent refuses an
unexpected receipt or WAL before native package authentication. The
installed child verifies the prior receipt under its fresh lock; the
creation primitive compares the independent digest with its exact
preflight bytes before any namespace effect and retains that prior
intent through creation and policy initialization. The existing
boot-rollover rules require a different boot, exact bindings and a
fresh empty namespace. Read-only verification and the byte-identical
prior archive must both succeed. No same-boot adoption, pending-WAL
selection, enablement, automatic boot ordering, public CLI or new
ingress authority is introduced. The native committed reboot fixture
uses the actual installer bridge, refuses a foreign prior pin before
namespace creation, and refuses replay after completion.

### Authenticated rollover of a prepared pending WAL

An explicit private signed-installer operation now recreates the absent
namespace after reboot for a prepared, withdrawn prior generation.
The WAL digest is independently pinned in addition to the committed
manifest, previous boot receipt, executable and profile. The committed
selector still refuses any pending WAL. The isolated installed child
retains the exact WAL and withdrawn resources under its own lock and
rechecks absence of stages, inactive routes, both disabled/stopped
units, signed placement and authenticated native package. Only the
existing v3 WAL prior-generation creation and read-only verification
primitives run; the old boot bytes must be archived exactly. No catalog
publication, WAL removal, source repair, service start or new authority
is implied. The native reboot fixture uses the authenticated pending
selector and refuses wrong WAL/boot pins and completed rollover replay.
This does not replace automatic boot or complete installed recovery.

### Authenticated first-boot preparation of a pending WAL

The same private signed installer now has a distinct first-boot pending
selector, with exact WAL and prior-manifest pins and no previous boot pin.
It refuses existing boot intent or history, leaves both services disabled
and stopped, preserves the withdrawn catalog and WAL, and verifies the
new closed namespace without activation or catalog publication. The
committed and rollover selectors retain their distinct refusal conditions.
One native pending scenario exercises the actual first-boot installer
bridge, including foreign pins and repeated invocation refusal; the
separate finalization scenario retains the existing SIGKILL and same-boot
resume witness. No public command, automated boot dispatch or active route
authority is introduced.

### Authenticated same-boot pending intent resume

A distinct private signed installer selector accepts the exact existing
boot-intent digest in addition to the manifest, WAL, executable and
profile pins. It opens only the retained fixed namespace, acquires the
worker's fresh lock, and rechecks the exact intent bytes, stopped units,
withdrawn catalog and prior resources before and after initializing the
closed policy. The underlying primitive independently binds the canonical
intent to the current boot and namespace inode. No new namespace, archive,
WAL deletion, service start or catalog publication is allowed. A repeat
with the same verified policy is read-only. The native SIGKILL fixture
leaves the actual uninitialized intent, releases its fixture lock, and
resumes through this signed bridge; verify-only and foreign pins refuse
before policy initialization, then exact resume and readback succeed.

### Authenticated prepared pending-WAL start

A distinct private installer selector starts an independently prepared
loopback generation while retaining the exact WAL and withdrawn catalog.
It authenticates the signed release, installed worker, native package,
profile, executable, prior manifest and current boot intent; the worker
rechecks under its own protected lock. The existing prepared-generation
start primitive retains its exact stopped-owner and compensation checks.
The signed parent rejects a published catalog, changed WAL, missing
recovery-required status or enablement change. The booted pending-WAL
scenario uses the authenticated selector and requires fresh TLS HTTP 404,
foreign pin refusal, committed selector refusal and active replay refusal.
The independent finalization fault and SIGKILL scenario remains intact.
No public CLI or automatic boot dispatch is introduced.

### Explicit authenticated activation recovery dispatch

The existing signed installer activation selects an already rolled,
prepared dedicated pending-WAL profile from protected state under its
lock, never from a CLI path or a caller-provided receipt. Incomplete,
foreign or cross-distribution dedicated evidence refuses before legacy
activation. The retained prior-boot record reconstructs the exact
current boot intent; the signed bridge repeats selection under a fresh
lock and refuses changed pins before running the installed worker. The
worker independently verifies package, executable, profile, namespace,
WAL and runtime and performs the existing guarded recovery. A distinct
recovery result reports the observed active service and unchanged disabled
enablement; it is not a claim of enabled service or automatic boot.
No fallback to the legacy start path on a dedicated recovery refusal.
The booted finalization scenario now invokes the existing signed installer
entry after actual SIGKILL and checks exact prior TLS publication and WAL
removal, while preserving the disabled unit state. First-boot dispatch,
committed dedicated activation, automatic boot and active route authority
remain separate prerequisites.

### Authenticated committed same-boot intent resume

The committed counterpart of the pending-WAL resume selector requires no
WAL, exact independently pinned committed manifest, executable, profile
and current boot receipt. The existing namespace is opened, never created
or replaced. The worker checks the stopped owner and exact receipt under
its fresh state lock and supplies the retained bytes as a compare-and-swap
input to the shared closed-policy initializer. Verify-only readback must
match the result; the same receipt and inode are retained. No unit start,
enablement or catalog mutation is authorized. The native committed boot
scenario retains the successful signed first-boot preparation and then
resets only the verified disposable fixture namespace and receipt while
both services are stopped and disabled. It injects a real SIGKILL after
durable committed boot intent but before nftables initialization. Verify-only
and foreign pins must refuse, then authenticated same-boot resume must
preserve receipt bytes, namespace identity, committed resources and disabled
service state. Repeated verification must be read-only. This fixture cleanup
is not an installed cleanup or recovery capability.

### Explicit rolled committed activation dispatch

The signed activation entry also selects a committed prepared post-reboot
profile without a WAL, reconstructing the current closed-policy receipt from
independent protected prior-boot history and exact committed generation.
The signed parent reconstructs those pins again before the fixed installed
start child. Missing or changed history, boot intent, generation, pending
WAL or any unverified service state refuses; no legacy fallback or unit
enablement is permitted. The booted committed scenario uses the existing
signed activation entry and observes exact TLS catalog, storage and scratch
mounts. An authenticated repeat uses the same reconstructed pins, verifies
the pre-existing master and fresh pinned TLS catalog, exact namespace policy,
storage and scratch identities, and never starts, stops, reloads, enables or
compensates that pre-existing master. The private start-only selector still
refuses active replay. Native tests repeat after committed start and after
successful WAL finalization and compare exact process/listener identity,
resources and enablement. Negative tests exercise failed observations without
stopping the pre-existing process. First-boot and automatic namespace
provisioning remain separate prerequisites.

### Authenticated initial committed profile placement

The private signed installer can place the fixed dedicated namespace drop-in
for an already committed loopback-only generation. It requires independently
pinned manifest and executable receipts, authenticates the installed worker,
source, native package and dedicated executable, and reacquires the worker
lock. Both services must be disabled and stopped, the effective original unit
must match, and no boot intent, history, namespace, pending WAL or existing
profile receipt may be adopted. After the existing atomic profile publication,
read back the exact fixed drop-in and recheck the unchanged generation and
service state. No daemon reload, service start, enablement, namespace creation,
catalog mutation or public operation is introduced. An uncertain or already
present profile is refused, not adopted; its subsequent recovery remains a
separate lifecycle prerequisite. The booted committed fixture uses this
signed installer path and exercises foreign pins and repeated placement refusal.

### Authenticated load of the stopped committed profile

The private signed installer accepts the independently retained executable,
profile and generation pins, reacquires the worker lock and verifies the
exact persistent profile and its stopped/disabled service boundary. Only
the exact old PID1 unit with no loaded drop-in and NeedDaemonReload=yes,
or the exact dedicated loaded unit, is accepted. The stale case permits
one fixed systemctl daemon-reload (a manager-wide unit-definition reload,
not an NGINX reload). Recheck authenticated resources and the exact loaded
profile; the already-loaded case is observation-only. Foreign or changing
observations, pending WAL/boot evidence, active services, incorrect pins and
failed/uncertain readback refuse without starting, stopping or enabling any
service. Keep the profile receipt for explicit retry; never clean up an
ambiguous load. This does not introduce a socket operation, automatic boot
activation, namespace creation or catalog publication. The committed VM
fixture now uses the actual signed load and read-only repeat paths. An
inactive unit may be garbage-collected and reloaded by PID1 on demand,
so the native fixture classifies both exact states rather than requiring
NeedDaemonReload=yes unconditionally. Evidence distinguishes an actual
manager reload from an already-loaded read-only observation; an unexercised
native reload branch is not a PASS. For the committed booted fixture, a
private system-bus RefUnit connection now retains the stopped base unit
through profile placement, foreign-pin refusals and the first signed load.
Require the exact stale state before the load and a true daemon-reload
result, then repeat with no reload. The connection closes on all paths;
no service is started, enabled or changed by the fixture reference. This
is test-only, not an additional installed authority. The installed worker's
exact-state refusals and authentication requirements are unchanged.


### Authenticated committed dedicated storage placement

The private installer may prepare only the fixed fresh storage for an
exact stopped, disabled committed loopback generation with no active
repositories. Independent release, executable, profile, generation and
current boot receipt pins are rechecked under a fresh installed-worker
lock. Verify the existing closed namespace policy without modifying it,
both services' inactive/disabled state, the loaded signed unit and exact
committed files before and after invoking the existing dedicated storage
primitive. Re-read the storage using allow_create=False. Refuse legacy
roots, drift, pending WAL, foreign pins and incomplete ownership; no
migration, deletion, relabeling of existing objects, systemctl effect,
catalog publication or service write proof. Existing valid dedicated
roots are read-only on repeat. Partial effects remain governed by the
existing storage ownership and refusal contract; no speculative cleanup.
The disposable committed VM still explicitly archives its empty legacy
fixture roots; this does not implement a production storage migration.


### Authenticated committed dedicated runtime preparation

After the exact dedicated storage and boot namespace policy are verified,
the private signed installer may prepare the fixed boot-local runtime
parent and five empty scratch leaves while both NGINX services remain
stopped and disabled. Open /run and the fixed child without following
symlinks; verify root ownership, mount identity, permissions and SELinux
enforcing. Create a new parent in mode 0700, assign only its descriptor
the exact dedicated PID context, then publish mode 0755. Never relabel,
chmod, chown or remove an existing parent. Reject an incomplete parent,
foreign entries and invalid labels, use the existing scratch primitive,
and recheck all identities and the committed policy and storage. A repeat
with exact existing leaves performs no file writes. No service start,
enablement, migration, catalog publication or arbitrary path authority.
The committed VM exercises the authenticated path; pending recovery still
uses the isolated fixture. A partial parent is retained for explicit
diagnosis; no automatic destructive cleanup or production repair authority.

### Dedicated read-only configuration preflight

Before starting an authenticated prepared or committed dedicated profile,
and throughout same-lock ownership rechecks, require the exact dedicated
read-only SELinux context on the retained configuration and public
directories, main configuration, managed include and committed catalog.
For pending recovery require catalog absence. Open fixed file names
without following links, verify root ownership, exact modes, one link,
mount continuity and stable inode metadata, and refuse extra xattrs.
The proof is read-only: no existing label is changed, no repair or new
privilege is authorized. Active repeat remains observation-only. A
disposable guest intentionally substitutes the fixture's old main-file
label, requires signed start refusal, and restores the label before the
positive start. TLS label preparation, fresh configuration placement and
installed lifecycle acceptance remain separate gates.

### Dedicated TLS read-only label and path proof

The isolated dedicated start, active repeat and prepared-WAL finalizer
also retain a read-only identity proof for the certificate/key paths
from the authenticated generation. Require the exact dedicated read-only
context on their direct parents and leaves, safe root-owned ancestry,
no extra ACLs/xattrs, same-mount traversal, distinct single-link regular
files and unchanged metadata. Retain the existing certificate chain,
hostname, expiry and pair validation; the new label proof does not
replace OpenSSL. Recheck the proof during the existing ownership guards.
Do not copy, log, relabel or repair any operator-owned TLS material.
The native fixture tests a foreign private-key label before real start,
restoring only its own disposable label. Fresh label placement, production
policy installation and complete installed activation remain separate gates.

### Dedicated finalizer configuration continuity

Before a prepared-WAL finalizer observes the running master or publishes
the prior catalog, re-establish the same full read-only configuration
label proof as the dedicated start. During every existing ownership guard,
check the complete unchanged main/include and NGINX directory identities,
the public directory's stable inode, owner, mode and mount, and the
exact catalog presence/absence and label. Catalog publication/withdrawal
may change only the public directory's size and timestamps across phases;
the full within-observation checks still apply. Refuse foreign labels and
same-byte configuration replacement, retaining the WAL; after a failed
publication use only the existing exact-byte compensation boundary.
The disposable native fixture substitutes the old main-file label during
the running prepared-WAL phase and requires signed refusal with HTTP 404
and an unchanged WAL, then restores its own label. No new write authority.

### Authenticated prepared-WAL storage and runtime placement

The stopped, withdrawn prior generation can now use the same private
signed installer placement boundaries as the committed generation.
The prepared-WAL selectors additionally pin the exact live WAL digest and
prior generation manifest, require exact withdrawn resources and no
orphan stages under the original lock, and read back the exact closed
prior-generation boot policy before and after placement. They return
explicit recovery-required and catalog-withdrawn evidence; the installer
checks these fields and all pins. No service, policy, WAL, catalog,
enablement, existing-object relabel or migration authority is added.
Runtime placement still requires already verified persistent storage.
Both pending native guest phases now exercise the authenticated selectors,
including foreign WAL/boot/profile pins, legacy and partial-root refusal,
and exact-inode read-only repeats, replacing direct fixture-only placement.

### Fresh read-only namespace and publication primitives

Private fresh dedicated namespace preparation assigns the fixed read-only
context to a newly created public directory before making its mode
0755; existing complete directories are verified without relabeling.
Root-owned descriptor ancestry, mount continuity, exact public inode
and lock are checked, and incomplete or legacy-labelled directories are
refused without cleanup. The trusted caller must independently verify
the enforcing host and the authenticated loaded policy; this primitive
does not authorize a host installation.

Fresh dedicated catalog publication now uses a single retained staging
descriptor, exact mode/owner/link/mount/label and byte checks, durable
private staging and Linux atomic no-replace rename. A foreign target
appearing at the final publication boundary is preserved, with the stage
retained for existing WAL recovery or explicit diagnosis. The same
primitive accepts only the fixed signed inert main bootstrap bytes for
future fresh configuration placement. Legacy writes and replacement
semantics remain unchanged. No existing object is relabelled, and no
new service, policy, migration or public command authority is introduced.

The dedicated inert bootstrap preparation reuses the original ownership
claim and exclusive state lock. Before any effect it requires the fresh
public label, empty public directory, no state generation or WAL, no
legacy owned filenames/vendor include, and fixed root-owned same-mount
ancestry. It assigns the read-only context only to the exclusively
created 0700 config directory, publishes mode 0755, and installs only
the exact inert signed bootstrap through the no-replace publisher.
Complete claimed repeats verify without changes; orphan stages,
incomplete claims and existing wrong labels are refused. The
authenticated installed worker exercises this in a detached enforcing
VM root using the already loaded dedicated policy. This is a fresh
placement component, not the real host installer composition, managed
generation commit, automatic policy installation or activation.

### Fresh signed worker placement and native policy readback

The private worker-placement candidate can request the fresh dedicated
public-directory context, using a policy-source digest checked against
the fixed member of the independently authenticated worker archive.
The normal installer remains unchanged. Before and after worker/receipt
placement under the existing lock, recheck the exact public-directory
ancestry, mount, label and enforcing state. Existing legacy-labelled
directories are refused, never relabelled.

The guarded enforcing VM authenticates the policy source independently
from the signed release and compares it with the installed archive.
Reject every preexisting module with the dedicated name at any
priority, compile the exact source, install only the fixed module at
priority 400 in the disposable VM, and read the stored HLL package
back with semodule's extraction operation. Require its SHA-256 to
match the freshly compiled package, a single enabled priority, and
unchanged other modules and booleans. Read back the same package
after reboot. This is module-store evidence, not an attestation of the
entire active kernel policy or production installation authority.

The detached-root fresh configuration witness now uses the same
authenticated worker placement, independently verified source and
native module readback, and runs the configuration primitive from the
newly placed archive in an isolated interpreter. No actual host
configuration, service, operator TLS material, or public CLI changes.

The private fresh placement selector is explicitly detached-root-only
until the initial host orchestration is accepted. Verify the public
label before each worker/unit/receipt write and before the completion
marker. If it drifts during placement, retain the pending claim, refuse
the remaining writes, and never silently create the completion marker.
The root-container recovery suite exercises this boundary as well as
same-inode repeats, wrong pins and actual-root refusal.

### Read-only first-generation candidate preflight

The enforcing AlmaLinux generation-one candidate path retains the exact
inert configuration and empty public namespace under the original lock.
The bootstrap-specific label proof requires the fixed main file only and
rejects any include, catalog, stage or foreign public entry. Before and
after the existing deterministic root-intake CAS renderer, verify exact
operator TLS labels and inode identities, unchanged bootstrap resources
and the same intake report and bytes. Refuse active repositories and stale
or changing inputs before returning a candidate. Bind the initially inspected
intake to the shared renderer before TLS verification or DNS resolution, so
a changed active-route proposal cannot reach the renderer's effects.
No WAL, catalog, service,
policy or host installation effect is permitted by this helper; the
initial authenticated transaction and health-gated publication remain
separate prerequisites. Existing committed and recovery proofs are unchanged.

The enforcing booted guest also invokes this preflight from a freshly
placed authenticated archive against a detached root, using the already
verified disposable CA and exact first-generation root intake copied
from the existing test fixture. It checks repeated exact preparation,
unchanged resource identities and absent WAL/catalog, then refuses a
foreign label on the disposable key before restoring that fixture only.
No host service activation or production trust claim follows.

### Initial-generation labelled configuration WAL writer

The existing fresh public publisher now shares its retained-descriptor
staging implementation with a guarded initial configuration writer. A
fresh include uses no-replace publication; the inert main is replaced only
after checking its exact bytes, inode, mount, mode, ownership and read-only
label immediately before rename. Only the fresh stage may receive a label.
The rollback path restores the original main before removing only the exact
WAL-owned include. Reject main-first and include-removal-first transitions,
check all other stages are absent, and retain the unaffected configuration
leaf's complete identity across every guarded write. A retained root-only
namespace and cooperating state lock
are required; the replacement does not claim atomic CAS against hostile root.

The private initial writer requires the unchanged published v3 WAL, an inert
predecessor, exact candidate hashes, no catalog/manifest, enforcing state and
unchanged ownership checks. It refuses the actual host root and retains the
journal even after successful detached reversal. Interrupted or foreign
stages are retained, not guessed or relabelled. This is an executable
filesystem component; initial installed orchestration, safe stage recovery,
real service health and final publication remain separate prerequisites.

Detached initial configuration-only recovery accepts only a published v3
WAL with the inert predecessor, no proposed state, manifest or catalog,
and a reachable configuration phase. At most one fixed NGINX stage may
exist. Retain its descriptor; verify root ownership, mount, link, exact
label, stable identity and mode, and for completed stages the WAL hash.
A partial private-mode stage is never interpreted as committed bytes.
Refuse wrong labels, foreign stages, multiple stages, unexpected phases
and private-state stages. Restore main before removing the include and
clear the WAL only after exact labelled bootstrap readback. This cleanup
is restricted to the detached configuration-only rehearsal, never live
service recovery; the real host path still requires health evidence.

The existing enforcing signed-worker detached-root scenario now executes
both initial configuration write/reversal and a deliberate pre-rename
interruption, verifies the retained completed stage, refuses its foreign
label without effects, restores only the disposable fixture label and
recovers the inert predecessor. The initial TLS and intake fixture copies
are exclusively created in mode 0600 before any payload write. The
scenario does not start a service in the detached root or publish a catalog.
