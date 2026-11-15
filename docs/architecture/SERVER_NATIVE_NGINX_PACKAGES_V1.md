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
