# Authenticated v0.6 worker staging (#64)

Use a trusted, security-assessed checkout for the verifier below. Supply a
private operator-owned staging parent, the exact source commit and the
operator-verified archive SHA-256. The asset directory contains
the v0.6.0 source archive, its signed manifest and detached signature.

~~~sh
/usr/bin/python3 -IS scripts/stage_native_root_worker.py \
  --assets /absolute/incoming \
  --output /absolute/private-stage/worker \
  --commit "$REVIEWED_SOURCE_SHA" \
  --archive-sha256 "$REVIEWED_ARCHIVE_SHA256"
~~~

An independently commissioned human security review is optional under the
issue #64 maintainer amendment (2026-11-21); the trusted signed source,
exact-SHA security evidence and native deployment gates remain mandatory.

The verifier uses the existing independently provisioned host trust store.
It checks the detached signature, canonical v0.6 release identity, two
operator-supplied pins and signed compatibility policy before staging.
The source archive is extracted into a private temporary directory using the
closed v0.6 member inventory. The trusted builder packages source files as
data and does not execute code from the candidate.

The new private directory contains the deterministic executable, two unit
files and worker-receipt.json. Compare the receipt's identities and individual
file hashes with the planned authenticated native installation. The receipt
is a staging record and never substitutes for re-verification at the eventual
privileged installation boundary. An interrupted attempt without a receipt
requires a fresh output directory. This command does not install the worker,
change systemd/SELinux or activate NGINX.

The exact combined two-distro workflow tests this with disposable Ed25519
keys and the canonical verifier from #249. It covers matching artifacts,
wrong trust data, wrong owner pins, unsupported OS and existing output.
Real publisher signing and booted Debian 13 and enforcing AlmaLinux 10
acceptance remain separate gates.


After separately authorized placement, the trusted verifier can check
the actual files before starting the socket. Use the same assets and pins,
and replace the output option with --verify-installed. The readback checks
root-owned regular files at /usr/libexec/repocache/server-control-worker
and /etc/systemd/system/repocache-control.{service,socket}. It refuses
symlinks, hard links, unsafe ancestor ownership/mode, unexpected installed
permissions and any content difference. Actual unit loading, drop-ins,
SELinux labels and service behavior require separate native acceptance.


## Authorized file placement

The fixed installer accepts the same independently authenticated offline
assets and owner pins. Run from the trusted checkout as root on a supported
booted host. Before reading candidate assets or creating any persistent
files, both worker placement and installed proposal staging require the
fixed root-owned OS identity, supported OS Python version, x86_64 machine
identity and exact native Python executable inode outside a virtual
environment. The packaged worker repeats the same target guard before
dispatching a fixed transaction. These observations do not attest package
provenance or confer authorization. The root-control CI additionally invokes
the real guard on Debian 13 and AlmaLinux 10, and calls both placement and
proposal-staging functions with a same-version copied interpreter or on an
actual Debian 12, AlmaLinux 9 or Ubuntu 24.04 target. The target reader is
not mocked; downstream host/asset/effect boundaries are test sentinels so
even a failed guard cannot cause actual installation. A successful native
identity observation never stages or activates a worker.
The command can prepare an absent fixed state namespace after
checking existing unit and worker destinations. The root-owned namespace
allows traversal to the public catalog directory (0711 parent, 0755 public).
The independent server state directory and its shared lock stay private
(0700 and 0600). The unprivileged application has a separate private home.
Existing namespaces must already match those modes. An interruption before
the complete protected lock exists requires operator reconciliation.

~~~sh
/usr/bin/python3 -IS scripts/install_native_root_worker.py \
  --assets /absolute/incoming \
  --commit "$REVIEWED_SOURCE_SHA" \
  --archive-sha256 "$REVIEWED_ARCHIVE_SHA256"
~~~

It reads PID 1's UnitPath, refuses conflicting units, unit overrides,
aliases, dependency links and an existing socket during incomplete work,
and places the executable and units at the fixed paths with root ownership.
A durable marker binds recovery to the same authenticated candidate.
Under that marker the placer creates missing fixed worker directories
below /usr and syncs the directory entries. It preserves existing safe
directory metadata. Re-executing with the same inputs resumes an interrupted
directory creation or no-replace placement. A completed placement is
checked without rewriting or creating directories.
An unrelated destination or a different candidate halts before replacement.

The placement command does not load, start or enable either unit. Review
the effective loaded unit and native labels and perform separately
authorized activation in the consolidated booted-host campaign.

## Stage a reviewed v2 proposal

For a clean first installation, prepare the snapshot from the reviewed
install-v1 document with `expected_state_generation` set to zero. The
following preparation step can run without root in a private output parent.
It authenticates the release candidate first and uses the adopted input
validators and repository ID planner. Missing IDs receive deterministic
initial suggestions. Existing deployment state and retired IDs use the
repair flow below.

~~~sh
/usr/bin/python3 -IS scripts/install_native_root_worker.py \
  --assets /absolute/incoming \
  --commit "$REVIEWED_SOURCE_SHA" \
  --archive-sha256 "$REVIEWED_ARCHIVE_SHA256" \
  --prepare-initial-v2-proposal /absolute/reviewed-install.json \
  --decision-sha256 "$REVIEWED_DECISION_SHA256" \
  --proposal-output /absolute/private-stage/reviewed-state.json
~~~

The output is a new 0600 canonical snapshot with generation one. Existing
output is refused. The JSON receipt includes its SHA-256 for independent
review. The decision digest binds the recorded decision reference. The
reference itself supplies no OS authorization. Review the complete output,
including generated IDs, before using its exact digest for locked staging.

Use a canonical v2 state snapshot and its independently reviewed SHA-256.
Run the same installer with the authenticated release asset arguments plus
`--stage-v2-proposal /absolute/reviewed-state.json --proposal-sha256 SHA256`.
It verifies the installed worker files and binds the snapshot to the actual
committed predecessor under the protected lock. A prior uncommitted proposal
is preserved. An exact staged retry is idempotent. After commit, staging the
same reviewed snapshot reports `AUTHENTICATED_V2_PROPOSAL_ALREADY_COMMITTED`
and preserves the existing proposal. Repeating `APPLY_V2` with that same
proposal returns `NATIVE_V2_NO_CHANGE` only after verifying the complete owned
resource set, re-reading the intake, validating the pinned TLS pair, matching
the fixed effective NGINX include, and observing the currently exposed HTTPS
generation and active-only catalogue. An absent/stale/foreign live exposure
refuses the no-op rather than claiming operational success. It performs no
reload, publication or generation increment. A separately requested `RELOAD_V2` validates
the fixed NGINX include section both before and after the service reload.
If the post-reload NGINX configuration dump differs despite matching
generation health and unchanged protected files, it refuses success and
leaves the managed files untouched for explicit operator investigation.
This source check alone does not establish live process provenance or
booted-systemd acceptance. A proposal from an older committed generation,
resource drift or a pending recovery journal still refuses.

A native package-effects
marker or pending WAL blocks staging and remains available for reconciliation.
Staging leaves the active state, NGINX and the catalogue untouched. Actual
activation still requires the separate kernel-credentialed worker operation.

## Prepare a same-version repair

Obtain a private read-only copy of the last committed
`/var/lib/repocache/server/state-v2.json` through the authorized operator.
Pin its independently reviewed SHA-256. Set the partial install document's
`expected_state_generation` to that snapshot's generation.

~~~sh
/usr/bin/python3 -IS scripts/install_native_root_worker.py \
  --assets /absolute/incoming \
  --commit "$REVIEWED_SOURCE_SHA" \
  --archive-sha256 "$REVIEWED_ARCHIVE_SHA256" \
  --prepare-v2-repair /absolute/reviewed-repair.json \
  --previous-v2-state /absolute/private-stage/committed-state.json \
  --previous-state-sha256 "$REVIEWED_PREVIOUS_STATE_SHA256" \
  --decision-sha256 "$REVIEWED_DECISION_SHA256" \
  --proposal-output /absolute/private-stage/reviewed-repair-state.json
~~~

The existing declarative planner preserves every omitted repository and
the all-time reservation ledger. A changed configuration advances one
generation. An unchanged partial request preserves the exact committed
snapshot, including its original approval reference. Adding and removing
repositories use the #95 lifecycle workflow. A stale generation, v1 state,
wrong predecessor hash or unallocated ID is refused before output.

Review the full generated snapshot and its receipt. During separately
authorized staging, also supply
`--expected-state-sha256 "$REVIEWED_PREVIOUS_STATE_SHA256"`. The installer
compares this pin with the actual protected predecessor under the same
exclusive lock before replacing a proposal. Repeating a completed staging
accepts either its recorded predecessor pin or the exact current snapshot
pin. The worker still checks all owned resources before an apply no-op.

The supplied snapshot remains untrusted input during preparation. Actual
predecessor identity and authorization are verified separately at staging
and execution. Package-effects reconciliation and booted-host acceptance
remain mandatory.

## Native package-effects reconciliation boundary (Stage A)

The post-APT/DNF read-only correlation now also executes the distro's
fixed `dpkg --verify nginx nginx-common` (Debian 13) or
`rpm -V nginx nginx-core` (AlmaLinux 10), requiring a zero exit and
an empty discrepancy listing, with the stock NGINX binary identity
unchanged across the check. This detects additional installed-file
drift before considering reconciliation; it is not signed package
provenance. The native effects marker **remains durable and blocking**:
local package-database consistency, a vendor unit and a signed release
worker do not alone justify removal after an ambiguous APT/DNF crash.
No new package, privileged operation, marker clearing or service
activation authority is introduced here.

Minimal distribution images may omit only explicitly bounded NGINX
changelog, manual and license files. Those exact missing-doc entries
are recorded as omissions and **never** imply verification of all package
bytes. Any binary, systemd-unit, runtime configuration, package-manager
failure or unknown discrepancy is still a hard refusal.

On AlmaLinux 10 the stock RPM may report exactly two metadata-only
differences on package-created ghost log files
`/var/log/nginx/{access,error}.log`. These are accepted only when their
on-disk objects are single-linked regular files owned by root or the
distro's `nginx` UID, with a trusted root-owned non-writable log
directory and no group/world-write permissions. Their owner/mode
differences are counted explicitly; they do not attest every package
byte or NGINX log-retention behavior. Any other runtime discrepancy
or untrusted log inode remains a refusal.

## Same-lock package completion — implementation boundary

The private `_complete_native_install_after_verified_manager_under_lock`
is an in-process completion primitive for the explicitly authorized,
uninterrupted native APT/DNF installer. It accepts only the root-owned
canonical pending journal and rechecks the fixed package identity,
installed operational-file integrity and vendor unit using the SAME
exclusive #31 lock. A durable root-owned completion receipt is fsynced
before the original pending marker is removed. Crash/failure before that
removal preserves the blocking pending marker; an ambiguous post-crash
native transaction is never silently adopted or retried.

The primitive MUST NOT be invoked from an untrusted client or merely
because a read-only observer sees installed NGINX. Only a separately
authenticated native installer that actually executed the fixed
distro-signed package transaction inside that same lock may invoke it.
The receipt explicitly does not attest owner-signed REPOCACHE artifacts,
booted systemd, enforcing SELinux, service exposure or production activation.

The completion receipt has a closed canonical schema and is validated
before the protected state-v2 lifecycle can reuse the namespace. Receipt
corruption, missing root ownership or any still-pending native effects
refuse further writes. The completed record blocks a second fresh native
package installation rather than authorizing an overwrite.

The two-distro CI now exercises both sides of the native effects
boundary on *fresh separate disposable containers*: the existing pending
path proves an uncompleted operation never authorizes re-entry, and the
additional genuine APT/DNF success path verifies the same retained lock,
strict package-owner/file/vendor-unit observations, durable completion
receipt and refusal of duplicate fresh installation. Neither case
installs a root broker or claims booted native systemd/SELinux.

### Privileged activation now requires audited package completion

The fixed native root-worker `APPLY_V2` and `RELOAD_V2` paths
fail closed *before* NGINX/state/catalog mutations without the canonical
root-owned native package completion receipt. They also repeat the
distro's current NGINX installed-file integrity check and require the
current fixed vendor `nginx.service` digest to match the durable audited
package-install receipt. Any pending
APT/DNF effects, missing/corrupt/mismatching receipt, foreign package
state or changed operational bytes refuses activation. `RECOVER_V2`
retains its independent WAL compensation path so a missing audit receipt
does not by itself disable emergency rollback. Fixture-only tests may
exercise the underlying transaction without a production host receipt;
this exception is never available to the installed worker protocol.


## Authenticated native NGINX package install — explicit opt-in

The first-install APT/DNF operation is now connected to the same signed
candidate installer as the fixed root worker. It is never implicit in worker
placement and is not exposed over the local administrator socket.

The operator first authenticates and places the worker and fixed systemd units
from the owner-signed exact v0.6 release candidate. After independent review
of the install-v1 document, the operator may separately select
--install-native-nginx with that document's exact --document-sha256 and the
same --assets, --commit, and --archive-sha256 publisher pins. The installer
requires matching installed worker bytes, a genuine initial user/root/systemd
host namespace, supported x86_64 native Python and distro, an unchanged
pinned document, initial generation zero, clean NGINX ownership observations,
and the OS distributor's protected signing anchor BEFORE any package effects.

One protected exclusive state lock spans the durable APT/DNF effects marker,
a fresh within-lock NGINX conflict observation, the exact approved official
distro APT/DNF refresh and install commands, package DB status, packaged
NGINX syntax and file ownership/integrity, and the existing audited durable
completion receipt. Debian reads the host dpkg status; AlmaLinux uses the
host's root with the fixed signature-enforcing BaseOS/AppStream sources,
not arbitrary enabled third-party repositories. The signed input never
supplies package-manager argv, shell, URLs or trust keys.

Because a package postinstall script may enable or start NGINX, a persistent
systemd service mask is placed only AFTER the irreversible-effects journal
and BEFORE the manager starts. It survives reboot following interruption.
After a successful install, the vendor unit is disabled while masked, the
known owned mask is removed, and both disabled and inactive states must be
observed before the same-lock completion receipt can be issued. Any failure
retains the blocking journal and never silently retries or clears ambiguous
package effects; if the mask had been removed, restoration is best-effort.
Do not manually delete an uncertain journal or mask based solely on a
successful package database read.

The operation does NOT enable, start or reload NGINX, publish the active
catalog, or claim publisher/SELinux/booted-service acceptance. Those remain
separately authorized steps of the coordinated final Debian 13 / AlmaLinux
10 booted-host campaign. Disposable CI validates the shared native package
commands and guarded WAL/receipt code, not real booted systemd behavior.


## Native operator authorization, revocation and recovery (issues #31/#64)

This section documents the **fixed-operation installed-worker boundary**, not a
grant of permission to deploy on production. For development, use only the
isolated Debian 13 and AlmaLinux 10 (SELinux Enforcing) guests with disposable
Ed25519 identities. The real owner-signed candidate, staging and publication
remain separately authorized Stage C steps under #76/#88.

**Before separately authorized host activation**, the administrator must
authenticate the installed worker against the **trusted host Ed25519 anchor**
and exact source/archive pins, verify the fixed systemd service/socket unit
bytes and current distro-provided NGINX package/unit, and inspect the actual
systemd/SELinux security context. An installed worker, a source-built archive,
a successful read-only preflight, and a `--yes` flag are not OS
authorization. Never copy a disposable test trust anchor into production.

The authorized operator group is `repocache-admin`, distinct from the
unprivileged service account `repocache`. Verify its membership and the
fixed root-owned AF_UNIX control socket (`/run/repocache/server-control.sock`:
root:repocache-admin, mode 0660). Group admission is a separate, logged
administrator decision; do not grant sudoers or broad systemctl rights.
Review effective memberships in a **new** login session after any change.
The systemd socket is intentionally **static/non-enableable**: explicitly
starting it after approval is not enabling it for boot. No installation or
repair command may silently start or enable it. The one-shot service is
root-owned and limited to `APPLY_V2`, `RELOAD_V2` and
`RECOVER_V2` with fixed arguments; the client cannot select an
executable, path, unit, environment, raw command or shell.

For a separately authorized already-installed managed deployment:

~~~sh
/usr/bin/systemctl is-enabled repocache-control.socket
/usr/bin/systemctl is-active repocache-control.socket
/usr/bin/systemctl show repocache-control.socket -p FragmentPath -p DropInPaths
/usr/bin/systemctl show repocache-control.service -p FragmentPath -p DropInPaths
/usr/bin/getent group repocache-admin
/usr/bin/getent passwd repocache
~~~

Review the fixed installed units and host-native security evidence before
starting the socket. To authorize **only that installed socket** under the
existing OS administration boundary, a root administrator may separately
start it with `systemctl start repocache-control.socket`; the user-group
membership and kernel peer credentials still control subsequent access.
There is no auto-enablement and no generic privilege escalation. On
AlmaLinux 10, require `getenforce` to report `Enforcing` and inspect
actual worker/socket labels and denials rather than inferring SELinux
acceptance merely from a green container CI check.

**Immediate revocation** is a separately authorized root administrator action:
stop `repocache-control.socket` and, if necessary, its one-shot service;
remove the individual from `repocache-admin` using the distribution's
approved account-management procedure, and invalidate the individual's
existing login sessions so cached supplementary group membership cannot
continue to authorize requests. Do **not** delete native journals, worker
receipts, TLS material, cache directories or managed NGINX includes as a
revocation shortcut. Revoking access or stopping the socket never implies
that a previously dispatched transaction rolled back; inspect durable state
before changing anything else.

**Noninteractive recovery**, after authorized installation and separate
socket activation, is `repocache deployment rollback --yes` (or `--json`).
It only invokes `RECOVER_V2` for a pending **native v2 WAL**:
`RECOVERED` or `CLEAN` are exact confirmed results. Missing socket,
wrong membership, unsafe unit/worker, invalid NGINX, foreign configuration,
lost reply or unverifiable state must refuse without fallback to direct
systemctl. A lost reply is **unknown**, never permission to retry blindly.
This action does not undo a completed release or replay native APT/DNF;
after an interrupted package manager, retain the persistent mask and
package-effects journal for explicit privileged offline reconciliation.
Repeat only read-only inspections until the operator has separately proven
the exact package, unit, filesystem and journal state.

**Compatibility and rollback limits:** support only clean initial v0.6.0
installations on Debian 13 and AlmaLinux 10 x86_64, plus same-version managed
v0.6.0 repair. Do not adopt legacy v1, v0.4.0 deployments, foreign NGINX or
third-party service units. A failed NGINX syntax/reload/health check must
retain or recover the last known-good protected generation and active-only
catalog. Real native APT/DNF effects are not universally atomic and cannot
be declared undone from a successful JSON WAL recovery. The exact-head booted
QEMU campaign and original issue checklist are the acceptance evidence; a
synthetically signed fixture must not be called a published release.
