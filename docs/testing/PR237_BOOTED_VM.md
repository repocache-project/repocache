# PR #237 — experimental booted GitHub-hosted VMs

**Scope:** PR #237 only. Non-required CI job; no release or production approval.
The matrix boots actual pinned Debian 13 and AlmaLinux 10 x86_64 cloud images
as full QEMU VMs on separate ubuntu-24.04 GitHub-hosted runners. Image URLs
are upstream HTTPS, build numbers fixed, and independently recorded SHA
digests are mandatory and fail closed. Debian SHA512 is recorded from the
Debian Cloud Image Finder exact build; Alma SHA256 is published on the
official AlmaLinux current x86_64 GenericCloud download page. Never silently
update the image or accept a mismatch.

The job probes /dev/kvm and labels real KVM versus QEMU TCG fallback.
GitHub does not officially support nested virtualization on standard runners.
A guest-specific ephemeral Ed25519 SSH key is used through a loopback-only
SSH forward. Neither the secret key nor the cloud-init seed nor a VM disk is
uploaded. Test artifacts are bounded and have 7-day retention.

Evidence includes actual guest OS/kernel, systemd PID1, SELinux enforcing
on AlmaLinux, root/manager, stock signed-distro NGINX APT/DNF installation,
masked/inactive service, distinct kernel boot IDs after a guest reboot,
mask persistence, systemd start/stop, local HTTP, and existing #237
journal/package-owner fixture tests on the booted system.

**NOT VERIFIED** even if green: owner-signed REPOCACHE installer/worker,
v2 native product transaction, interrupted installed-product recovery, safe
same-version repair, TLS/cache/log preservation, foreign service recovery,
real publisher trust, production safety and broader milestone gates. Stock
NGINX smoke and fixture tests must never be called signed-host acceptance.
All package manager operations are restricted to the disposable guests;
no host service is changed and no third-party action is used.

Failure at boot/image/cloud-init/SELinux/package-test stage is reported as
FAIL or NOT VERIFIED with stage-specific logs, not silently skipped. Keep
this an experiment until the maintainer decides whether to extend it.

## Expanded native host security and failure injection

After the guest boots and reboots with a masked, inactive service, a
separate real-host exercise performs the **actual REPOCACHE read-only native
root/PID1/user-namespace/mount preflight** (not a mocked function), the
distro package-owner and installed-file-integrity checks, and the exact
vendor systemd NGINX unit inventory. It injects a temporary foreign unit
drop-in and requires the actual vendor inspector to **refuse**, then removes
the drop-in without loading it into PID1.

With the stock NGINX service running, it creates one exclusively named
invalid configuration include under /etc/nginx/conf.d in the disposable
VM, requires genuine nginx -t AND systemctl reload to fail, and asserts the
previous NGINX master PID and local HTTP response are unchanged. After
removing only that include, successful syntax/reload and repeated package
and unit integrity are mandatory. These are **live stock-NGINX failure
tests**, not the complete signed REPOCACHE v2 APPLY/RECOVER transaction or a
claim that service drop-in drift was actually loaded by systemd.

Safety: the test fails without writing if a foreign drop-in or test include
already exists, verifies a QEMU/KVM booted guest, PID1 systemd and the
pr237-ci image context, and runs privileged mutations exclusively in that
discarded guest. It never installs or starts the REPOCACHE worker. If the
negative scenario fails, the workflow must fail rather than silently
falling back to fixture-only acceptance.

## Two actual guest reboots and persistent *synthetic* pending journal

After the live NGINX syntax/reload/foreign-unit exercises, the independent
native guest fixture calls the real protected-namespace bootstrap and the real
exclusive-lock durable package-journal preparer against the guest's fixed
/var/lib/repocache/server path. It **does not invoke APT/DNF in this phase**
and is **not** a recovery of an actual package-manager interruption. The
fixture intentionally records a synthetic pending marker and masks NGINX,
reboots the guest kernel **again**, and verifies:

- A changed second kernel boot ID and intact root-owned pending marker,
  inode and canonical contents, with mode 0600 and a retained state lock.
- A persistent NGINX mask and inactive service after the second reboot.
- Two genuine calls to the protected native journal preparer refuse
  re-entry and preserve the original marker bytes, inode and metadata.

This demonstrates the fail-closed *journal persistence and retry refusal*
mechanics under real systemd reboot. It does **not** prove rollback of native
APT/DNF side effects, owner-signed installed worker, REPOCACHE v2 transaction
recovery or production service behavior. A genuine interrupted package
manager acceptance case remains NOT VERIFIED. No marker is cleared: the
entire VM is discarded after the experiment.

## Actual installed worker: pinned synthetic fixture using integrated #249, never publisher acceptance

PR #249 was squash-merged into protected `integration/v0.6.0` on
2026-11-22 as commit
`69b13b8882560b29515ec2405463b70e40c8aa44`. Its historical PR
source HEAD `0ca54da8dc5d73b2df892ecf8551110c36340794` is **not**
the commit to use for protected-branch ancestry checks. The VM runner now
fetches the protected integration ref, requires that exact accepted merge
commit to be an ancestor, and locally combines it with the current PR #237
HEAD in a throwaway Git worktree. It records three identities: current PR
HEAD, accepted integration commit, and ephemeral merge. It does not rely on
the mutable/deletable #249 source branch. There is **no additional GitHub
merge, queue operation, publisher signing or production key**.

Only after the actual full-VM kernel/systemd/NGINX tests, the guest generates
its own short-lived **synthetic Ed25519 private key** and host trust anchor,
builds the exact v0.6.0 candidate from the assembled source inventory and
uses the unchanged real root installer to exercise:

- Explicit invalid detached Ed25519 signature refusal before any persistent
  worker, unit or namespace placement.
- Real authenticated worker and two root-owned systemd unit files installed
  at the actual fixed Linux paths, followed by a full signed readback.
- Second real installer call with exact unchanged inode, timestamps and bytes.
- Corrupted installed unit bytes refused; restored bytes independently match.
- A systemd daemon reload observing the installed units **without starting,
  enabling, masking or exposing any REPOCACHE control service**.

Synthetic asset key material stays in the disposable guest, never Actions
artifacts. The later test-only journal phase reuses the already created
protected namespace with its exact empty completed placement marker, rather
than creating an unrelated fixture namespace. These results are credible
**native installed-worker mechanics with synthetic trust**, not real signed
publisher release acceptance, authorization to activate services, production
rollback or proof of enforcing SELinux for the worker.

The final post-reboot check also runs a **fresh isolated signed-worker CLI
process** on the verified temporary assets, confirms exact signed installed
worker and unit readback still PASS, and proves neither REPOCACHE control
service/socket is active. The signing key is synthetic and was erased from
the guest after creating the detached signature.

## First actual native APT/DNF installation through the signed-worker entrypoint

A separate two-distro `native-installer` matrix scenario boots a **fresh**
second guest (no existing NGINX). It reuses the same pinned official qcow2
images and exact SHA-prerequisite synthetic Ed25519 fixture described above.
The source branch and package manager are never executed on the GitHub runner.

After installing the authenticated worker's real fixed executable and two
systemd unit files, the guest obtains the reviewed example install-v1 document
from the same pinned source. The real
`install_authenticated_native_nginx(...)` Python host-root entrypoint is
called rather than a test substitute. The guest first sends an intentionally
wrong document SHA-256 and checks there are **no NGINX package effects or
native pending markers**. For the positive path, it requires the genuine
native APT/DNF package transaction, root lock, persistent mask/no autostart,
strict package database/file integrity and vendor-unit checks, signed-fixture
worker readback and durable canonical package-completion receipt. Re-running
the exact fresh installation must refuse with no new package effects.

The guest then reboots its actual kernel, and requires the native receipt to
retain its SHA-256, the same synthetic installed worker to verify, NGINX to
remain disabled/inactive, and the REPOCACHE control service/socket to remain
inactive. The independent `smoke` scenario still tests a live stock NGINX
HTTP reload failure and repeated journal recovery refusal. Neither path
exercises real publisher signing, production activation, deployed v2 APPLY,
safe same-version repair with TLS/cache/log retention, or actual hard-power
loss mid-APT/DNF. These remain NOT VERIFIED until separately run and accepted.

The package scenario is deliberately **non-required** and limited to PR #237.
A failure is a FAIL for this experiment and must be investigated rather than
interpreted as a permission to bypass native checks.

## Native process-name compatibility boundary

The real native first-package installer correctly refused to proceed on
Debian 13 because its NGINX process scanner encountered a **43-byte**
kernel /proc/PID/comm record and required at most 32 bytes. Two reproducible
QEMU runs recorded the failure; root/systemd, signed OS trust anchor and
generation-zero protected state checks independently passed.

The scanner now accepts **at most 64 bytes**, maintaining its previous
bounded first read and mandatory second-read overflow refusal. It does not
ignore inaccessible process records or a running NGINX task. Focused tests
cover benign 43/64-byte names, refusal beyond 64 bytes and positive
detection of long nginx-prefixed names. This source change needs exact-HEAD
CI and native Debian acceptance before being counted as PASS.

## Post-install native v2 proposal staging (synthetic trust, no activation)

After the **real** signed-fixture root installer completes native APT/DNF,
issues a protected completion receipt, and survives an actual kernel reboot,
the guest prepares an initial generation-one proposal from the exact reviewed
install-v1 example through the authenticated source verifier. A wrong proposed
SHA must be refused **before** any root-owned proposal is written. The
correct reviewed SHA is staged using the real installed worker verifier and
the existing protected v2 state lock. A second identical call must preserve
the exact staged envelope inode, timestamp and bytes. The package receipt
must remain unchanged, no committed state-v2 or pending native WAL may exist,
and NGINX/REPOCACHE service/socket units must remain inactive.

This is **not** live `APPLY_V2` or `RECOVER_V2`. The proposal is a
synthetic-key-authorized test candidate, not an owner-published release or
external operator approval. The original operational repair, TLS/cache/log
preservation, SELinux worker enforcement and real publisher gates remain open.

## Native post-reboot completion receipt integrity refusal

The separate `native-installer` VM case now invokes the **actual protected
lock and native package completion receipt reader** against the real
root-owned `/var/lib/repocache/server` directory, after native APT/DNF
install, guest kernel reboot, and signed-fixture proposal staging. It proves
that the stored audit explicitly does **not** claim publisher signing or a
booted production service. The disposable guest then changes exactly the
`native_package_file_integrity_verified` field from true to false, requires
the real closed-schema reader to refuse the forged receipt, and proves that
the existing proposal, state/WAL absence and NGINX service state are preserved.
The original receipt is restored and rechecked byte-for-byte with the durable
pre-fault SHA-256; the VM is discarded afterwards.

The same guest also calls the **actual non-fixture APPLY/RELOAD package-audit
gate** with a real protected state FD, before corruption, during corruption and
after restoration. It requires the gate to refuse the altered receipt before
any candidate activation; no apply/reload itself is invoked.

This deliberately tests the real file validator and protected lock, **not**
the full installed-worker `APPLY_V2` execution or failover after an interrupted
APT/DNF transaction. It creates no new activation or recovery authority.


## Experimental installed native socket APPLY/RELOAD/RECOVER lifecycle

The \`native-installer\` VM scenario now attempts a **separate, real
socket-activated systemd transaction** after the native APT/DNF installation,
reboot, proposal staging and audited receipt tamper/restoration exercise.
This is not a fixture call to \`_apply_locked\`: the test connects through
\`request_native_fixed_v2\` over the real root-owned AF_UNIX SOCK_SEQPACKET
socket to the **installed signed-fixture zipapp**. The kernel supplies
SO_PEERCRED/SO_PEERGROUPS, and the actual worker enforces fixed operation
selection. Both \`repocache\` and \`repocache-admin\` test identities are
provisioned only within the disposable guest; the socket remains disabled
for boot and is explicitly started for this test.

The guest creates an ephemeral CA and hostname-valid TLS leaf/key,
adds the synthetic CA to its *own* OS trust store, and uses the fixed
\`cache.example.invalid\` test document. Signing keys never leave the VM,
and no production trust store is touched. The expected live acceptance is:
\`RECOVER_V2/CLEAN\` before activation, \`APPLY_V2/APPLIED\` generating
the NGINX include/state/catalog, real systemd reload, independently verified
local TLS generation and catalog, \`RELOAD_V2/RELOADED\`, idempotent
\`APPLY_V2/UNCHANGED\` and \`RECOVER_V2/CLEAN\`; verify stable inode,
mtime and SHA-256 of all managed resources and TLS assets, no pending WAL,
and disabled/stopped units afterward. AlmaLinux must retain SELinux Enforcing.

The PR237 CI experiment **must actually run and pass both VM jobs at the
new exact HEAD** before any of the new native-transaction criteria can
be marked PASS. Failure is a blocker requiring diagnosis, not a skipped
validation or permission to disable SELinux. Even a PASS demonstrates only
**synthetically signed guest installation**; interrupted power-loss
recovery, same-version repair, foreign file preservation, SELinux negative
policy tests, release publisher signing and production acceptance remain
separate NOT VERIFIED criteria.


### Partial same-version native v0.6 repair and genuine failed-apply WAL recovery

The PR237-only guest now prepares an authenticated **generation-two partial
configuration repair** from the actually committed generation-one state. It
changes a deployment retention setting while retaining all repository IDs and
the native worker. The real installed worker/socket attempts a second
\`APPLY_V2\`, then a real \`RELOAD_V2\`, idempotent \`APPLY_V2\`, and
\`RECOVER_V2/CLEAN\`. The guest checks nonempty synthetic cache, log and
metrics files and the genuine TLS certificate/key by SHA-256, inode and mtime.
A directory merely existing is not accepted as preservation evidence.

The installed guest now **re-runs the identical signed-fixture worker and unit
placement after generation two is live**, asserting unchanged hashes, inodes,
mtimes, owner/mode and current HTTPS response. Re-entry into the separate
**fresh-install-only APT/DNF** operation must refuse with the exact native
prepackage boundary code and no new journal, package effects, service reload,
managed-state change or TLS/cache/log/metrics loss. This is bounded repeat
installation safety; it does **not** claim that a currently unsupported complete
same-version deployment installer command was successfully executed.

A further reviewed synthetic generation-three proposal deliberately meets an
invalid foreign NGINX directive during the **real installed apply**, after
the native v2 WAL is published. The expected refusal must leave a recoverable
root-owned WAL and the previous generation still answering HTTPS. After
removing only the test-owned invalid include, the guest persists a separate
root-owned, fsynced test record of the WAL inode/hash/mtime and prior managed,
unmanaged and preservation digests, then performs an **actual kernel reboot**.
The independent post-reboot process proves a different boot identity and the
unchanged durable WAL, starts only the already-installed disabled vendor
NGINX and fixed control socket, and invokes the installed
\`RECOVER_V2\` operation. It must restore the exact previous managed
digests and live generation-two HTTPS exposure; repeated recovery must be
CLEAN, real reload must pass, and synthetic TLS/cache/log/metrics contents and
unmanaged NGINX files must remain intact.
Because recovery may atomically replace files, only content digests (not
necessarily inode identity) are required across the rollback.

The script also confirms the installed socket refuses the unprivileged
\`repocache\` service UID at the kernel permissions boundary and keeps both
control and NGINX units disabled for boot. Requests are spaced to respect
the unchanged systemd one-shot service start-rate limit; the test never
modifies that limit or bypasses the kernel credential check.

**Evidence status: NOT VERIFIED until the exact source SHA passes both booted
VM jobs**. This is a real OS/socket/transaction experiment using synthetic
keys, with a real reboot between a failed v2 WAL transaction and recovery;
it is not publisher signing, a simultaneous hard-power cut during the WAL
write, production approval, or a complete same-version installer
reinstatement test. On failure, preserve stage-specific errors; never
reinterpret the desired outcomes as observed PASS.


## Real disposable APT/DNF manager interruption (separate two-distro matrix)

The experimental native VM matrix has two additional **independent fresh
guests** with scenario \`native-package-interruption\`. Neither shares the
successful installed-server disk. Each uses the same official immutable
Debian 13 / AlmaLinux 10 image pins, prepares the authenticated synthetic
signed-source worker and native first-install document, then invokes the
**unmodified real native NGINX package installer in a child process**.

The guest supervisor only targets a verified **direct child of that exact
installer process**, independently matching the native APT or DNF executable
(and DNF4 Python script interpreter when applicable). It sends actual
SIGKILL during the package-manager command, asserts the install process
reports failure, and confirms the manager's genuine durable pending journal
and masked/inactive NGINX service. After a real guest kernel reboot, it
requires the *same journal inode, timestamp and SHA-256*, no completed
receipt, disabled control services, preserved mask and two genuine
journal-reentry refusals without removing or rewriting the marker.
The same guest now retries the **actual signed-fixture first-install entrypoint**
after reboot with the identical reviewed document and source digest. It must
return the fixed prepackage refusal before any fresh APT/DNF execution and
preserve the native journal bytes/inode/mtime, masked inactive NGINX and
inactive worker services. A private journal-reader refusal alone is not
treated as proof that the installed public entrypoint is fail-closed.

This **does not simulate a complete host power loss**: the package-manager
process is forcibly terminated, while the kernel and native installer
supervisor initially remain alive. The separate actual guest reboot proves
durability of the ambiguous state; it is not the same as power interruption
during a native transaction. The test never claims rollback of partly
written APT/DNF databases, automatic repair or publisher trust. Because
the approved native installer contract is fail-closed, its expected outcome
is **refusal pending operator reconciliation**, not unsafe automatic retry.

The native interruption acceptance is NOT VERIFIED until both extra jobs
are completed and their evidence inspected at the same exact source SHA.
The matrix remains PR237-only, non-required, secret-free and disposable.


## Fixed native NGINX cache directory required by the systemd sandbox

Actual AlmaLinux 10 native VM execution exposed a missing provisioning step:
the independently authenticated native package installer could complete with
no \`/var/cache/nginx\` directory, while the unchanged signed control service
requires it as one of its exact \`ReadWritePaths\`. On socket activation,
systemd correctly refused the worker *before execution* with
\`ExecMainStatus=226/NAMESPACE\`; the client returned
\`NATIVE_ROOT_CLIENT_OUTCOME_UNCONFIRMED\` rather than inventing transaction
success. The same source path is tested on Debian 13.

Under the existing durable native package lock, and only after an audited
APT/DNF NGINX install plus verified vendor unit, the native installer now
ensures the **single fixed cache parent** exists with root:root ownership
and mode 0755 **before writing the completed package receipt**. It opens
\`/\`, \`/var\`, \`/var/cache\` and \`nginx\` with no-follow descriptor-relative
operations, refuses foreign symlinks/files, unsafe owner/mode or mount drift,
and fsyncs an exclusively created directory and parent. An existing safe
directory and its cache contents are never replaced or altered. The original
systemd \`ReadWritePaths\`, isolation and fail-closed service definition
remain byte-for-byte unchanged; no privileged socket or service is enabled
by this installer. If this step fails, the pending native journal remains
for operator reconciliation rather than marking the installation complete.

New source tests cover clean creation, repeated idempotency, preservation of
existing nonempty files, and refusal of unsafe parent paths and foreign
cache inode types/modes. The booted native installer scenarios verify the
actual root-owned cache directory both before and after reboot. No PASS
is claimed for this correction until **exact current HEAD** source and
booted-VM CI complete on both supported OS targets. Publisher signing,
SELinux installed-worker deny tests and full issue #31 acceptance remain
independent prerequisites.

## Installed worker path substitution refusal (native #64 evidence)

The existing synthetic-signed native worker placement scenario now checks an
actual **root-owned installed executable** path substitution on the booted
disposable guest, in addition to the previously tested unit-file byte drift.
After initial placement and successful signed-fixture readback, the test moves
only the installed fixed worker to a uniquely named temporary sibling and
replaces its canonical path with a symlink to that sibling. The unchanged real
`verify_installed_worker` auditor must refuse the symlink; its descriptor-
pinned, no-follow asset reader rejects non-regular installed paths.

The test then restores the original installed worker inode and mtime, requires
the complete authenticated installed worker/unit readback to PASS, and proceeds
to the existing systemd and reboot tests. An unexpected replacement or
restoration mismatch fails the guest rather than being ignored. This is one
narrow native helper-path substitution refusal using a **synthetic signing
key**; it is neither a complete privileged-path attack matrix nor real
publisher-signed candidate acceptance. See `synthetic-installed-worker.txt`
in each relevant VM artifact; judge PASS only at the exact tested source SHA.

## First-install foreign state refused before native package-effects journal

The authenticated first-install path now checks the fixed NGINX package
footprint, trusted native OS signing anchor and fixed service mask under the
single protected lock *before* creating a persistent APT/DNF effects journal.
These are refusal-only observations, not authorization. The checks are
repeated after journal publication before any irreversible package operation;
a concurrent replacement remains fail-closed with its WAL retained.

The `native-installer` QEMU guest injects an externally owned NGINX file on
an otherwise clean host and requires the installer to refuse without changing
its bytes/inode/mode/mtime, starting services, installing packages or writing
a pending journal. Only that disposable guest file is removed. Debian 13 and
AlmaLinux 10 run the same negative. Root-lock regression tests ensure a
pre-journal refusal leaves the host eligible for a later clean attempt.
This is bounded native/CI evidence only, not publisher acceptance.

The same `native-installer` QEMU scenario also introduces a **valid canonical
state-v1 generation** into the existing protected root, invokes the actual
signed-fixture native installer, and requires the fixed legacy-state refusal
before any native APT/DNF package or systemd effect. It compares the legacy
file's inode, owner, mode, mtime and exact bytes, checks for absence of the
native-effects journal and NGINX executable, then removes only the original
test-created inode. This is a booted Debian/Alma negative for #31's unsupported
older-state refusal, **not** a v0.4-to-v0.6 migration or publisher acceptance.

## Native vendor NGINX and foreign include preservation (issue #31)

The installed-worker `native-installer` VM scenario now records the vendor
`/etc/nginx/nginx.conf` (and `mime.types`, when installed) before its first
v2 apply. It compares file hashes, device/inode identities, modification times,
ownership and modes after an idempotent reload, a generation-two same-version
repair and a real journal-backed recovery. Both Debian 13 and AlmaLinux 10
must retain the original global files exactly.

After generation one is live, the disposable guest also replaces the single
REPOCACHE-managed NGINX include temporarily with a symlink to its original
inode. The installed privileged worker must refuse `RELOAD_V2` without
following that foreign replacement, creating a WAL, changing published state
or disturbing the live TLS health endpoint. The test restores the original
include inode and mtime, verifies its original hash, then requires normal
authenticated reload to succeed. Only the temporary guest-owned symlink is
removed; no user-owned or real host configuration is modified.

This is **bounded booted-VM Stage B evidence** for vendor config preservation
and one managed-resource drift refusal, not proof of every foreign-state,
owner-signed installed-product or production release acceptance criterion.

## Installed raw-packet unit-injection refusal (native #64 evidence)

The `native-installer` scenario additionally sends one 30-byte raw
AF_UNIX SOCK_SEQPACKET request directly to the installed root-owned systemd
worker, bypassing the unprivileged client's local operation allowlist. Its
first command is the otherwise valid `reload-v2` token, followed in the
**same packet** by an attacker-selected `unit=sshd.service` field. The
real installed broker must close the connection without returning a successful
reply. No additional operation, arbitrary unit selection or fallback command
is permitted.

The same guest also forks a real `repocache` service-UID process, drops all
supplementary groups and attempts to open the root-owned synthetic TLS private
key using `O_NOFOLLOW`. A kernel `EACCES` denial is required; an unexpected
successful read or other OS error fails the test. This is a narrow native
file-permission negative, not proof of all privileged-file protections.

The test then independently compares the durable managed-state, NGINX
include, published catalog, TLS generation response and absence of a pending
WAL to their earlier values. A subsequent legitimate `RELOAD_V2` request
through the exact same installed socket must succeed without changing the
managed snapshot. This is meaningful booted-OS evidence for *one specific*
#64 malformed-input refusal, on both disposable Debian 13 and enforcing
AlmaLinux 10 guests. It is **not** a complete #64 adversarial matrix, nor
owner-signed/released worker acceptance.

The relevant stage output is saved as `native-socket-v2.txt` inside each
per-platform `native-installer` workflow artifact, with source HEAD and
the pinned synthetic candidate in the adjacent provenance records. A green
workflow on a *different* HEAD is not acceptance for this test.
