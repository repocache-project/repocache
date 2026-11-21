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

## Actual installed worker: pinned synthetic #249 prerequisite, never publisher acceptance

The native guest now additionally receives a disposable **exact-source combined
tree**: the current PR #237 HEAD plus the *read-only, pinned* #249 source
`fba69bc8baad0dc6b5d6be7d59812572928f5efa`. The CI runner uses a
throwaway Git worktree and records all three identities (PR head, dependency,
ephemeral local merge). It refuses an unexpectedly moved dependency. There is
**no GitHub merge, queue operation, publisher signing or production key**.

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
