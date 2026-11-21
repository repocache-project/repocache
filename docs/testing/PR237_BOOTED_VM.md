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
